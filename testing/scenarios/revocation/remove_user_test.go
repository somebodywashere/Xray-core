package revocation_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// Each stream is carried by a real VLESS TCP mux connection. Observe both
// ends: a local EOF alone would not detect a leaked destination socket.
func TestAlterInboundRevokesOnlyRegisteredAccount(t *testing.T) {
	const a = "11111111-1111-4111-8111-111111111111"
	const b = "22222222-2222-4222-8222-222222222222"
	start := func(config string) *core.Instance {
		t.Helper()
		inst, err := core.StartInstance("json", []byte(config))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { inst.Close() })
		return inst
	}
	listen := func() *net.TCPListener {
		t.Helper()
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l.(*net.TCPListener)
	}
	port := func() int {
		l := listen()
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	in := func(tag string, port int) string {
		return fmt.Sprintf(`{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":%q,"email":"a@test"},{"id":%q,"email":"b@test"}]}}`, tag, port, a, b)
	}
	var ports [4]int
	var reserved []*net.TCPListener
	for i := range ports {
		l := listen()
		reserved = append(reserved, l)
		ports[i] = l.Addr().(*net.TCPAddr).Port
	}
	for _, l := range reserved {
		l.Close()
	}
	apiPort, p1, p2, p3 := ports[0], ports[1], ports[2], ports[3]
	const allow = `{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]},{"action":"block"}]}}`
	instance := start(fmt.Sprintf(`{"api":{"tag":"api","listen":"127.0.0.1:%d","services":["HandlerService"]},"inbounds":[%s,%s],"outbounds":[%s]}`, apiPort, in("one", p1), in("two", p2), allow))
	start(fmt.Sprintf(`{"inbounds":[%s],"outbounds":[%s]}`, in("one", p3), allow))
	api, err := grpc.NewClient(fmt.Sprintf("passthrough:///127.0.0.1:%d", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	alter := func(op proto.Message) {
		t.Helper()
		_, err := command.NewHandlerServiceClient(api).AlterInbound(ctx, &command.AlterInboundRequest{Tag: "one", Operation: serial.ToTypedMessage(op)})
		if err != nil {
			t.Fatal(err)
		}
	}
	l := listen()
	defer l.Close()
	client := func(serverPort int, id string) string {
		proxyPort := port()
		start(fmt.Sprintf(`{
			"inbounds":[{"protocol":"tunnel","listen":"127.0.0.1","port":%d,"settings":{"address":"127.0.0.1","port":%d,"network":"tcp"}}],
			"outbounds":[{"protocol":"vless","settings":{"address":"127.0.0.1","port":%d,"id":%q,"encryption":"none"},"mux":{"enabled":true,"concurrency":8}}]
		}`, proxyPort, l.Addr().(*net.TCPAddr).Port, serverPort, id))
		return fmt.Sprintf("127.0.0.1:%d", proxyPort)
	}
	type stream struct{ local, remote net.Conn }
	dial := func(address string) net.Conn {
		t.Helper()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		if _, err := conn.Write([]byte("a")); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	open := func(c string) stream {
		t.Helper()
		local := dial(c)
		l.SetDeadline(time.Now().Add(4 * time.Second))
		remote, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { remote.Close() })
		remote.SetDeadline(time.Now().Add(4 * time.Second))
		var buf [1]byte
		if _, err = io.ReadFull(remote, buf[:]); err != nil || buf[0] != 'a' {
			t.Fatalf("target read: %q, %v", buf, err)
		}
		return stream{local, remote}
	}
	check := func(s stream) {
		t.Helper()
		s.remote.SetDeadline(time.Now().Add(3 * time.Second))
		s.local.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := s.remote.Write([]byte("b")); err != nil {
			t.Fatal(err)
		}
		var buf [1]byte
		if _, err := io.ReadFull(s.local, buf[:]); err != nil || buf[0] != 'b' {
			t.Fatalf("surviving stream: %q, %v", buf, err)
		}
	}
	closed := func(c net.Conn) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var buf [1]byte
		_, err := c.Read(buf[:])
		if err == nil {
			t.Fatal("removed user received data")
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("removed user's stream remained open: %v", err)
		}
	}

	ca := client(p1, a)
	first, second := open(ca), open(ca)
	survivors := []stream{open(client(p1, b)), open(client(p2, a)), open(client(p3, a))}
	alter(&command.RemoveUserOperation{Email: "a@test"})
	for _, s := range []stream{first, second} {
		closed(s.remote)
		closed(s.local)
	}
	for _, s := range survivors {
		check(s)
	}
	closed(dial(client(p1, a)))
	alter(&command.AddUserOperation{User: &protocol.User{Email: "a@test", Account: serial.ToTypedMessage(&vless.Account{Id: a})}})
	readded := open(client(p1, a))
	check(readded)

	// Hold a cleanup callback open while adding the same credential again.
	// The previous Remove must neither block registration nor affect its sockets.
	handler, err := instance.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	user := handler.(proxy.GetInbound).GetInbound().(proxy.UserManager).GetUser(ctx, "a@test")
	started, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	release, ok := user.Sessions.Track(func() { close(started); <-resume })
	if !ok {
		t.Fatal("current generation already revoked")
	}
	defer release()
	removed := make(chan error, 1)
	go func() {
		_, err := command.NewHandlerServiceClient(api).AlterInbound(ctx, &command.AlterInboundRequest{Tag: "one", Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "a@test"})})
		removed <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	alter(&command.AddUserOperation{User: &protocol.User{Email: "a@test", Account: serial.ToTypedMessage(&vless.Account{Id: a})}})
	replacement := open(client(p1, a))
	unblock()
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	closed(readded.remote)
	check(replacement)
}
