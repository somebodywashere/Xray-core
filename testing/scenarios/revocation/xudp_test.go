package revocation_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Reconnecting the same account reuses the destination socket. Two different
// accounts using the same wire ID get separate sockets; removing A releases
// even its parked socket while B continues receiving replies.
func TestRemoveUserWithSavedXUDP(t *testing.T) {
	ports := [2]int{}
	var reservations []net.Listener
	for i := range ports {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
		ports[i] = l.Addr().(*net.TCPAddr).Port
	}
	for _, l := range reservations {
		l.Close()
	}
	a := &vless.Account{Id: "11111111-1111-4111-8111-111111111111"}
	b := &vless.Account{Id: "22222222-2222-4222-8222-222222222222"}
	config := fmt.Sprintf(`{"api":{"tag":"api","listen":"127.0.0.1:%d","services":["HandlerService"]},"inbounds":[{"listen":"127.0.0.1","port":%d,"tag":"xudp","protocol":"vless","settings":{"decryption":"none","clients":[{"id":%q,"email":"A"},{"id":%q,"email":"B"}]}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]},{"action":"block"}]}}]}`, ports[0], ports[1], a.Id, b.Id)
	s, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	dest := xnet.DestinationFromAddr(target.LocalAddr())
	api, err := grpc.NewClient(fmt.Sprintf("passthrough:///127.0.0.1:%d", ports[0]), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	type flow struct {
		c      net.Conn
		w      *mux.Writer
		r      *xudp.PacketReader
		header *protocol.RequestHeader
		ready  bool
	}
	open := func(user *vless.Account, id byte) *flow {
		t.Helper()
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", ports[1]), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		account, err := user.AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		h := &protocol.RequestHeader{User: &protocol.MemoryUser{Account: account}, Command: protocol.RequestCommandMux}
		if err := encoding.EncodeRequestHeader(c, h, &encoding.Addons{}); err != nil {
			t.Fatal(err)
		}
		return &flow{c: c, w: mux.NewWriter(1, dest, buf.NewWriter(c), protocol.TransferTypePacket, [8]byte{id}, nil), r: xudp.NewPacketReader(c), header: h}
	}
	exchange := func(f *flow, msg string) *net.UDPAddr {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		target.SetDeadline(deadline)
		f.c.SetDeadline(deadline)
		payload := buf.FromBytes([]byte(msg))
		payload.UDP = &dest
		if err := f.w.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			t.Fatal(err)
		}
		var data [128]byte
		n, peer, err := target.ReadFromUDP(data[:])
		if err != nil || string(data[:n]) != msg {
			t.Fatalf("target got %q: %v", data[:n], err)
		}
		if _, err = target.WriteToUDP(data[:n], peer); err != nil {
			t.Fatal(err)
		}
		if !f.ready {
			if _, err := encoding.DecodeResponseHeader(f.c, f.header); err != nil {
				t.Fatal(err)
			}
			f.ready = true
		}
		reply, err := f.r.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		defer buf.ReleaseMulti(reply)
		if reply.String() != msg {
			t.Fatalf("wrong reply %q", reply)
		}
		return peer
	}
	park := func(f *flow) {
		t.Helper()
		f.c.SetDeadline(time.Now().Add(3 * time.Second))
		if err := f.w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.r.ReadMultiBuffer(); err != io.EOF {
			t.Fatalf("closing logical XUDP stream: %v", err)
		}
		f.c.Close()
	}
	first := open(a, 7)
	addrA := exchange(first, "first A")
	park(first)
	second := open(b, 7)
	addrB := exchange(second, "B")
	if addrA.String() == addrB.String() {
		t.Fatal("different users shared a destination socket")
	}
	resumed := open(a, 7)
	if got := exchange(resumed, "resumed A"); got.String() != addrA.String() {
		t.Fatal("A lost its saved UDP socket")
	}
	park(resumed)
	live := open(a, 8)
	addrLive := exchange(live, "active A")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := command.NewHandlerServiceClient(api).AlterInbound(ctx, &command.AlterInboundRequest{Tag: "xudp", Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "A"})}); err != nil {
		t.Fatal(err)
	}
	// Bind both of A's local endpoints to verify that the actual live and
	// parked destination sockets were released by the server.
	for _, address := range []*net.UDPAddr{addrA, addrLive} {
		deadline := time.Now().Add(3 * time.Second)
		for {
			probe, err := net.ListenUDP("udp4", address)
			if err == nil {
				probe.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("UDP socket still held after removal: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if got := exchange(second, "B after removal"); got.String() != addrB.String() {
		t.Fatal("B lost its socket")
	}
}
