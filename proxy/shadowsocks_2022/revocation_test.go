package shadowsocks_2022_test

import (
	"context"
	"encoding/base64"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestRemoveUserSharedUDPSessionID(t *testing.T) {
	ctx := newTestContext()
	master := []byte("0123456789abcdef")
	in, err := ss.NewMultiServer(ctx, &ss.MultiUserServerConfig{
		Method: ss.MethodAES128GCM, Key: base64.StdEncoding.EncodeToString(master),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &protocol.MemoryUser{Email: "A", Account: &ss.MemoryAccount{Key: []byte("abcdefghijklmnop")}}
	b := &protocol.MemoryUser{Email: "B", Account: &ss.MemoryAccount{Key: []byte("ponmlkjihgfedcba")}}
	add := func(u *protocol.MemoryUser) {
		t.Helper()
		if err := in.AddUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	add(a)
	add(b)
	type event struct {
		user  string
		msg   string
		reply *pipe.Writer
	}
	received := make(chan event, 8)
	dispatcher := &dummyDispatcher{onDispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		email := session.InboundFromContext(ctx).User.Email
		r, w := pipe.New()
		return &transport.Link{Reader: r, Writer: &customWriter{write: func(mb buf.MultiBuffer) error {
			defer buf.ReleaseMulti(mb)
			received <- event{email, mb.String(), w}
			return nil
		}}}, nil
	}}
	c, srv := stdnet.Pipe()
	processDone := make(chan struct{})
	go func() {
		defer close(processDone)
		_ = in.Process(ctx, net.Network_UDP, &dummyStatConn{Conn: srv}, dispatcher)
	}()
	t.Cleanup(func() {
		_ = c.Close()
		_ = srv.Close()
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
			t.Error("Shadowsocks UDP ingress did not stop")
		}
	})
	const sid = 19
	send := func(u *protocol.MemoryUser, packet uint64, msg string) {
		t.Helper()
		wire, err := encodeRelayClientUDPPacket(master, u.Account.(*ss.MemoryAccount).Key, sid, packet, net.UDPDestination(net.LocalHostIP, 80), []byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(u *protocol.MemoryUser, msg string) *pipe.Writer {
		t.Helper()
		select {
		case e := <-received:
			if e.user != u.Email || e.msg != msg {
				t.Fatalf("got %s %q; want %s %q", e.user, e.msg, u.Email, msg)
			}
			return e.reply
		case <-time.After(2 * time.Second):
			t.Fatalf("missing packet %s %q", u.Email, msg)
			return nil
		}
	}
	send(a, 1, "first")
	old := expect(a, "first")
	send(b, 1, "same sid and packet id")
	bReply := expect(b, "same sid and packet id")
	if err := in.RemoveUser(ctx, a.Email); err != nil {
		t.Fatal(err)
	}
	if err := old.WriteMultiBuffer(buf.MergeBytes(nil, []byte("retired"))); err == nil {
		t.Fatal("retired account retained UDP dispatch link")
	}
	send(a, 2, "retired packet")
	send(b, 2, "still here")
	if bReply != expect(b, "still here") {
		t.Fatal("removing A replaced B's UDP association")
	}
	add(a)
	send(a, 1, "new generation")
	if expect(a, "new generation") == old {
		t.Fatal("new generation inherited retired association")
	}
	if err := in.RemoveUser(ctx, a.Email); err != nil {
		t.Fatal(err)
	}
	if err := in.RemoveUser(ctx, b.Email); err != nil {
		t.Fatal(err)
	}
}
