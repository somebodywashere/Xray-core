package inbound

import (
	"crypto/mlkem"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
)

// Record the deadlines visible to the first header read and to the established
// stream. The handler owns this connection throughout the handshake.
type handshakeDeadlineConn struct {
	stdnet.Conn
	read, write        time.Time
	firstRead, bounded bool
}

func (c *handshakeDeadlineConn) SetDeadline(d time.Time) error {
	c.read, c.write = d, d
	return c.Conn.SetDeadline(d)
}

func (c *handshakeDeadlineConn) SetReadDeadline(d time.Time) error {
	c.read = d
	return c.Conn.SetReadDeadline(d)
}

func (c *handshakeDeadlineConn) SetWriteDeadline(d time.Time) error {
	c.write = d
	return c.Conn.SetWriteDeadline(d)
}

func (c *handshakeDeadlineConn) Read(b []byte) (int, error) {
	if !c.firstRead {
		c.firstRead = true
		c.bounded = !c.read.IsZero() && !c.write.IsZero()
	}
	return c.Conn.Read(b)
}

func TestEncryptionHandshakeDeadline(t *testing.T) {
	l, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := stdnet.DialTimeout("tcp4", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	trace := &handshakeDeadlineConn{Conn: server}
	schedule := func(s string) []*custom.TCPSequence {
		return []*custom.TCPSequence{{Sequence: []*custom.TCPItem{{Packet: []byte(s)}}}}
	}
	mask := &custom.TCPConfig{Clients: schedule("client"), Servers: schedule("server")}
	cs, err := mask.WrapConnClient(raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := mask.WrapConnServer(trace)
	if err != nil {
		t.Fatal(err)
	}
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{validator: new(vless.MemoryValidator), policyManager: policy.DefaultManager{}, decryption: new(encryption.ServerInstance)}
	if err := h.decryption.Init([][]byte{key.Bytes()}, 0, 0, 0, "100-35-35"); err != nil {
		t.Fatal(err)
	}
	defer h.decryption.Close()
	client := new(encryption.ClientInstance)
	if err := client.Init([][]byte{key.EncapsulationKey().Bytes()}, 0, 0, "100-35-35"); err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(uuid.New())}}
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{})
	if err := h.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	dispatch := new(observeDispatch)
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, net.Network_TCP, ss, dispatch) }()
	enc, err := client.Handshake(cs)
	if err != nil {
		t.Fatal(err)
	}
	req := &protocol.RequestHeader{User: user, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 80}
	if err := encoding.EncodeRequestHeader(enc, req, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VLESS handler did not finish")
	}
	if !dispatch.called || !trace.bounded || !trace.read.IsZero() || !trace.write.IsZero() {
		t.Fatalf("dispatch=%v first read bounded=%v remaining deadlines=%v/%v", dispatch.called, trace.bounded, trace.read, trace.write)
	}
}
