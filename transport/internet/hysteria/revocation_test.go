package hysteria

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestRevokeAuthenticatedQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	v := account.NewValidator()
	const authA = "00112233-4455-4677-8899-aabbccddeeff"
	const routedA = "00112233-4455-4001-8899-aabbccddeeff"
	a := &protocol.MemoryUser{Email: "A", Account: common.Must2((&account.Account{Auth: authA}).AsAccount())}
	b := &protocol.MemoryUser{Email: "B", Account: &account.MemoryAccount{Auth: "bravo"}}
	common.Must(v.Add(a))
	common.Must(v.Add(b))
	c, _ := cert.MustGenerate(nil)
	tlsCfg := &tls.Config{NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{
		Certificate: [][]byte{c.Certificate}, PrivateKey: common.Must2(x509.ParsePKCS8PrivateKey(c.PrivateKey)),
	}}}
	quicCfg := &quic.Config{EnableDatagrams: true}
	l := common.Must2(quic.ListenAddr("127.0.0.1:0", tlsCfg, quicCfg))
	defer l.Close()
	server := &Listener{
		validator: v, config: &Config{Auth: routedA, UdpIdleTimeout: 60},
		masqHandler: http.NotFoundHandler(), quicParams: &internet.QuicParams{Congestion: "reno"},
		addConn: func(c stat.Connection) {
			go func() {
				defer c.Close()
				var buf [128]byte
				for {
					n, err := c.Read(buf[:])
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		},
	}
	go func() {
		for {
			conn, err := l.Accept(ctx)
			if err != nil {
				return
			}
			go server.handleClient(conn)
		}
	}()
	connect := func(auth string, status int) *quic.Conn {
		t.Helper()
		var conn *quic.Conn
		rt := &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			QUICConfig:      quicCfg.Clone(),
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				var err error
				conn, err = quic.DialAddr(ctx, l.Addr().String(), tlsCfg, qc)
				return conn, err
			},
		}
		t.Cleanup(func() { _ = rt.Close() })
		req := common.Must2(http.NewRequestWithContext(ctx, http.MethodPost, "https://"+URLHost+URLPath, nil))
		req.Header.Set(RequestHeaderAuth, auth)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatalf("auth %q status %d want %d", auth, resp.StatusCode, status)
		}
		return conn
	}
	stream := func(c *quic.Conn) *quic.Stream {
		t.Helper()
		s, err := c.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		prefix := quicvarint.Append(nil, FrameTypeTCPRequest)
		if _, err := s.Write(prefix); err != nil {
			t.Fatal(err)
		}
		return s
	}
	echo := func(q *quic.Conn, s *quic.Stream) {
		t.Helper()
		deadline, _ := ctx.Deadline()
		common.Must(s.SetDeadline(deadline))
		if _, err := s.Write([]byte{'S'}); err != nil {
			t.Fatal(err)
		}
		var reply [1]byte
		if n, err := s.Read(reply[:]); n != 1 || err != nil || reply[0] != 'S' {
			t.Fatalf("stream echo %v %v", reply, err)
		}
		msg := []byte{0, 0, 0, 1, 'D'}
		if err := q.SendDatagram(msg); err != nil {
			t.Fatal(err)
		}
		d, err := q.ReceiveDatagram(ctx)
		if err != nil || !bytes.Equal(d, msg) {
			t.Fatalf("datagram echo %x %v", d, err)
		}
	}
	qA, qB := connect(routedA, StatusAuthOK), connect("bravo", StatusAuthOK)
	sA, sB := stream(qA), stream(qB)
	echo(qA, sA)
	echo(qB, sB)
	common.Must(v.DelByEmail("A"))
	select {
	case <-qA.Context().Done():
	case <-ctx.Done():
		t.Fatal("A's QUIC association remained open")
	}
	echo(qB, sB)
	_ = connect(routedA, http.StatusNotFound)
	common.Must(v.DelByEmail("B"))
	_ = connect(routedA, http.StatusNotFound) // static transport password must not revive A
	common.Must(v.Add(a))
	newA := connect(authA, StatusAuthOK)
	echo(newA, stream(newA))
}
