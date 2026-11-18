package splithttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestCloseXHTTPWithBlockedResponse(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprintf("HTTP%d", version), func(t *testing.T) { testCloseXHTTPWithBlockedResponse(t, version) })
	}
}

type observedUploadBody struct {
	io.ReadCloser
	once    sync.Once
	started chan struct{}
}

func (b *observedUploadBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}

func TestClosePacketUpWithPendingBody(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("HTTP%d", version), func(t *testing.T) {
			cfg := &Config{Mode: "packet-up", XPaddingBytes: &RangeConfig{From: 1, To: 1}}
			accepted := make(chan stat.Connection, 2)
			h := &requestHandler{path: "/", sessionMu: new(sync.Mutex), config: cfg, ln: &Listener{
				config: cfg, addConn: func(c stat.Connection) { accepted <- c },
			}}
			started, returned := make(chan struct{}), make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/a/0" {
					r.Body = &observedUploadBody{ReadCloser: r.Body, started: started}
					defer close(returned)
				}
				h.ServeHTTP(w, r)
			})
			client, url, _ := xhttpPeer(t, version, handler)
			down := func(id string) stat.Connection {
				t.Helper()
				resp, err := client.Get(url + "/" + id + "?x_padding=X")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { resp.Body.Close() })
				if resp.ProtoMajor != version || resp.StatusCode != http.StatusOK {
					t.Fatalf("GET %s: %s (%s)", id, resp.Status, resp.Proto)
				}
				c := <-accepted
				t.Cleanup(func() { c.Close() })
				return c
			}
			a, b := down("a"), down("b")
			rd, wr := io.Pipe()
			t.Cleanup(func() { wr.Close(); rd.Close() })
			post, err := http.NewRequest(http.MethodPost, url+"/a/0?x_padding=X", rd)
			if err != nil {
				t.Fatal(err)
			}
			post.ContentLength = 8
			go func() {
				resp, err := client.Do(post)
				if err == nil {
					resp.Body.Close()
				}
			}()
			// Send the first byte and leave the rest of the body outstanding.
			if _, err := wr.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("POST handler did not read body")
			}
			a.Close()
			select {
			case <-returned:
			case <-time.After(3 * time.Second):
				t.Fatal("POST reader survived its downlink")
			}
			resp, err := client.Post(url+"/b/0?x_padding=X", "application/octet-stream", strings.NewReader("ok"))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var reply [2]byte
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("other session: %s", resp.Status)
			}
			if _, err := io.ReadFull(b, reply[:]); err != nil || string(reply[:]) != "ok" {
				t.Fatalf("other session received %q: %v", reply, err)
			}
		})
	}
}

func testCloseXHTTPWithBlockedResponse(t *testing.T, version int) {
	active := make(chan *httpServerConn, 1)
	writeDone := make(chan error, 1)
	remote := make(chan string, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote <- r.RemoteAddr
		if r.URL.Path == "/other" {
			io.WriteString(w, "ok")
			return
		}
		conn := &httpServerConn{Instance: done.New(), Reader: r.Body, ResponseWriter: w}
		defer conn.Close()
		w.(http.Flusher).Flush()
		active <- conn
		_, err := conn.Write(make([]byte, 1<<20))
		writeDone <- err
	})
	client, url, quicConnections := xhttpPeer(t, version, handler)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != version {
		t.Fatalf("expected HTTP/%d, got %s", version, resp.Proto)
	}
	// Read one byte to ensure Write has started, then stop draining.
	if _, err := io.ReadFull(resp.Body, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	conn := <-active
	select {
	case err := <-writeDone:
		t.Fatalf("response unexpectedly finished before close: %v", err)
	default:
	}
	closed := make(chan struct{})
	go func() {
		conn.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("close waited for the unread flow-controlled stream")
	}
	if err := <-writeDone; err == nil {
		t.Fatal("blocked Write completed successfully")
	}
	other, err := client.Get(url + "/other")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Body.Close()
	body, err := io.ReadAll(other.Body)
	if err != nil || string(body) != "ok" || <-remote != <-remote || quicConnections.Load() > 1 {
		t.Fatalf("connection did not serve the other stream: %q, %v", body, err)
	}
}

func xhttpPeer(t *testing.T, version int, handler http.Handler) (*http.Client, string, *atomic.Int32) {
	t.Helper()
	var url string
	var client *http.Client
	var quicConnections atomic.Int32
	if version == 1 {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		client, url = srv.Client(), srv.URL
	} else if version == 2 {
		srv := httptest.NewUnstartedServer(handler)
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(func() { srv.Close() })
		client = srv.Client()
		client.Transport.(*http.Transport).HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10}
		url = srv.URL
	} else {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { socket.Close() })
		generated, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
		pair, err := tls.X509KeyPair(generated.ToPEM())
		if err != nil {
			t.Fatal(err)
		}
		srv := &http3.Server{
			Handler:   handler,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
			ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
				quicConnections.Add(1)
				return ctx
			},
		}
		go srv.Serve(socket)
		t.Cleanup(func() { srv.Close() })
		rt := &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			QUICConfig: &quic.Config{
				InitialStreamReceiveWindow: 64 << 10,
				MaxStreamReceiveWindow:     64 << 10,
			},
		}
		t.Cleanup(func() { rt.Close() })
		client = &http.Client{Transport: rt}
		url = "https://" + socket.LocalAddr().String()
	}
	client.Timeout = 10 * time.Second
	return client, url, &quicConnections
}
