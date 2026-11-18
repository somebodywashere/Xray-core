package mux

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type observedInput struct {
	*pipe.Reader
	consumed chan struct{}
}

func (i *observedInput) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	b, err := i.Reader.ReadMultiBufferTimeout(d)
	i.consumed <- struct{}{}
	return b, err
}

func TestCancelQueuedMuxFrame(t *testing.T) {
	for _, tc := range []struct {
		name string
		open bool
	}{
		{"new_waiting_for_carrier", false},
		{"data_waiting_for_pipe_capacity", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, upstream := pipe.New(pipe.WithSizeLimit(1))
			defer wire.Interrupt()
			incoming, peer := pipe.New()
			defer peer.Close()
			w, err := NewClientWorker(transport.Link{Reader: incoming, Writer: upstream}, ClientStrategy{})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			carrier := w.link.Writer.(*clientFrameWriter)
			r, input := pipe.New()
			defer input.Close()
			observer := &observedInput{r, make(chan struct{}, 1)}
			var survivor *pipe.Reader
			user := (&protocol.MemoryUser{}).NewGeneration()
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{User: user})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 80)}})
			if !tc.open {
				// Another stream currently holds the serialized writer.
				carrier.gate <- struct{}{}
			}
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				w.Dispatch(ctx, &transport.Link{Reader: observer, Writer: buf.Discard})
			}()
			write := func(dst buf.Writer, s string) {
				t.Helper()
				if err := dst.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(s))}); err != nil {
					t.Fatal(err)
				}
			}
			read := func() string {
				t.Helper()
				b, err := wire.ReadMultiBufferTimeout(2 * time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer buf.ReleaseMulti(b)
				return b.String()
			}
			write(input, "first")
			select {
			case <-observer.consumed:
			case <-time.After(2 * time.Second):
				t.Fatal("initial data not read")
			}
			if tc.open {
				read() // NEW delivered successfully
				bInput, feedB := pipe.New()
				defer feedB.Close()
				var bOutput *pipe.Writer
				survivor, bOutput = pipe.New()
				defer survivor.Interrupt()
				b := (&protocol.MemoryUser{}).NewGeneration()
				defer func() { b.Sessions.Revoke()() }()
				bctx := session.ContextWithInbound(ctx, &session.Inbound{User: b})
				go w.Dispatch(bctx, &transport.Link{Reader: bInput, Writer: bOutput})
				write(feedB, "B")
				read() // B has wire ID 2 on the same carrier.
				write(upstream, "sibling data")
				write(input, "cancelled payload")
				until := time.Now().Add(2 * time.Second)
				for len(carrier.gate) == 0 {
					if time.Now().After(until) {
						t.Fatal("stream did not reach the full pipe")
					}
					time.Sleep(time.Millisecond)
				}
			}
			user.Sessions.Revoke()()
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("Dispatch stayed blocked")
			}
			if tc.open {
				// A slow last stream can keep the carrier alive up to the
				// end of the wire ID space.
				sm := w.sessionManager
				sm.Lock()
				sm.count = 0xffff
				sm.Unlock()
				if !w.IsClosing() || sm.Allocate(&ClientStrategy{}, nil, nil) != nil {
					t.Fatal("reused ID before sending pending End")
				}
				if got := read(); got != "sibling data" {
					t.Fatalf("sibling frame changed: %q", got)
				}
				got := []byte(read())
				if len(got) != 6 || got[2] != 0 || got[3] != 1 || got[4] != byte(SessionStatusEnd) {
					t.Fatalf("unexpected frame after removal: %x", got)
				}
				if sm.allocate(&ClientStrategy{}, nil, nil, true) != nil {
					t.Fatal("local End reused ID without peer acknowledgement")
				}
				write(NewResponseWriter(1, peer, protocol.TransferTypeStream), "late reply for A")
				write(NewResponseWriter(2, peer, protocol.TransferTypeStream), "reply for B")
				read() // unknown retired ID gets an End
				reply, err := survivor.ReadMultiBufferTimeout(2 * time.Second)
				if err != nil {
					t.Fatal(err)
				}
				gotReply := reply.String()
				buf.ReleaseMulti(reply)
				if gotReply != "reply for B" {
					t.Fatalf("surviving owner read %q", gotReply)
				}
			} else {
				<-carrier.gate
			}
			write(carrier, "survivor")
			if got := read(); got != "survivor" {
				t.Fatalf("unexpected bytes ahead of surviving stream: %q", got)
			}
		})
	}
}

func TestFirstTrackedStreamAfterLegacyIDWrap(t *testing.T) {
	m := NewSessionManager()
	m.count = 0xffff
	legacy := m.Allocate(&ClientStrategy{}, nil, nil)
	if legacy == nil {
		t.Fatal("legacy stream failed")
	}
	if m.allocate(&ClientStrategy{}, nil, nil, true) != nil {
		t.Fatal("tracked stream admitted on a carrier that has reused IDs")
	}
	if _, ok := m.Get(legacy.ID); !ok {
		t.Fatal("retiring the carrier interrupted the active stream")
	}
	legacy.Close(false)
}

func TestClientFrameWriterInterruptWhileFull(t *testing.T) {
	reader, wire := pipe.New(pipe.WithSizeLimit(0))
	defer reader.Interrupt()
	w := &clientFrameWriter{writer: wire, gate: make(chan struct{}, 1)}
	write := func() error { return w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("frame"))}) }
	if err := write(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- write() }()
	deadline := time.Now().Add(2 * time.Second)
	for len(w.gate) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("writer never entered carrier")
		}
		time.Sleep(time.Millisecond)
	}
	go w.Interrupt()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("interrupted write succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Interrupt waited behind the blocked writer")
	}
}
