package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type muxContextKey struct{}

type contextRecordingOutbound struct {
	seen    chan context.Context
	release chan struct{}
	exited  chan struct{}
}

func (p *contextRecordingOutbound) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	p.seen <- ctx
	<-p.release
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
	p.exited <- struct{}{}
	return nil
}

func TestDialingWorkerPreservesDetachedContext(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		name := "nil_context"
		if inherited {
			name = "instance_context"
		}
		t.Run(name, func(t *testing.T) {
			instance := new(core.Instance)
			var base context.Context
			original := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("old.invalid"), 80)}
			if inherited {
				base = context.WithValue(context.Background(), muxContextKey{}, "resolver")
				base = context.WithValue(base, core.XrayKey(1), instance)
				base = session.ContextWithOutbounds(base, []*session.Outbound{original})
				var cancel context.CancelFunc
				base, cancel = context.WithDeadline(base, time.Now().Add(-time.Second))
				defer cancel()
			}

			p := &contextRecordingOutbound{
				seen:    make(chan context.Context, 2),
				release: make(chan struct{}),
				exited:  make(chan struct{}, 2),
			}
			factory := &mux.DialingWorkerFactory{Context: base, Proxy: p}
			var workers []*mux.ClientWorker
			t.Cleanup(func() {
				close(p.release)
				for _, worker := range workers {
					worker.Close()
					select {
					case <-p.exited:
					case <-time.After(3 * time.Second):
						t.Error("proxy did not exit")
					}
				}
			})

			var contexts []context.Context
			for range 2 {
				worker, err := factory.Create()
				if err != nil {
					t.Fatal(err)
				}
				workers = append(workers, worker)
				select {
				case ctx := <-p.seen:
					contexts = append(contexts, ctx)
				case <-time.After(3 * time.Second):
					t.Fatal("proxy was not called")
				}
			}

			for _, ctx := range contexts {
				if ctx.Err() != nil {
					t.Fatalf("worker inherited cancellation: %v", ctx.Err())
				}
				if _, ok := ctx.Deadline(); ok {
					t.Fatal("worker inherited a deadline")
				}
				if inherited && (core.FromContext(ctx) != instance || ctx.Value(muxContextKey{}) != "resolver") {
					t.Fatal("worker lost instance or resolver context")
				}
				outbounds := session.OutboundsFromContext(ctx)
				if len(outbounds) != 1 || outbounds[0] == original || outbounds[0].Target.Address.Domain() != "v1.mux.cool" {
					t.Fatal("worker did not get a fresh Mux destination")
				}
			}
			first := session.OutboundsFromContext(contexts[0])[0]
			second := session.OutboundsFromContext(contexts[1])[0]
			first.Tag = "first-worker"
			if first == second || second.Tag != "" || original.Tag != "" {
				t.Fatal("workers share mutable outbound state")
			}
		})
	}
}
