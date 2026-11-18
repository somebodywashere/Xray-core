package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type delayedSelection struct {
	outbound.Manager
	selected func() outbound.Handler
}

func (m delayedSelection) GetDefaultHandler() outbound.Handler { return m.selected() }

type recordingOutbound struct {
	outbound.Handler
	called bool
}

func (h *recordingOutbound) Tag() string                               { return "test" }
func (h *recordingOutbound) Dispatch(context.Context, *transport.Link) { h.called = true }

// Account deletion can finish during route selection, e.g. while resolving a
// domain. Such a request must not enter the selected outbound afterwards.
func TestRemovalDuringRouteSelection(t *testing.T) {
	user := new(protocol.MemoryUser).NewGeneration()
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{User: user})
	out := new(recordingOutbound)
	d := DefaultDispatcher{ohm: delayedSelection{selected: func() outbound.Handler {
		user.Sessions.Revoke()()
		return out
	}}}
	if err := d.DispatchLink(ctx, net.TCPDestination(net.LocalHostIP, 80), &transport.Link{}); err != nil {
		t.Fatal(err)
	}
	if out.called {
		t.Fatal("started an outbound operation after revocation completed")
	}
}
