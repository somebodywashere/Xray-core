package inbound

import (
	"bytes"
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	obm "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestRemoveReverseAfterTagReplacement(t *testing.T) {
	manager, err := obm.New(t.Context(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(t.Context(), &Reverse{tag: "default"}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{ctx: t.Context(), outboundHandlerManager: manager, validator: new(vless.MemoryValidator)}
	account := &vless.MemoryAccount{ID: protocol.NewID(uuid.New()), Reverse: &vless.Reverse{Tag: "dynamic"}}
	if err := h.AddUser(t.Context(), &protocol.MemoryUser{Email: "a", Account: account}); err != nil {
		t.Fatal(err)
	}
	r, err := h.GetReverse(account)
	if err != nil {
		t.Fatal(err)
	}
	worker := func() *reverse.PortalWorker {
		t.Helper()
		in, _ := pipe.New()
		_, out := pipe.New()
		client, err := mux.NewClientWorker(transport.Link{Reader: in, Writer: out}, mux.ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		w, err := reverse.NewPortalWorker(client)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	active := worker()
	r.picker.AddWorker(active)
	if err := manager.RemoveHandler(t.Context(), r.Tag()); err != nil {
		t.Fatal(err)
	}
	replacement := &Reverse{tag: r.Tag()}
	if err := manager.AddHandler(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveUser(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	manager.RemoveHandlerIf(r.Tag(), r)
	if manager.GetHandler(r.Tag()) != replacement || !active.Closed() {
		t.Fatal("revocation did not close exactly the original picker")
	}
	late := worker()
	r.picker.AddWorker(late)
	if !late.Closed() {
		t.Fatal("retired picker accepted another worker")
	}
}

type pausedLookup struct {
	vless.MemoryValidator
	matched chan struct{}
	resume  chan struct{}
}

func (v *pausedLookup) Get(id uuid.UUID) *protocol.MemoryUser {
	u := v.MemoryValidator.Get(id)
	close(v.matched)
	<-v.resume
	return u
}

type observeDispatch struct {
	routing.Dispatcher
	called bool
}

func (o *observeDispatch) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	o.called = true
	return nil
}

func TestRemoveWhileVLESSHeaderAuthenticates(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	v := &pausedLookup{matched: make(chan struct{}), resume: make(chan struct{})}
	h := &Handler{validator: v, policyManager: policy.DefaultManager{}}
	u := &protocol.MemoryUser{Email: "user", Account: &vless.MemoryAccount{ID: protocol.NewID(uuid.New())}}
	if err := h.AddUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	var request bytes.Buffer
	if err := encoding.EncodeRequestHeader(&request, &protocol.RequestHeader{
		User: u, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 80,
	}, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}

	server, client := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	dispatched := new(observeDispatch)
	result := make(chan error, 1)
	go func() {
		result <- h.Process(session.ContextWithInbound(ctx, &session.Inbound{}), net.Network_TCP, server, dispatched)
	}()
	if _, err := client.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-v.matched:
	case <-ctx.Done():
		t.Fatal("header did not reach authentication")
	}
	if err := h.RemoveUser(ctx, u.Email); err != nil {
		t.Fatal(err)
	}
	if err := h.AddUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	close(v.resume)
	select {
	case err := <-result:
		if err == nil || dispatched.called {
			t.Fatal("partially authenticated connection used a removed generation")
		}
	case <-ctx.Done():
		t.Fatal("old connection did not exit")
	}
}
