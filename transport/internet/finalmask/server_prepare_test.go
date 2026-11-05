package finalmask_test

import (
	"context"
	"errors"
	"fmt"
	gonet "net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type preparedTestMask struct {
	preparations atomic.Int32
	clientCalls  atomic.Int32
	result       finalmask.TCPMask
	err          error
}

func (m *preparedTestMask) PrepareServer() (finalmask.TCPMask, error) {
	m.preparations.Add(1)
	return m.result, m.err
}

func (m *preparedTestMask) WrapConnClient(c net.Conn, _ *net.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	m.clientCalls.Add(1)
	return c, nil
}

func (m *preparedTestMask) WrapConnServer(net.Conn) (net.Conn, error) {
	return nil, errors.New("unprepared server mask used")
}

type tracedMask struct{ name string }

type tracedConn struct {
	net.Conn
	order []string
}

func (m *tracedMask) WrapConnClient(net.Conn, *net.Destination, *finalmask.Dialer) (net.Conn, error) {
	return nil, errors.New("server mask used on client")
}

func (m *tracedMask) WrapConnServer(c net.Conn) (net.Conn, error) {
	if traced, ok := c.(*tracedConn); ok {
		traced.order = append(traced.order, m.name)
		return traced, nil
	}
	return &tracedConn{Conn: c, order: []string{m.name}}, nil
}

type listenerMask struct{ tracedMask }

func (m *listenerMask) Listen(l net.Listener) (net.Listener, error) {
	return &tracedListener{Listener: l, mask: &m.tracedMask}, nil
}

type tracedListener struct {
	net.Listener
	mask *tracedMask
}

func (l *tracedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.mask.WrapConnServer(c)
}

func listenPreparedTest(_ context.Context, addr net.Addr) (net.Listener, error) {
	return gonet.Listen(addr.Network(), addr.String())
}

func TestServerPreparationSharedAcrossListeners(t *testing.T) {
	m := &preparedTestMask{result: &tracedMask{name: "prepared"}}
	fm := finalmask.NewFinalMask([]finalmask.TCPMask{m}, nil, nil, listenPreparedTest, nil, nil)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			listener, err := fm.Listen(context.Background(), &gonet.TCPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Error(err)
				return
			}
			defer listener.Close()
			peer, err := gonet.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer peer.Close()
			conn, err := listener.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if got, ok := conn.(*tracedConn); !ok || !slices.Equal(got.order, []string{"prepared"}) {
				t.Errorf("server returned unprepared connection: %T", conn)
			}
		})
	}
	wg.Wait()
	if got := m.preparations.Load(); got != 1 {
		t.Fatalf("prepared %d times, want once per FinalMask", got)
	}
	// A newly created runtime prepares independently, even with the same mask.
	fresh := finalmask.NewFinalMask([]finalmask.TCPMask{m}, nil, nil, listenPreparedTest, nil, nil)
	l, err := fresh.Listen(context.Background(), &gonet.TCPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if got := m.preparations.Load(); got != 2 {
		t.Fatalf("new runtime did not prepare independently: %d", got)
	}
}

func TestServerPreparationPreservesClientAndMaskOrder(t *testing.T) {
	m := &preparedTestMask{result: &tracedMask{name: "prepared"}}
	clientRaw, peer := gonet.Pipe()
	defer clientRaw.Close()
	defer peer.Close()
	dial := func(context.Context, net.Destination) (net.Conn, error) { return clientRaw, nil }
	fm := finalmask.NewFinalMask([]finalmask.TCPMask{m}, nil, dial, listenPreparedTest, nil, nil)
	l, err := fm.Listen(context.Background(), &gonet.TCPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := fm.DialTCP(context.Background(), net.TCPDestination(net.LocalHostIP, 1234)); err != nil {
		t.Fatal(err)
	}
	if m.clientCalls.Load() != 1 || m.preparations.Load() != 1 {
		t.Fatal("client did not use the original mask independently of server preparation")
	}

	// NewFinalMask reverses configured masks. The optional Listen hook must
	// preserve every surrounding mask and apply the prepared one exactly once.
	chain := finalmask.NewFinalMask([]finalmask.TCPMask{
		&tracedMask{name: "outer"}, m, &listenerMask{tracedMask{name: "listener"}}, &tracedMask{name: "inner"},
	}, nil, nil, listenPreparedTest, nil, nil)
	l2, err := chain.Listen(context.Background(), &gonet.TCPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	p, err := gonet.Dial("tcp", l2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := l2.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	want := []string{"inner", "listener", "prepared", "outer"}
	if got, ok := c.(*tracedConn); !ok || !slices.Equal(got.order, want) {
		t.Fatalf("mask chain = %#v, want %v", c, want)
	}
}

func TestServerPreparationFailureDoesNotOpenListener(t *testing.T) {
	for _, failure := range []error{errors.New("bad configuration"), nil} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			m := &preparedTestMask{err: failure}
			var opened atomic.Int32
			listen := func(context.Context, net.Addr) (net.Listener, error) {
				opened.Add(1)
				return nil, errors.New("unexpected listener creation")
			}
			fm := finalmask.NewFinalMask([]finalmask.TCPMask{m}, nil, nil, listen, nil, nil)
			for range 2 {
				if _, err := fm.Listen(context.Background(), &gonet.TCPAddr{}); err == nil || (failure != nil && !errors.Is(err, failure)) {
					t.Fatalf("preparation error = %v, expected %v", err, failure)
				}
			}
			if opened.Load() != 0 || m.preparations.Load() != 1 {
				t.Fatalf("opened=%d preparations=%d", opened.Load(), m.preparations.Load())
			}
		})
	}
}
