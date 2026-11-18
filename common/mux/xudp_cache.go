package mux

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// Each inbound has its own Server/cache. The wire ID is meaningful only within
// the account generation that created the UDP association.
type xudpKey struct {
	id     [8]byte
	owner  *protocol.UserSessions
	legacy *protocol.MemoryUser
}

type xudpCache struct {
	sync.Mutex
	entries map[xudpKey]*XUDP
	closed  bool
}

func (c *xudpCache) close() {
	c.Lock()
	c.closed = true
	entries := make([]*XUDP, 0, len(c.entries))
	for _, x := range c.entries {
		entries = append(entries, x)
	}
	c.Unlock()
	for _, x := range entries {
		x.remove(nil)
	}
}

type XUDP struct {
	cache      *xudpCache
	key        xudpKey
	cancel     context.CancelFunc
	release    func()
	removed    chan struct{}
	link       *transport.Link
	attachment *Session
	timer      *time.Timer
	busy       bool
}

type xudpReader struct {
	*pipe.Reader
	stop <-chan struct{}
}

func (r xudpReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferUntil(r.stop)
}

func (s *Session) reader() buf.Reader {
	if r, ok := s.input.(*pipe.Reader); ok && s.XUDP != nil {
		return xudpReader{r, s.done.Wait()}
	}
	return s.input
}

func (x *XUDP) detach(s *Session) {
	if _, ok := s.input.(*pipe.Reader); !ok {
		// A custom dispatcher can return a reader without cancellable reads.
		// The live link works, but cannot be parked between carriers.
		x.remove(nil)
		return
	}
	c := x.cache
	c.Lock()
	defer c.Unlock()
	if c.entries[x.key] == x && !x.busy && x.attachment == s {
		x.timer = time.AfterFunc(time.Minute, func() { x.remove(s) })
	}
}

// A delayed expiry may race with reattachment or replacement. Only the
// matching attachment of the original association may be expired.
func (x *XUDP) remove(expired *Session) {
	c := x.cache
	c.Lock()
	if c.entries[x.key] != x {
		c.Unlock()
		// Another remover owns teardown. A revocation cannot return while
		// that goroutine still holds the cached link.
		<-x.removed
		return
	}
	if expired != nil && (x.busy || x.attachment != expired) {
		c.Unlock()
		return
	}
	delete(c.entries, x.key)
	if x.timer != nil {
		x.timer.Stop()
	}
	link := x.link
	c.Unlock()
	x.cancel()
	if link != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	x.release()
	close(x.removed)
}

func (c *xudpCache) acquire(ctx context.Context, key xudpKey) (*XUDP, *Session, context.Context, error) {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return nil, nil, nil, errors.New("Mux server closed")
	}
	if x := c.entries[key]; x != nil {
		if x.busy {
			return nil, nil, nil, nil
		}
		x.busy = true
		if x.timer != nil {
			x.timer.Stop()
		}
		return x, x.attachment, nil, nil
	}

	// A saved link outlives its first Mux carrier. Revocation and cache
	// expiry still cancel its outbound, including a dial in progress.
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	x := &XUDP{cache: c, key: key, cancel: cancel, busy: true, removed: make(chan struct{})}
	release, ok := key.owner.Track(func() { x.remove(nil) })
	if !ok {
		cancel()
		return nil, nil, nil, errors.New("account removed")
	}
	x.release = release
	if c.entries == nil {
		c.entries = make(map[xudpKey]*XUDP)
	}
	c.entries[key] = x
	return x, nil, session.ContextWithTimeoutOnly(ctx, false), nil
}

func (x *XUDP) attach(s *Session) bool {
	m := s.parent
	m.Lock()
	defer m.Unlock()
	c := x.cache
	c.Lock()
	defer c.Unlock()
	if c.entries[x.key] != x || !m.add(s) {
		return false
	}
	x.busy = false
	x.attachment = s
	return true
}

func (w *ServerWorker) handleXUDP(ctx context.Context, user *protocol.MemoryUser, meta *FrameMetadata, r *buf.BufferedReader) error {
	key := xudpKey{id: meta.GlobalID, owner: user.Sessions}
	if key.owner == nil {
		key.legacy = user
	}
	mb, err := NewPacketReader(r, &meta.Target).ReadMultiBuffer()
	if err != nil {
		return err
	}
	for {
		x, old, dispatchCtx, err := w.cache.acquire(ctx, key)
		if x == nil {
			buf.ReleaseMulti(mb)
			return err
		}
		var link *transport.Link
		if old != nil {
			old.Close(false)
			if _, ok := old.input.(*pipe.Reader); !ok {
				x.remove(nil)
				continue
			}
			link = &transport.Link{Reader: old.input, Writer: old.output}
			// Retry a closed saved link with a fresh dispatch.
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			if err = link.Writer.WriteMultiBuffer(mb); err != nil {
				x.remove(nil)
				mb = buf.MultiBuffer{b}
				continue
			}
			b.Release()
		} else {
			link, err = w.dispatcher.Dispatch(dispatchCtx, meta.Target)
			if err != nil {
				buf.ReleaseMulti(mb)
				x.remove(nil)
				return err
			}
			x.cache.Lock()
			valid := x.cache.entries[key] == x
			if valid {
				x.link = link
			}
			x.cache.Unlock()
			if !valid {
				buf.ReleaseMulti(mb)
				common.Interrupt(link.Reader)
				common.Interrupt(link.Writer)
				return errors.New("account removed")
			}
			if err := link.Writer.WriteMultiBuffer(mb); err != nil {
				x.remove(nil)
				return err
			}
		}
		s := &Session{
			input: link.Reader, output: link.Writer, parent: w.sessionManager,
			ID: meta.SessionID, transferType: protocol.TransferTypePacket,
			done: done.New(), XUDP: x,
		}
		if !x.attach(s) {
			x.remove(nil)
			return errors.New("failed to add XUDP session")
		}
		go handle(ctx, s, w.link.Writer)
		return nil
	}
}
