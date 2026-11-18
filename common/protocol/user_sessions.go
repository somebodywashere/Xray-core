package protocol

import (
	"context"
	"errors"
	"io"
	"sync"
)

// NewGeneration gives a validator its own identity, even when callers reuse a
// MemoryUser in another inbound or add it back after deletion.
func (u *MemoryUser) NewGeneration() *MemoryUser {
	v := *u
	v.Sessions = new(UserSessions)
	return &v
}

type UserSessions struct {
	mu      sync.Mutex
	revoked bool
	nextID  uint64
	active  map[uint64]func()
}

func noop() {}

func (s *UserSessions) Revoked() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

// Track registers the resource before it becomes usable by the peer. Release
// forgets a finished resource. A callback already claimed by Revoke may run
// concurrently with release, and must act only on that resource.
func (s *UserSessions) Track(stop func()) (release func(), ok bool) {
	if s == nil {
		return noop, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return nil, false
	}
	if s.active == nil {
		s.active = make(map[uint64]func())
	}
	id := s.nextID
	s.nextID++
	s.active[id] = stop
	return func() {
		s.mu.Lock()
		delete(s.active, id)
		s.mu.Unlock()
	}, true
}

// Revoke seals admission while the validator removes its credential indexes.
// Run the returned cleanup after releasing the validator lock, before replying
// to RemoveUser. No network I/O runs under the account or validator lock.
func (s *UserSessions) Revoke() func() {
	if s == nil {
		return noop
	}
	s.mu.Lock()
	s.revoked = true
	active := s.active
	s.active = nil
	s.mu.Unlock()
	return func() {
		for _, stop := range active {
			stop()
		}
	}
}

// TrackConnection keeps the original transport object intact for callers
// which depend on TLS state, half-close or splice.
func (u *MemoryUser) TrackConnection(ctx context.Context, conn io.Closer) (context.Context, func(), error) {
	if u == nil || u.Sessions == nil {
		return ctx, noop, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	release, ok := u.Sessions.Track(func() {
		cancel()
		_ = conn.Close()
	})
	if !ok {
		cancel()
		return ctx, nil, errors.New("account removed")
	}
	return ctx, func() {
		release()
		cancel()
	}, nil
}
