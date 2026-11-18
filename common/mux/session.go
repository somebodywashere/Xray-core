package mux

import (
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal/done"
)

type SessionManager struct {
	sync.RWMutex
	sessions map[uint16]*Session
	count    uint16
	wrapped  bool
	tracked  bool
	closed   bool
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		count:    0,
		sessions: make(map[uint16]*Session, 16),
	}
}

func (m *SessionManager) Closed() bool {
	m.RLock()
	defer m.RUnlock()

	return m.closed
}

func (m *SessionManager) Size() int {
	m.RLock()
	defer m.RUnlock()

	return len(m.sessions)
}

func (m *SessionManager) Count() int {
	m.RLock()
	defer m.RUnlock()

	return int(m.count)
}

func (m *SessionManager) Allocate(Strategy *ClientStrategy, input buf.Reader, output buf.Writer) *Session {
	return m.allocate(Strategy, input, output, false)
}

func (m *SessionManager) allocate(Strategy *ClientStrategy, input buf.Reader, output buf.Writer, tracked bool) *Session {
	m.Lock()
	defer m.Unlock()

	MaxConcurrency := int(Strategy.MaxConcurrency)
	MaxConnection := uint16(Strategy.MaxConnection)

	if tracked {
		m.tracked = true
	}
	if m.closed || m.idSpaceExhausted() || (MaxConcurrency > 0 && len(m.sessions) >= MaxConcurrency) || (MaxConnection > 0 && m.count >= MaxConnection) {
		return nil
	}
	m.count++
	if m.count == 0 {
		m.wrapped = true
	}
	s := &Session{
		input:  input,
		output: output,
		ID:     m.count,
		parent: m,
		done:   done.New(),
	}
	m.sessions[s.ID] = s
	return s
}

// End has no peer acknowledgement. On a carrier used by a revocable account
// an ID must never be reused, even after its End was sent. A legacy carrier
// that has already wrapped must retire before accepting its first such user.
// The caller holds the manager lock.
func (m *SessionManager) idSpaceExhausted() bool {
	return m.tracked && (m.wrapped || m.count == 0xffff)
}

func (m *SessionManager) Add(s *Session) bool {
	m.Lock()
	defer m.Unlock()
	return m.add(s)
}

func (m *SessionManager) add(s *Session) bool {
	if m.closed {
		return false
	}

	m.count++
	m.sessions[s.ID] = s
	return true
}

func (m *SessionManager) Remove(locked bool, id uint16) {
	if !locked {
		m.Lock()
		defer m.Unlock()
	}
	locked = true

	if m.closed {
		return
	}

	delete(m.sessions, id)

	/*
		if len(m.sessions) == 0 {
			m.sessions = make(map[uint16]*Session, 16)
		}
	*/
}

func (m *SessionManager) Get(id uint16) (*Session, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.closed {
		return nil, false
	}

	s, found := m.sessions[id]
	return s, found
}

func (m *SessionManager) CloseIfNoSessionAndIdle(checkSize int, checkCount int) bool {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return true
	}

	if len(m.sessions) != 0 || checkSize != 0 || checkCount != int(m.count) {
		return false
	}

	m.closed = true

	m.sessions = nil
	return true
}

func (m *SessionManager) Close() error {
	m.Lock()
	m.closed = true
	sessions := m.sessions
	m.sessions = nil
	m.Unlock()
	for _, s := range sessions {
		s.Close(false)
	}
	return nil
}

// Session represents a client connection in a Mux connection.
type Session struct {
	input        buf.Reader
	output       buf.Writer
	parent       *SessionManager
	ID           uint16
	transferType protocol.TransferType
	closed       bool
	done         *done.Instance
	XUDP         *XUDP
}

// Close closes all resources associated with this session.
func (s *Session) Close(locked bool) error {
	return s.close(locked, false)
}

func (s *Session) close(locked, interrupt bool) error {
	if !locked {
		s.parent.Lock()
	}
	if s.closed {
		if !locked {
			s.parent.Unlock()
		}
		return nil
	}
	s.closed = true
	if s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
	if s.done != nil {
		s.done.Close()
	}
	if !locked {
		s.parent.Unlock()
	}
	if s.XUDP != nil {
		s.XUDP.detach(s)
	} else {
		common.Interrupt(s.input)
		if interrupt {
			common.Interrupt(s.output)
		} else {
			common.Close(s.output)
		}
	}
	return nil
}

// NewReader creates a buf.Reader based on the transfer type of this Session.
func (s *Session) NewReader(reader *buf.BufferedReader, dest *net.Destination) buf.Reader {
	if s.transferType == protocol.TransferTypeStream {
		return NewStreamReader(reader)
	}
	return NewPacketReader(reader, dest)
}
