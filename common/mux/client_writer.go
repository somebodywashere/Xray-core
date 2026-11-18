package mux

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/pipe"
)

type clientFrameWriter struct {
	writer buf.Writer
	gate   chan struct{}
	mu     sync.Mutex
	ends   []uint16
}

func (w *clientFrameWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	return w.write(b, nil)
}

func (w *clientFrameWriter) write(b buf.MultiBuffer, stop <-chan struct{}) error {
	select {
	case w.gate <- struct{}{}:
	case <-stop:
		buf.ReleaseMulti(b)
		return io.ErrClosedPipe
	}
	defer func() { <-w.gate }()
	if stop != nil {
		select {
		case <-stop:
			buf.ReleaseMulti(b)
			return io.ErrClosedPipe
		default:
		}
		if p, ok := w.writer.(*pipe.Writer); ok {
			return p.WriteMultiBufferUntil(b, stop)
		}
	}
	return w.writer.WriteMultiBuffer(b)
}

func (w *clientFrameWriter) Interrupt() { common.Interrupt(w.writer) }

// Only already-opened streams need an End on the shared carrier. One worker
// drains these control frames when backpressure clears. Each tracked wire ID
// is issued only once per carrier, bounding the queue to the ID space.
func (w *clientFrameWriter) endLater(id uint16) {
	w.mu.Lock()
	start := w.ends == nil
	w.ends = append(w.ends, id)
	w.mu.Unlock()
	if start {
		go func() {
			for {
				w.mu.Lock()
				if len(w.ends) == 0 {
					w.ends = nil
					w.mu.Unlock()
					return
				}
				id := w.ends[0]
				w.ends = w.ends[1:]
				w.mu.Unlock()
				end := NewResponseWriter(id, w, protocol.TransferTypeStream)
				end.hasError = true
				end.Close()
			}
		}()
	}
}

type trackedFrameWriter struct {
	carrier *clientFrameWriter
	stop    <-chan struct{}
	sent    bool
}

func (w *trackedFrameWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	err := w.carrier.write(b, w.stop)
	if err == nil {
		w.sent = true
	}
	return err
}
