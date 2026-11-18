package pipe

import (
	"github.com/xtls/xray-core/common/buf"
)

// Writer is a buf.Writer that writes data into a pipe.
type Writer struct {
	pipe *pipe
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.pipe.WriteMultiBuffer(mb)
}

// WriteMultiBufferUntil allows a single producer to stop waiting for capacity
// without interrupting other writers on this pipe.
func (w *Writer) WriteMultiBufferUntil(mb buf.MultiBuffer, stop <-chan struct{}) error {
	return w.pipe.writeMultiBufferUntil(mb, stop)
}

// Close implements io.Closer. After the pipe is closed, writing to the pipe will return io.ErrClosedPipe, while reading will return io.EOF.
func (w *Writer) Close() error {
	return w.pipe.Close()
}

func (w *Writer) Len() int32 {
	return w.pipe.Len()
}

// Interrupt implements common.Interruptible.
func (w *Writer) Interrupt() {
	w.pipe.Interrupt()
}
