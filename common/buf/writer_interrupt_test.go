package buf_test

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

type observedInterruptWriter struct {
	*pipe.Writer
	entered     chan struct{}
	interrupted chan struct{}
}

func (w *observedInterruptWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	close(w.entered)
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *observedInterruptWriter) Interrupt() {
	close(w.interrupted)
	w.Writer.Interrupt()
}

func TestBufferedWriterInterruptUnblocksWrite(t *testing.T) {
	reader, rawWriter := pipe.New(pipe.WithSizeLimit(0))
	t.Cleanup(reader.Interrupt)
	// The first byte fills the pipe; its next write waits for a reader.
	if err := rawWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("a"))}); err != nil {
		t.Fatal(err)
	}
	underlying := &observedInterruptWriter{
		Writer:      rawWriter,
		entered:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
	writer := buf.NewBufferedWriter(underlying)
	if err := writer.SetBuffered(false); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan struct{})
	var writeErr error
	go func() {
		writeErr = writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("b"))})
		close(writeDone)
	}()
	t.Cleanup(func() {
		rawWriter.Interrupt()
		select {
		case <-writeDone:
		case <-time.After(3 * time.Second):
			t.Error("blocked writer did not exit during cleanup")
		}
	})
	select {
	case <-underlying.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not reach the full pipe")
	}
	// WriteMultiBuffer now holds BufferedWriter's mutex. Interrupt must reach
	// the pipe without waiting for that mutex (as Close/Flush would do).
	interruptDone := make(chan struct{})
	var interruptErr error
	go func() {
		interruptErr = common.Interrupt(writer)
		close(interruptDone)
	}()
	t.Cleanup(func() {
		rawWriter.Interrupt()
		select {
		case <-interruptDone:
		case <-time.After(3 * time.Second):
			t.Error("Interrupt did not exit during cleanup")
		}
	})
	select {
	case <-interruptDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Interrupt waited for the blocked writer instead of interrupting the pipe")
	}
	if interruptErr != nil {
		t.Fatal(interruptErr)
	}
	select {
	case <-underlying.interrupted:
	default:
		t.Fatal("underlying Interrupt was not called")
	}
	select {
	case <-writeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("underlying Interrupt did not unblock the write")
	}
	if !errors.Is(writeErr, io.ErrClosedPipe) {
		t.Fatalf("write error = %v, want closed pipe", writeErr)
	}
	mb, err := reader.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if !mb.IsEmpty() || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("interrupted pipe retained data or remained readable: len=%d err=%v", mb.Len(), err)
	}
}
