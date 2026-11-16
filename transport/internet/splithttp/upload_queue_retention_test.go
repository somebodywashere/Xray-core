package splithttp

import (
	"bytes"
	"testing"
)

func TestUploadQueueReleasesConsumedPayloads(t *testing.T) {
	q := NewUploadQueue(4)
	defer q.Close()
	packets := [][]byte{bytes.Repeat([]byte{1}, 4096), bytes.Repeat([]byte{2}, 4096), bytes.Repeat([]byte{3}, 4096)}
	for _, seq := range []uint64{2, 1, 0} {
		if err := q.Push(Packet{Seq: seq, Payload: packets[seq]}); err != nil {
			t.Fatal(err)
		}
	}
	// Exercise the public read path, including reordering and partial reads.
	var received bytes.Buffer
	buf := make([]byte, 257)
	for received.Len() < 3*4096 {
		n, err := q.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("unexpected zero-length read")
		}
		received.Write(buf[:n])
	}
	if !bytes.Equal(received.Bytes(), bytes.Join(packets, nil)) {
		t.Fatal("reassembled payload mismatch")
	}
	if len(q.heap) != 0 || len(q.pushedPackets) != 0 {
		t.Fatal("queue has not drained")
	}
	// GC scans the backing array, including slots beyond the slice length.
	for i, packet := range q.heap[:cap(q.heap)] {
		if packet.Payload != nil || packet.Reader != nil {
			t.Errorf("consumed heap slot %d still retains payload or reader", i)
		}
	}
}
