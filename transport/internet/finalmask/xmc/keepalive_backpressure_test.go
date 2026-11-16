package xmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type keepAliveSignalConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
}

func (c *keepAliveSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

type keepAliveTestWriter func([]byte) (int, error)

func (f keepAliveTestWriter) Write(p []byte) (int, error) { return f(p) }

func awaitKeepAliveWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("keep-alive worker did not stop")
	}
}

func TestKeepAliveDoesNotBlockDownloadUnderUploadBackpressure(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })
	clientRaw.SetDeadline(time.Now().Add(5 * time.Second))
	serverRaw.SetDeadline(time.Now().Add(5 * time.Second))
	secret := []byte("0123456789abcdef")
	signaled := &keepAliveSignalConn{Conn: clientRaw, entered: make(chan struct{})}
	clientReader, err := newCryptoReader(clientRaw, secret)
	if err != nil {
		t.Fatal(err)
	}
	clientWriter, err := newCryptoWriter(signaled, secret)
	if err != nil {
		t.Fatal(err)
	}
	serverReader, err := newCryptoReader(serverRaw, secret)
	if err != nil {
		t.Fatal(err)
	}
	serverWriter, err := newCryptoWriter(serverRaw, secret)
	if err != nil {
		t.Fatal(err)
	}
	client := newPacketStream(clientReader, clientWriter, true)
	client.closeConn = clientRaw.Close
	t.Cleanup(client.Stop)
	upload := bytes.Repeat([]byte("upload"), 20000)
	writeDone := make(chan error, 1)
	go func() { _, err := client.Write(upload); writeDone <- err }()
	awaitKeepAliveWorker(t, signaled.entered)

	ids := []Long{42, 43, 44}
	serverDone := make(chan error, 1)
	go func() {
		for _, id := range ids {
			if err := writePacket(serverWriter, configurationKeepAlive, &id); err != nil {
				serverDone <- err
				return
			}
		}
		channel := String(packetChannel)
		payload := RestBytes([]byte("download"))
		serverDone <- writePacket(serverWriter, configurationClientboundCustomPayload, &channel, &payload)
	}()
	// The server has deliberately not read any upload bytes. Reading the
	// download must not wait for that upload or its write mutex to complete.
	download := make([]byte, len("download"))
	if _, err := io.ReadFull(client, download); err != nil {
		t.Fatal(err)
	}
	if string(download) != "download" {
		t.Fatalf("download = %q", download)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	var received []byte
	for len(received) < len(upload) {
		packet, err := readPacket(serverReader)
		if err != nil {
			t.Fatal(err)
		}
		if packet.packetID != configurationServerboundCustomPayload {
			t.Fatalf("unexpected upload packet %d", packet.packetID)
		}
		payload, ok, err := parseCustomPayload(packet)
		if err != nil || !ok {
			t.Fatalf("parse upload: ok=%v err=%v", ok, err)
		}
		received = append(received, payload...)
	}
	if !bytes.Equal(received, upload) {
		t.Fatal("upload contents changed")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	for _, want := range ids {
		packet, err := readPacket(serverReader)
		if err != nil {
			t.Fatal(err)
		}
		var got Long
		if packet.packetID != configurationKeepAlive || packet.readFields(&got) != nil || got != want {
			t.Fatalf("keep-alive reply id=%d packet=%d, want %d", got, packet.packetID, want)
		}
	}
	client.Stop()
	awaitKeepAliveWorker(t, client.replyDone)
}

func TestKeepAliveWriteErrorUnblocksRead(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientRaw.SetDeadline(time.Now().Add(3 * time.Second))
	serverRaw.SetDeadline(time.Now().Add(3 * time.Second))
	want := errors.New("test keep-alive write failure")
	client := newPacketStream(clientRaw, keepAliveTestWriter(func([]byte) (int, error) { return 0, want }), true)
	var closes atomic.Int32
	client.closeConn = func() error { closes.Add(1); return clientRaw.Close() }
	defer client.Stop()
	serverDone := make(chan error, 1)
	go func() { id := Long(1); serverDone <- writePacket(serverRaw, configurationKeepAlive, &id) }()
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, want) {
		t.Fatalf("Read error = %v, want %v", err, want)
	}
	awaitKeepAliveWorker(t, client.replyDone)
	if _, err := client.Write([]byte("data")); !errors.Is(err, want) {
		t.Fatalf("Write error = %v, want %v", err, want)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 1 {
		t.Fatalf("socket closed %d times", closes.Load())
	}
}

func TestKeepAliveReplyQueueIsBounded(t *testing.T) {
	var input bytes.Buffer
	for n := 1; n <= maxKeepAliveReplies+1; n++ {
		id := Long(n)
		if err := writePacket(&input, configurationKeepAlive, &id); err != nil {
			t.Fatal(err)
		}
	}
	entered, released := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(released) }) }
	defer release()
	client := newPacketStream(&input, keepAliveTestWriter(func([]byte) (int, error) {
		close(entered)
		<-released
		return 0, io.ErrClosedPipe
	}), true)
	var closes atomic.Int32
	client.closeConn = func() error { closes.Add(1); release(); return nil }
	defer client.Stop()
	if err := client.queueKeepAlive(0); err != nil {
		t.Fatal(err)
	}
	awaitKeepAliveWorker(t, entered)
	_, err := client.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), "too many pending") {
		t.Fatalf("overflow error = %v", err)
	}
	awaitKeepAliveWorker(t, client.replyDone)
	if cap(client.replies) != maxKeepAliveReplies || len(client.replies) > maxKeepAliveReplies {
		t.Fatal("reply queue exceeded its bound")
	}
	if _, again := client.Read(make([]byte, 1)); again != err {
		t.Fatalf("first error changed: %v -> %v", err, again)
	}
	if closes.Load() != 1 {
		t.Fatalf("socket closed %d times", closes.Load())
	}
}

func TestKeepAliveCloseUnblocksWorker(t *testing.T) {
	for _, applicationWrite := range []bool{false, true} {
		name := "network_write"
		if applicationWrite {
			name = "write_mutex"
		}
		t.Run(name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()
			signaled := &keepAliveSignalConn{Conn: clientRaw, entered: make(chan struct{})}
			stream := newPacketStream(clientRaw, signaled, true)
			stream.closeConn = clientRaw.Close
			owner := &clientConn{c: clientRaw, packet: stream}
			writeDone := make(chan error, 1)
			if applicationWrite {
				go func() { _, err := stream.Write([]byte("blocked")); writeDone <- err }()
				awaitKeepAliveWorker(t, signaled.entered)
			}
			if err := stream.queueKeepAlive(1); err != nil {
				t.Fatal(err)
			}
			if !applicationWrite {
				awaitKeepAliveWorker(t, signaled.entered)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			awaitKeepAliveWorker(t, stream.replyDone)
			if applicationWrite {
				if err := <-writeDone; err == nil {
					t.Fatal("blocked write succeeded after close")
				}
			}
		})
	}
}

func TestKeepAliveStopDoesNotWriteQueuedReply(t *testing.T) {
	var wire bytes.Buffer
	stream := newPacketStream(bytes.NewReader(nil), &wire, true)
	stream.writeMu.Lock()
	if err := stream.queueKeepAlive(1); err != nil {
		stream.writeMu.Unlock()
		t.Fatal(err)
	}
	stream.Stop()
	stream.writeMu.Unlock()
	awaitKeepAliveWorker(t, stream.replyDone)
	if wire.Len() != 0 {
		t.Fatal("reply was written after stopping while waiting for the write mutex")
	}
}
