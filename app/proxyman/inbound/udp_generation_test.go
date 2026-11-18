package inbound

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestLateUDPWorkerCleanupPreservesNewAssociation(t *testing.T) {
	w := &udpWorker{ctx: t.Context(), address: net.LocalHostIP, activeConn: make(map[connID]*udpConn)}
	id := connID{src: net.UDPDestination(net.LocalHostIP, 40000)}
	old, _ := w.getConnection(id)
	old.writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("queued before removal")))
	old.Close()
	if data, err := old.ReadMultiBuffer(); err == nil || !data.IsEmpty() {
		buf.ReleaseMulti(data)
		t.Fatal("removed association delivered a queued packet")
	}
	current, existing := w.getConnection(id)
	defer current.Close()
	if existing || current == old {
		t.Fatal("closed association was reused")
	}
	if _, err := old.Write([]byte("stale reply")); err == nil {
		t.Fatal("closed association could still send a reply")
	}
	w.removeConn(id, old)
	if got, found := w.getConnection(id); !found || got != current {
		t.Fatal("an old worker removed its replacement")
	}
	w.removeConn(id, current)
	if len(w.activeConn) != 0 {
		t.Fatal("finished association was retained")
	}
}
