package mux

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

// Model the permitted gap between removing credentials and executing the
// old generation's callbacks. Reusing an email/ID cannot affect the new link.
func TestRevokedXUDPGenerationCannotPublishOrRemoveReplacement(t *testing.T) {
	oldUser := (&protocol.MemoryUser{Email: "one"}).NewGeneration()
	newUser := oldUser.NewGeneration()
	c := &xudpCache{}
	defer c.close()
	oldKey := xudpKey{owner: oldUser.Sessions, id: [8]byte{42}}
	newKey := xudpKey{owner: newUser.Sessions, id: oldKey.id}
	old, _, oldCtx, err := c.acquire(context.Background(), oldKey)
	if err != nil {
		t.Fatal(err)
	}
	stop := oldUser.Sessions.Revoke()
	next, _, nextCtx, err := c.acquire(context.Background(), newKey)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if oldCtx.Err() == nil || nextCtx.Err() != nil || c.entries[newKey] != next {
		t.Fatal("revocation did not isolate the two generation lifetimes")
	}
	if old.attach(&Session{parent: NewSessionManager()}) {
		t.Fatal("late return from dispatch reattached a revoked generation")
	}
	if _, _, _, err = c.acquire(context.Background(), oldKey); err == nil {
		t.Fatal("revoked generation admitted to XUDP cache")
	}
}
