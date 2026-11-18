package vless

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func TestDuplicateRoutedUUID(t *testing.T) {
	var v MemoryValidator
	id := uuid.New()
	a := &protocol.MemoryUser{Email: "a", Account: &MemoryAccount{ID: protocol.NewID(id)}}
	alias := id
	alias[7] ^= 0xff
	b := &protocol.MemoryUser{Email: "b", Account: &MemoryAccount{ID: protocol.NewID(alias)}}
	if err := v.Add(a); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(b); err == nil || v.GetByEmail("b") != nil || v.Get(alias) != a {
		t.Fatal("routed UUID duplicate displaced the registered account")
	}
	if err := v.Del("a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(b); err != nil || v.Get(id) != b {
		t.Fatalf("failed to register replacement: %v", err)
	}
}
