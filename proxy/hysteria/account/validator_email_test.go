package account

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestEmailIndexPreservesExactOwner(t *testing.T) {
	v := NewValidator()
	a := &protocol.MemoryUser{Email: "A", Account: &MemoryAccount{Auth: "one"}}
	b := &protocol.MemoryUser{Email: "a", Account: &MemoryAccount{Auth: "two"}}
	for _, u := range []*protocol.MemoryUser{a, b} {
		if err := v.Add(u); err != nil {
			t.Fatal(err)
		}
	}
	original := v.GetByEmail("A")
	if original != v.Get("one") || v.GetByEmail("a") != v.Get("two") {
		t.Fatal("wrong owner indexed")
	}
	if err := v.DelByEmail("A"); err != nil {
		t.Fatal(err)
	}
	if v.GetByEmail("A") != nil || v.Get("one") != nil || v.Get("two") == nil {
		t.Fatal("incorrect owner removed")
	}
	if err := v.Add(a); err != nil {
		t.Fatal(err)
	}
	if next := v.GetByEmail("A"); next == nil || next.Sessions == original.Sessions {
		t.Fatal("old generation reused")
	}
}
