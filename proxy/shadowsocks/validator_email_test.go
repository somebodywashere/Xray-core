package shadowsocks

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestDistinctUnicodeEmailsRemainAddressable(t *testing.T) {
	add := func(v *Validator, email, secret string) error {
		account, err := (&Account{Password: secret, CipherType: CipherType_AES_128_GCM}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		return v.Add((&protocol.MemoryUser{Email: email, Account: account}).NewGeneration())
	}
	v := new(Validator)
	// The simple-fold class of Latin capital I with dot does not contain 'i'.
	if err := add(v, "i", "first"); err != nil {
		t.Fatal(err)
	}
	if err := add(v, "\u0130", "second"); err != nil {
		t.Fatal(err)
	}
	if u := v.GetByEmail("\u0130"); u == nil || u.Email != "\u0130" {
		t.Fatal("wrong owner resolved")
	}
	if err := v.Del("\u0130"); err != nil {
		t.Fatal(err)
	}
	if v.GetByEmail("i") == nil {
		t.Fatal("other account removed")
	}
	if err := add(v, "\u0130", "second"); err != nil {
		t.Fatal(err)
	}

	// Kelvin sign and ASCII K belong to the same simple-fold class.
	if err := add(v, "\u212a", "third"); err != nil {
		t.Fatal(err)
	}
	if err := add(v, "k", "fourth"); err == nil {
		t.Fatal("accepted an equivalent email")
	}
	if err := v.Del("K"); err != nil {
		t.Fatal(err)
	}
	if err := add(v, "k", "fourth"); err != nil {
		t.Fatal(err)
	}
}
