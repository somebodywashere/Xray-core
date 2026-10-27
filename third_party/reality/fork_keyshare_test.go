package reality

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestClassicX25519KeyShare(t *testing.T) {
	classic := keyShare{group: X25519, data: bytes.Repeat([]byte{1}, 32)}
	hybrid := keyShare{group: X25519MLKEM768, data: make([]byte, mlkem.EncapsulationKeySize768+32)}
	short := keyShare{group: X25519, data: make([]byte, 31)}
	long := keyShare{group: X25519, data: make([]byte, 33)}
	empty := keyShare{group: X25519}
	badHybrid := keyShare{group: X25519MLKEM768, data: []byte{1}}
	grease := keyShare{group: CurveID(0x0a0a), data: []byte{1}}
	other := keyShare{group: CurveP256, data: []byte{4}}

	// Hybrid hellos must never use this fallback helper. Their acceptance is
	// covered by the Server handshake tests, through the unchanged upstream path.
	tests := []struct {
		name   string
		groups []CurveID
		shares []keyShare
		want   bool
	}{
		{"hybrid_only", []CurveID{X25519MLKEM768}, []keyShare{hybrid}, false},
		{"hybrid_and_classic", []CurveID{X25519MLKEM768, X25519}, []keyShare{hybrid, classic}, false},
		{"classic_only", []CurveID{X25519}, []keyShare{classic}, true},
		{"hybrid_advertised_without_share", []CurveID{X25519MLKEM768, X25519}, []keyShare{classic}, false},
		{"hybrid_advertised_after_classic", []CurveID{X25519, X25519MLKEM768}, []keyShare{classic}, false},
		{"unadvertised_hybrid_before_classic", []CurveID{X25519}, []keyShare{hybrid, classic}, false},
		{"unadvertised_hybrid_after_classic", []CurveID{X25519}, []keyShare{classic, hybrid}, false},
		{"malformed_hybrid_before_classic", []CurveID{X25519}, []keyShare{badHybrid, classic}, false},
		{"malformed_hybrid_after_classic", []CurveID{X25519}, []keyShare{classic, badHybrid}, false},
		{"empty_hybrid_after_classic", []CurveID{X25519}, []keyShare{classic, {group: X25519MLKEM768}}, false},
		{"duplicate_classic", []CurveID{X25519}, []keyShare{classic, classic}, false},
		{"duplicate_classic_separated_by_grease", []CurveID{X25519}, []keyShare{classic, grease, classic}, false},
		{"short_classic", []CurveID{X25519}, []keyShare{short}, false},
		{"long_classic", []CurveID{X25519}, []keyShare{long}, false},
		{"empty_classic", []CurveID{X25519}, []keyShare{empty}, false},
		{"classic_then_short", []CurveID{X25519}, []keyShare{classic, short}, false},
		{"short_then_classic", []CurveID{X25519}, []keyShare{short, classic}, false},
		{"classic_then_long", []CurveID{X25519}, []keyShare{classic, long}, false},
		{"classic_then_empty", []CurveID{X25519}, []keyShare{classic, empty}, false},
		{"empty_then_classic", []CurveID{X25519}, []keyShare{empty, classic}, false},
		{"no_shares", []CurveID{X25519}, nil, false},
		{"no_suitable_share", []CurveID{CurveP256}, []keyShare{other}, false},
		{"empty_hello", nil, nil, false},
		{"classic_with_other_groups_and_shares", []CurveID{CurveID(0x0a0a), CurveP256, X25519}, []keyShare{grease, other, classic, grease}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := &clientHelloMsg{supportedCurves: tt.groups, keyShares: tt.shares}
			got := classicX25519KeyShare(hello)
			if tt.want {
				if !bytes.Equal(got, classic.data) {
					t.Fatalf("got %x, want classic X25519 share %x", got, classic.data)
				}
			} else if got != nil {
				t.Fatalf("got %x, want rejection", got)
			}
		})
	}
}
