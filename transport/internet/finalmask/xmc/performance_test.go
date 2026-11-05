package xmc

import (
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// The optional interfaces keep this benchmark source usable on the unmodified
// release, so both versions execute the same workloads and setup boundaries.
type performanceServerPreparer interface {
	PrepareServer() (finalmask.TCPMask, error)
}

type performanceProfileLookup interface {
	lookupProfile(string, UUID) (loginProfile, bool)
}

var (
	performanceKeysOnce sync.Once
	performanceDER      []byte
	performancePublic   []byte
	performanceKeyErr   error
	performanceSink     any
	performanceProfile  loginProfile
	performanceFound    bool
)

func performanceConfig(tb testing.TB, count int) *Config {
	tb.Helper()
	const password = "xmc-performance-fixture"
	performanceKeysOnce.Do(func() {
		var key *rsa.PrivateKey
		key, performanceKeyErr = DeriveRSAKey(password)
		if performanceKeyErr == nil {
			performanceDER = x509.MarshalPKCS1PrivateKey(key)
			performancePublic, performanceKeyErr = x509.MarshalPKIXPublicKey(&key.PublicKey)
		}
	})
	if performanceKeyErr != nil {
		tb.Fatal(performanceKeyErr)
	}
	cfg := &Config{Password: password, Hostname: "localhost", RsaPrivateKey: performanceDER, RsaPublicKey: performancePublic}
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("BenchUser%05d", i)
		digest := sha256.Sum256([]byte(name))
		cfg.Profiles = append(cfg.Profiles, &Profile{
			Username: name, Uuid: bytes.Clone(digest[:16]),
			TexturesValue:     name + strings.Repeat("texture-value-", 40),
			TexturesSignature: name + strings.Repeat("texture-signature-", 24),
		})
	}
	return cfg
}

func performanceServer(tb testing.TB, cfg *Config) finalmask.TCPMask {
	tb.Helper()
	if preparer, ok := any(cfg).(performanceServerPreparer); ok {
		mask, err := preparer.PrepareServer()
		if err != nil {
			tb.Fatal(err)
		}
		return mask
	}
	return cfg
}

// Preparation is a one-time cost in the patched server. On the release these
// same profile conversion/key parse operations occur for each connection.
func BenchmarkXMCServerPreparation(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("Profiles%d", count), func(b *testing.B) {
			cfg := performanceConfig(b, count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if preparer, ok := any(cfg).(performanceServerPreparer); ok {
					prepared, err := preparer.PrepareServer()
					if err != nil {
						b.Fatal(err)
					}
					performanceSink = prepared
				} else {
					profiles, err := profilesFromConfig(cfg.Profiles)
					if err != nil {
						b.Fatal(err)
					}
					key, err := x509.ParsePKCS1PrivateKey(cfg.RsaPrivateKey)
					if err != nil {
						b.Fatal(err)
					}
					performanceSink = struct {
						profiles []loginProfile
						key      *rsa.PrivateKey
					}{profiles, key}
				}
			}
		})
	}
}

type performanceConn struct{}

func (performanceConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (performanceConn) Write(p []byte) (int, error)     { return len(p), nil }
func (performanceConn) Close() error                    { return nil }
func (performanceConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (performanceConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (performanceConn) SetDeadline(time.Time) error     { return nil }
func (performanceConn) SetReadDeadline(time.Time) error { return nil }
func (performanceConn) SetWriteDeadline(time.Time) error {
	return nil
}

// This measures the server wrapper constructed on Accept, without TCP/handshake
// I/O. It includes a fresh randomized padding schedule and connection state.
func BenchmarkXMCServerWrap(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("Profiles%d", count), func(b *testing.B) {
			mask := performanceServer(b, performanceConfig(b, count))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				conn, err := mask.WrapConnServer(performanceConn{})
				if err != nil {
					b.Fatal(err)
				}
				if err := conn.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkXMCProfileLookup(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("Profiles%d", count), func(b *testing.B) {
			cfg := performanceConfig(b, count)
			profiles, err := profilesFromConfig(cfg.Profiles)
			if err != nil {
				b.Fatal(err)
			}
			lookup := func(name string, id UUID) (loginProfile, bool) { return findProfile(profiles, name, id) }
			if prepared, ok := performanceServer(b, cfg).(performanceProfileLookup); ok {
				lookup = prepared.lookupProfile
			}
			for _, tc := range []struct {
				name    string
				profile loginProfile
			}{
				{"First", profiles[0]},
				{"Last", profiles[len(profiles)-1]},
				{"Miss", loginProfile{Username: "BenchUserXXXXX"}},
			} {
				b.Run(tc.name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						performanceProfile, performanceFound = lookup(tc.profile.Username, tc.profile.UUID)
					}
				})
			}
		})
	}
}

func BenchmarkXMCCFB8(b *testing.B) {
	for _, size := range []int{1 << 10, 8 << 10, 64 << 10, 1 << 20} {
		for _, decrypt := range []bool{false, true} {
			for _, inplace := range []bool{false, true} {
				name := fmt.Sprintf("Bytes%d/Decrypt%t/InPlace%t", size, decrypt, inplace)
				b.Run(name, func(b *testing.B) {
					secret := []byte("0123456789abcdef")
					block, err := aes.NewCipher(secret)
					if err != nil {
						b.Fatal(err)
					}
					stream := newCFB8(block, secret, decrypt)
					src, dst := make([]byte, size), make([]byte, size)
					if inplace {
						dst = src
					}
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						stream.XORKeyStream(dst, src)
					}
				})
			}
		}
	}
}

func BenchmarkXMCCryptoWrite(b *testing.B) {
	for _, size := range []int{1 << 10, 8 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("Bytes%d", size), func(b *testing.B) {
			writer, err := newCryptoWriter(io.Discard, []byte("0123456789abcdef"))
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := writer.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
