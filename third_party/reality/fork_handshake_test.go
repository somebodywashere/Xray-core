package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

const forkServerName = "reality.test"

var forkShortID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

func forkPrivateKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func forkListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

type forkServerResult struct {
	conn *Conn
	err  error
}

func forkStartServer(t *testing.T, dest string, key *ecdh.PrivateKey) (net.Conn, <-chan forkServerResult) {
	t.Helper()
	l := forkListener(t)
	config := &Config{
		Type: "tcp", Dest: dest, PrivateKey: key,
		ServerNames:  map[string]bool{forkServerName: true},
		ShortIds:     map[[8]byte]bool{forkShortID: true},
		MinClientVer: []byte{26, 10, 21}, MaxClientVer: []byte{26, 10, 21},
		MaxTimeDiff: time.Minute,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
			if err == nil {
				c.SetDeadline(time.Now().Add(10 * time.Second))
			}
			return c, err
		},
	}
	// The local fixture disables session tickets and emits no post-handshake
	// records. Seed the normal target-probe cache with that known result.
	cacheKey := dest + " " + forkServerName + " 0"
	GlobalPostHandshakeRecordsLens.Store(cacheKey, []int{})
	t.Cleanup(func() { GlobalPostHandshakeRecordsLens.Delete(cacheKey) })
	result := make(chan forkServerResult, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			result <- forkServerResult{err: err}
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		s, err := Server(context.Background(), c, config)
		if err == nil {
			var payload [4]byte
			_, err = io.ReadFull(s, payload[:])
			if err == nil && string(payload[:]) != "ping" {
				err = fmt.Errorf("unexpected application payload %q", payload)
			}
			if err == nil {
				_, err = s.Write([]byte("REALITY"))
			}
		}
		result <- forkServerResult{conn: s, err: err}
	}()
	c, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c, result
}

func forkSealHello(t *testing.T, raw, random []byte, clientKey, serverKey *ecdh.PrivateKey) []byte {
	t.Helper()
	shared, err := clientKey.ECDH(serverKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	authKey, err := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 16)
	copy(plain, []byte{26, 10, 21})
	binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Unix()))
	copy(plain[8:], forkShortID[:])
	clear(raw[39:71])
	sealed := aead.Seal(nil, random[20:], plain, raw)
	copy(raw[39:71], sealed)
	return authKey
}

func forkClient(t *testing.T, conn net.Conn, key *ecdh.PrivateKey, curves, shares []utls.CurveID) (*utls.UConn, []byte, *bool) {
	t.Helper()
	var authKey []byte
	verified := false
	c := utls.UClient(conn, &utls.Config{
		ServerName: forkServerName, InsecureSkipVerify: true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if ok {
				h := hmac.New(sha512.New, authKey)
				h.Write(pub)
				verified = hmac.Equal(h.Sum(nil), cert.Signature)
			}
			return nil
		},
	}, utls.HelloCustom)
	keyShares := &utls.KeyShareExtension{}
	for _, group := range shares {
		keyShares.KeyShares = append(keyShares.KeyShares, utls.KeyShare{Group: group})
	}
	if err := c.ApplyPreset(&utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS13, TLSVersMax: utls.VersionTLS13,
		CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{Curves: curves},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.Ed25519}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			keyShares,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	keys := c.HandshakeState.State13.KeyShareKeys
	clientKey := keys.Ecdhe
	if clientKey == nil {
		clientKey = keys.MlkemEcdhe
	}
	if keys.Ecdhe != nil && keys.MlkemEcdhe != nil && bytes.Equal(keys.Ecdhe.Bytes(), keys.MlkemEcdhe.Bytes()) {
		t.Fatal("hybrid and classic test shares must use distinct keys")
	}
	// This uTLS version requires Ecdhe to be non-nil even for a hybrid-only
	// custom hello. Populate its private state without adding a wire share.
	if keys.Ecdhe == nil {
		keys.Ecdhe = keys.MlkemEcdhe
	}
	hello := c.HandshakeState.Hello
	authKey = forkSealHello(t, hello.Raw, hello.Random, clientKey, key)
	copy(hello.SessionId, hello.Raw[39:71])
	return c, authKey, &verified
}

func forkTLSTarget(t *testing.T, curves []stdtls.CurveID) (string, []byte, <-chan error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{forkServerName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	l := forkListener(t)
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		c := stdtls.Server(conn, &stdtls.Config{
			Certificates: []stdtls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: priv}},
			MinVersion:   stdtls.VersionTLS13, SessionTicketsDisabled: true,
			CurvePreferences: curves,
		})
		if err = c.Handshake(); err == nil {
			var payload [4]byte
			_, err = io.ReadFull(c, payload[:])
			if err == nil && string(payload[:]) != "ping" {
				err = fmt.Errorf("unexpected fallback payload %q", payload)
			}
			if err == nil {
				_, err = c.Write([]byte("FALLBACK"))
			}
		}
		done <- err
	}()
	return l.Addr().String(), cert, done
}

func TestForkREALITYHandshake(t *testing.T) {
	for _, tc := range []struct {
		name           string
		curves, shares []utls.CurveID
		accepted       bool
	}{
		{"hybrid", []utls.CurveID{utls.X25519MLKEM768}, []utls.CurveID{utls.X25519MLKEM768}, true},
		{"hybrid_and_classic", []utls.CurveID{utls.X25519MLKEM768, utls.X25519}, []utls.CurveID{utls.X25519MLKEM768, utls.X25519}, true},
		{"classic", []utls.CurveID{utls.X25519}, []utls.CurveID{utls.X25519}, true},
		{"advertised_hybrid_without_share", []utls.CurveID{utls.X25519MLKEM768, utls.X25519}, []utls.CurveID{utls.X25519}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetCurves := []stdtls.CurveID{stdtls.X25519MLKEM768, stdtls.X25519}
			if !tc.accepted {
				// Accept the offered classic share instead of requesting a new
				// hybrid share, so fallback can complete a real TLS handshake.
				targetCurves = []stdtls.CurveID{stdtls.X25519}
			}
			dest, targetCert, targetDone := forkTLSTarget(t, targetCurves)
			key := forkPrivateKey(t)
			raw, serverDone := forkStartServer(t, dest, key)
			client, authKey, verified := forkClient(t, raw, key, tc.curves, tc.shares)
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if *verified != tc.accepted {
				t.Fatalf("REALITY certificate verified = %v, want %v", *verified, tc.accepted)
			}
			if !tc.accepted && !bytes.Equal(client.ConnectionState().PeerCertificates[0].Raw, targetCert) {
				t.Fatal("fallback did not present the target certificate")
			}
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			want := "REALITY"
			if !tc.accepted {
				want = "FALLBACK"
			}
			response := make([]byte, len(want))
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if string(response) != want {
				t.Fatalf("response = %q, want %q", response, want)
			}
			raw.Close()
			result := <-serverDone
			if tc.accepted {
				if result.err != nil {
					t.Fatal(result.err)
				}
				if result.conn == nil || !result.conn.ConnectionState().HandshakeComplete || !bytes.Equal(result.conn.AuthKey, authKey) || result.conn.ClientShortId != forkShortID || result.conn.ClientVer != [3]byte{26, 10, 21} {
					t.Fatal("server did not complete authenticated REALITY handshake")
				}
				if got := client.HandshakeState.ServerHello.ServerShare.Group; got != tc.shares[0] {
					t.Fatalf("negotiated group = %v, want %v", got, tc.shares[0])
				}
			} else if result.conn != nil || result.err == nil || !strings.Contains(result.err.Error(), "authentication failed") {
				t.Fatalf("rejected hello returned %v, %v", result.conn, result.err)
			}
			targetErr := <-targetDone
			if !tc.accepted && targetErr != nil {
				t.Fatal(targetErr)
			}
		})
	}
}

func TestForkREALITYRejectedHelloFallback(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mutate        func(*clientHelloMsg)
		authenticated bool
	}{
		{"authenticated_classic_control", func(h *clientHelloMsg) {}, true},
		{"advertised_hybrid_without_share", func(h *clientHelloMsg) { h.supportedCurves = append(h.supportedCurves, X25519MLKEM768) }, false},
		{"duplicate_classic", func(h *clientHelloMsg) { h.keyShares = append(h.keyShares, h.keyShares[0]) }, false},
		{"short_classic", func(h *clientHelloMsg) { h.keyShares[0].data = h.keyShares[0].data[:31] }, false},
		{"long_classic", func(h *clientHelloMsg) { h.keyShares[0].data = append(h.keyShares[0].data, 0) }, false},
		{"low_order_classic", func(h *clientHelloMsg) { h.keyShares[0].data = make([]byte, 32) }, false},
		{"no_share", func(h *clientHelloMsg) { h.keyShares = nil }, false},
		{"unadvertised_hybrid_after_classic", func(h *clientHelloMsg) {
			h.keyShares = append(h.keyShares, keyShare{group: X25519MLKEM768, data: []byte{1}})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverKey, clientKey := forkPrivateKey(t), forkPrivateKey(t)
			hello := &clientHelloMsg{
				vers: VersionTLS12, random: make([]byte, 32), sessionId: make([]byte, 32),
				cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []byte{0},
				serverName: forkServerName, supportedVersions: []uint16{VersionTLS13},
				supportedSignatureAlgorithms: []SignatureScheme{Ed25519},
				supportedCurves:              []CurveID{X25519},
				keyShares:                    []keyShare{{group: X25519, data: clientKey.PublicKey().Bytes()}},
			}
			if _, err := rand.Read(hello.random); err != nil {
				t.Fatal(err)
			}
			tc.mutate(hello)
			body, err := hello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			forkSealHello(t, body, hello.random, clientKey, serverKey)
			record := append([]byte{22, 3, 1, byte(len(body) >> 8), byte(len(body))}, body...)
			target := forkListener(t)
			targetDone := make(chan error, 1)
			go func() {
				conn, err := target.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				got := make([]byte, len(record))
				if _, err = io.ReadFull(conn, got); err == nil && !bytes.Equal(got, record) {
					err = fmt.Errorf("target received modified ClientHello")
				}
				if err == nil {
					_, err = conn.Write([]byte("fallback-marker"))
				}
				if err == nil {
					var challenge [4]byte
					_, err = io.ReadFull(conn, challenge[:])
					if err == nil {
						_, err = conn.Write(challenge[:])
					}
				}
				targetDone <- err
			}()
			client, serverDone := forkStartServer(t, target.Addr().String(), serverKey)
			if _, err := client.Write(record); err != nil {
				t.Fatal(err)
			}
			marker := make([]byte, len("fallback-marker"))
			if _, err := io.ReadFull(client, marker); err != nil {
				t.Fatal(err)
			}
			if string(marker) != "fallback-marker" {
				t.Fatalf("unexpected fallback response %q", marker)
			}
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(client, echo); err != nil {
				t.Fatal(err)
			}
			if string(echo) != "ping" {
				t.Fatalf("unexpected fallback echo %q", echo)
			}
			client.(*net.TCPConn).CloseWrite()
			result := <-serverDone
			wantFailure := "authentication failed"
			if tc.authenticated {
				// Positive control for this raw serializer and AEAD fixture:
				// authentication succeeds, then the non-TLS target causes fallback.
				wantFailure = "target sent incorrect server hello"
			}
			if result.conn != nil || result.err == nil || !strings.Contains(result.err.Error(), wantFailure) {
				t.Fatalf("hello returned %v, %v; want %q", result.conn, result.err, wantFailure)
			}
			if err := <-targetDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
