package xmc

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type profileKey struct {
	username string
	uuid     UUID
}

// serverRuntime is fully initialized before publication and never mutated.
// Each listener and connection holds a reference; no global cache retains it.
type serverRuntime struct {
	profiles      map[profileKey]loginProfile
	password      string
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  []byte
}

func newServerRuntime(profiles []loginProfile, password string, privateKeyDER, publicKey []byte) (*serverRuntime, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("empty profiles")
	}
	if len(privateKeyDER) == 0 {
		return nil, fmt.Errorf("empty rsa private key")
	}
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("empty rsa public key")
	}
	// ParsePKCS1PrivateKey validates and precomputes the key. Decryption can
	// safely share it provided that neither it nor its fields are modified.
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse rsa private key: %w", err)
	}
	index := make(map[profileKey]loginProfile, len(profiles))
	for _, profile := range profiles {
		key := profileKey{username: profile.Username, uuid: profile.UUID}
		if _, found := index[key]; !found {
			// findProfile returns the first matching entry, including when
			// later entries have different textures for the same identity.
			index[key] = profile
		}
	}
	return &serverRuntime{
		profiles:      index,
		password:      password,
		rsaPrivateKey: privateKey,
		rsaPublicKey:  bytes.Clone(publicKey),
	}, nil
}

func (r *serverRuntime) lookupProfile(username string, uuid UUID) (loginProfile, bool) {
	profile, found := r.profiles[profileKey{username: username, uuid: uuid}]
	return profile, found
}

type preparedServerMask struct {
	clientConfig *Config
	runtime      *serverRuntime
}

func (m *preparedServerMask) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	return m.clientConfig.WrapConnClient(conn, dest, dialer)
}

func (m *preparedServerMask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	wrapped, err := m.runtime.wrapConn(conn)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	return wrapped, nil
}

func (m *preparedServerMask) lookupProfile(username string, uuid UUID) (loginProfile, bool) {
	return m.runtime.lookupProfile(username, uuid)
}
