package xmc

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func runtimeTestConfig(t *testing.T, password string, profiles ...loginProfile) *Config {
	t.Helper()
	privateKey, publicKey := deriveTestRSAKey(t, password)
	config := &Config{Password: password, RsaPrivateKey: privateKey, RsaPublicKey: publicKey, Hostname: "localhost"}
	for _, profile := range profiles {
		config.Profiles = append(config.Profiles, &Profile{
			Username:          profile.Username,
			Uuid:              bytes.Clone(profile.UUID[:]),
			TexturesValue:     profile.TexturesValue,
			TexturesSignature: profile.TexturesSignature,
		})
	}
	return config
}

func prepareRuntimeForTest(t *testing.T, config *Config) *preparedServerMask {
	t.Helper()
	mask, err := config.PrepareServer()
	if err != nil {
		t.Fatal(err)
	}
	return mask.(*preparedServerMask)
}

func TestPreparedServerProfileLookup(t *testing.T) {
	first := testLoginProfile("CaseSensitive")
	duplicate := first
	duplicate.TexturesValue = "different-value"
	duplicate.TexturesSignature = "different-signature"
	otherUUID := first
	otherUUID.UUID[0] ^= 0xff
	otherName := first
	otherName.Username = strings.ToLower(first.Username)
	profiles := []loginProfile{first, duplicate, otherUUID, otherName}
	mask := prepareRuntimeForTest(t, runtimeTestConfig(t, "lookup-password", profiles...))
	for _, profile := range profiles {
		want, wantFound := findProfile(profiles, profile.Username, profile.UUID)
		got, found := mask.lookupProfile(profile.Username, profile.UUID)
		if found != wantFound || got != want {
			t.Fatalf("lookup for %q differs from first-match behavior", profile.Username)
		}
	}
	for _, query := range []loginProfile{
		{Username: "missing", UUID: first.UUID},
		{Username: first.Username, UUID: UUID{}},
		{Username: strings.ToUpper(first.Username), UUID: first.UUID},
	} {
		if _, found := mask.lookupProfile(query.Username, query.UUID); found {
			t.Fatalf("unexpected profile match for %q", query.Username)
		}
	}
}

func TestPrepareServerRejectsInvalidConfiguration(t *testing.T) {
	profile := testLoginProfile("ValidUser")
	valid := runtimeTestConfig(t, "invalid-config-password", profile)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"empty_profiles", func(c *Config) { c.Profiles = nil }, "empty profiles"},
		{"nil_profile", func(c *Config) { c.Profiles = append(c.Profiles, nil) }, "invalid profile"},
		{"empty_username", func(c *Config) { c.Profiles[0].Username = "" }, "invalid profile"},
		{"bad_uuid", func(c *Config) { c.Profiles[0].Uuid = []byte{1} }, "bad profile UUID length"},
		{"missing_textures", func(c *Config) { c.Profiles[0].TexturesValue = "" }, "incomplete profile textures"},
		{"invalid_later_duplicate", func(c *Config) {
			c.Profiles = append(c.Profiles, &Profile{Username: profile.Username, Uuid: bytes.Clone(profile.UUID[:]), TexturesValue: profile.TexturesValue})
		}, "incomplete profile textures"},
		{"missing_private_key", func(c *Config) { c.RsaPrivateKey = nil }, "empty rsa private key"},
		{"missing_public_key", func(c *Config) { c.RsaPublicKey = nil }, "empty rsa public key"},
		{"invalid_private_key", func(c *Config) { c.RsaPrivateKey = []byte{1, 2, 3} }, "parse rsa private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				Password: valid.Password, RsaPrivateKey: bytes.Clone(valid.RsaPrivateKey), RsaPublicKey: bytes.Clone(valid.RsaPublicKey),
				Profiles: []*Profile{{Username: profile.Username, Uuid: bytes.Clone(profile.UUID[:]), TexturesValue: profile.TexturesValue, TexturesSignature: profile.TexturesSignature}},
			}
			tc.mutate(config)
			if _, err := config.PrepareServer(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PrepareServer error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPreparedServerOwnsConfigurationSnapshot(t *testing.T) {
	const password = "snapshot-password"
	profile := testLoginProfile("SnapshotUser")
	config := runtimeTestConfig(t, password, profile)
	publicKey := bytes.Clone(config.RsaPublicKey)
	mask := prepareRuntimeForTest(t, config)
	config.Password = "changed"
	config.Profiles[0].Username = "ChangedUser"
	clear(config.Profiles[0].Uuid)
	config.Profiles[0].TexturesValue = "changed"
	config.Profiles[0].TexturesSignature = "changed"
	clear(config.RsaPrivateKey)
	clear(config.RsaPublicKey)
	config.Profiles = nil
	if got, found := mask.lookupProfile(profile.Username, profile.UUID); !found || got != profile {
		t.Fatal("configuration mutation changed prepared profile")
	}
	if !bytes.Equal(mask.runtime.rsaPublicKey, publicKey) {
		t.Fatal("configuration mutation changed prepared public key")
	}
	clientErr, serverErr := runtimeRoundTrip(t, mask, profile, password, publicKey)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("snapshot round trip: client=%v server=%v", clientErr, serverErr)
	}
}

func TestPreparedServerConnectionsShareRuntimeAndIsolatePadding(t *testing.T) {
	mask := prepareRuntimeForTest(t, runtimeTestConfig(t, "shared-runtime-password", testLoginProfile("SharedUser")))
	var connections []*serverConn
	for range 2 {
		clientRaw, serverRaw := net.Pipe()
		t.Cleanup(func() { clientRaw.Close() })
		wrapped, err := mask.WrapConnServer(serverRaw)
		if err != nil {
			serverRaw.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { wrapped.Close() })
		connections = append(connections, wrapped.(*serverConn))
	}
	first, second := connections[0], connections[1]
	if first.serverRuntime != mask.runtime || second.serverRuntime != mask.runtime {
		t.Fatal("connections did not reuse the prepared runtime")
	}
	if first.rsaPrivateKey != second.rsaPrivateKey {
		t.Fatal("connections did not reuse the parsed RSA key")
	}
	want := second.paddingSchedule[0].minLength
	first.paddingSchedule[0].minLength++
	if second.paddingSchedule[0].minLength != want {
		t.Fatal("per-connection padding schedule is shared")
	}
}

func TestPreparedServerReplacement(t *testing.T) {
	oldProfile, newProfile := testLoginProfile("OldUser"), testLoginProfile("NewUser")
	config := runtimeTestConfig(t, "old-password", oldProfile)
	oldPublicKey := bytes.Clone(config.RsaPublicKey)
	oldMask := prepareRuntimeForTest(t, config)
	newConfig := runtimeTestConfig(t, "new-password", newProfile)
	newMask := prepareRuntimeForTest(t, newConfig)
	if oldMask.runtime == newMask.runtime || oldMask.runtime.rsaPrivateKey == newMask.runtime.rsaPrivateKey {
		t.Fatal("replacement reused previous runtime/key")
	}
	if _, found := newMask.lookupProfile(oldProfile.Username, oldProfile.UUID); found {
		t.Fatal("replacement retained a removed profile")
	}
	if _, found := oldMask.lookupProfile(newProfile.Username, newProfile.UUID); found {
		t.Fatal("replacement changed the previous snapshot")
	}
	for _, tc := range []struct {
		name     string
		mask     *preparedServerMask
		profile  loginProfile
		password string
		key      []byte
	}{
		{"old", oldMask, oldProfile, "old-password", oldPublicKey},
		{"new", newMask, newProfile, "new-password", newConfig.RsaPublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientErr, serverErr := runtimeRoundTrip(t, tc.mask, tc.profile, tc.password, tc.key)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("round trip: client=%v server=%v", clientErr, serverErr)
			}
		})
	}
}

func TestPreparedServerConcurrentHandshakes(t *testing.T) {
	const password = "parallel-password"
	profiles := []loginProfile{testLoginProfile("FirstUser"), testLoginProfile("SecondUser")}
	config := runtimeTestConfig(t, password, profiles...)
	mask := prepareRuntimeForTest(t, config)
	for i := range 16 {
		t.Run(fmt.Sprintf("connection_%d", i), func(t *testing.T) {
			t.Parallel()
			clientErr, serverErr := runtimeRoundTrip(t, mask, profiles[i%len(profiles)], password, config.RsaPublicKey)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("round trip: client=%v server=%v", clientErr, serverErr)
			}
		})
	}
}

func TestPreparedServerAuthenticationFailures(t *testing.T) {
	const password = "authentication-password"
	profile := testLoginProfile("ValidUser")
	config := runtimeTestConfig(t, password, profile)
	mask := prepareRuntimeForTest(t, config)
	_, wrongPublicKey := deriveTestRSAKey(t, "different-rsa-key")
	for _, tc := range []struct {
		name       string
		profile    loginProfile
		password   string
		key        []byte
		clientWant string
		serverWant string
	}{
		{"password", profile, "wrong", config.RsaPublicKey, "authentication rejected", "bad password"},
		{"profile", testLoginProfile("UnknownUser"), password, config.RsaPublicKey, "not white-listed", "unknown login profile"},
		{"password_before_profile", testLoginProfile("UnknownUser"), "wrong", config.RsaPublicKey, "authentication rejected", "bad password"},
		{"rsa_key", profile, password, wrongPublicKey, "server public key mismatch", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientErr, serverErr := runtimeRoundTrip(t, mask, tc.profile, tc.password, tc.key)
			if clientErr == nil || !strings.Contains(clientErr.Error(), tc.clientWant) {
				t.Fatalf("client error = %v, want %q", clientErr, tc.clientWant)
			}
			if serverErr == nil || (tc.serverWant != "" && !strings.Contains(serverErr.Error(), tc.serverWant)) {
				t.Fatalf("server error = %v, want %q", serverErr, tc.serverWant)
			}
		})
	}
}

func runtimeRoundTrip(t *testing.T, mask finalmask.TCPMask, profile loginProfile, password string, publicKey []byte) (error, error) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	wrapped, err := mask.WrapConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	server := wrapped.(*serverConn)
	defer server.Close()
	client, err := newClientConn(clientRaw, []loginProfile{profile}, password, publicKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(20 * time.Second)
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("runtime-round-trip"), 512)
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(server, received); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(received, payload) {
			done <- fmt.Errorf("server payload mismatch")
			return
		}
		_, err := server.Write(received)
		done <- err
	}()
	_, clientErr := client.Write(payload)
	if clientErr == nil {
		received := make([]byte, len(payload))
		_, clientErr = io.ReadFull(client, received)
		if clientErr == nil && !bytes.Equal(received, payload) {
			clientErr = fmt.Errorf("client payload mismatch")
		}
	}
	client.Close()
	select {
	case serverErr := <-done:
		return clientErr, serverErr
	case <-time.After(21 * time.Second):
		t.Fatal("server did not finish after closing client")
		return nil, nil
	}
}
