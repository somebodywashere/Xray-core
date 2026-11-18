package scenarios

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestRemoveConnectedProtocolUsers(t *testing.T) {
	for _, p := range []string{"vmess", "trojan", "shadowsocks", "shadowsocks-2022"} {
		t.Run(p, func(t *testing.T) {
			start := func(config string) *core.Instance {
				t.Helper()
				s, err := core.StartInstance("json", []byte(config))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			echo := tcp.Server{MsgProcessor: func(b []byte) []byte { return b }}
			dest, err := echo.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { echo.Close() })
			credentials := func(value string) string {
				if p == "vmess" {
					return fmt.Sprintf(`"id":%q`, value)
				}
				if p == "shadowsocks" {
					return fmt.Sprintf(`"method":"aes-128-gcm","password":%q`, value)
				}
				return fmt.Sprintf(`"password":%q`, value)
			}
			serverPort := tcp.PickPort()
			idA, idB := uuid.New(), uuid.New()
			a, b := idA.String(), idB.String()
			wireProtocol, methodSettings := p, ""
			const master = "MDEyMzQ1Njc4OWFiY2RlZg=="
			if p == "shadowsocks-2022" {
				wireProtocol = "shadowsocks"
				methodSettings = fmt.Sprintf(`"method":"2022-blake3-aes-128-gcm","password":%q,`, master)
				a, b = base64.StdEncoding.EncodeToString(idA[:]), base64.StdEncoding.EncodeToString(idB[:])
			}
			server := start(fmt.Sprintf(`{
				"inbounds":[{"listen":"127.0.0.1","port":%d,"tag":"test","protocol":%q,
					"settings":{%s"clients":[{"email":"a",%s},{"email":"b",%s}]}}],
				"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]
			}`, serverPort, wireProtocol, methodSettings, credentials(a), credentials(b)))
			in, err := server.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(t.Context(), "test")
			if err != nil {
				t.Fatal(err)
			}
			users := in.(proxy.GetInbound).GetInbound().(proxy.UserManager)
			original := protocol.ToProtoUser(users.GetUser(t.Context(), "a"))
			duplicate := protocol.ToProtoUser(users.GetUser(t.Context(), "a"))
			duplicate.Email = "alias"
			if err := (&command.AddUserOperation{User: duplicate}).ApplyInbound(t.Context(), in); err == nil ||
				users.GetUser(t.Context(), "alias") != nil || users.GetUsersCount(t.Context()) != 2 {
				t.Fatal("duplicate credentials accepted or left an email index")
			}
			client := func(cred string) func() net.Conn {
				t.Helper()
				port := tcp.PickPort()
				clientAccount := credentials(cred)
				if p == "shadowsocks-2022" {
					clientAccount = fmt.Sprintf(`"method":"2022-blake3-aes-128-gcm","password":%q`, master+":"+cred)
				}
				start(fmt.Sprintf(`{
					"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door",
						"settings":{"address":"127.0.0.1","port":%d,"network":"tcp"}}],
					"outbounds":[{"protocol":%q,"settings":{"address":"127.0.0.1","port":%d,%s}}]
				}`, port, dest.Port, wireProtocol, serverPort, clientAccount))
				return func() net.Conn {
					t.Helper()
					c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.Close() })
					return c
				}
			}
			exchange := func(c net.Conn) {
				t.Helper()
				message := []byte("roundtrip after auth")
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write(message); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(message))
				if _, err := io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, message) {
					t.Fatalf("reply = %q, err = %v", reply, err)
				}
			}
			closed := func(c net.Conn) {
				t.Helper()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := c.Read(make([]byte, 1))
				if err == nil {
					t.Fatal("deleted account still returned data")
				}
				if n, ok := err.(net.Error); ok && n.Timeout() {
					t.Fatal("deleted account connection stayed open")
				}
			}
			dialA, dialB := client(a), client(b)
			connA, connB := dialA(), dialB()
			exchange(connA)
			exchange(connB)
			if err := (&command.RemoveUserOperation{Email: "A"}).ApplyInbound(t.Context(), in); err != nil {
				t.Fatal(err)
			}
			closed(connA)
			exchange(connB)
			rejected := dialA()
			// VMess drains some bytes from an unauthenticated connection before closing.
			rejected.Write(make([]byte, 8192))
			closed(rejected)
			if err := (&command.AddUserOperation{User: original}).ApplyInbound(t.Context(), in); err != nil {
				t.Fatal(err)
			}
			exchange(dialA())
			exchange(connB)
		})
	}
}
