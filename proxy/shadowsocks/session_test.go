package shadowsocks_test

import (
	"fmt"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy"
	ss "github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestRevokeUDPSender(t *testing.T) {
	echo := common.Must2(stdnet.ListenPacket("udp4", "127.0.0.1:0"))
	t.Cleanup(func() { echo.Close() })
	go func() {
		var packet [2048]byte
		for {
			n, addr, err := echo.ReadFrom(packet[:])
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(packet[:n], addr)
		}
	}()
	reserved := common.Must2(stdnet.ListenPacket("udp4", "127.0.0.1:0"))
	address := reserved.LocalAddr().String()
	port := reserved.LocalAddr().(*stdnet.UDPAddr).Port
	common.Must(reserved.Close())
	s, err := core.StartInstance("json", []byte(fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"tag":"ss","protocol":"shadowsocks",
		"settings":{"network":"udp","clients":[{"email":"A","method":"aes-128-gcm","password":"key-A"},{"email":"B","method":"aes-128-gcm","password":"key-B"}]}}],
		"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}`, port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h := common.Must2(s.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(t.Context(), "ss"))
	users := h.(proxy.GetInbound).GetInbound().(proxy.UserManager)
	a, b := users.GetUser(t.Context(), "A"), users.GetUser(t.Context(), "B")
	conn := func() stdnet.Conn {
		c := common.Must2(stdnet.Dial("udp4", address))
		t.Cleanup(func() { c.Close() })
		return c
	}
	cA, cB := conn(), conn()
	exchange := func(c stdnet.Conn, u *protocol.MemoryUser, msg string, retired bool) {
		t.Helper()
		req := &protocol.RequestHeader{User: u, Address: net.LocalHostIP, Port: net.Port(echo.LocalAddr().(*stdnet.UDPAddr).Port)}
		data := common.Must2(ss.EncodeUDPPacket(req, []byte(msg)))
		_, err := c.Write(data.Bytes())
		data.Release()
		if err != nil {
			t.Fatal(err)
		}
		timeout := 2 * time.Second
		if retired {
			timeout = 200 * time.Millisecond
		}
		common.Must(c.SetReadDeadline(time.Now().Add(timeout)))
		reply := buf.New()
		defer reply.Release()
		_, err = reply.ReadFrom(c)
		if retired {
			if n, ok := err.(stdnet.Error); !ok || !n.Timeout() {
				t.Fatalf("deleted account received a response: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		validator := new(ss.Validator)
		common.Must(validator.Add(u))
		_, payload, err := ss.DecodeUDPPacket(validator, reply)
		if err != nil || payload.String() != msg {
			t.Fatalf("unexpected UDP response: %v", err)
		}
	}
	exchange(cA, a, "A before", false)
	exchange(cB, b, "B before", false)
	common.Must(users.RemoveUser(t.Context(), "A"))
	exchange(cA, a, "retired", true)
	exchange(cB, b, "B after", false)
	common.Must(users.AddUser(t.Context(), a))
	exchange(cA, a, "A after", false)
}
