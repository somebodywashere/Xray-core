package xudp

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestAccountRevocationAtChainedXUDPHop(t *testing.T) {
	// A subsequent proxy in a chain sees just one outbound account for
	// both local clients; it cannot revoke or distinguish their identities.
	ctx := context.WithValue(context.Background(), "cone", true)
	in := &session.Inbound{Name: "shadowsocks", Source: net.UDPDestination(net.LocalHostIP, 45000)}
	ctx = session.ContextWithInbound(ctx, in)
	if GetGlobalID(ctx) == [8]byte{} {
		t.Fatal("ordinary untracked XUDP source lost cross-carrier association")
	}
	in.User = (&protocol.MemoryUser{Email: "one"}).NewGeneration()
	if GetGlobalID(ctx) != [8]byte{} {
		t.Fatal("next hop would park a revocable user's flow under shared credentials")
	}
}
