package xmc_test

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/xmc"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func integrationXMCConfig(t *testing.T, password, prefix string) *xmc.Config {
	t.Helper()
	key, err := xmc.DeriveRSAKey(password)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &xmc.Config{
		Password: password, Hostname: "localhost",
		RsaPrivateKey: x509.MarshalPKCS1PrivateKey(key), RsaPublicKey: publicKey,
	}
	for i := range 100 {
		name := fmt.Sprintf("%s%03d", prefix, i)
		digest := sha256.Sum256([]byte(name))
		config.Profiles = append(config.Profiles, &xmc.Profile{
			Username: name, Uuid: bytes.Clone(digest[:16]),
			TexturesValue: "signed-texture-" + name, TexturesSignature: "signature-" + name,
		})
	}
	return config
}

func integrationCore(t *testing.T, config *core.Config) *core.Instance {
	t.Helper()
	config.App = append(config.App,
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}))
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

func integrationHandlerAPI(t *testing.T, instance *core.Instance) command.HandlerServiceClient {
	t.Helper()
	service, err := core.CreateObject(instance, &command.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	service.(interface{ Register(*grpc.Server) }).Register(server)
	listener := bufconn.Listen(1 << 20)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); listener.Close() })
	conn, err := grpc.NewClient("passthrough:///xmc-inbound-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return command.NewHandlerServiceClient(conn)
}

func integrationServerInbound(port int, mask *xmc.Config, privateKey, userID string) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag: "xmc-api-inbound",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen: xnet.NewIPOrDomain(xnet.LocalHostIP),
			PortList: &xnet.PortList{Range: []*xnet.PortRange{
				{From: uint32(port), To: uint32(port)},
			}},
			StreamSettings: &internet.StreamConfig{
				ProtocolName: "tcp", Tcpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)},
			},
		}),
		ProxySettings: serial.ToTypedMessage(&vlessin.Config{
			Users:      []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: userID})}},
			Decryption: privateKey, SecondsFrom: 600,
		}),
	}
}

func integrationClient(t *testing.T, port int, mask *xmc.Config, publicKey, userID string, zeroRTT bool) *core.Instance {
	t.Helper()
	var seconds uint32
	if zeroRTT {
		seconds = 1
	}
	return integrationCore(t, &core.Config{
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&vlessout.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port),
					User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
						Id: userID, Encryption: publicKey, Seconds: seconds,
					})},
				},
			}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: &internet.StreamConfig{
					ProtocolName: "tcp", Tcpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)},
				},
			}),
		}},
	})
}

func integrationExchange(instance *core.Instance, dest xnet.Destination, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, instance, dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err = io.Copy(conn, bytes.NewReader(payload)); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("XMC/VLESS encrypted round-trip changed payload")
	}
	return nil
}

// Exercise the production listener path and the real HandlerService API. All
// padding and encryption remain enabled; no sleeps are removed for this test.
func TestXMCVLESSEncryptionInboundRecreation(t *testing.T) {
	for _, zeroRTT := range []bool{false, true} {
		name := "1rtt"
		if zeroRTT {
			name = "0rtt"
		}
		t.Run(name, func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { echo.Close() })
			go func() {
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); conn.SetDeadline(time.Now().Add(30 * time.Second)); io.Copy(conn, conn) }()
				}
			}()
			dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port))
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()

			seed := make([]byte, 64)
			if _, err := rand.Read(seed); err != nil {
				t.Fatal(err)
			}
			key, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				t.Fatal(err)
			}
			privateKey := base64.RawURLEncoding.EncodeToString(seed)
			publicKey := base64.RawURLEncoding.EncodeToString(key.EncapsulationKey().Bytes())
			userID := "048a298d-2831-4aa6-a69d-14cfbb2161e1"
			server := integrationCore(t, &core.Config{
				Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				})}},
			})
			api := integrationHandlerAPI(t, server)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			oldMask := integrationXMCConfig(t, "old-xmc-test-password", "OldUser")
			if _, err := api.AddInbound(ctx, &command.AddInboundRequest{Inbound: integrationServerInbound(port, oldMask, privateKey, userID)}); err != nil {
				t.Fatal(err)
			}
			oldClient := integrationClient(t, port, oldMask, publicKey, userID, zeroRTT)
			payload := bytes.Repeat([]byte("XMC plus MLKEM768 and X25519: authenticated data\n"), 2048)
			// The second 0rtt-configured request reuses the same outbound instance
			// after its initial handshake has obtained a server session ticket.
			for range 2 {
				if err := integrationExchange(oldClient, dest, payload); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := api.RemoveInbound(ctx, &command.RemoveInboundRequest{Tag: "xmc-api-inbound"}); err != nil {
				t.Fatal(err)
			}
			newMask := integrationXMCConfig(t, "new-xmc-test-password", "NewUser")
			if _, err := api.AddInbound(ctx, &command.AddInboundRequest{Inbound: integrationServerInbound(port, newMask, privateKey, userID)}); err != nil {
				t.Fatal(err)
			}
			if err := integrationExchange(oldClient, dest, []byte("old credentials")); err == nil {
				t.Fatal("recreated inbound accepted the previous profiles/key/password")
			}
			wrongProfile := proto.Clone(newMask).(*xmc.Config)
			wrongProfile.Profiles = oldMask.Profiles
			if err := integrationExchange(integrationClient(t, port, wrongProfile, publicKey, userID, zeroRTT), dest, []byte("old profiles")); err == nil {
				t.Fatal("recreated inbound accepted removed Minecraft profiles")
			}
			wrongID := "058a298d-2831-4aa6-a69d-14cfbb2161e1"
			if err := integrationExchange(integrationClient(t, port, newMask, publicKey, wrongID, zeroRTT), dest, []byte("wrong VLESS UUID")); err == nil {
				t.Fatal("XMC profile/password bypassed VLESS UUID authentication")
			}
			newClient := integrationClient(t, port, newMask, publicKey, userID, zeroRTT)
			for range 2 {
				if err := integrationExchange(newClient, dest, payload); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
