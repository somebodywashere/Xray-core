package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestMuxConfiguration(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)

	tests := []struct {
		name     string
		settings *proxyman.MultiplexingConfig
		wantTCP  int32
		wantXUDP int32
	}{
		{name: "absent"},
		{name: "disabled", settings: &proxyman.MultiplexingConfig{Concurrency: 8, XudpConcurrency: 16}},
		{name: "default", settings: &proxyman.MultiplexingConfig{Enabled: true}, wantTCP: 128},
		{name: "explicit_one", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 1}, wantTCP: 1},
		{name: "explicit_eight", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8}, wantTCP: 8},
		{name: "explicit_127", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 127}, wantTCP: 127},
		{name: "explicit_128", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 128}, wantTCP: 128},
		{name: "explicit_256", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 256}, wantTCP: 256},
		{name: "negative_tcp", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: -1}, wantTCP: -1},
		{name: "independent_xudp", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8, XudpConcurrency: 16}, wantTCP: 8, wantXUDP: 16},
		{name: "xudp_only", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: -1, XudpConcurrency: 16}, wantTCP: -1, wantXUDP: 16},
		{name: "negative_xudp", settings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8, XudpConcurrency: -1}, wantTCP: 8, wantXUDP: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := NewHandler(ctx, &core.OutboundHandlerConfig{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{MultiplexSettings: tt.settings}),
				ProxySettings:  serial.ToTypedMessage(&blackhole.Config{}),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := raw.Close(); err != nil {
					t.Error(err)
				}
			})
			handler := raw.(*Handler)
			checkMuxStrategy(t, "TCP", handler.mux, tt.wantTCP)
			checkMuxStrategy(t, "XUDP", handler.xudp, tt.wantXUDP)
		})
	}
}

// A zero expectation means no manager, and a negative one means explicitly disabled.
func checkMuxStrategy(t *testing.T, name string, manager *mux.ClientManager, want int32) {
	t.Helper()
	if want == 0 {
		if manager != nil {
			t.Errorf("%s: unexpected mux manager", name)
		}
		return
	}
	if manager == nil {
		t.Errorf("%s: missing mux manager", name)
		return
	}
	if want < 0 {
		if manager.Enabled || manager.Picker != nil {
			t.Errorf("%s: expected disabled mux manager", name)
		}
		return
	}
	if !manager.Enabled {
		t.Errorf("%s: mux is disabled", name)
		return
	}
	picker, ok := manager.Picker.(*mux.IncrementalWorkerPicker)
	if !ok {
		t.Fatalf("%s: unexpected worker picker %T", name, manager.Picker)
	}
	factory, ok := picker.Factory.(*mux.DialingWorkerFactory)
	if !ok {
		t.Fatalf("%s: unexpected worker factory %T", name, picker.Factory)
	}
	// Inspect the policy used to allocate real mux workers, not the input config.
	expected := mux.ClientStrategy{MaxConcurrency: uint32(want), MaxConnection: 1024}
	if factory.Strategy != expected {
		t.Errorf("%s: worker strategy = %+v, want %+v", name, factory.Strategy, expected)
	}
}
