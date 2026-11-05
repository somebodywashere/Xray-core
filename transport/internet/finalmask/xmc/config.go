package xmc

import (
	"fmt"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc, err := newClientConn(conn, profiles, c.Password, c.RsaPublicKey, c.Hostname)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	prepared, err := c.PrepareServer()
	if err != nil {
		return nil, err
	}
	return prepared.WrapConnServer(conn)
}

// PrepareServer creates the immutable state shared by this server mask's
// connections. FinalMask prepares it once when starting its server listeners.
func (c *Config) PrepareServer() (finalmask.TCPMask, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	runtime, err := newServerRuntime(profiles, c.Password, c.RsaPrivateKey, c.RsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	return &preparedServerMask{clientConfig: c, runtime: runtime}, nil
}
