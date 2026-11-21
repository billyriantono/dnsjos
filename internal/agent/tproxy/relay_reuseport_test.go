//go:build linux

package tproxy

import (
	"context"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// wildcardDNSListener mirrors what dnsdist holds in production: a plain (non
// IP_TRANSPARENT) UDP socket bound to a wildcard address with SO_REUSEADDR and
// SO_REUSEPORT.
func wildcardDNSListener(t *testing.T, network, addr string) *net.UDPConn {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
	}}
	c, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		t.Fatalf("wildcard dnsdist listener on %s: %v", addr, err)
	}
	conn, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		t.Fatal("not a UDPConn")
	}
	return conn
}

// replyProbe returns a concrete address the reply socket can bind on network. IPv4 uses
// 127.0.0.1; IPv6 needs a real address, so it takes the first global unicast IPv6 the
// host has. Binding ::1 fails on a host with no IPv6 configured, so an empty string
// means "no IPv6 here" and the caller skips the IPv6 case.
func replyProbe(network string) string {
	if network == "udp4" {
		return "127.0.0.1"
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To16() == nil || ipnet.IP.To4() != nil {
				continue
			}
			if ip := ipnet.IP; ip.IsGlobalUnicast() {
				return ip.String()
			}
		}
	}
	return ""
}

// wildcard53 is the dnsdist wildcard address for network, or the same address on a free
// high port when port 53 is already taken (a host running dnsdist itself). The
// REUSEPORT semantics under test are identical either way. probe is a concrete address
// the reply socket can bind on the same port, or "" when the host has no IPv6.
func wildcard53(t *testing.T, network string) (wildcard, probe string) {
	t.Helper()
	local := replyProbe(network)
	if local == "" {
		t.Skip("no IPv6 address on this host")
	}
	host := "0.0.0.0"
	if network == "udp6" {
		host = "::"
	}
	wildcard = net.JoinHostPort(host, "53")
	if _, err := net.ListenPacket("udp", wildcard); err == nil {
		return wildcard, net.JoinHostPort(local, "53")
	}
	t.Log("wildcard :53 taken; exercising the same REUSEPORT semantics on a free high port")
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	w := net.JoinHostPort(host, strconv.Itoa(port))
	return w, net.JoinHostPort(local, strconv.Itoa(port))
}

// TestReplySocketBindsBesideWildcardListener reproduces the production failure: dnsdist
// holds the wildcard :53 with SO_REUSEADDR+SO_REUSEPORT, and the relay must still bind
// the original destination (e.g. 1.1.1.1:53) to answer from the right source. Without
// SO_REUSEPORT on the reply socket the bind fails with EADDRINUSE and the relay falls
// back to answering from its own listener, which clients reject.
func TestReplySocketBindsBesideWildcardListener(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for IP_TRANSPARENT")
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			wildcard, probe := wildcard53(t, network)
			dummy := wildcardDNSListener(t, network, wildcard)
			defer dummy.Close()

			// The relay's reply socket must bind a concrete address on the same port,
			// next to the wildcard listener, and survive a second bind of the same
			// original destination (two clients asking the same resolver at once).
			c, err := listenTransparentPacket(context.Background(), network, probe, false)
			if err != nil {
				t.Fatalf("transparent reply socket on %s: %v", probe, err)
			}
			defer c.Close()

			c2, err := listenTransparentPacket(context.Background(), network, probe, false)
			if err != nil {
				t.Fatalf("second transparent reply socket on %s: %v", probe, err)
			}
			c2.Close()
		})
	}
}
