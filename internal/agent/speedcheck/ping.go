package speedcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ping sends one ICMP echo to ip (smartdns' "ping" speed check) and returns its round
// trip, -1 on timeout or error. It tries an unprivileged ICMP socket first, then a raw
// one (the agent runs as root).
func ping(ctx context.Context, ip string) time.Duration {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return -1
	}
	a = a.Unmap()
	typ, proto := icmp.Type(ipv4.ICMPTypeEcho), 1
	nets := [][2]string{{"udp4", "0.0.0.0"}, {"ip4:icmp", "0.0.0.0"}}
	if a.Is6() {
		typ, proto = ipv6.ICMPTypeEchoRequest, 58
		nets = [][2]string{{"udp6", "::"}, {"ip6:ipv6-icmp", "::"}}
	}
	var c *icmp.PacketConn
	var dst net.Addr
	for _, n := range nets {
		if c, err = icmp.ListenPacket(n[0], n[1]); err == nil {
			if n[0][:3] == "udp" {
				dst = &net.UDPAddr{IP: a.AsSlice()}
			} else {
				dst = &net.IPAddr{IP: a.AsSlice()}
			}
			break
		}
	}
	if c == nil {
		return -1
	}
	defer c.Close()
	token := make([]byte, 16) // matches our reply among every echo reply a raw socket sees
	rand.Read(token)
	msg, _ := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(token[0])<<8 | int(token[1]), Seq: 1, Data: token}}).Marshal(nil)
	deadline := time.Now().Add(probeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	start := time.Now()
	if _, err := c.WriteTo(msg, dst); err != nil {
		return -1
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return -1
		}
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && (m.Type == ipv4.ICMPTypeEchoReply || m.Type == ipv6.ICMPTypeEchoReply) &&
			bytes.Equal(e.Data, token) {
			return time.Since(start)
		}
	}
}
