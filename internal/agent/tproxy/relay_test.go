package tproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The relay opens IP_TRANSPARENT sockets, which needs CAP_NET_ADMIN, and the test drives
// it through a fake dnsdist on loopback (127.0.0.2 stands in for the address a client
// queried). Skipped on unprivileged or non-Linux hosts.
func requireTransparent(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for IP_TRANSPARENT")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		t.Skipf("IP_TRANSPARENT unsupported: %v", err)
	}
}

type backend struct {
	port int
	seen chan proxySeen
}

type proxySeen struct {
	src, dst string
	tcp      bool
}

// startBackend runs a fake dnsdist on 127.0.0.1 with UDP and TCP on the same port. It
// answers every query with one A record and reports the PROXY v2 addresses the relay sent.
func startBackend(t *testing.T) *backend {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		uc.Close()
		t.Fatal(err)
	}
	b := &backend{port: port, seen: make(chan proxySeen, 16)}
	t.Cleanup(func() { uc.Close(); ln.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload, src, dst, ok := splitProxy(buf[:n])
			if !ok {
				continue
			}
			b.seen <- proxySeen{src: src, dst: dst}
			if _, err := uc.WriteToUDP(dnsReply(payload), peer); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTCPConn(c, b)
		}
	}()
	return b
}

func handleTCPConn(c net.Conn, b *backend) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	rest := make([]byte, binary.BigEndian.Uint16(hdr[14:16]))
	if _, err := io.ReadFull(c, rest); err != nil {
		return
	}
	_, src, dst, ok := splitProxy(append(hdr, rest...))
	if !ok {
		return
	}
	b.seen <- proxySeen{src: src, dst: dst, tcp: true}
	for {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		r := dnsReply(q)
		out := make([]byte, 2+len(r))
		binary.BigEndian.PutUint16(out[:2], uint16(len(r)))
		copy(out[2:], r)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// splitProxy parses the PROXY v2 header and returns the DNS payload.
func splitProxy(msg []byte) (payload []byte, src, dst string, ok bool) {
	if len(msg) < 16 || string(msg[:12]) != proxyV2Signature {
		return nil, "", "", false
	}
	alen := int(binary.BigEndian.Uint16(msg[14:16]))
	if len(msg) < 16+alen {
		return nil, "", "", false
	}
	addr := msg[16 : 16+alen]
	port := func(i int) int { return int(binary.BigEndian.Uint16(addr[i : i+2])) }
	switch msg[13] {
	case proxyFamUDP4, proxyFamTCP4:
		src = net.IP(addr[0:4]).String() + ":" + strconv.Itoa(port(8))
		dst = net.IP(addr[4:8]).String() + ":" + strconv.Itoa(port(10))
	case proxyFamUDP6, proxyFamTCP6:
		src = "[" + net.IP(addr[0:16]).String() + "]:" + strconv.Itoa(port(32))
		dst = "[" + net.IP(addr[16:32]).String() + "]:" + strconv.Itoa(port(34))
	default:
		return nil, "", "", false
	}
	return msg[16+alen:], src, dst, true
}

// dnsReply turns a query into a minimal answer so the client can match it.
func dnsReply(q []byte) []byte {
	r := append([]byte(nil), q...)
	if len(r) < 12 {
		return r
	}
	r[2] |= 0x80
	r[3] = 0x80
	binary.BigEndian.PutUint16(r[6:8], 1)
	binary.BigEndian.PutUint16(r[8:10], 0)
	binary.BigEndian.PutUint16(r[10:12], 0)
	return append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
}

func dnsQuery(id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func startRelay(t *testing.T, port int, backend string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunRelay(ctx, RelayConfig{
			Port: port, DNSDistAddr: backend,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("relay stopped with %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("relay did not stop")
		}
	})
	time.Sleep(300 * time.Millisecond) // listeners bind immediately; let goroutines start
}

func TestRelayUDPRoundTrip(t *testing.T) {
	requireTransparent(t)
	b := startBackend(t)
	port := freePort(t)
	startRelay(t, port, net.JoinHostPort("127.0.0.1", strconv.Itoa(b.port)))

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	const id = 0xbeef
	query := dnsQuery(id)
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	if got := binary.BigEndian.Uint16(buf[:2]); got != id {
		t.Fatalf("reply id = %#x, want %#x (the relay must restore the client id)", got, id)
	}
	if buf[2]&0x80 == 0 {
		t.Fatalf("reply is not a response: %x", buf[:4])
	}
	if n < len(query) {
		t.Fatalf("short reply: %d bytes", n)
	}
	select {
	case seen := <-b.seen:
		src := "127.0.0.1:" + strconv.Itoa(client.LocalAddr().(*net.UDPAddr).Port)
		if seen.src != src {
			t.Errorf("dnsdist saw client %q, want %q", seen.src, src)
		}
		if want := "127.0.0.2:" + strconv.Itoa(port); seen.dst != want {
			t.Errorf("dnsdist saw destination %q, want %q", seen.dst, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dnsdist never saw the query")
	}
}

func TestRelayTCPRoundTrip(t *testing.T) {
	requireTransparent(t)
	b := startBackend(t)
	port := freePort(t)
	startRelay(t, port, net.JoinHostPort("127.0.0.1", strconv.Itoa(b.port)))

	c, err := net.Dial("tcp4", "127.0.0.2:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	const id = 0x1234
	query := dnsQuery(id)
	out := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(out[:2], uint16(len(query)))
	copy(out[2:], query)
	if _, err := c.Write(out); err != nil {
		t.Fatal(err)
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatalf("no TCP reply: %v", err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(reply[:2]); got != id {
		t.Fatalf("TCP reply id = %#x, want %#x", got, id)
	}
	select {
	case seen := <-b.seen:
		if !seen.tcp {
			t.Errorf("backend saw UDP, want TCP")
		}
		if want := "127.0.0.2:" + strconv.Itoa(port); seen.dst != want {
			t.Errorf("dnsdist saw destination %q, want %q", seen.dst, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dnsdist never saw the TCP query")
	}
}

// TestRelayDirectToLocalPort covers a client querying the interception port on the
// node's own address (no TPROXY). The reply must not create a socket that shadows the
// listener and swallows later queries.
func TestRelayDirectToLocalPort(t *testing.T) {
	requireTransparent(t)
	b := startBackend(t)
	port := freePort(t)
	startRelay(t, port, net.JoinHostPort("127.0.0.1", strconv.Itoa(b.port)))

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	for i := 0; i < 5; i++ {
		id := uint16(0x4000 + i)
		if _, err := client.Write(dnsQuery(id)); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("query %d: no reply: %v", i, err)
		}
		if got := binary.BigEndian.Uint16(buf[:2]); got != id || n < 12 {
			t.Fatalf("query %d: reply id %#x, %d bytes", i, got, n)
		}
	}
}
