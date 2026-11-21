// Transparent DNS relay for TPROXY mode.
//
// dnsdist cannot open IP_TRANSPARENT sockets, so nftables TPROXY cannot deliver
// intercepted packets to it directly. This relay owns the transparent UDP/TCP sockets,
// receives packets together with their original destination, and forwards them to a
// loopback dnsdist listener with a PROXY protocol v2 header. dnsdist therefore keeps
// seeing the real client address. Replies are sent back from the original destination
// address and port, which is what FBF / policy-routed core routers require.
package tproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// RelayConfig configures the transparent relay.
type RelayConfig struct {
	// Port is the TPROXY port (the nftables "to :Port" target).
	Port int
	// DNSDistAddr is the loopback listener configured with enableProxyProtocol.
	DNSDistAddr string
	Log         *slog.Logger
}

// RunRelay runs the transparent relay until ctx is cancelled.
func RunRelay(ctx context.Context, cfg RelayConfig) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("tproxy relay: invalid port %d", cfg.Port)
	}
	if cfg.DNSDistAddr == "" {
		return errors.New("tproxy relay: dnsdist address is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	backendAddr, err := net.ResolveUDPAddr("udp", cfg.DNSDistAddr)
	if err != nil {
		return fmt.Errorf("tproxy relay: dnsdist address: %w", err)
	}
	// Every backend keeps its own 16-bit id space. A client always hashes to the same
	// backend, so retries stay together, while the pool raises the concurrency ceiling
	// above the ~6k in-flight queries of a single socket.
	backends := make([]*udpBackend, relayBackends)
	for i := range backends {
		conn, err := net.DialUDP("udp", nil, backendAddr)
		if err != nil {
			for _, b := range backends[:i] {
				b.conn.Close()
			}
			return fmt.Errorf("tproxy relay: connecting to dnsdist: %w", err)
		}
		backends[i] = &udpBackend{conn: conn, pending: make(map[uint16]pending)}
	}
	r := &relay{
		cfg:        cfg,
		backends:   backends,
		clientConn: make(map[netip.AddrPort]*clientSock),
		done:       make(chan struct{}),
		tcpSlots:   make(chan struct{}, 256),
	}
	defer r.close()

	udp4, err := listenTransparentPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", cfg.Port), true)
	if err != nil {
		return fmt.Errorf("tproxy relay: udp4 listener: %w", err)
	}
	r.udp4 = udp4
	defer udp4.Close()
	udp6, err := listenTransparentPacket(ctx, "udp6", fmt.Sprintf("[::]:%d", cfg.Port), true)
	if err != nil {
		cfg.Log.Warn("tproxy relay: udp6 listener unavailable", "err", err)
	} else {
		r.udp6 = udp6
		defer udp6.Close()
	}
	tcp4, err := listenTransparentStream(ctx, "tcp4", fmt.Sprintf("0.0.0.0:%d", cfg.Port))
	if err != nil {
		return fmt.Errorf("tproxy relay: tcp4 listener: %w", err)
	}
	r.tcp4 = tcp4
	defer tcp4.Close()
	tcp6, err := listenTransparentStream(ctx, "tcp6", fmt.Sprintf("[::]:%d", cfg.Port))
	if err != nil {
		cfg.Log.Warn("tproxy relay: tcp6 listener unavailable", "err", err)
	} else {
		r.tcp6 = tcp6
		defer tcp6.Close()
	}

	var wg sync.WaitGroup
	spawn := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	spawn(func() { r.readUDP(r.udp4) })
	if r.udp6 != nil {
		spawn(func() { r.readUDP(r.udp6) })
	}
	for _, b := range r.backends {
		spawn(func() { r.readBackend(b) })
	}
	spawn(func() { r.acceptTCP(r.tcp4) })
	if r.tcp6 != nil {
		spawn(func() { r.acceptTCP(r.tcp6) })
	}
	spawn(r.expire)

	cfg.Log.Info("tproxy relay listening", "port", cfg.Port, "dnsdist", cfg.DNSDistAddr)
	<-ctx.Done()
	r.close()
	r.tcpWG.Wait()
	wg.Wait()
	return nil
}

type pending struct {
	src, dst netip.AddrPort
	origID   uint16
	at       time.Time
}

// clientSock is a transparent reply socket bound to one original destination, kept for
// reuse and evicted when idle.
type clientSock struct {
	conn *net.UDPConn
	last time.Time
}

// udpBackend is one connected socket to dnsdist plus the transaction ids it owns.
type udpBackend struct {
	conn    *net.UDPConn
	pending map[uint16]pending
	nextID  uint16
}

// relayBackends is the number of dnsdist UDP sockets. Each one gives 65535 outstanding
// transaction ids, so four sockets are far beyond any realistic in-flight count.
const relayBackends = 4

type relay struct {
	cfg      RelayConfig
	backends []*udpBackend
	udp4     *net.UDPConn
	udp6     *net.UDPConn
	tcp4     net.Listener
	tcp6     net.Listener

	mu         sync.Mutex
	clientConn map[netip.AddrPort]*clientSock
	local      map[netip.Addr]bool
	localAt    time.Time
	closed     bool
	done       chan struct{}
	tcpWG      sync.WaitGroup
	tcpSlots   chan struct{}
}

func (r *relay) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.done)
	conns := make([]*net.UDPConn, 0, len(r.clientConn))
	for _, c := range r.clientConn {
		conns = append(conns, c.conn)
	}
	r.clientConn = map[netip.AddrPort]*clientSock{}
	r.mu.Unlock()
	for _, b := range r.backends {
		b.conn.Close()
	}
	if r.udp4 != nil {
		r.udp4.Close()
	}
	if r.udp6 != nil {
		r.udp6.Close()
	}
	if r.tcp4 != nil {
		r.tcp4.Close()
	}
	if r.tcp6 != nil {
		r.tcp6.Close()
	}
	for _, c := range conns {
		c.Close()
	}
}

// readUDP handles one transparent UDP socket.
func (r *relay) readUDP(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, src, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			if isClosed(err) || r.isClosed() {
				return
			}
			r.cfg.Log.Debug("tproxy relay: udp read", "err", err)
			continue
		}
		if n < 12 { // DNS header
			continue
		}
		dst, ok := origDst(oob[:oobn])
		if !ok {
			continue
		}
		srcAP := udpAddrPort(src)
		if !srcAP.IsValid() || !dst.IsValid() || srcAP.Addr().Is4() != dst.Addr().Is4() {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		if !r.forwardUDP(srcAP, dst, payload) {
			continue
		}
	}
}

// forwardUDP rewrites the DNS id to a relay-unique one and sends the query to dnsdist.
func (r *relay) forwardUDP(src, dst netip.AddrPort, payload []byte) bool {
	origID := binary.BigEndian.Uint16(payload[0:2])
	b := r.backends[backendIndex(src, len(r.backends))]
	id, ok := r.allocID(b)
	if !ok {
		return false
	}
	binary.BigEndian.PutUint16(payload[0:2], id)
	r.mu.Lock()
	b.pending[id] = pending{src: src, dst: dst, origID: origID, at: time.Now()}
	r.mu.Unlock()

	hdr := proxyHeader(src, dst, false)
	msg := make([]byte, 0, len(hdr)+len(payload))
	msg = append(msg, hdr...)
	msg = append(msg, payload...)
	if _, err := b.conn.Write(msg); err != nil {
		r.mu.Lock()
		delete(b.pending, id)
		r.mu.Unlock()
		return false
	}
	return true
}

// readBackend reads replies from dnsdist, restores the original id and sends them back
// from the original destination address and port.
func (r *relay) readBackend(b *udpBackend) {
	buf := make([]byte, 65535)
	for {
		n, err := b.conn.Read(buf)
		if err != nil {
			if isClosed(err) || r.isClosed() {
				return
			}
			r.cfg.Log.Debug("tproxy relay: dnsdist read", "err", err)
			continue
		}
		if n < 12 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[0:2])
		r.mu.Lock()
		p, ok := b.pending[id]
		if ok {
			delete(b.pending, id)
		}
		r.mu.Unlock()
		if !ok {
			continue
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		binary.BigEndian.PutUint16(resp[0:2], p.origID)
		if err := r.sendToClient(p.dst, p.src, resp); err != nil {
			r.cfg.Log.Debug("tproxy relay: sending to client", "err", err, "client", p.src)
		}
	}
}

func (r *relay) sendToClient(from, to netip.AddrPort, payload []byte) error {
	conn, err := r.replySocket(from)
	if err != nil {
		return err
	}
	dst := &net.UDPAddr{IP: net.IP(to.Addr().AsSlice()), Port: int(to.Port())}
	_, err = conn.WriteToUDP(payload, dst)
	return err
}

// replySocket returns the socket an answer to to is sent from. When the original
// destination is one of this node's own addresses (a client queried the interception
// port directly instead of being intercepted), the listener already owns that
// address:port and a transparent socket bound to it would shadow the listener and
// swallow later queries. Answer through the listener in that case.
func (r *relay) replySocket(from netip.AddrPort) (*net.UDPConn, error) {
	if r.isLocal(from.Addr()) {
		if c := r.listenerFor(from); c != nil {
			return c, nil
		}
	}
	c, err := r.clientSocket(from)
	if err == nil {
		return c, nil
	}
	if c := r.listenerFor(from); c != nil {
		r.cfg.Log.Warn("tproxy relay: transparent reply socket unavailable, answering from the listener",
			"dest", from, "err", err)
		return c, nil
	}
	return nil, err
}

func (r *relay) listenerFor(from netip.AddrPort) *net.UDPConn {
	if from.Addr().Is4() {
		return r.udp4
	}
	return r.udp6
}

// isLocal reports whether addr is configured on this node. The set is refreshed every
// 30s so address changes are picked up without a restart.
func (r *relay) isLocal(addr netip.Addr) bool {
	r.mu.Lock()
	if time.Since(r.localAt) < 30*time.Second && r.local != nil {
		local := r.local[addr]
		r.mu.Unlock()
		return local
	}
	r.mu.Unlock()

	set := make(map[netip.Addr]bool, 16)
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipnet.IP); ok {
					set[ip.Unmap()] = true
				}
			}
		}
	}
	r.mu.Lock()
	r.local, r.localAt = set, time.Now()
	local := set[addr]
	r.mu.Unlock()
	return local
}

func (r *relay) clientSocket(from netip.AddrPort) (*net.UDPConn, error) {
	r.mu.Lock()
	if c := r.clientConn[from]; c != nil {
		c.last = time.Now()
		r.mu.Unlock()
		return c.conn, nil
	}
	r.mu.Unlock()
	network := "udp4"
	if !from.Addr().Is4() {
		network = "udp6"
	}
	c, err := listenTransparentPacket(context.Background(), network,
		net.JoinHostPort(from.Addr().String(), strconv.Itoa(int(from.Port()))), false)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if existing := r.clientConn[from]; existing != nil {
		existing.last = time.Now()
		r.mu.Unlock()
		c.Close()
		return existing.conn, nil
	}
	r.clientConn[from] = &clientSock{conn: c, last: time.Now()}
	r.mu.Unlock()
	return c, nil
}

func (r *relay) allocID(b *udpBackend) (uint16, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(b.pending) >= 65535 { // every non-zero id is in flight; do not scan under the lock
		return 0, false
	}
	for i := 0; i < 65536; i++ {
		b.nextID++
		if _, used := b.pending[b.nextID]; !used && b.nextID != 0 {
			return b.nextID, true
		}
	}
	return 0, false
}

func (r *relay) expire() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			// dnsdist's UDP timeout is ~2s. A longer TTL lets dropped queries (dynblock,
			// rate limits) exhaust the 16-bit id space in 30s and stall the relay.
			cutoff := time.Now().Add(-5 * time.Second)
			idle := time.Now().Add(-5 * time.Minute)
			var stale []*net.UDPConn
			r.mu.Lock()
			for _, b := range r.backends {
				for id, p := range b.pending {
					if p.at.Before(cutoff) {
						delete(b.pending, id)
					}
				}
			}
			for from, c := range r.clientConn {
				if c.last.Before(idle) {
					delete(r.clientConn, from)
					stale = append(stale, c.conn)
				}
			}
			r.mu.Unlock()
			for _, c := range stale {
				c.Close()
			}
		}
	}
}

// backendIndex hashes a client to one backend so its retries stay on the same socket.
func backendIndex(src netip.AddrPort, n int) int {
	h := uint32(2166136261)
	a := src.Addr().As16()
	for _, c := range a {
		h ^= uint32(c)
		h *= 16777619
	}
	h ^= uint32(src.Port())
	h *= 16777619
	return int(h % uint32(n))
}

func (r *relay) acceptTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if isClosed(err) || r.isClosed() {
				return
			}
			r.cfg.Log.Debug("tproxy relay: tcp accept", "err", err)
			continue
		}
		r.tcpWG.Add(1)
		go func() {
			defer r.tcpWG.Done()
			defer c.Close()
			r.handleTCP(c)
		}()
	}
}

func (r *relay) handleTCP(client net.Conn) {
	select {
	case r.tcpSlots <- struct{}{}:
		defer func() { <-r.tcpSlots }()
	default: // too many TCP connections; drop this one rather than exhaust goroutines
		return
	}
	src := tcpAddrPort(client.RemoteAddr())
	dst := tcpAddrPort(client.LocalAddr())
	if !src.IsValid() || !dst.IsValid() || src.Addr().Is4() != dst.Addr().Is4() {
		return
	}
	backend, err := net.DialTimeout("tcp", r.cfg.DNSDistAddr, 5*time.Second)
	if err != nil {
		r.cfg.Log.Debug("tproxy relay: tcp dnsdist dial", "err", err)
		return
	}
	defer backend.Close()
	deadline := time.Now().Add(30 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = backend.SetDeadline(deadline)
	if _, err := backend.Write(proxyHeader(src, dst, true)); err != nil {
		return
	}
	// A client may half-close after its query. Forward independently, but return only
	// when dnsdist answers or closes, so the reply still reaches the client.
	var tcpWG sync.WaitGroup
	tcpWG.Add(1)
	go func() {
		defer tcpWG.Done()
		_, _ = io.Copy(backend, client)
		if tc, ok := backend.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, backend)
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	tcpWG.Wait()
}

func (r *relay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// listenTransparentPacket opens a UDP socket with IP_TRANSPARENT. When recvOrigDst is
// set, it also enables IP_RECVORIGDSTADDR so the original destination is available.
func listenTransparentPacket(ctx context.Context, network, address string, recvOrigDst bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if err := setTransparentUDP(fd, network, recvOrigDst); err != nil {
				serr = err
			}
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("not a UDP connection")
	}
	return conn, nil
}

// setTransparentUDP applies the socket options every transparent UDP socket needs.
//
// SO_REUSEADDR is required for IP_TRANSPARENT to work at all. SO_REUSEPORT is required
// on a reply socket because dnsdist commonly holds the wildcard 0.0.0.0:53 and
// [::]:53 with SO_REUSEPORT; without it, binding the original destination (e.g.
// 1.1.1.1:53) fails with EADDRINUSE and every answer would leave from the wrong source.
// Joining the REUSEPORT group is safe here: the kernel picks a REUSEPORT group by exact
// destination address, so a socket bound to 1.1.1.1:53 lives in its own group and never
// competes with the wildcard group dnsdist owns.
func setTransparentUDP(fd uintptr, network string, recvOrigDst bool) error {
	opt, level := unix.IP_TRANSPARENT, unix.SOL_IP
	if network == "udp6" || network == "tcp6" {
		opt, level = unix.IPV6_TRANSPARENT, unix.SOL_IPV6
	}
	if err := unix.SetsockoptInt(int(fd), level, opt, 1); err != nil {
		return err
	}
	if recvOrigDst {
		recvOpt, recvLevel := unix.IP_RECVORIGDSTADDR, unix.SOL_IP
		if network == "udp6" {
			recvOpt, recvLevel = unix.IPV6_RECVORIGDSTADDR, unix.SOL_IPV6
		}
		if err := unix.SetsockoptInt(int(fd), recvLevel, recvOpt, 1); err != nil {
			return err
		}
	}
	for _, o := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o, 1); err != nil {
			return err
		}
	}
	return nil
}

func listenTransparentStream(ctx context.Context, network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if err := setTransparentUDP(fd, network, false); err != nil {
				serr = err
			}
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(ctx, network, address)
}

func origDst(oob []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for i := range msgs {
		sa, err := unix.ParseOrigDstAddr(&msgs[i])
		if err != nil {
			continue
		}
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), true
		case *unix.SockaddrInet6:
			// Unmap so a v4-mapped destination compares and encodes as IPv4,
			// matching udpAddrPort and proxyHeader.
			return netip.AddrPortFrom(netip.AddrFrom16(a.Addr).Unmap(), uint16(a.Port)), true
		}
	}
	return netip.AddrPort{}, false
}

func udpAddrPort(a *net.UDPAddr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
}

func tcpAddrPort(a net.Addr) netip.AddrPort {
	switch x := a.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(x.IP)
		if !ok {
			return netip.AddrPort{}
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(x.Port))
	case *net.UDPAddr:
		return udpAddrPort(x)
	}
	return netip.AddrPort{}
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EBADF)
}

// PROXY protocol v2 (https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt).
const (
	proxyV2Signature = "\r\n\r\n\x00\r\nQUIT\n"
	proxyV2Version   = 0x21 // version 2, command PROXY
	proxyFamTCP4     = 0x11
	proxyFamUDP4     = 0x12
	proxyFamTCP6     = 0x21
	proxyFamUDP6     = 0x22
)

// proxyHeader builds a PROXY v2 header for a query forwarded to dnsdist.
func proxyHeader(src, dst netip.AddrPort, tcp bool) []byte {
	srcAddr, dstAddr := src.Addr().Unmap(), dst.Addr().Unmap()
	var fam byte
	switch {
	case srcAddr.Is4() && tcp:
		fam = proxyFamTCP4
	case srcAddr.Is4():
		fam = proxyFamUDP4
	case tcp:
		fam = proxyFamTCP6
	default:
		fam = proxyFamUDP6
	}
	addrLen := 4
	if !srcAddr.Is4() {
		addrLen = 16
	}
	var b bytes.Buffer
	b.Grow(16 + 2*addrLen + 4)
	b.WriteString(proxyV2Signature)
	b.WriteByte(proxyV2Version)
	b.WriteByte(fam)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(2*addrLen+4))
	b.Write(l[:])
	if srcAddr.Is4() {
		s4, d4 := srcAddr.As4(), dstAddr.As4()
		b.Write(s4[:])
		b.Write(d4[:])
	} else {
		s16, d16 := srcAddr.As16(), dstAddr.As16()
		b.Write(s16[:])
		b.Write(d16[:])
	}
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], src.Port())
	binary.BigEndian.PutUint16(ports[2:4], dst.Port())
	b.Write(ports[:])
	return b.Bytes()
}
