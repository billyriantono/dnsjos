// Package dnstap receives dnsdist's dnstap streams: blocked queries are aggregated
// into (day, qname, qtype) → count (SPEC §9.4); Serve also feeds the analytics stream.
package dnstap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	dt "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Other is the qname/qtype that absorbs keys beyond the aggregation cap.
const Other = "_other_"

type key struct{ day, qname, qtype string }

// Agg counts blocked queries per flush window with at most Cap distinct keys.
type Agg struct {
	Cap int
	Loc *time.Location // day boundary; default time.Local

	mu sync.Mutex
	m  map[key]int64
}

func (a *Agg) Add(t time.Time, qname, qtype string) {
	loc := a.Loc
	if loc == nil {
		loc = time.Local
	}
	k := key{t.In(loc).Format(time.DateOnly), qname, qtype}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[key]int64{}
	}
	if _, ok := a.m[k]; !ok && a.Cap > 0 && len(a.m) >= a.Cap {
		k.qname, k.qtype = Other, Other
	}
	a.m[k]++
}

// Observe counts the question of m (a Serve callback).
func (a *Agg) Observe(t time.Time, m *dns.Msg) {
	q := m.Question[0]
	a.Add(t, strings.TrimSuffix(strings.ToLower(q.Name), "."), dns.TypeToString[q.Qtype])
}

// Take returns the window's items and starts a new window.
func (a *Agg) Take() []api.BlockedItem {
	a.mu.Lock()
	m := a.m
	a.m = nil
	a.mu.Unlock()
	out := make([]api.BlockedItem, 0, len(m))
	for k, n := range m {
		out = append(out, api.BlockedItem{Day: k.day, QName: k.qname, QType: k.qtype, Count: n})
	}
	return out
}

// Observer receives every decoded message that has a question; it must not keep m.
type Observer func(t time.Time, m *dns.Msg)

// Serve accepts framestream connections on l and passes every CLIENT_QUERY and
// CLIENT_RESPONSE to obs until ctx is done.
func Serve(ctx context.Context, l net.Listener, obs Observer, log *slog.Logger) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	go func() {
		<-ctx.Done()
		l.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
	}()
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := readConn(c, obs); err != nil && ctx.Err() == nil {
				log.Warn("dnstap connection closed", "remote", c.RemoteAddr().String(), "err", err)
			}
			c.Close()
			mu.Lock()
			delete(conns, c)
			mu.Unlock()
		}()
	}
}

func readConn(c net.Conn, obs Observer) error {
	r, err := dt.NewReader(c, &dt.ReaderOptions{Bidirectional: true, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	buf := make([]byte, dt.MaxPayloadSize)
	var m dt.Dnstap
	var msg dns.Msg
	for {
		n, err := r.ReadFrame(buf)
		if err != nil {
			switch {
			case errors.Is(err, framestream.ErrDataFrameTooLarge):
				continue
			case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
				return nil
			}
			return err
		}
		if proto.Unmarshal(buf[:n], &m) != nil || m.Message == nil {
			continue
		}
		t, wire, ok := parts(m.Message)
		if !ok || msg.Unpack(wire) != nil || len(msg.Question) == 0 {
			continue
		}
		obs(t, &msg)
	}
}

func parts(m *dt.Message) (time.Time, []byte, bool) {
	switch m.GetType() {
	case dt.Message_CLIENT_QUERY:
		return ts(m.QueryTimeSec, m.QueryTimeNsec), m.QueryMessage, m.QueryMessage != nil
	case dt.Message_CLIENT_RESPONSE:
		return ts(m.ResponseTimeSec, m.ResponseTimeNsec), m.ResponseMessage, m.ResponseMessage != nil
	}
	return time.Time{}, nil, false
}

func ts(sec *uint64, nsec *uint32) time.Time {
	if sec == nil {
		return time.Now()
	}
	var ns int64
	if nsec != nil {
		ns = int64(*nsec)
	}
	return time.Unix(int64(*sec), ns)
}
