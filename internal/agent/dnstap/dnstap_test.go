package dnstap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	dt "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func frame(t *testing.T, typ dt.Message_Type, name string, qtype uint16, at time.Time) *dt.Dnstap {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	sec, nsec := uint64(at.Unix()), uint32(0)
	msg := &dt.Message{Type: &typ}
	if typ == dt.Message_CLIENT_QUERY {
		msg.QueryMessage, msg.QueryTimeSec, msg.QueryTimeNsec = wire, &sec, &nsec
	} else {
		msg.ResponseMessage, msg.ResponseTimeSec, msg.ResponseTimeNsec = wire, &sec, &nsec
	}
	kind := dt.Dnstap_MESSAGE
	return &dt.Dnstap{Type: &kind, Identity: []byte("node1"), Message: msg}
}

func TestServeAggregates(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	agg := &Agg{Cap: 3, Loc: time.UTC}
	done := make(chan error)
	go func() { done <- Serve(ctx, l, agg.Observe, discard) }()

	day1 := time.Date(2026, 9, 26, 23, 59, 0, 0, time.UTC)
	day2 := day1.Add(2 * time.Minute)
	frames := []*dt.Dnstap{
		frame(t, dt.Message_CLIENT_QUERY, "Blocked.Example.", dns.TypeA, day1),
		frame(t, dt.Message_CLIENT_QUERY, "blocked.example.", dns.TypeA, day1),
		frame(t, dt.Message_CLIENT_QUERY, "blocked.example.", dns.TypeHTTPS, day1),
		frame(t, dt.Message_CLIENT_RESPONSE, "ip.example.", dns.TypeA, day2),
		frame(t, dt.Message_CLIENT_QUERY, "overflow1.example.", dns.TypeA, day2), // over the cap
		frame(t, dt.Message_CLIENT_QUERY, "overflow2.example.", dns.TypeA, day2),
		frame(t, dt.Message_RESOLVER_QUERY, "ignored.example.", dns.TypeA, day2),
	}
	// Two connections, like dnsdist's reconnecting logger.
	for _, part := range [][]*dt.Dnstap{frames[:3], frames[3:]} {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		w, err := dt.NewWriter(c, &dt.WriterOptions{Bidirectional: true, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteFrame([]byte{0xff, 0x01, 0x02}); err != nil { // garbage must be skipped
			t.Fatal(err)
		}
		enc := dt.NewEncoder(w)
		for _, f := range part {
			if err := enc.Encode(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil { // STOP → FINISH handshake: all frames were read
			t.Fatal(err)
		}
		c.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	var items []api.BlockedItem
	for len(items) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		agg.mu.Lock()
		n := len(agg.m)
		agg.mu.Unlock()
		if n == 4 {
			items = agg.Take()
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Day+items[i].QName+items[i].QType < items[j].Day+items[j].QName+items[j].QType
	})
	want := []api.BlockedItem{
		{Day: "2026-09-26", QName: "blocked.example", QType: "A", Count: 2},
		{Day: "2026-09-26", QName: "blocked.example", QType: "HTTPS", Count: 1},
		{Day: "2026-09-27", QName: "_other_", QType: "_other_", Count: 2},
		{Day: "2026-09-27", QName: "ip.example", QType: "A", Count: 1},
	}
	if len(items) != len(want) {
		t.Fatalf("items: %+v", items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Fatalf("item %d: got %+v want %+v", i, items[i], want[i])
		}
	}
	if len(agg.Take()) != 0 {
		t.Fatal("Take must start a new window")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestSpool(t *testing.T) {
	dir := t.TempDir()
	var got []api.BlockedBatch
	fail := errors.New("panel down")
	s := &Spool[api.BlockedBatch]{Dir: dir, MaxFiles: 2, Log: discard, Post: func(_ context.Context, b api.BlockedBatch) error {
		if fail != nil {
			return fail
		}
		got = append(got, b)
		return nil
	}}
	item := func(n int64) []api.BlockedBatch {
		return BlockedBatches([]api.BlockedItem{{Day: "2026-09-27", QName: "x", QType: "A", Count: n}})
	}
	s.Flush(context.Background(), item(1))
	s.Flush(context.Background(), item(2))
	s.Flush(context.Background(), item(3)) // over MaxFiles: the oldest is dropped
	if f := s.files(); len(f) != 2 {
		t.Fatalf("spool files: %v", f)
	}
	fail = nil
	s.Flush(context.Background(), item(4))
	if len(got) != 3 || got[0].Items[0].Count != 2 || got[1].Items[0].Count != 3 || got[2].Items[0].Count != 4 {
		t.Fatalf("delivered: %+v", got)
	}
	if f := s.files(); len(f) != 0 {
		t.Fatalf("spool not drained: %v", f)
	}
	// a permanent rejection drops the batch instead of retrying forever
	fail = &client.StatusError{Code: 400}
	s.Flush(context.Background(), item(5))
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("rejected batch was spooled: %v", ents)
	}

	// MaxBytes keeps only the newest batches that fit
	fail = errors.New("panel down")
	s.MaxFiles, s.MaxBytes = 10, 150
	for n := range int64(4) {
		s.Flush(context.Background(), item(10+n))
	}
	if f := s.files(); len(f) != 2 || !strings.Contains(read(f[1]), `"count":13`) {
		t.Fatalf("spool by size: %v", f)
	}
}

func read(p string) string { b, _ := os.ReadFile(p); return string(b) }
