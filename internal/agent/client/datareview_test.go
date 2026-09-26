package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// The panel commits the batch but the answer is lost (connection dropped after the
// commit, proxy 502/504, client timeout): the client retries the POST. Every attempt
// must carry the same idempotency key so the panel can skip the already-committed batch.
func TestReviewBlockedRetryAfterCommitDoubleCounts(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get(IdempotencyHeader))
		first := len(keys) == 1
		mu.Unlock()
		if first {
			c, _, _ := w.(http.Hijacker).Hijack() // response lost after commit
			c.Close()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok", "1")
	err := c.PostBlocked(context.Background(), "k1", api.BlockedBatch{Items: []api.BlockedItem{{Day: "2026-01-02", QName: "x.example", QType: "A", Count: 5}}})
	if err != nil || len(keys) != 2 || keys[0] != "k1" || keys[1] != "k1" {
		t.Fatalf("err %v, keys %q", err, keys)
	}
}
