package dnstap

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// A full chunk of long blocked qnames (random-subdomain floods under a blocked domain)
// exceeds the panel's 10 MiB body limit → 400 → Spool treats it as permanent and drops it.
func TestReviewBlockedChunkExceedsBodyLimit(t *testing.T) {
	items := make([]api.BlockedItem, 60000)
	for i := range items {
		name := strings.Repeat("a", 150) + ".blocked.example" // 166 chars, valid (< 255)
		items[i] = api.BlockedItem{Day: "2026-01-02", QName: name, QType: "A", Count: 1}
	}
	b := BlockedBatches(items)[0]
	raw, _ := json.Marshal(b)
	if len(raw) > 10<<20 {
		t.Fatalf("DEFECT: first batch is %d bytes > panel MaxBody %d; panel answers 400 and the agent drops %d blocked items", len(raw), 10<<20, len(b.Items))
	}
}
