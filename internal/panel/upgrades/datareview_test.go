package upgrades

import (
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// A node already upgrading (manual command, upgrade_in_progress in its heartbeat, still
// "online") does not stop a rolling run from starting another node: two at once.
func TestReviewRunStartsWhileAnotherNodeUpgrades(t *testing.T) {
	e := setup(t)
	a := e.node("ns-a", "2.0.0-1", 0)
	b := e.node("ns-b", "2.0.0-1", 10)
	// ns-a: manual upgrade_dnsdist delivered, agent reports it is upgrading.
	e.run(`INSERT INTO node_commands (node_id, type, params, delivered_at) VALUES ($1, 'upgrade_dnsdist', '{"version":"2.0.1-1"}', now())`, a)
	e.run(`UPDATE nodes SET last_heartbeat = '{"upgrade_in_progress": true, "dnsdist_running": true}' WHERE id = $1`, a)

	// Fixed: the run is refused while ns-a upgrades.
	if eb := e.call(409, "POST", "/api/v1/upgrades", api.UpgradeRunCreate{Kind: api.UpgradeDnsdist, TargetVersion: "2.0.1-1", NodeIDs: []string{b}}, nil); eb.Error.Code != "nodes_not_ready" {
		t.Fatalf("DEFECT: run on ns-b accepted while ns-a is still upgrading: %+v", eb)
	}
	e.tick()
	var n int
	e.scalar("SELECT count(*) FROM node_commands WHERE type = 'upgrade_dnsdist' AND node_id = $1", &n, b)
	if n != 0 {
		t.Fatal("DEFECT: run sent upgrade_dnsdist to ns-b while ns-a is still upgrading")
	}
}
