package api

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// dnsdist and agent upgrades (SPEC §18).

const (
	UpgradeDnsdist = "dnsdist"
	UpgradeAgent   = "agent"
)

var UpgradeKinds = []string{UpgradeDnsdist, UpgradeAgent}

// upgrade_runs.status
const (
	RunRunning = "running"
	RunPaused  = "paused"
	RunDone    = "done"
	RunFailed  = "failed"
	RunAborted = "aborted"
)

// upgrade_run_steps.status
const (
	StepPending = "pending"
	StepRunning = "running"
	StepOK      = "ok"
	StepFailed  = "failed"
	StepSkipped = "skipped"
)

// Validate checks a POST /nodes/{id}/commands body. available is the node's
// dnsdist_available, supportedSeries is dnsconf.SupportedSeries (api cannot import dnsconf).
// Params not used by the type must be empty.
func (r CommandRequest) Validate(available, supportedSeries []string) error {
	if !slices.Contains(CommandTypes, r.Type) {
		return fmt.Errorf("type: unknown command %q", r.Type)
	}
	if r.Type == CmdUpgradeDnsdist {
		if !slices.Contains(available, r.Version) {
			return fmt.Errorf("version: %q is not available on this node (check_updates refreshes the list)", r.Version)
		}
	} else if r.Version != "" {
		return fmt.Errorf("version: only valid for %s", CmdUpgradeDnsdist)
	}
	if r.Type == CmdSetDnsdistSeries {
		if !slices.Contains(supportedSeries, r.Series) {
			return fmt.Errorf("series: %q is not supported (supported: %v)", r.Series, supportedSeries)
		}
	} else if r.Series != "" {
		return fmt.Errorf("series: only valid for %s", CmdSetDnsdistSeries)
	}
	return nil
}

// UpgradeRun is one rolling upgrade across nodes; Steps are ordered by position.
type UpgradeRun struct {
	ID            int64            `json:"id"`
	Kind          string           `json:"kind"`
	TargetVersion string           `json:"target_version"`
	Status        string           `json:"status"`
	CreatedBy     *string          `json:"created_by"`
	CreatedAt     time.Time        `json:"created_at"`
	FinishedAt    *time.Time       `json:"finished_at"`
	Message       string           `json:"message"`
	Steps         []UpgradeRunStep `json:"steps"`
}

type UpgradeRunStep struct {
	Position    int        `json:"position"` // 0-based upgrade order
	NodeID      string     `json:"node_id"`
	NodeName    string     `json:"node_name"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	Message     string     `json:"message"`
	FromVersion string     `json:"from_version"`
	ToVersion   string     `json:"to_version"`
}

// UpgradeRunCreate is POST /upgrades. TargetVersion is required for dnsdist and must be
// in every chosen node's dnsdist_available; for agent it must be empty or the panel's
// embedded agent version. NodeIDs empty = every live node, least busy (qps) first.
type UpgradeRunCreate struct {
	Kind          string   `json:"kind"`
	TargetVersion string   `json:"target_version"`
	NodeIDs       []string `json:"node_ids,omitempty"`
}

// Validate checks the body shape; node availability and versions are checked by the handler.
func (c UpgradeRunCreate) Validate() error {
	if !slices.Contains(UpgradeKinds, c.Kind) {
		return fmt.Errorf("kind: must be %s or %s", UpgradeDnsdist, UpgradeAgent)
	}
	if c.Kind == UpgradeDnsdist && c.TargetVersion == "" {
		return errors.New("target_version: required for dnsdist")
	}
	for i, id := range c.NodeIDs {
		if slices.Contains(c.NodeIDs[:i], id) {
			return fmt.Errorf("node_ids: %s listed twice", id)
		}
	}
	return nil
}

// NodeVersions is GET /nodes/{id}/versions (the node detail "Versions" card).
type NodeVersions struct {
	Installed         string         `json:"installed"`
	Candidate         string         `json:"candidate"`
	Available         []string       `json:"available"` // [] until the first inventory, never null
	Series            string         `json:"series"`
	InventoryAt       *time.Time     `json:"inventory_at"`
	LastUpgrade       *UpgradeResult `json:"last_upgrade"`
	UpgradeInProgress bool           `json:"upgrade_in_progress"`
	AgentVersion      string         `json:"agent_version"`
	PanelAgentVersion string         `json:"panel_agent_version"`
	AgentOutdated     bool           `json:"agent_outdated"`
}

// Meta is GET /meta.
type Meta struct {
	PanelVersion    string   `json:"panel_version"`
	AgentVersion    string   `json:"agent_version"` // version of the agent binaries embedded in the panel
	SupportedSeries []string `json:"supported_series"`
}
