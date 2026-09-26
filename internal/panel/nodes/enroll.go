package nodes

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func (s *svc) listTokens(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.d.Pool.Query(r.Context(), `SELECT id, node_name, labels, profile_id, created_by, created_at,
		expires_at, used_at, used_by_node FROM enrollment_tokens ORDER BY created_at DESC LIMIT 500`)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.EnrollmentToken, error) {
		var t api.EnrollmentToken
		err := row.Scan(&t.ID, &t.NodeName, &t.Labels, &t.ProfileID, &t.CreatedBy, &t.CreatedAt,
			&t.ExpiresAt, &t.UsedAt, &t.UsedByNode)
		return t, err
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.EnrollmentToken]{Items: items, Total: len(items)})
}

func (s *svc) createToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req api.EnrollmentTokenCreate
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	// An empty node_name means "use the node's hostname" at enrollment.
	req.NodeName = strings.TrimSpace(req.NodeName)
	if req.NodeName != "" {
		if err := validName(req.NodeName); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	if req.Labels == nil {
		req.Labels = map[string]string{}
	}
	if err := validLabels(req.Labels); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if req.ProfileID != nil && *req.ProfileID == "" {
		req.ProfileID = nil
	}
	if req.TTLHours == 0 {
		req.TTLHours = 24
	}
	if req.TTLHours < 1 || req.TTLHours > 720 {
		httpx.BadRequest(w, "ttl_hours must be 1..720")
		return
	}
	tok := app.NewToken()
	out := api.EnrollmentTokenCreated{
		Token:          tok,
		InstallCommand: "curl -fsSL " + s.d.Settings.PublicURL() + "/install.sh | sudo sh -s -- --token " + tok,
		ExpiresAt:      time.Now().Add(time.Duration(req.TTLHours) * time.Hour).UTC().Truncate(time.Second),
	}
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO enrollment_tokens (token_hash, node_name, labels, profile_id, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, app.HashToken(tok), req.NodeName, req.Labels,
			req.ProfileID, app.UserIDFrom(ctx), out.ExpiresAt).Scan(&out.ID); err != nil {
			return err
		}
		return audit.Record(r, tx, "enrollment_token.create", "enrollment_token", out.ID, req)
	})
	if db.IsInvalidInput(err) || db.IsForeignKeyViolation(err) {
		httpx.BadRequest(w, "profile_id: no such profile")
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (s *svc) deleteToken(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "DELETE FROM enrollment_tokens WHERE id = $1 RETURNING id", id).Scan(&id); err != nil {
			return err
		}
		return audit.Record(r, tx, "enrollment_token.delete", "enrollment_token", id, nil)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// nameFromHostname turns a hostname into a valid node name.
func nameFromHostname(h string) string {
	b := []byte(clip(h, 64))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '-'
		}
	}
	return strings.TrimLeft(string(b), "._-")
}

var errUnusableName = errors.New("hostname is not usable as a node name; set node_name on the enrollment token")

// enroll claims a single-use enrollment token and creates the node, or re-keys the live
// node of the same name (re-installing a machine keeps its history).
func (s *svc) enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req api.EnrollRequest
	if err := httpx.ReadJSON(r, &req, 64<<10); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if req.Token == "" {
		httpx.BadRequest(w, "token required")
		return
	}
	ip := clip(req.PublicIP, 64)
	if _, err := netip.ParseAddr(ip); err != nil {
		ip = httpx.ClientIP(r)
	}
	nodeTok := app.NewToken()
	var nodeID, name string
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		var tokID string
		var labels map[string]string
		var profileID *string
		if err := tx.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING id, node_name, labels, profile_id`, app.HashToken(req.Token)).
			Scan(&tokID, &name, &labels, &profileID); err != nil {
			return err
		}
		if name == "" {
			name = nameFromHostname(req.Hostname)
		}
		if validName(name) != nil {
			return errUnusableName
		}
		if labels == nil {
			labels = map[string]string{}
		}
		over := json.RawMessage(`{}`)
		if req.Adopt {
			over = normalizeOverrides(req.AdoptOverrides)
			if err := checkOverrides(ctx, tx, profileID, over); err != nil {
				return err
			}
		}
		// Re-enrolling resets the seeded blocklist: the (re-installed) agent reports it again.
		if err := tx.QueryRow(ctx, `
			INSERT INTO nodes (name, hostname, public_ip, labels, profile_id, token_hash, enrolled_at,
			                   agent_version, dnsdist_version, os, arch, adopted, overrides)
			VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8, $9, $10, $11, $12)
			ON CONFLICT (name) WHERE deleted_at IS NULL DO UPDATE SET
				hostname = EXCLUDED.hostname, public_ip = EXCLUDED.public_ip,
				labels = nodes.labels || EXCLUDED.labels,
				profile_id = coalesce(EXCLUDED.profile_id, nodes.profile_id),
				token_hash = EXCLUDED.token_hash, enrolled_at = now(), last_heartbeat = NULL,
				agent_version = EXCLUDED.agent_version, dnsdist_version = EXCLUDED.dnsdist_version,
				os = EXCLUDED.os, arch = EXCLUDED.arch,
				adopted = nodes.adopted OR EXCLUDED.adopted,
				overrides = CASE WHEN EXCLUDED.adopted THEN EXCLUDED.overrides ELSE nodes.overrides END,
				seeded_blocklist_sha256 = ''
			RETURNING id`,
			name, clip(req.Hostname, 253), ip, labels, profileID, app.HashToken(nodeTok),
			clip(req.AgentVersion, 64), clip(req.DnsdistVersion, 128), clip(req.OS, 128), clip(req.Arch, 32),
			req.Adopt, []byte(over)).
			Scan(&nodeID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE enrollment_tokens SET used_by_node = $2 WHERE id = $1", tokID, nodeID); err != nil {
			return err
		}
		return audit.Log(ctx, tx, nil, "node.enroll", "node", nodeID,
			map[string]any{"name": name, "hostname": req.Hostname, "token_id": tokID, "adopt": req.Adopt}, httpx.ClientIP(r))
	})
	switch {
	case db.IsNotFound(err):
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "enrollment token is invalid, expired or already used")
		return
	case errors.Is(err, errUnusableName):
		httpx.BadRequest(w, err.Error())
		return
	case err != nil:
		writeOverridesErr(w, r, "adopt_overrides", err)
		return
	}
	s.d.Live.Delete(nodeID)
	s.mu.Lock()
	delete(s.rates, nodeID)
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, api.EnrollResponse{
		NodeID: nodeID, Name: name, NodeToken: nodeTok, PollIntervalS: s.d.Settings.Get().AgentPollIntervalS})
}
