package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/panel/install"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type svc struct {
	d    *app.Deps
	tmpl *template.Template

	mu    sync.Mutex
	rates map[string]rate // node id → rates derived from the last two heartbeats
}

type rate struct{ qps, cacheHit float64 }

// Register mounts the node, enrollment, agent and installer routes and the status job.
func Register(r *app.Router, d *app.Deps) {
	s := &svc{d: d, rates: map[string]rate{},
		tmpl: template.Must(template.ParseFS(install.Assets(), "install.sh.tmpl"))}

	r.Viewer("GET /api/v1/enrollment-tokens", s.listTokens)
	r.Admin("POST /api/v1/enrollment-tokens", s.createToken)
	r.Admin("DELETE /api/v1/enrollment-tokens/{id}", s.deleteToken)

	r.Viewer("GET /api/v1/nodes", s.listNodes)
	r.Viewer("GET /api/v1/nodes/{id}", s.getNode)
	r.Admin("PATCH /api/v1/nodes/{id}", s.patchNode)
	r.Admin("DELETE /api/v1/nodes/{id}", s.deleteNode)
	r.Viewer("GET /api/v1/nodes/{id}/live", s.live)
	r.Viewer("GET /api/v1/nodes/{id}/cgk", s.cgkLatest)
	r.Admin("POST /api/v1/nodes/{id}/commands", s.command)

	r.Public("POST /agent/v1/enroll", s.enroll)
	r.Agent("GET /agent/v1/config", s.config)
	r.Agent("POST /agent/v1/heartbeat", s.heartbeat)
	r.Agent("POST /agent/v1/blocked", s.blocked)
	r.Agent("POST /agent/v1/cgk", s.cgk)

	r.Public("GET /install.sh", s.installScript)
	r.Public("GET /dl/agent/linux/{arch}", s.download)

	if d.Jobs != nil {
		d.Jobs.Every("node-status", 15*time.Second, s.statusTick)
	}
}

// configVersion is the version an agent sees (AgentConfig.Version, ETag, HeartbeatAck):
// the profile's published version v when the node has no overrides, otherwise
// v*100000 + (fnv32a(overrides jsonb text) % 99999) + 1, so editing overrides changes the
// version and the ETag. overrides comes from jsonb, whose text form is canonical.
// ponytail: 1-in-99999 chance an override edit hashes to the same version (the node then
// picks it up with the next profile publish); fits int4 up to profile version 21474.
func configVersion(v int, overrides []byte) int {
	if o := strings.TrimSpace(string(overrides)); o == "" || o == "{}" || o == "null" {
		return v
	}
	h := fnv.New32a()
	h.Write(overrides)
	return v*100000 + int(h.Sum32()%99999) + 1
}

// currentBuild returns the newest ok blocklist build (empty when there is none).
func currentBuild(ctx context.Context, q db.Querier) (sha string, size int64, err error) {
	err = q.QueryRow(ctx, `SELECT sha256, size_bytes FROM blocklist_builds WHERE status = 'ok'
		ORDER BY finished_at DESC NULLS LAST, id DESC LIMIT 1`).Scan(&sha, &size)
	if db.IsNotFound(err) {
		err = nil
	}
	return
}

// profileSpec returns the newest published spec of a profile (nil id = "default"), or
// the built-in defaults when it has none.
func profileSpec(ctx context.Context, q db.Querier, profileID *string) (api.ConfigSpec, error) {
	var raw []byte
	err := q.QueryRow(ctx, `SELECT v.spec FROM config_versions v
		WHERE v.profile_id = coalesce($1::uuid, (SELECT id FROM config_profiles WHERE name = 'default')) AND v.published
		ORDER BY v.version DESC LIMIT 1`, profileID).Scan(&raw)
	if db.IsNotFound(err) {
		return api.DefaultConfigSpec(), nil
	}
	if err != nil {
		return api.ConfigSpec{}, err
	}
	var spec api.ConfigSpec
	return spec, json.Unmarshal(raw, &spec)
}

// overridesError is a merge patch that does not merge into a valid spec (422).
type overridesError struct{ error }

// normalizeOverrides maps an empty, null or {} patch to {} ("no overrides").
func normalizeOverrides(o json.RawMessage) json.RawMessage {
	if s := strings.TrimSpace(string(o)); s == "" || s == "null" || s == "{}" {
		return json.RawMessage(`{}`)
	}
	return o
}

// checkOverrides merges non-empty overrides over the profile's published spec and
// validates the result.
func checkOverrides(ctx context.Context, q db.Querier, profileID *string, over json.RawMessage) error {
	if string(over) == "{}" {
		return nil
	}
	base, err := profileSpec(ctx, q, profileID)
	if err != nil {
		return err
	}
	merged, err := api.MergeSpec(base, over)
	if err == nil {
		err = merged.Validate()
	}
	if err != nil {
		return overridesError{err}
	}
	return nil
}

func writeOverridesErr(w http.ResponseWriter, r *http.Request, field string, err error) {
	var oe overridesError
	if errors.As(err, &oe) {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_config", field+": "+oe.Error())
		return
	}
	httpx.WriteDBError(w, r, err)
}

const nodeSelect = `
SELECT n.id, n.name, n.hostname, n.public_ip, n.labels, n.status, n.profile_id, coalesce(p.name, ''),
       n.overrides, n.enrolled_at, n.last_seen_at, n.agent_version, n.dnsdist_version, n.os, n.arch,
       n.applied_config_version, n.applied_blocklist_sha256, n.last_error, n.created_at, pv.version
FROM nodes n
LEFT JOIN config_profiles p ON p.id = coalesce(n.profile_id, (SELECT id FROM config_profiles WHERE name = 'default'))
LEFT JOIN LATERAL (SELECT version FROM config_versions v WHERE v.profile_id = p.id AND v.published
                   ORDER BY v.version DESC LIMIT 1) pv ON true
WHERE n.deleted_at IS NULL`

func (s *svc) queryNodes(ctx context.Context, where string, args ...any) ([]api.Node, error) {
	blSHA, _, err := currentBuild(ctx, s.d.Pool)
	if err != nil {
		return nil, err
	}
	rows, _ := s.d.Pool.Query(ctx, nodeSelect+where+" ORDER BY n.name", args...)
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.Node, error) {
		var n api.Node
		var pv *int
		err := row.Scan(&n.ID, &n.Name, &n.Hostname, &n.PublicIP, &n.Labels, &n.Status, &n.ProfileID, &n.ProfileName,
			&n.Overrides, &n.EnrolledAt, &n.LastSeenAt, &n.AgentVersion, &n.DnsdistVersion, &n.OS, &n.Arch,
			&n.AppliedConfigVersion, &n.AppliedBlocklistSHA256, &n.LastError, &n.CreatedAt, &pv)
		if pv != nil {
			v := configVersion(*pv, n.Overrides)
			n.DesiredConfigVersion = &v
			n.ConfigInSync = n.AppliedConfigVersion != nil && *n.AppliedConfigVersion == v
		}
		n.DesiredBlocklistSHA256 = blSHA
		n.BlocklistInSync = n.AppliedBlocklistSHA256 == blSHA
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		if n.Status != api.NodeOffline {
			if e, ok := s.d.Live.Get(n.ID); ok {
				n.LatencyAvgMs = e.Heartbeat.LatencyAvgMs
			}
			s.mu.Lock()
			r := s.rates[n.ID]
			s.mu.Unlock()
			n.QPS, n.CacheHitRatio = r.qps, r.cacheHit
		}
		return n, err
	})
}

func (s *svc) listNodes(w http.ResponseWriter, r *http.Request) {
	items, err := s.queryNodes(r.Context(), "")
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.Node]{Items: items, Total: len(items)})
}

func (s *svc) oneNode(ctx context.Context, id string) (api.Node, error) {
	items, err := s.queryNodes(ctx, " AND n.id = $1", id)
	if err == nil && len(items) == 0 {
		err = pgx.ErrNoRows
	}
	if err != nil {
		return api.Node{}, err
	}
	return items[0], nil
}

func (s *svc) getNode(w http.ResponseWriter, r *http.Request) {
	n, err := s.oneNode(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, n)
}

var nodeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validName(name string) error {
	if !nodeNameRe.MatchString(name) {
		return fmt.Errorf("name %q: 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}

func validLabels(l map[string]string) error {
	if len(l) > 50 {
		return fmt.Errorf("labels: at most 50")
	}
	for k, v := range l {
		if k == "" || len(k) > 64 || len(v) > 256 {
			return fmt.Errorf("labels: keys 1-64 and values up to 256 characters")
		}
	}
	return nil
}

func (s *svc) patchNode(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	var p api.NodePatch
	if err := httpx.ReadJSON(r, &p, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	cur, err := s.oneNode(ctx, id)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if p.Name != nil {
		cur.Name = strings.TrimSpace(*p.Name)
		if err := validName(cur.Name); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	if p.Labels != nil {
		cur.Labels = *p.Labels
		if cur.Labels == nil {
			cur.Labels = map[string]string{}
		}
		if err := validLabels(cur.Labels); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	if p.ProfileID != nil {
		cur.ProfileID = p.ProfileID
		if *p.ProfileID == "" {
			cur.ProfileID = nil
		}
	}
	if p.Overrides != nil {
		cur.Overrides = normalizeOverrides(p.Overrides)
	}
	if p.ProfileID != nil || p.Overrides != nil {
		if cur.ProfileID != nil {
			var ok bool
			if err := s.d.Pool.QueryRow(ctx, "SELECT true FROM config_profiles WHERE id = $1", *cur.ProfileID).Scan(&ok); err != nil {
				if db.IsNotFound(err) || db.IsInvalidInput(err) {
					httpx.BadRequest(w, "profile_id: no such profile")
				} else {
					httpx.WriteDBError(w, r, err)
				}
				return
			}
		}
		if err := checkOverrides(ctx, s.d.Pool, cur.ProfileID, cur.Overrides); err != nil {
			writeOverridesErr(w, r, "overrides", err)
			return
		}
	}
	err = pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE nodes SET name = $2, labels = $3, profile_id = $4, overrides = $5
			WHERE id = $1 AND deleted_at IS NULL`, id, cur.Name, cur.Labels, cur.ProfileID, []byte(cur.Overrides)); err != nil {
			return err
		}
		return audit.Record(r, tx, "node.update", "node", id, p)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	s.getNode(w, r)
}

func (s *svc) deleteNode(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		var name string
		// Soft delete keeps metrics/reports; dropping the token hash locks the agent out.
		if err := tx.QueryRow(ctx, `UPDATE nodes SET deleted_at = now(), token_hash = NULL
			WHERE id = $1 AND deleted_at IS NULL RETURNING name`, id).Scan(&name); err != nil {
			return err
		}
		return audit.Record(r, tx, "node.delete", "node", id, map[string]string{"name": name})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	s.d.Live.Delete(id)
	s.mu.Lock()
	delete(s.rates, id)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *svc) live(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var raw []byte
	var seen *time.Time
	err := s.d.Pool.QueryRow(r.Context(), `SELECT last_heartbeat, last_seen_at FROM nodes
		WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&raw, &seen)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	out := api.NodeLive{NodeID: id}
	if e, ok := s.d.Live.Get(id); ok {
		out.Heartbeat, out.ReceivedAt = &e.Heartbeat, &e.ReceivedAt
	} else if raw != nil { // panel restarted since the last heartbeat
		var hb api.Heartbeat
		if json.Unmarshal(raw, &hb) == nil {
			out.Heartbeat, out.ReceivedAt = &hb, seen
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// cgkLatest returns the node's newest CGK report, or JSON null when there is none yet.
func (s *svc) cgkLatest(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	var one int
	if err := s.d.Pool.QueryRow(ctx, "SELECT 1 FROM nodes WHERE id = $1 AND deleted_at IS NULL", id).Scan(&one); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	var c api.CGKReport
	err := s.d.Pool.QueryRow(ctx, `SELECT measured_at, ok, message, aliases, rewrite_ranges, pools FROM cgk_reports
		WHERE node_id = $1 ORDER BY measured_at DESC, id DESC LIMIT 1`, id).
		Scan(&c.MeasuredAt, &c.OK, &c.Message, &c.Aliases, &c.RewriteRanges, &c.Pools)
	switch {
	case db.IsNotFound(err):
		httpx.WriteJSON(w, http.StatusOK, nil)
	case err != nil:
		httpx.WriteDBError(w, r, err)
	default:
		httpx.WriteJSON(w, http.StatusOK, c)
	}
}

var commandTypes = []string{api.CmdCGKRefresh, api.CmdRestartDnsdist, api.CmdReapply}

func (s *svc) command(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	var req api.CommandRequest
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if !slices.Contains(commandTypes, req.Type) {
		httpx.BadRequest(w, "type must be one of "+strings.Join(commandTypes, ", "))
		return
	}
	var c api.Command
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO node_commands (node_id, type, created_by)
			SELECT id, $2, $3 FROM nodes WHERE id = $1 AND deleted_at IS NULL RETURNING id, type`,
			id, req.Type, app.UserIDFrom(ctx)).Scan(&c.ID, &c.Type); err != nil {
			return err
		}
		return audit.Record(r, tx, "node.command", "node", id, c)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, c)
}

// statusTick marks nodes offline after 3 missed heartbeats and closes offender events
// unseen for 10 minutes. online/degraded is decided on each heartbeat.
func (s *svc) statusTick(ctx context.Context) error {
	secs := 3 * s.d.Settings.Get().AgentHeartbeatIntervalS
	if _, err := s.d.Pool.Exec(ctx, `UPDATE nodes SET status = 'offline'
		WHERE deleted_at IS NULL AND status IN ('online', 'degraded')
		  AND last_seen_at < now() - make_interval(secs => $1)`, secs); err != nil {
		return err
	}
	_, err := s.d.Pool.Exec(ctx, `UPDATE offender_events SET closed = true
		WHERE NOT closed AND last_seen < now() - interval '10 minutes'`)
	return err
}
