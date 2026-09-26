package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/blocklist"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type effective struct {
	profile string
	version int // configVersion(profile version, profile, overrides)
	spec    []byte
	over    []byte
}

// effectiveConfig loads the newest published version of the node's profile ("default"
// when unset). ok is false when that profile has nothing published.
func effectiveConfig(ctx context.Context, q db.Querier, nodeID string) (e effective, ok bool, err error) {
	var v int
	var key string
	err = q.QueryRow(ctx, `
		SELECT p.name, v.version, v.spec, n.overrides, `+profileKeySQL+`
		FROM nodes n
		JOIN config_profiles p ON p.id = coalesce(n.profile_id, (SELECT id FROM config_profiles WHERE name = 'default'))
		JOIN LATERAL (SELECT version, spec FROM config_versions WHERE profile_id = p.id AND published
		              ORDER BY version DESC LIMIT 1) v ON true
		WHERE n.id = $1`, nodeID).Scan(&e.profile, &v, &e.spec, &e.over, &key)
	if db.IsNotFound(err) {
		return e, false, nil
	}
	e.version = configVersion(v, key, e.over)
	return e, err == nil, err
}

func (s *svc) config(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	e, ok, err := effectiveConfig(ctx, s.d.Pool, app.NodeIDFrom(ctx))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "no_config", "the node's profile has no published version")
		return
	}
	sha, size, err := currentBuild(ctx, s.d.Pool)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if sha == "" { // SPEC §17: an adopted node must never run without a blocklist
		var unseeded bool
		if err := s.d.Pool.QueryRow(ctx, "SELECT adopted AND seeded_blocklist_sha256 = '' FROM nodes WHERE id = $1",
			app.NodeIDFrom(ctx)).Scan(&unseeded); err != nil {
			httpx.WriteDBError(w, r, err)
			return
		}
		if unseeded {
			httpx.WriteError(w, http.StatusConflict, "no_blocklist",
				"adopted node: waiting for a panel blocklist build or a seeded local CDB")
			return
		}
	}
	etag := `"` + strconv.Itoa(e.version) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if httpx.ETagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	var base api.ConfigSpec
	if err := json.Unmarshal(e.spec, &base); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	spec, err := api.MergeSpec(base, e.over)
	if err == nil {
		err = spec.Validate()
	}
	if err != nil {
		// A new profile version can make old overrides invalid; the agent keeps its config.
		httpx.WriteError(w, http.StatusConflict, "invalid_config", "effective config is invalid: "+err.Error())
		return
	}
	al, err := blocklist.ActiveAllowlist(ctx, s.d.Pool)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	set := s.d.Settings.Get()
	out := api.AgentConfig{AllowlistVersion: al.Version,
		Version: e.version, Spec: spec, Profile: e.profile,
		PollIntervalS: set.AgentPollIntervalS, HeartbeatIntervalS: set.AgentHeartbeatIntervalS,
	}
	if sha != "" {
		out.Blocklist = api.BlocklistRef{SHA256: sha, Size: size, URL: "/agent/v1/blocklist"}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// counterDelta converts raw dnsdist counters into increments. Any counter going down
// means dnsdist restarted, so the new values are the increments. No previous
// heartbeat → no baseline → zero (a long-running dnsdist would otherwise spike).
func counterDelta(prev *api.Counters, cur api.Counters) api.Counters {
	if prev == nil {
		return api.Counters{}
	}
	p, c := counterSlice(*prev), counterSlice(cur)
	for i := range c {
		if c[i] < p[i] {
			return cur
		}
	}
	return api.Counters{
		Queries: cur.Queries - prev.Queries, Responses: cur.Responses - prev.Responses,
		CacheHits: cur.CacheHits - prev.CacheHits, CacheMisses: cur.CacheMisses - prev.CacheMisses,
		Blocked: cur.Blocked - prev.Blocked, DynBlocked: cur.DynBlocked - prev.DynBlocked,
		RuleDrops: cur.RuleDrops - prev.RuleDrops, Servfail: cur.Servfail - prev.Servfail,
		NXDomain: cur.NXDomain - prev.NXDomain, NoError: cur.NoError - prev.NoError,
		CGKRewrites: cur.CGKRewrites - prev.CGKRewrites,
	}
}

func counterSlice(c api.Counters) []int64 {
	return []int64{c.Queries, c.Responses, c.CacheHits, c.CacheMisses, c.Blocked, c.DynBlocked,
		c.RuleDrops, c.Servfail, c.NXDomain, c.NoError, c.CGKRewrites}
}

func nodeStatus(hb *api.Heartbeat) string {
	if !hb.DnsdistRunning || hb.ApplyError != "" || hb.BlocklistError != "" {
		return api.NodeDegraded
	}
	for _, b := range hb.Backends {
		if strings.EqualFold(b.State, "down") {
			return api.NodeDegraded
		}
	}
	return api.NodeOnline
}

// maxGapMinutes caps how far back a heartbeat gap's traffic is spread (one row per minute).
// ponytail: a gap longer than a week books its remainder in the oldest spread minute.
const maxGapMinutes = 7 * 24 * 60

// gapMinutes is the number of minute buckets a delta covering gap is spread over: 1 for
// normal heartbeats, so traffic accumulated over a panel outage or network blip does not
// land as one huge spike in the current minute.
func gapMinutes(gap time.Duration) int {
	n := int((gap + time.Minute - 1) / time.Minute)
	return max(1, min(n, maxGapMinutes))
}

// metricsInsert adds a counter delta to metrics_minutely, spread evenly over the $15
// minutes ending at the current one (integer remainders go to the newest minutes, so the
// totals are exact). Latency samples belong to the current minute only.
var metricsInsert = func() string {
	cols := []string{"queries", "responses", "cache_hits", "cache_misses", "blocked", "dyn_blocked", "rule_drops",
		"servfail", "nxdomain", "noerror", "cgk_rewrites"}
	var sel, upd strings.Builder
	for i, c := range cols {
		fmt.Fprintf(&sel, ", $%[1]d::bigint / $15 + (k < $%[1]d::bigint %% $15)::int", i+2)
		fmt.Fprintf(&upd, "%[1]s = metrics_minutely.%[1]s + EXCLUDED.%[1]s, ", c)
	}
	return `INSERT INTO metrics_minutely (node_id, ts, ` + strings.Join(cols, ", ") + `, latency_sum_ms, samples)
		SELECT $1, date_trunc('minute', now()) - make_interval(mins => k)` + sel.String() + `,
			CASE WHEN k = 0 THEN $13::double precision ELSE 0 END, CASE WHEN k = 0 THEN $14::int ELSE 0 END
		FROM generate_series(0, $15::int - 1) AS k
		ON CONFLICT (node_id, ts) DO UPDATE SET ` + upd.String() + `
			latency_sum_ms = metrics_minutely.latency_sum_ms + EXCLUDED.latency_sum_ms,
			samples = metrics_minutely.samples + EXCLUDED.samples`
}()

func (s *svc) heartbeat(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), app.NodeIDFrom(r.Context())
	var hb api.Heartbeat
	if err := httpx.ReadJSON(r, &hb, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if len(hb.Backends) > 1000 || len(hb.DynBlocks) > 20000 || len(hb.AckedCommands) > 1000 {
		httpx.BadRequest(w, "too many backends, dynblocks or acked commands")
		return
	}
	raw, err := json.Marshal(hb)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	var ack api.HeartbeatAck
	var rt *rate
	err = pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		var prevRaw []byte
		// FOR UPDATE serialises concurrent heartbeats of one node (delta math).
		if err := tx.QueryRow(ctx, "SELECT last_heartbeat FROM nodes WHERE id = $1 FOR UPDATE", id).Scan(&prevRaw); err != nil {
			return err
		}
		var prev *api.Heartbeat
		if prevRaw != nil {
			prev = new(api.Heartbeat)
			// A heartbeat with dnsdist down carries zero counters, not a baseline: using it
			// would book dnsdist's lifetime totals as one interval's traffic.
			if json.Unmarshal(prevRaw, prev) != nil || !prev.DnsdistRunning {
				prev = nil
			}
		}
		var pc *api.Counters
		if prev != nil {
			pc = &prev.Counters
		}
		d := counterDelta(pc, hb.Counters)
		// An older heartbeat whose counters went down is a late/duplicate delivery, not a
		// dnsdist restart: book nothing and keep the newer baseline.
		if prev != nil && hb.Time.Before(prev.Time) && d == hb.Counters && d != (api.Counters{}) {
			d, prev, raw = api.Counters{}, nil, prevRaw
		}
		if prev != nil {
			rt = liveRate(prev, &hb, d)
		}

		errs := make([]string, 0, 2)
		for _, e := range []string{hb.ApplyError, hb.BlocklistError} {
			if e != "" {
				errs = append(errs, e)
			}
		}
		appliedVer := &hb.AppliedConfigVersion
		if hb.AppliedConfigVersion == 0 {
			appliedVer = nil
		}
		if _, err := tx.Exec(ctx, `UPDATE nodes SET last_seen_at = now(), last_heartbeat = $2, status = $3,
			agent_version = $4, dnsdist_version = $5, os = $6, applied_config_version = $7,
			applied_blocklist_sha256 = $8, last_error = $9,
			seeded_blocklist_sha256 = CASE WHEN $8 <> '' THEN $8 ELSE seeded_blocklist_sha256 END WHERE id = $1`,
			id, raw, nodeStatus(&hb), clip(hb.AgentVersion, 64), clip(hb.DnsdistVersion, 128), clip(hb.OS, 128),
			appliedVer, clip(hb.BlocklistSHA256, 64), clip(strings.Join(errs, "; "), 4000)); err != nil {
			return err
		}

		samples, latency := 0, 0.0
		if hb.DnsdistRunning && d.Queries > 0 {
			samples, latency = 1, hb.LatencyAvgMs
		}
		if d != (api.Counters{}) || samples > 0 {
			spread := 1
			if prev != nil {
				spread = gapMinutes(hb.Time.Sub(prev.Time))
			}
			if _, err := tx.Exec(ctx, metricsInsert, id, d.Queries, d.Responses, d.CacheHits, d.CacheMisses, d.Blocked,
				d.DynBlocked, d.RuleDrops, d.Servfail, d.NXDomain, d.NoError, d.CGKRewrites, latency, samples, spread); err != nil {
				return err
			}
		}

		if err := storeUpgradeState(ctx, tx, id, &hb); err != nil {
			return err
		}
		if err := upsertBackends(ctx, tx, id, hb.Backends); err != nil {
			return err
		}
		if err := upsertOffenders(ctx, tx, id, hb.DynBlocks); err != nil {
			return err
		}

		if len(hb.AckedCommands) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE node_commands SET acked_at = now()
				WHERE node_id = $1 AND id = ANY($2) AND acked_at IS NULL`, id, hb.AckedCommands); err != nil {
				return err
			}
		}
		rows, _ := tx.Query(ctx, `UPDATE node_commands SET delivered_at = now()
			WHERE node_id = $1 AND delivered_at IS NULL
			RETURNING id, type, coalesce(params->>'version', ''), coalesce(params->>'series', '')`, id)
		cmds, err := pgx.CollectRows(rows, pgx.RowToStructByPos[api.Command])
		if err != nil {
			return err
		}
		ack.Commands = cmds

		e, ok, err := effectiveConfig(ctx, tx, id)
		if err != nil {
			return err
		}
		if ok {
			ack.ConfigVersion = e.version
		}
		if ack.BlocklistSHA256, _, err = currentBuild(ctx, tx); err != nil {
			return err
		}
		al, err := blocklist.ActiveAllowlist(ctx, tx)
		ack.AllowlistVersion = al.Version
		return err
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	s.d.Live.Set(id, hb)
	if rt != nil {
		s.mu.Lock()
		s.rates[id] = *rt
		s.mu.Unlock()
	}
	httpx.WriteJSON(w, http.StatusOK, ack)
}

// storeUpgradeState copies the §18 inventory (only once the agent has refreshed it, so a
// restarted agent does not blank it) and the last upgrade result onto the node.
func storeUpgradeState(ctx context.Context, tx pgx.Tx, id string, hb *api.Heartbeat) error {
	if hb.InventoryAt != nil {
		avail := make([]string, 0, len(hb.DnsdistAvailable))
		for _, v := range hb.DnsdistAvailable[:min(len(hb.DnsdistAvailable), 500)] {
			avail = append(avail, clip(v, 128))
		}
		if _, err := tx.Exec(ctx, `UPDATE nodes SET dnsdist_candidate = $2, dnsdist_available = $3,
			dnsdist_repo_series = $4, inventory_at = $5 WHERE id = $1`,
			id, clip(hb.DnsdistCandidate, 128), avail, clip(hb.DnsdistRepoSeries, 16), hb.InventoryAt); err != nil {
			return err
		}
	}
	if u := hb.LastUpgrade; u != nil {
		u.Kind, u.From, u.To, u.Error = clip(u.Kind, 16), clip(u.From, 128), clip(u.To, 128), clip(u.Error, 4000)
		if _, err := tx.Exec(ctx, "UPDATE nodes SET last_upgrade = $2 WHERE id = $1", id, u); err != nil {
			return err
		}
	}
	return nil
}

// liveRate derives qps and cache hit ratio from two consecutive heartbeats.
func liveRate(prev, cur *api.Heartbeat, d api.Counters) *rate {
	dt := cur.Time.Sub(prev.Time).Seconds()
	if dt <= 0 || dt > 300 {
		return nil
	}
	r := &rate{qps: float64(d.Queries) / dt}
	if lookups := d.CacheHits + d.CacheMisses; lookups > 0 {
		r.cacheHit = float64(d.CacheHits) / float64(lookups)
	}
	return r
}

func upsertBackends(ctx context.Context, tx pgx.Tx, id string, bs []api.BackendStat) error {
	var addr, name, pool, state []string
	var weight, order []int32
	var qps, lat []float64
	var queries, drops []int64
	seen := map[string]bool{}
	for _, b := range bs {
		a := clip(b.Address, 128)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		addr, name, pool, state = append(addr, a), append(name, clip(b.Name, 128)), append(pool, clip(b.Pool, 128)), append(state, clip(b.State, 32))
		weight, order = append(weight, int32(b.Weight)), append(order, int32(b.Order))
		qps, lat = append(qps, b.QPS), append(lat, b.LatencyMs)
		queries, drops = append(queries, b.Queries), append(drops, b.Drops)
	}
	if addr == nil {
		addr = []string{}
	}
	if len(addr) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO backend_status (node_id, address, name, pool, state, weight, "order", qps, latency_ms, queries, drops, updated_at)
			SELECT $1::uuid, *, now() FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::int[],
				$8::float8[], $9::float8[], $10::bigint[], $11::bigint[])
			ON CONFLICT (node_id, address) DO UPDATE SET name = EXCLUDED.name, pool = EXCLUDED.pool,
				state = EXCLUDED.state, weight = EXCLUDED.weight, "order" = EXCLUDED."order", qps = EXCLUDED.qps,
				latency_ms = EXCLUDED.latency_ms, queries = EXCLUDED.queries, drops = EXCLUDED.drops,
				updated_at = now()`,
			id, addr, name, pool, state, weight, order, qps, lat, queries, drops); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, "DELETE FROM backend_status WHERE node_id = $1 AND NOT (address = ANY($2))", id, addr)
	return err
}

// upsertOffenders refreshes the open event per (client, reason) or opens a new one.
// Events are closed by statusTick once unseen for 10 minutes.
func upsertOffenders(ctx context.Context, tx pgx.Tx, id string, dbs []api.DynBlock) error {
	var client, reason, stage []string
	var blocks []int64
	seen := map[[2]string]int{}
	for _, b := range dbs {
		c, rs := clip(b.Client, 64), clip(b.Reason, 256)
		if c == "" {
			continue
		}
		st := "blocked"
		if b.Stage == "warning" {
			st = "warning"
		}
		k := [2]string{c, rs}
		if i, ok := seen[k]; ok { // same client+reason twice: keep the worst
			if st == "blocked" {
				stage[i] = st
			}
			blocks[i] = max(blocks[i], b.Blocks)
			continue
		}
		seen[k] = len(client)
		client, reason, stage, blocks = append(client, c), append(reason, rs), append(stage, st), append(blocks, b.Blocks)
	}
	if len(client) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		WITH d AS (SELECT * FROM unnest($2::text[], $3::text[], $4::text[], $5::bigint[]) AS d(client, reason, stage, blocks)),
		upd AS (
			UPDATE offender_events o SET last_seen = now(), blocks = GREATEST(o.blocks, d.blocks),
				stage = CASE WHEN o.stage = 'blocked' THEN 'blocked' ELSE d.stage END
			FROM d WHERE o.node_id = $1 AND NOT o.closed AND o.client = d.client AND o.reason = d.reason
			RETURNING o.client, o.reason)
		INSERT INTO offender_events (node_id, client, reason, stage, blocks)
		SELECT $1::uuid, d.client, d.reason, d.stage, d.blocks FROM d
		WHERE NOT EXISTS (SELECT 1 FROM upd WHERE upd.client = d.client AND upd.reason = d.reason)`,
		id, client, reason, stage, blocks)
	return err
}

const maxBlockedItems = 250_000

func (s *svc) blocked(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), app.NodeIDFrom(r.Context())
	key := r.Header.Get(api.IdempotencyHeader)
	if len(key) > db.MaxBatchKey {
		httpx.BadRequest(w, "Idempotency-Key: too long")
		return
	}
	var b api.BlockedBatch
	if err := httpx.ReadJSON(r, &b, httpx.MaxBody); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if len(b.Items) > maxBlockedItems {
		httpx.BadRequest(w, "at most 250000 items per batch")
		return
	}
	now := time.Now().UTC()
	oldest, newest := now.AddDate(0, 0, -800), now.AddDate(0, 0, 1)
	days := make([]string, 0, len(b.Items))
	names := make([]string, 0, len(b.Items))
	types := make([]string, 0, len(b.Items))
	counts := make([]int64, 0, len(b.Items))
	skipped := 0
	for _, it := range b.Items {
		day, err := time.Parse(time.DateOnly, it.Day)
		q := strings.ToLower(strings.TrimSuffix(it.QName, "."))
		if q == "" {
			q = "."
		}
		// Invalid items are dropped rather than failing the batch: the agent would retry
		// a rejected spool file forever.
		if err != nil || day.Before(oldest) || day.After(newest) || len(q) > 255 ||
			it.QType == "" || len(it.QType) > 16 || it.Count <= 0 {
			skipped++
			continue
		}
		days, names, types, counts = append(days, it.Day), append(names, q), append(types, it.QType), append(counts, it.Count)
	}
	if skipped > 0 {
		s.d.Log.Warn("blocked batch: invalid items dropped", "node_id", id, "skipped", skipped)
	}
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if fresh, err := db.ClaimBatch(ctx, tx, id, key); err != nil || !fresh || len(days) == 0 {
			return err
		}
		// GROUP BY: one INSERT .. ON CONFLICT cannot touch the same row twice.
		_, err := tx.Exec(ctx, `
			INSERT INTO blocked_daily (day, node_id, qname, qtype, count)
			SELECT d::date, $1::uuid, q, t, sum(c) FROM unnest($2::text[], $3::text[], $4::text[], $5::bigint[]) AS x(d, q, t, c)
			GROUP BY d, q, t
			ON CONFLICT (day, node_id, qname, qtype) DO UPDATE SET count = blocked_daily.count + EXCLUDED.count`,
			id, days, names, types, counts)
		return err
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *svc) cgk(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), app.NodeIDFrom(r.Context())
	var c api.CGKReport
	if err := httpx.ReadJSON(r, &c, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if len(c.Aliases) > 4096 || len(c.RewriteRanges) > 4096 || len(c.Pools) > 4096 {
		httpx.BadRequest(w, "too many aliases, rewrite ranges or pools")
		return
	}
	if c.MeasuredAt.IsZero() {
		c.MeasuredAt = time.Now()
	}
	orEmpty := func(v any, n int) any {
		if n == 0 {
			return []string{}
		}
		return v
	}
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO cgk_reports (node_id, measured_at, ok, message, aliases, rewrite_ranges, pools)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, c.MeasuredAt, c.OK, clip(c.Message, 4000),
			orEmpty(c.Aliases, len(c.Aliases)), orEmpty(c.RewriteRanges, len(c.RewriteRanges)), orEmpty(c.Pools, len(c.Pools))); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM cgk_reports WHERE node_id = $1 AND id NOT IN (
			SELECT id FROM cgk_reports WHERE node_id = $1 ORDER BY measured_at DESC, id DESC LIMIT 100)`, id)
		return err
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
