package blocklist

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	keys "github.com/billyriantono/dnsjos/internal/shared/cdb"
)

// minDomains is the sanity floor applied when a TrustPositif domains source is enabled.
var minDomains = 100_000

const (
	userAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	keepBuilds = 3
	// Bump when parsing/encoding changes so unchanged inputs still rebuild.
	builderVersion = "1"
)

var errBusy = errors.New("a blocklist build is already running")

type Service struct {
	d      *app.Deps
	dir    string // $DATA_DIR/blocklist
	client *http.Client
	// rangeClient speaks HTTP/1.1 only: over HTTP/2 every "parallel" range would be
	// multiplexed onto one TCP connection, which is slower than a single stream.
	rangeClient *http.Client
	mu          sync.Mutex // single-flight build
	dirtyMu     sync.Mutex
	dirty       map[string]bool // scopes invalidated by successful source syncs
}

func newService(d *app.Deps) *Service {
	return &Service{d: d, dir: filepath.Join(d.Cfg.DataDir, "blocklist"), client: newHTTPClient(true), rangeClient: newHTTPClient(false), dirty: make(map[string]bool)}
}

func (s *Service) markDirty(ctx context.Context, sourceID string) {
	rows, err := s.d.Pool.Query(ctx, `SELECT coalesce(sp.profile_id::text, '') FROM blocklist_sources bs
		LEFT JOIN blocklist_source_profiles sp ON sp.source_id = bs.id WHERE bs.id = $1`, sourceID)
	if err != nil {
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return
	}
	global := len(ids) == 0
	for _, id := range ids {
		if id == "" {
			global = true
		}
	}
	if global {
		ids = s.scopes(ctx)
	}
	s.dirtyMu.Lock()
	defer s.dirtyMu.Unlock()
	for _, id := range ids {
		s.dirty[id] = true
	}
}

func (s *Service) isDirty(profileID string) bool {
	s.dirtyMu.Lock()
	defer s.dirtyMu.Unlock()
	return s.dirty[profileID]
}
func (s *Service) clearDirty(profileID string) {
	s.dirtyMu.Lock()
	delete(s.dirty, profileID)
	s.dirtyMu.Unlock()
}
func (s *Service) artifact(sha string) string { return filepath.Join(s.dir, sha+".cdb") }
func (s *Service) sourcePath(id string) string {
	return filepath.Join(s.dir, "sources", id+".txt")
}

type source struct {
	ID, Kind, URL, Content, ETag, LastModified string
}

func isURLKind(k string) bool {
	return strings.HasPrefix(k, "trustpositif_") || strings.HasPrefix(k, "url_")
}

// isRPZDomainsKind is the kind the RPZ slave fills from AXFR/IXFR transfers. It is NOT a
// URL source: its content is the transferred domain list, written by the sync job.
func isRPZDomainsKind(k string) bool { return k == api.SourceRPZDomains }
func isDomainKind(k string) bool     { return strings.HasSuffix(k, "_domains") }
func isIPKind(k string) bool         { return strings.HasSuffix(k, "_ips") }

const buildCols = `b.id, coalesce(b.profile_id::text, ''), coalesce(p.name, ''), b.started_at, b.finished_at, b.status, b.trigger, b.domains, b.ips, b.whitelisted, b.skipped, b.size_bytes, b.sha256, b.error, b.added, b.removed`

// buildFrom joins the owning profile so a build row carries its name. Every query that
// selects buildCols must use this FROM.
const buildFrom = `FROM blocklist_builds b LEFT JOIN config_profiles p ON p.id = b.profile_id`

func scanBuild(row pgx.Row) (api.BlocklistBuild, error) {
	var b api.BlocklistBuild
	err := row.Scan(&b.ID, &b.ProfileID, &b.ProfileName, &b.StartedAt, &b.FinishedAt, &b.Status, &b.Trigger, &b.Domains, &b.IPs,
		&b.Whitelisted, &b.Skipped, &b.SizeBytes, &b.SHA256, &b.Error, &b.Added, &b.Removed)
	return b, err
}

// ProfileID is the empty string for the global scope. It keys every query that has to
// pick one scope apart from the others.
//
// scopeWhere builds a "profile_id IS NULL" / "profile_id = $n" predicate on a plain
// profile_id column (blocklist_builds keeps one). Use sourceScopeWhere for sources, whose
// profiles live in the blocklist_source_profiles join table.
func scopeWhere(col string, n int) string {
	return fmt.Sprintf("((%s IS NULL AND $%d = '') OR %s = nullif($%d, '')::uuid)", col, n, col, n)
}

// sourceScopeWhere builds the predicate that selects the sources one scope builds from:
// the sources tied to $n by the blocklist_source_profiles join table, plus every global
// source. A source with no join row is global and so belongs to every scope, including
// the empty one. srcAlias is the blocklist_sources alias (e.g. "blocklist_sources" or "s").
func sourceScopeWhere(srcAlias string, n int) string {
	return fmt.Sprintf(
		`(EXISTS (SELECT 1 FROM blocklist_source_profiles sp WHERE sp.source_id = %s.id AND sp.profile_id = nullif($%d, '')::uuid)
			OR NOT EXISTS (SELECT 1 FROM blocklist_source_profiles sp2 WHERE sp2.source_id = %s.id))`,
		srcAlias, n, srcAlias)
}

// Current returns the newest ok build for one scope, or nil when there is none. An empty
// profileID is the global build. It never falls back: the fallback belongs to serving, so
// the UI can still tell "this profile has no build of its own" apart from "it uses global".
func Current(ctx context.Context, q db.Querier, profileID string) (*api.BlocklistBuild, error) {
	b, err := scanBuild(q.QueryRow(ctx, "SELECT "+buildCols+" "+buildFrom+
		" WHERE b.status = 'ok' AND "+scopeWhere("b.profile_id", 1)+" ORDER BY b.finished_at DESC, b.id DESC LIMIT 1", profileID))
	if db.IsNotFound(err) {
		return nil, nil
	}
	return &b, err
}

// Start runs a build for one scope in the background and returns its running row; errBusy
// when a build is already in progress. profileID is "" for the global build. force
// re-downloads every URL source (no conditional request) and rebuilds even when the inputs
// are unchanged.
func (s *Service) Start(trigger, profileID string, force bool) (api.BlocklistBuild, error) {
	if !s.mu.TryLock() {
		return api.BlocklistBuild{}, errBusy
	}
	b, err := s.insert(context.Background(), trigger, profileID)
	if err != nil {
		s.mu.Unlock()
		return b, err
	}
	go func() {
		defer s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		if _, err := s.execute(ctx, b.ID, profileID, force); err != nil {
			s.d.Log.Error("blocklist build", "id", b.ID, "profile", profileID, "err", err)
		}
	}()
	return b, nil
}

// tick is the scheduled job: rebuilds every scope whose interval has passed. The global
// build and each profile that owns at least one source are separate scopes.
func (s *Service) tick(ctx context.Context) error {
	every := time.Duration(s.d.Settings.Get().BlocklistBuildIntervalMinutes) * time.Minute
	for _, profileID := range s.scopes(ctx) {
		var last *time.Time
		if err := s.d.Pool.QueryRow(ctx, "SELECT max(started_at) FROM blocklist_builds WHERE "+scopeWhere("profile_id", 1),
			profileID).Scan(&last); err != nil {
			return err
		}
		if last != nil && time.Since(*last) < every && !s.isDirty(profileID) {
			continue
		}
		if !s.mu.TryLock() {
			return nil // a build is running; the next tick retries
		}
		b, err := s.insert(ctx, "schedule", profileID)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.clearDirty(profileID)
		_, err = s.execute(ctx, b.ID, profileID, false)
		s.mu.Unlock()
		if err != nil {
			s.dirtyMu.Lock()
			s.dirty[profileID] = true
			s.dirtyMu.Unlock()
			return err
		}
	}
	return nil
}

// scopes lists the scopes that need building: the global scope, every profile that owns at
// least one enabled source, and every profile that still has an ok build. The last group is
// what lets a profile whose sources were all deleted or moved converge: it keeps getting
// rebuilt (from the global sources alone) instead of pinning a stale artifact forever.
func (s *Service) scopes(ctx context.Context) []string {
	rows, _ := s.d.Pool.Query(ctx, `
		SELECT coalesce(profile_id::text, '') FROM (
			-- every profile that owns at least one enabled source...
			SELECT sp.profile_id FROM blocklist_source_profiles sp
				JOIN blocklist_sources s ON s.id = sp.source_id WHERE s.enabled
			UNION
			-- ...plus the global scope whenever an enabled global source (no join rows) exists
			SELECT NULL::uuid WHERE EXISTS (SELECT 1 FROM blocklist_sources s
				WHERE s.enabled AND NOT EXISTS (SELECT 1 FROM blocklist_source_profiles sp WHERE sp.source_id = s.id))
			UNION
			-- ...plus every profile that still has an ok build, so a profile whose sources were
			-- all removed or moved keeps converging instead of pinning a stale artifact forever.
			SELECT profile_id FROM blocklist_builds WHERE status = 'ok'
		) u GROUP BY profile_id ORDER BY profile_id NULLS FIRST`)
	profiles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		s.d.Log.Error("blocklist scopes", "err", err)
		return []string{""}
	}
	return profiles
}

func (s *Service) insert(ctx context.Context, trigger, profileID string) (api.BlocklistBuild, error) {
	return scanBuild(s.d.Pool.QueryRow(ctx,
		`WITH ins AS (INSERT INTO blocklist_builds (trigger, profile_id)
			VALUES ($1, nullif($2, '')::uuid) RETURNING *)
		 SELECT `+buildCols+` FROM ins b LEFT JOIN config_profiles p ON p.id = b.profile_id`, trigger, profileID))
}

type result struct {
	status                             string // ok | skipped
	domains, ips, whitelisted, skipped int
	added, removed                     int             // versus the previous ok build
	changes                            map[string]bool // name → added
	size                               int64
	sha                                string
	entries                            map[string]int // per source id
	fingerprint                        string
}

// execute runs build and records its outcome on row id. Caller holds s.mu.
func (s *Service) execute(ctx context.Context, id int64, profileID string, force bool) (api.BlocklistBuild, error) {
	res, buildErr := s.build(ctx, profileID, force)
	status, msg := res.status, ""
	if buildErr != nil {
		status, msg = "failed", buildErr.Error()
	}
	// A cancelled ctx must still be able to close the row.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	b, err := scanBuild(s.d.Pool.QueryRow(wctx, `WITH upd AS (UPDATE blocklist_builds SET finished_at = now(), status = $2,
		domains = $3, ips = $4, whitelisted = $5, skipped = $6, size_bytes = $7, sha256 = $8, error = $9,
		added = $10, removed = $11
		WHERE id = $1 RETURNING *)
		SELECT `+buildCols+` FROM upd b LEFT JOIN config_profiles p ON p.id = b.profile_id`,
		id, status, res.domains, res.ips, res.whitelisted, res.skipped, res.size, res.sha, msg, res.added, res.removed))
	if err != nil {
		return b, err
	}
	if status == "ok" {
		for sid, n := range res.entries {
			if _, err := s.d.Pool.Exec(wctx, "UPDATE blocklist_sources SET entries = $2 WHERE id = $1", sid, n); err != nil {
				return b, err
			}
		}
		if err := s.saveChanges(wctx, id, res.changes); err != nil {
			s.d.Log.Warn("blocklist changes", "id", id, "err", err) // history only; the build stands
		}
		if err := os.WriteFile(s.fingerprintPath(profileID), []byte(res.fingerprint), 0o644); err != nil {
			return b, err
		}
		s.prune(wctx)
	}
	debug.FreeOSMemory() // the CDB writer's index is transient; hand it back to the OS
	return b, buildErr
}

func (s *Service) build(ctx context.Context, profileID string, force bool) (res result, err error) {
	if err := os.MkdirAll(filepath.Join(s.dir, "sources"), 0o755); err != nil {
		return res, err
	}
	// A profile builds from its own sources plus the global ones; anything scoped to a
	// different profile is invisible here.
	rows, _ := s.d.Pool.Query(ctx, `SELECT id, kind, url, content, etag, last_modified
		FROM blocklist_sources WHERE enabled AND `+sourceScopeWhere("blocklist_sources", 1)+
		` ORDER BY id`, profileID)
	srcs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[source])
	if err != nil {
		return res, err
	}

	var fetched []string // sources that got a fresh 200 this run
	defer func() {
		// A failed build must not leave a bad download pinned by its ETag.
		if err != nil && len(fetched) > 0 {
			_, _ = s.d.Pool.Exec(context.WithoutCancel(ctx),
				"UPDATE blocklist_sources SET etag = '', last_modified = '' WHERE id = ANY($1)", fetched)
		}
	}()
	for _, src := range srcs {
		if !isURLKind(src.Kind) {
			continue
		}
		changed, ferr := s.fetch(ctx, src, force)
		if ferr != nil {
			s.d.Log.Warn("blocklist fetch", "source", src.ID, "url", src.URL, "err", ferr)
		} else if changed {
			fetched = append(fetched, src.ID)
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}

	// Active allowlist entries are left out of the CDB too, so they survive a node that
	// restarts before its first allowlist sync (SPEC §7.5).
	al, err := ActiveAllowlist(ctx, s.d.Pool)
	if err != nil {
		return res, err
	}
	res.fingerprint = s.fingerprint(srcs, al.Version)
	cur, err := Current(ctx, s.d.Pool, profileID)
	if err != nil {
		return res, err
	}
	if cur != nil {
		old, _ := os.ReadFile(s.fingerprintPath(profileID))
		if _, err := os.Stat(s.artifact(cur.SHA256)); err == nil && string(old) == res.fingerprint && !force {
			res.status = "skipped"
			return res, nil
		}
	}

	wl := map[string]struct{}{}
	for _, n := range al.Domains {
		wl[n] = struct{}{}
	}
	allowIPs := make([]netip.Prefix, 0, len(al.IPs))
	for _, v := range al.IPs {
		if p, err := parseAllowIP(v); err == nil {
			allowIPs = append(allowIPs, p)
		}
	}
	var inputs []input
	trustPositif := false
	for _, src := range srcs {
		switch {
		case src.Kind == "whitelist":
			for line := range strings.Lines(src.Content) {
				if n, ok := normalizeDomain(stripLine(line)); ok {
					wl[n] = struct{}{}
				}
			}
		case isURLKind(src.Kind):
			trustPositif = trustPositif || src.Kind == "trustpositif_domains"
			path := s.sourcePath(src.ID)
			if _, err := os.Stat(path); err != nil {
				continue // never downloaded successfully; its last_status says why
			}
			inputs = append(inputs, input{src.ID, src.Kind, func() (io.ReadCloser, error) { return os.Open(path) }})
		default:
			content := src.Content
			inputs = append(inputs, input{src.ID, src.Kind, func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(content)), nil
			}})
		}
	}

	f, err := os.CreateTemp(s.dir, ".build-*.tmp")
	if err != nil {
		return res, err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name()) // no-op after the rename
	}()
	st, err := writeCDB(ctx, f, inputs, wl, allowIPs)
	res.domains, res.ips, res.whitelisted, res.skipped, res.entries = st.domains, st.ips, st.whitelisted, st.skipped, st.entries
	if err != nil {
		return res, err
	}
	if trustPositif && res.domains < minDomains {
		return res, fmt.Errorf("sanity floor: only %d domains (< %d); keeping the previous build", res.domains, minDomains)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return res, err
	}
	h := sha256.New()
	if res.size, err = io.Copy(h, f); err != nil {
		return res, err
	}
	res.sha = hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(f.Name(), s.artifact(res.sha)); err != nil {
		return res, err
	}
	syncDir(s.dir)
	if cur != nil && cur.SHA256 != res.sha {
		// Informational only: a missing/pruned previous artifact must not fail the build.
		if d, err := diffCDB(s.artifact(cur.SHA256), s.artifact(res.sha)); err != nil {
			s.d.Log.Warn("blocklist diff", "prev", cur.SHA256, "err", err)
		} else {
			res.added, res.removed, res.changes = d.added, d.removed, d.names
		}
	}
	res.status = "ok"
	return res, nil
}

type input struct {
	id, kind string
	open     func() (io.ReadCloser, error)
}

type stats struct {
	domains, ips, whitelisted, skipped int
	entries                            map[string]int
}

// writeCDB streams every input line by line into a CDB at f and fsyncs it. Duplicates
// are written as-is (dnsdist uses the first match), so memory is the writer's 8-byte
// index entry per key, never the keys themselves.
func writeCDB(ctx context.Context, f *os.File, inputs []input, wl map[string]struct{}, allowIPs []netip.Prefix) (st stats, err error) {
	st.entries = map[string]int{}
	// Hide f's Close so Writer.Close only finalizes; we fsync and close ourselves.
	w, err := cdb.NewWriter(struct{ io.WriteSeeker }{f}, nil)
	if err != nil {
		return st, err
	}
	for _, in := range inputs {
		rc, err := in.open()
		if err != nil {
			return st, err
		}
		n := 0
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := stripLine(sc.Text())
			if line == "" {
				continue
			}
			if n&0xffff == 0 && ctx.Err() != nil {
				rc.Close()
				return st, ctx.Err()
			}
			switch {
			case isDomainKind(in.kind):
				name, ok := normalizeDomain(line)
				if !ok {
					st.skipped++
				} else if whitelisted(wl, name) {
					st.whitelisted++
				} else if err = w.Put(keys.DomainKey(name), nil); err == nil {
					st.domains++
					n++
				}
			case isIPKind(in.kind):
				if !eachIPv4(line, func(a netip.Addr) {
					if err != nil {
						return
					}
					if _, ok := wl[a.String()]; ok || slices.ContainsFunc(allowIPs, func(p netip.Prefix) bool { return p.Contains(a) }) {
						st.whitelisted++
					} else if err = w.Put(keys.IPv4Key(a), nil); err == nil {
						st.ips++
						n++
					}
				}) {
					st.skipped++
				}
			}
			if err != nil {
				rc.Close()
				return st, err
			}
		}
		rc.Close()
		if err := sc.Err(); err != nil {
			return st, fmt.Errorf("source %s: %w", in.id, err)
		}
		st.entries[in.id] = n
	}
	if err := w.Close(); err != nil {
		return st, err
	}
	return st, f.Sync()
}

func (s *Service) saveChanges(ctx context.Context, id int64, changes map[string]bool) error {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(changes))
	for name, added := range changes {
		rows = append(rows, []any{id, name, added})
	}
	_, err := s.d.Pool.CopyFrom(ctx, pgx.Identifier{"blocklist_changes"}, []string{"build_id", "name", "added"}, pgx.CopyFromRows(rows))
	return err
}

// fetch downloads a URL source to its raw file. changed=false on 304 (the previous
// download stays and is still built from). force skips the conditional request.
// The status records size, time, throughput and streams so download speed can be compared.
func (s *Service) fetch(ctx context.Context, src source, force bool) (changed bool, err error) {
	path := s.sourcePath(src.ID)
	start := time.Now()
	var n int64
	streams := 1
	same := false // a 200 whose body equals the file we already hold
	defer func() {
		took := time.Since(start)
		status := fmt.Sprintf("not modified (%d ms)", took.Milliseconds())
		if err != nil {
			status = "error: " + err.Error()
		} else if changed || same {
			status = fetchStatus(n, took, streams)
			if same {
				status += ", content unchanged"
			}
			s.d.Log.Info("blocklist fetch", "source", src.ID, "bytes", n, "seconds", took.Seconds(),
				"mb_per_s", float64(n)/1e6/took.Seconds(), "streams", streams)
		}
		_, _ = s.d.Pool.Exec(context.WithoutCancel(ctx),
			"UPDATE blocklist_sources SET last_fetch_at = now(), last_status = $2 WHERE id = $1", src.ID, status)
	}()
	hdr := map[string]string{}
	_, statErr := os.Stat(path)
	haveFile := statErr == nil
	if haveFile && !force { // conditional only when we still hold the copy a 304 refers to
		if src.ETag != "" {
			hdr["If-None-Match"] = src.ETag
		}
		if src.LastModified != "" {
			hdr["If-Modified-Since"] = src.LastModified
		}
	}
	resp, err := s.get(ctx, src.URL, hdr)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && haveFile:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := path + ".tmp"
	var etag, lastMod string
	n, streams, etag, lastMod, err = s.download(ctx, resp, src.URL, tmp, s.d.Settings.Get().BlocklistDownloadSegments)
	if err == nil && haveFile {
		same, err = sameFile(tmp, path)
	}
	if err == nil && !same {
		// Keeping the old file (and its mtime) on identical content leaves the fingerprint
		// alone, so the build is skipped instead of rebuilding the same CDB.
		err = os.Rename(tmp, path)
	}
	if same {
		os.Remove(tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	_, err = s.d.Pool.Exec(ctx, "UPDATE blocklist_sources SET etag = $2, last_modified = $3 WHERE id = $1",
		src.ID, etag, lastMod)
	return err == nil && !same, err
}

// sameFile reports whether a and b have identical contents.
func sameFile(a, b string) (bool, error) {
	fa, err := os.Open(a)
	if err != nil {
		return false, err
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false, err
	}
	defer fb.Close()
	sa, err := fa.Stat()
	if err != nil {
		return false, err
	}
	if sb, err := fb.Stat(); err != nil || sa.Size() != sb.Size() {
		return false, err
	}
	bufA, bufB := make([]byte, 1<<20), make([]byte, 1<<20)
	for {
		na, errA := io.ReadFull(fa, bufA)
		nb, errB := io.ReadFull(fb, bufB)
		if !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false, nil
		}
		if errA == io.EOF || errA == io.ErrUnexpectedEOF { // equal sizes: b ends here too
			return true, nil
		}
		if err := cmp.Or(errA, errB); err != nil {
			return false, err
		}
	}
}

// fingerprint identifies the build inputs: raw files by size+mtime (a 200 rewrites
// the file), manual lists by content.
func (s *Service) fingerprint(srcs []source, allowVersion string) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%s floor=%d allow=%s\n", builderVersion, minDomains, allowVersion)
	for _, src := range srcs {
		fmt.Fprintf(h, "%s %s ", src.ID, src.Kind)
		if isURLKind(src.Kind) {
			if st, err := os.Stat(s.sourcePath(src.ID)); err == nil {
				fmt.Fprintf(h, "%d %d", st.Size(), st.ModTime().UnixNano())
			}
		} else {
			fmt.Fprintf(h, "%d:%s", len(src.Content), src.Content)
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fingerprintPath is where a scope's last built fingerprint is kept; an empty profileID is
// the global scope. The file lets an unchanged scope skip rebuilding.
func (s *Service) fingerprintPath(profileID string) string {
	if profileID == "" {
		return filepath.Join(s.dir, "inputs.fp")
	}
	return filepath.Join(s.dir, "inputs-"+profileID+".fp")
}

// prune keeps the artifacts still referenced by any scope: the last keepBuilds distinct ok
// builds per scope, and the newest ok build of every scope (a profile's fallback is the
// global artifact, which must outlive the global build's own keep window). The second
// branch is not redundant: the first ranks each artifact by max(finished_at) and max(id)
// taken independently, so with equal finish times the artifact Current() serves can rank
// below keepBuilds; the DISTINCT ON branch keeps it whatever the ranking says.
func (s *Service) prune(ctx context.Context) {
	rows, _ := s.d.Pool.Query(ctx, `
		(SELECT sha256 FROM (
			SELECT sha256, row_number() OVER (PARTITION BY profile_id ORDER BY max(finished_at) DESC, max(id) DESC) AS rn
			FROM blocklist_builds WHERE status = 'ok' GROUP BY profile_id, sha256
		) t WHERE rn <= $1)
		UNION
		(SELECT DISTINCT ON (profile_id) sha256 FROM blocklist_builds
			WHERE status = 'ok' ORDER BY profile_id, finished_at DESC, id DESC)`, keepBuilds)
	keep, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		s.d.Log.Error("blocklist prune", "err", err)
		return
	}
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		name := e.Name()
		stale := strings.HasPrefix(name, ".build-") // leftovers of a crashed build (we hold the lock)
		if sha, ok := strings.CutSuffix(name, ".cdb"); ok {
			stale = !slices.Contains(keep, sha)
		}
		if stale && e.Type()&fs.ModeType == 0 {
			os.Remove(filepath.Join(s.dir, name))
		}
	}
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
