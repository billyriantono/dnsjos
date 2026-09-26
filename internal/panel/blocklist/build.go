package blocklist

import (
	"bufio"
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
	mu     sync.Mutex // single-flight build
}

func newService(d *app.Deps) *Service {
	return &Service{d: d, dir: filepath.Join(d.Cfg.DataDir, "blocklist"), client: &http.Client{Timeout: 120 * time.Second}}
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
func isDomainKind(k string) bool { return strings.HasSuffix(k, "_domains") }
func isIPKind(k string) bool     { return strings.HasSuffix(k, "_ips") }

const buildCols = "id, started_at, finished_at, status, trigger, domains, ips, whitelisted, skipped, size_bytes, sha256, error"

func scanBuild(row pgx.Row) (api.BlocklistBuild, error) {
	var b api.BlocklistBuild
	err := row.Scan(&b.ID, &b.StartedAt, &b.FinishedAt, &b.Status, &b.Trigger, &b.Domains, &b.IPs,
		&b.Whitelisted, &b.Skipped, &b.SizeBytes, &b.SHA256, &b.Error)
	return b, err
}

// Current returns the newest ok build, or nil when there is none.
func Current(ctx context.Context, q db.Querier) (*api.BlocklistBuild, error) {
	b, err := scanBuild(q.QueryRow(ctx, "SELECT "+buildCols+
		" FROM blocklist_builds WHERE status = 'ok' ORDER BY finished_at DESC LIMIT 1"))
	if db.IsNotFound(err) {
		return nil, nil
	}
	return &b, err
}

// Start runs a build in the background and returns its running row; errBusy when
// a build is already in progress. force re-downloads every URL source (no
// conditional request) and rebuilds even when the inputs are unchanged.
func (s *Service) Start(trigger string, force bool) (api.BlocklistBuild, error) {
	if !s.mu.TryLock() {
		return api.BlocklistBuild{}, errBusy
	}
	b, err := s.insert(context.Background(), trigger)
	if err != nil {
		s.mu.Unlock()
		return b, err
	}
	go func() {
		defer s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		if _, err := s.execute(ctx, b.ID, force); err != nil {
			s.d.Log.Error("blocklist build", "id", b.ID, "err", err)
		}
	}()
	return b, nil
}

// tick is the scheduled job: builds once the configured interval has passed.
func (s *Service) tick(ctx context.Context) error {
	var last *time.Time
	if err := s.d.Pool.QueryRow(ctx, "SELECT max(started_at) FROM blocklist_builds").Scan(&last); err != nil {
		return err
	}
	every := time.Duration(s.d.Settings.Get().BlocklistBuildIntervalMinutes) * time.Minute
	if last != nil && time.Since(*last) < every {
		return nil
	}
	if !s.mu.TryLock() {
		return nil
	}
	defer s.mu.Unlock()
	b, err := s.insert(ctx, "schedule")
	if err != nil {
		return err
	}
	_, err = s.execute(ctx, b.ID, false)
	return err
}

func (s *Service) insert(ctx context.Context, trigger string) (api.BlocklistBuild, error) {
	return scanBuild(s.d.Pool.QueryRow(ctx,
		"INSERT INTO blocklist_builds (trigger) VALUES ($1) RETURNING "+buildCols, trigger))
}

type result struct {
	status                             string // ok | skipped
	domains, ips, whitelisted, skipped int
	size                               int64
	sha                                string
	entries                            map[string]int // per source id
	fingerprint                        string
}

// execute runs build and records its outcome on row id. Caller holds s.mu.
func (s *Service) execute(ctx context.Context, id int64, force bool) (api.BlocklistBuild, error) {
	res, buildErr := s.build(ctx, force)
	status, msg := res.status, ""
	if buildErr != nil {
		status, msg = "failed", buildErr.Error()
	}
	// A cancelled ctx must still be able to close the row.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	b, err := scanBuild(s.d.Pool.QueryRow(wctx, `UPDATE blocklist_builds SET finished_at = now(), status = $2,
		domains = $3, ips = $4, whitelisted = $5, skipped = $6, size_bytes = $7, sha256 = $8, error = $9
		WHERE id = $1 RETURNING `+buildCols,
		id, status, res.domains, res.ips, res.whitelisted, res.skipped, res.size, res.sha, msg))
	if err != nil {
		return b, err
	}
	if status == "ok" {
		for sid, n := range res.entries {
			if _, err := s.d.Pool.Exec(wctx, "UPDATE blocklist_sources SET entries = $2 WHERE id = $1", sid, n); err != nil {
				return b, err
			}
		}
		if err := os.WriteFile(filepath.Join(s.dir, "inputs.fp"), []byte(res.fingerprint), 0o644); err != nil {
			return b, err
		}
		s.prune(wctx)
	}
	debug.FreeOSMemory() // the CDB writer's index is transient; hand it back to the OS
	return b, buildErr
}

func (s *Service) build(ctx context.Context, force bool) (res result, err error) {
	if err := os.MkdirAll(filepath.Join(s.dir, "sources"), 0o755); err != nil {
		return res, err
	}
	rows, _ := s.d.Pool.Query(ctx, `SELECT id, kind, url, content, etag, last_modified
		FROM blocklist_sources WHERE enabled ORDER BY id`)
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
	if cur, err := Current(ctx, s.d.Pool); err != nil {
		return res, err
	} else if cur != nil {
		old, _ := os.ReadFile(filepath.Join(s.dir, "inputs.fp"))
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

// fetch downloads a URL source to its raw file. changed=false on 304 (the previous
// download stays and is still built from). force skips the conditional request.
// The status records size, time, throughput and streams so download speed can be compared.
func (s *Service) fetch(ctx context.Context, src source, force bool) (changed bool, err error) {
	path := s.sourcePath(src.ID)
	start := time.Now()
	var n int64
	streams := 1
	defer func() {
		took := time.Since(start)
		status := fmt.Sprintf("not modified (%d ms)", took.Milliseconds())
		if err != nil {
			status = "error: " + err.Error()
		} else if changed {
			status = fetchStatus(n, took, streams)
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
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	_, err = s.d.Pool.Exec(ctx, "UPDATE blocklist_sources SET etag = $2, last_modified = $3 WHERE id = $1",
		src.ID, etag, lastMod)
	return err == nil, err
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

// prune keeps the artifacts of the last keepBuilds distinct ok builds.
func (s *Service) prune(ctx context.Context) {
	rows, _ := s.d.Pool.Query(ctx, `SELECT sha256 FROM blocklist_builds WHERE status = 'ok'
		GROUP BY sha256 ORDER BY max(finished_at) DESC LIMIT $1`, keepBuilds)
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
