package blocklist

import (
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/config"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// newProfileSvc spins up a dnsdist-free Service on its own database, with every seeded
// (network) source disabled so a build only sees the manual sources a test inserts.
// It returns the service and the pool.
func newProfileSvc(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.New(t, "blocklist")
	d := &app.Deps{Pool: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Live: app.NewLiveStore(),
		Settings: app.NewSettings(pool, "http://x"), Cfg: config.Config{DataDir: t.TempDir()}}
	if err := d.Settings.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The seeded TrustPositif sources point at the internet; a build must not fetch them.
	exec(t, pool, `UPDATE blocklist_sources SET enabled = false`)
	return newService(d), pool
}

// newProfile creates a config profile and returns its id (the "default" profile from the
// seed is returned as-is).
func newProfile(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO config_profiles (name) VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name = excluded.name RETURNING id::text`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// addSource inserts one enabled manual source in a scope ("" = global) and returns its id.
// A non-empty scope also gets a blocklist_source_profiles row, mirroring what the migration
// backfills and what the CRUD writes, so the join table is the single source of truth.
func addSource(t *testing.T, pool *pgxpool.Pool, name, kind, content, profileID string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO blocklist_sources (name, kind, content, profile_id)
		 VALUES ($1, $2, $3, nullif($4, '')::uuid) RETURNING id::text`,
		name, kind, content, profileID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if profileID != "" {
		if _, err := pool.Exec(ctx,
			`INSERT INTO blocklist_source_profiles (source_id, profile_id) VALUES ($1, $2)`, id, profileID); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// addSharedSource inserts one enabled manual source tied to every profile in profileIDs via
// the join table (an empty list = global) and returns its id.
func addSharedSource(t *testing.T, pool *pgxpool.Pool, name, kind, content string, profileIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO blocklist_sources (name, kind, content) VALUES ($1, $2, $3) RETURNING id::text`,
		name, kind, content).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, pid := range profileIDs {
		if _, err := pool.Exec(ctx, `INSERT INTO blocklist_source_profiles (source_id, profile_id) VALUES ($1, $2)`, id, pid); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// buildScope runs one build for a scope and returns it, failing unless it is ok.
func buildScope(t *testing.T, s *Service, profileID string) api.BlocklistBuild {
	t.Helper()
	b, err := s.insert(context.Background(), "manual", profileID)
	if err != nil {
		t.Fatal(err)
	}
	b, err = s.execute(context.Background(), b.ID, profileID, false)
	if err != nil || b.Status != "ok" {
		t.Fatalf("build %q: %+v err %v", profileID, b, err)
	}
	return b
}

// blockedIn reports whether a name is present in the scope's artifact.
func blockedIn(t *testing.T, s *Service, b api.BlocklistBuild, name string) bool {
	t.Helper()
	res, err := lookupCDB(s.artifact(b.SHA256), name)
	if err != nil {
		t.Fatal(err)
	}
	return res.Blocked
}

func TestDirtySourceForcesRecentScopeBuild(t *testing.T) {
	s, pool := newProfileSvc(t)
	profile := newProfile(t, pool, "dirty-profile")
	sourceID := addSource(t, pool, "dirty", "rpz_domains", "old.example", profile)
	before := buildScope(t, s, profile)

	// The normal interval would skip this recent build; a successful source sync marks
	// the owning scope dirty and must make tick rebuild it immediately.
	exec(t, pool, `UPDATE blocklist_sources SET content = 'new.example' || chr(10) WHERE id = $1`, sourceID)
	s.markDirty(context.Background(), sourceID)
	if err := s.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	cur, err := Current(context.Background(), pool, profile)
	if err != nil || cur == nil || cur.ID == before.ID {
		t.Fatalf("dirty scope current = %+v (before %d), err=%v", cur, before.ID, err)
	}
	if !blockedIn(t, s, *cur, "new.example") || blockedIn(t, s, *cur, "old.example") {
		t.Fatalf("dirty rebuild artifact does not reflect updated source")
	}
}

// A profile build is its own sources plus the global ones, and nothing from another
// profile: A's CDB differs from the global and B builds and carries only A+global names.
func TestProfileBuildScoping(t *testing.T) {
	s, pool := newProfileSvc(t)
	a, b := newProfile(t, pool, "A"), newProfile(t, pool, "B")

	addSource(t, pool, "g", "manual_domains", "global.com", "")
	addSource(t, pool, "a", "manual_domains", "a.com", a)
	addSource(t, pool, "b", "manual_domains", "b.com", b)

	gb := buildScope(t, s, "")
	ab := buildScope(t, s, a)
	bb := buildScope(t, s, b)

	if gb.SHA256 == ab.SHA256 || ab.SHA256 == bb.SHA256 || gb.SHA256 == bb.SHA256 {
		t.Fatalf("scopes share a sha: global %s A %s B %s", gb.SHA256, ab.SHA256, bb.SHA256)
	}
	if gb.Domains != 1 || ab.Domains != 2 || bb.Domains != 2 {
		t.Fatalf("domains: global %d A %d B %d", gb.Domains, ab.Domains, bb.Domains)
	}
	for _, tc := range []struct {
		b    api.BlocklistBuild
		name string
		want bool
	}{
		{ab, "a.com", true}, {ab, "global.com", true}, {ab, "b.com", false},
		{bb, "b.com", true}, {bb, "global.com", true}, {bb, "a.com", false},
		{gb, "global.com", true}, {gb, "a.com", false}, {gb, "b.com", false},
	} {
		if got := blockedIn(t, s, tc.b, tc.name); got != tc.want {
			t.Errorf("build %d: %s blocked = %v, want %v", tc.b.ID, tc.name, got, tc.want)
		}
	}
}

// Current is scoped: it returns A's own build, never global, and nil when A has none.
func TestProfileCurrent(t *testing.T) {
	s, pool := newProfileSvc(t)
	a, b := newProfile(t, pool, "A"), newProfile(t, pool, "B")
	addSource(t, pool, "g", "manual_domains", "global.com", "")

	gb := buildScope(t, s, "")
	ab := buildScope(t, s, a)

	// A has its own build → Current("A") returns it, not the global one.
	cur, err := Current(context.Background(), pool, a)
	if err != nil || cur == nil {
		t.Fatal("no current build for A", err)
	}
	if cur.ID != ab.ID || cur.SHA256 != ab.SHA256 {
		t.Fatalf("Current(A) = %d/%s, want %d/%s", cur.ID, cur.SHA256, ab.ID, ab.SHA256)
	}
	if cur.ID == gb.ID {
		t.Fatal("Current(A) fell back to the global build")
	}
	// The global scope still sees the global build.
	if g, _ := Current(context.Background(), pool, ""); g == nil || g.ID != gb.ID {
		t.Fatalf("Current(global) = %+v, want id %d", g, gb.ID)
	}
	// No fallback at this layer: a scope with no build of its own is nil.
	if c, err := Current(context.Background(), pool, b); err != nil || c != nil {
		t.Fatalf("Current(B with no build) = %+v %v, want nil", c, err)
	}
}

// scopes is the profiles that own an enabled source plus any profile that still has an ok
// build (so a profile whose sources were removed keeps converging). The global build is a
// scope of its own and is only listed while an enabled global source or an ok build exists.
func TestScopes(t *testing.T) {
	s, pool := newProfileSvc(t)
	a, b := newProfile(t, pool, "A"), newProfile(t, pool, "B")
	ctx := context.Background()

	// Every seeded source was disabled: nothing needs building.
	if got := s.scopes(ctx); len(got) != 0 {
		t.Fatalf("scopes with no enabled source = %v, want empty", got)
	}

	addSource(t, pool, "g", "manual_domains", "global.com", "")  // global scope
	addSource(t, pool, "a", "manual_domains", "a.com", a)        // A
	addSource(t, pool, "a2", "manual_domains", "a2.com", a)      // A, second source
	bid := addSource(t, pool, "b", "manual_domains", "b.com", b) // B, its only enabled source

	want := []string{"", a, b} // sorted NULLS FIRST: global, then A, then B
	slices.Sort(want[1:])
	if got := s.scopes(ctx); !slices.Equal(got, want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}

	// B builds with b.com, then loses its only source. The ok build keeps B in the scope
	// list so it still converges: the next build is global-only and drops b.com.
	buildScope(t, s, "")
	bb := buildScope(t, s, b)
	if !blockedIn(t, s, bb, "b.com") {
		t.Fatal("B's own build is missing b.com")
	}
	exec(t, pool, "UPDATE blocklist_sources SET enabled = false WHERE id = $1", bid)
	wantAfter := []string{"", a, b}
	slices.Sort(wantAfter[1:])
	if got := s.scopes(ctx); !slices.Equal(got, wantAfter) {
		t.Fatalf("scopes after B lost its sources = %v, want %v", got, wantAfter)
	}
	nb := buildScope(t, s, b)
	if blockedIn(t, s, nb, "b.com") {
		t.Fatal("B still serves its removed source after converging")
	}
	if !blockedIn(t, s, nb, "global.com") {
		t.Fatal("B's converged build lost the global sources")
	}
}

// Two ok builds in the same scope can share a finished_at timestamp (both are stamped by
// now(), which is the transaction time). The newest one must win deterministically: Current
// and the profiles listing order by finished_at then id, and prune keeps that same row, so
// the artifact Current points at is never the one prune deletes.
func TestCurrentTieBreakIsByID(t *testing.T) {
	s, pool := newProfileSvc(t)
	ctx := context.Background()

	addSource(t, pool, "g", "manual_domains", "g.com", "")
	first := buildScope(t, s, "")
	exec(t, pool, "UPDATE blocklist_sources SET content = 'h.com' WHERE kind = 'manual_domains'")
	second := buildScope(t, s, "")
	if first.SHA256 == second.SHA256 {
		t.Fatal("second build did not change the artifact")
	}
	// Force the tie the tie-break exists for.
	exec(t, pool, "UPDATE blocklist_builds SET finished_at = (SELECT finished_at FROM blocklist_builds WHERE id = $1) WHERE id = $2",
		first.ID, second.ID)

	cur, err := Current(ctx, pool, "")
	if err != nil || cur == nil {
		t.Fatal("Current:", err)
	}
	if cur.ID != second.ID {
		t.Fatalf("Current picked build %d, want the higher id %d", cur.ID, second.ID)
	}
	// prune must keep the artifact Current serves, not the tied older row.
	for i := 0; i < keepBuilds; i++ {
		exec(t, pool, "UPDATE blocklist_sources SET content = $1 WHERE kind = 'manual_domains'",
			[]string{"i1.com", "i2.com", "i3.com"}[i])
		buildScope(t, s, "")
	}
	cur, _ = Current(ctx, pool, "")
	if _, err := os.Stat(s.artifact(cur.SHA256)); err != nil {
		t.Fatalf("prune removed the artifact Current serves: %v", err)
	}
}
