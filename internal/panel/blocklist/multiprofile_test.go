package blocklist

import (
	"context"
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A source shared by two profiles is built into both, never into a third: the join table
// lets one source feed several profile builds (the feature this table exists for).
func TestSharedSourceBuildsIntoEveryProfile(t *testing.T) {
	s, pool := newProfileSvc(t)
	a, b, c := newProfile(t, pool, "A"), newProfile(t, pool, "B"), newProfile(t, pool, "C")

	addSharedSource(t, pool, "shared", "manual_domains", "shared.com", a, b)
	addSharedSource(t, pool, "only-c", "manual_domains", "c.com", c)

	ab := buildScope(t, s, a)
	bb := buildScope(t, s, b)
	cb := buildScope(t, s, c)

	for _, bld := range []api.BlocklistBuild{ab, bb} {
		if !blockedIn(t, s, bld, "shared.com") {
			t.Errorf("build %d missing the shared source", bld.ID)
		}
		if blockedIn(t, s, bld, "c.com") {
			t.Errorf("build %d leaked a source scoped to C", bld.ID)
		}
	}
	if !blockedIn(t, s, cb, "c.com") || blockedIn(t, s, cb, "shared.com") {
		t.Error("C's build has the wrong source set")
	}
}

// A source with no join rows is global: every scope builds it, including a profile that
// also has its own sources.
func TestSourceWithNoJoinRowsIsGlobal(t *testing.T) {
	s, pool := newProfileSvc(t)
	a := newProfile(t, pool, "A")
	addSharedSource(t, pool, "global", "manual_domains", "global.com") // no profiles
	addSharedSource(t, pool, "a", "manual_domains", "a.com", a)

	ab := buildScope(t, s, a)
	gb := buildScope(t, s, "")
	if !blockedIn(t, s, ab, "global.com") || blockedIn(t, s, ab, "a.com") == blockedIn(t, s, gb, "a.com") {
		t.Fatal("global source leaked or A source hidden")
	}
	if !blockedIn(t, s, gb, "global.com") {
		t.Fatal("global build missing the shared source")
	}
}

// The sources listing reports the full profile set (ids + names) and keeps ProfileID as the
// first profile, so both the multi-select and the legacy single-profile view stay correct.
func TestListSourcesReportsProfileSet(t *testing.T) {
	_, pool, call := newHandlerSvc(t)
	a, b := newProfile(t, pool, "A"), newProfile(t, pool, "B")
	id := addSharedSource(t, pool, "shared", "manual_domains", "shared.com", a, b)

	var list api.List[api.BlocklistSource]
	call("GET", "/api/v1/blocklist/sources", "", 200, &list)
	if list.Total != 1 {
		t.Fatalf("total = %d, want 1", list.Total)
	}
	got := list.Items[0]
	if got.ID != id || len(got.ProfileIDs) != 2 {
		t.Fatalf("profile_ids = %v, want 2 entries", got.ProfileIDs)
	}
	if !contains(got.ProfileIDs, a) || !contains(got.ProfileIDs, b) {
		t.Fatalf("profile_ids = %v, want {%s,%s}", got.ProfileIDs, a, b)
	}
	if len(got.ProfileNames) != 2 {
		t.Fatalf("profile_names = %v", got.ProfileNames)
	}
	if got.ProfileID != got.ProfileIDs[0] || got.ProfileName != got.ProfileNames[0] {
		t.Fatalf("first-profile mirror %q/%q != %v/%v", got.ProfileID, got.ProfileName, got.ProfileIDs, got.ProfileNames)
	}

	// Each profile's scoped listing sees the shared source.
	var scoped api.List[api.BlocklistSource]
	call("GET", "/api/v1/blocklist/sources?profile_id="+a, "", 200, &scoped)
	if scoped.Total != 1 || scoped.Items[0].ID != id {
		t.Fatalf("A listing = %+v", scoped)
	}
}

// Creating a source with profile_ids writes one join row per profile; patching replaces the
// whole set (add and remove), and an empty set returns it to global.
func TestSourceProfileSetCRUD(t *testing.T) {
	_, pool, call := newHandlerSvc(t)
	a, b, c := newProfile(t, pool, "A"), newProfile(t, pool, "B"), newProfile(t, pool, "C")

	var src api.BlocklistSource
	call("POST", "/api/v1/blocklist/sources",
		`{"name":"shared","kind":"manual_domains","content":"s.com","profile_ids":["`+a+`","`+b+`"]}`, 201, &src)
	if len(src.ProfileIDs) != 2 || !contains(src.ProfileIDs, a) || !contains(src.ProfileIDs, b) {
		t.Fatalf("created profile_ids = %v", src.ProfileIDs)
	}
	if rows := joinCount(t, pool, src.ID); rows != 2 {
		t.Fatalf("join rows after create = %d, want 2", rows)
	}

	// Replace {A,B} with {B,C}: A removed, C added, B kept.
	call("PATCH", "/api/v1/blocklist/sources/"+src.ID,
		`{"profile_ids":["`+b+`","`+c+`"]}`, 200, &src)
	if len(src.ProfileIDs) != 2 || !contains(src.ProfileIDs, b) || !contains(src.ProfileIDs, c) || contains(src.ProfileIDs, a) {
		t.Fatalf("patched profile_ids = %v", src.ProfileIDs)
	}
	if rows := joinCount(t, pool, src.ID); rows != 2 {
		t.Fatalf("join rows after patch = %d, want 2", rows)
	}

	// Empty set = global: no join rows, and the legacy column is cleared too.
	call("PATCH", "/api/v1/blocklist/sources/"+src.ID, `{"profile_ids":[]}`, 200, &src)
	if len(src.ProfileIDs) != 0 || src.ProfileID != "" {
		t.Fatalf("global source = %+v", src)
	}
	if rows := joinCount(t, pool, src.ID); rows != 0 {
		t.Fatalf("join rows after global = %d, want 0", rows)
	}
	var legacy string
	if err := pool.QueryRow(context.Background(),
		`SELECT coalesce(profile_id::text, '') FROM blocklist_sources WHERE id = $1`, src.ID).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != "" {
		t.Fatalf("legacy profile_id = %q, want empty", legacy)
	}
}

// The legacy single profile_id still works on create and patch (folding into the set), so
// an older client that never learned profile_ids keeps behaving.
func TestSourceLegacyProfileIDFoldsIn(t *testing.T) {
	_, pool, call := newHandlerSvc(t)
	a := newProfile(t, pool, "A")

	var src api.BlocklistSource
	call("POST", "/api/v1/blocklist/sources",
		`{"name":"legacy","kind":"manual_domains","content":"l.com","profile_id":"`+a+`"}`, 201, &src)
	if len(src.ProfileIDs) != 1 || src.ProfileIDs[0] != a || src.ProfileID != a {
		t.Fatalf("create folded to %v (profile_id %q)", src.ProfileIDs, src.ProfileID)
	}
	if rows := joinCount(t, pool, src.ID); rows != 1 {
		t.Fatalf("join rows = %d, want 1", rows)
	}

	// profile_ids wins over a stale profile_id in the same patch body.
	b := newProfile(t, pool, "B")
	call("PATCH", "/api/v1/blocklist/sources/"+src.ID,
		`{"profile_id":"`+a+`","profile_ids":["`+b+`"]}`, 200, &src)
	if len(src.ProfileIDs) != 1 || src.ProfileIDs[0] != b {
		t.Fatalf("patch kept %v, want [%s]", src.ProfileIDs, b)
	}
}

// An unknown profile id in the set is a 400 (validated up front), and the source keeps its
// previous set untouched when the profile set is invalid.
func TestSourceProfileSetRejectsUnknown(t *testing.T) {
	_, pool, call := newHandlerSvc(t)
	a := newProfile(t, pool, "A")
	const missing = "00000000-0000-0000-0000-000000000000"

	var src api.BlocklistSource
	call("POST", "/api/v1/blocklist/sources",
		`{"name":"s","kind":"manual_domains","content":"s.com","profile_ids":["`+missing+`"]}`, 400, nil)
	call("POST", "/api/v1/blocklist/sources",
		`{"name":"s","kind":"manual_domains","content":"s.com","profile_ids":["`+a+`"]}`, 201, &src)

	call("PATCH", "/api/v1/blocklist/sources/"+src.ID, `{"profile_ids":["`+missing+`"]}`, 400, nil)
	if rows := joinCount(t, pool, src.ID); rows != 1 {
		t.Fatalf("failed patch changed the set: %d join rows", rows)
	}
	var cur api.BlocklistSource
	call("PATCH", "/api/v1/blocklist/sources/"+src.ID, `{"name":"s2"}`, 200, &cur)
	if len(cur.ProfileIDs) != 1 || cur.ProfileIDs[0] != a {
		t.Fatalf("set after failed patch = %v", cur.ProfileIDs)
	}
}

// joinCount reads the number of join rows for a source directly from the DB.
func joinCount(t *testing.T, pool *pgxpool.Pool, sourceID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM blocklist_source_profiles WHERE source_id = $1`, sourceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
