package db

import (
	"context"
	neturl "net/url"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestMigrate(t *testing.T) {
	url := os.Getenv("DNSJOS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("DNSJOS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	// Migrate a throwaway database so other packages' tests on the shared DB are unaffected.
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	name := admin.Config().Database + "_migrate"
	for _, q := range []string{"DROP DATABASE IF EXISTS " + name + " WITH (FORCE)", "CREATE DATABASE " + name} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := neturl.Parse(url)
	u.Path = "/" + name
	pool, err := Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Two concurrent runners: the advisory lock must make exactly one apply 0001.
	var wg sync.WaitGroup
	results := make([][]string, 2)
	for i := range results {
		wg.Go(func() {
			var err error
			if results[i], err = Migrate(ctx, pool); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if (len(results[0]) == 0) == (len(results[1]) == 0) || !slices.Contains(append(results[0], results[1]...), "0001_init") {
		t.Fatalf("applied %v / %v, want exactly one runner to apply everything", results[0], results[1])
	}

	again, err := Migrate(ctx, pool)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run: %v %v", again, err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM config_profiles WHERE name='default'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("seed: %d %v", n, err)
	}
}

// TestMigrateDefaultGroupID covers installs that carry the blocklist_groups feature (from
// an earlier branch): it adds a NOT NULL group_id (no default) to blocklist_sources and
// blocklist_builds, so every insert that does not name a group fails with SQLSTATE 23502
// (scheduled builds and RPZ master creation 500'd in production). 0016_default_group_id
// must pin the default group as the column default.
func TestMigrateDefaultGroupID(t *testing.T) {
	url := os.Getenv("DNSJOS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("DNSJOS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	name := admin.Config().Database + "_groups"
	for _, q := range []string{"DROP DATABASE IF EXISTS " + name + " WITH (FORCE)", "CREATE DATABASE " + name} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := neturl.Parse(url)
	u.Path = "/" + name
	pool, err := Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// A fresh install from this tree has no groups table: 0016 must be a no-op.
	if _, err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Recreate the groups feature on top of the migrated schema and let the migration run
	// again, exactly as on an install that already had the feature.
	for _, q := range []string{
		`CREATE TABLE blocklist_groups (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			name text NOT NULL,
			description text NOT NULL DEFAULT '',
			is_default boolean NOT NULL DEFAULT false,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE UNIQUE INDEX blocklist_groups_default_idx ON blocklist_groups (is_default) WHERE is_default`,
		`INSERT INTO blocklist_groups (name, is_default) VALUES ('default', true)`,
		`ALTER TABLE blocklist_sources ADD COLUMN group_id uuid REFERENCES blocklist_groups(id) ON DELETE CASCADE`,
		`UPDATE blocklist_sources SET group_id = (SELECT id FROM blocklist_groups WHERE is_default)`,
		`ALTER TABLE blocklist_sources ALTER COLUMN group_id SET NOT NULL`,
		`ALTER TABLE blocklist_builds ADD COLUMN group_id uuid REFERENCES blocklist_groups(id) ON DELETE CASCADE`,
		`ALTER TABLE blocklist_builds ALTER COLUMN group_id SET NOT NULL`,
		`DELETE FROM schema_migrations WHERE version = '0016_default_group_id'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%v: %v", q, err)
		}
	}
	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(applied, "0016_default_group_id") {
		t.Fatalf("applied %v, want 0016_default_group_id", applied)
	}

	var gid string
	if err := pool.QueryRow(ctx, `SELECT id FROM blocklist_groups WHERE is_default`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	// The scheduled build and the RPZ master create path both insert without naming a group.
	var buildGroup string
	if err := pool.QueryRow(ctx,
		`INSERT INTO blocklist_builds (trigger) VALUES ('manual') RETURNING group_id`).Scan(&buildGroup); err != nil {
		t.Fatalf("insert build: %v", err)
	}
	var srcGroup string
	if err := pool.QueryRow(ctx,
		`INSERT INTO blocklist_sources (name, kind) VALUES ('probe', 'url_domains') RETURNING group_id`).Scan(&srcGroup); err != nil {
		t.Fatalf("insert source: %v", err)
	}
	if srcGroup != gid || buildGroup != gid {
		t.Fatalf("group_id = source %s / build %s, want %s", srcGroup, buildGroup, gid)
	}
}
