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
