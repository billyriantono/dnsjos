// Package dbtest gives DB tests a fresh, migrated database of their own.
package dbtest

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/db"
)

// New skips the test unless DNSJOS_TEST_DATABASE_URL is set, then (re)creates the
// database "<that db>_<suffix>", migrates it and returns a pool closed at test end.
// Use a distinct suffix per package: packages run their tests in parallel.
func New(t testing.TB, suffix string) *pgxpool.Pool {
	t.Helper()
	raw := os.Getenv("DNSJOS_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("DNSJOS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	name := pgx.Identifier{admin.Config().Database + "_" + suffix}
	for _, q := range []string{"DROP DATABASE IF EXISTS " + name.Sanitize() + " WITH (FORCE)", "CREATE DATABASE " + name.Sanitize()} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name[0]
	pool, err := db.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}
