// Package db owns the pgx pool and the migration runner.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/migrations"
)

// Querier is satisfied by *pgxpool.Pool, *pgxpool.Conn and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Connect opens a small pool: the panel is mostly idle and must stay lean.
func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	if !strings.Contains(url, "pool_max_conns") {
		cfg.MaxConns = 10
	}
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	return pool, nil
}

const migrateLockID = 0x646e736a6f73 // "dnsjos"

// Migrate applies every not-yet-applied migrations/*.up.sql in lexical order, each in
// its own transaction. A session advisory lock serialises concurrent panels.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (applied []string, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateLockID); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrateLockID)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	rows, _ := conn.Query(ctx, "SELECT version FROM schema_migrations")
	done, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	files, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	for _, f := range files {
		version := strings.TrimSuffix(f, ".up.sql")
		if slices.Contains(done, version) {
			continue
		}
		sql, err := fs.ReadFile(migrations.FS, f)
		if err != nil {
			return applied, err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", f, err)
		}
		applied = append(applied, version)
	}
	return applied, nil
}

// LockUpgrades takes the transaction-scoped lock that serialises everything that starts a
// dnsdist/agent upgrade (upgrade runs and manual upgrade commands), so the "is anything
// upgrading?" check and the insert that starts one cannot interleave (SPEC §18: never more
// than one node upgrading at a time).
func LockUpgrades(ctx context.Context, q Querier) error {
	_, err := q.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('dnsjos.upgrades'))")
	return err
}

// MaxBatchKey caps the agents' Idempotency-Key header.
const MaxBatchKey = 255

// ClaimBatch records an agent batch's idempotency key in the caller's transaction, so the
// key commits together with the batch's data. false = already committed: skip the batch.
// An empty key (older agents) always claims.
func ClaimBatch(ctx context.Context, q Querier, nodeID, key string) (bool, error) {
	if key == "" {
		return true, nil
	}
	tag, err := q.Exec(ctx, "INSERT INTO ingested_batches (node_id, batch_key) VALUES ($1, $2) ON CONFLICT DO NOTHING", nodeID, key)
	return tag.RowsAffected() == 1, err
}

// Postgres error helpers used to map DB errors to HTTP statuses.

func IsUniqueViolation(err error) bool { return pgCode(err) == "23505" }

func IsForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

// IsInvalidInput is true for malformed values such as a bad UUID in a path.
func IsInvalidInput(err error) bool { return pgCode(err) == "22P02" }

func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
