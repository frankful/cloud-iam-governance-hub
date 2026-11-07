package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"
)

const migrationAdvisoryLockKey = 74219001

// ApplyAll applies every pending embedded migration, recording each version in
// the schema_migrations ledger. It is idempotent and safe to call on every
// startup: already-applied versions are skipped.
//
// All work runs on a single dedicated connection: the pg_advisory_lock that
// serializes competing instances is session-scoped, and a *sql.DB pool would
// otherwise apply the lock on one connection while migrating on another.
//
// The 0001 guard refuses to apply the initial schema over an untracked
// hand-built database, keeping the failure loud instead of silently merging
// two schema histories.
func ApplyAll(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	if db == nil {
		return errors.New("database handle must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx,
		fmt.Sprintf(`SELECT pg_advisory_lock(%d)`, migrationAdvisoryLockKey),
	); err != nil {
		return fmt.Errorf("lock database migrations: %w", err)
	}
	// conn.Close() ends the session and drops the advisory lock anyway, but an
	// explicit unlock keeps the invariant visible. The unlock runs on the same
	// session with its own context because the caller's context may already be
	// cancelled by the time this deferred call executes.
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlockCtx,
			fmt.Sprintf(`SELECT pg_advisory_unlock(%d)`, migrationAdvisoryLockKey))
	}()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(128) PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	migrationNames, err := fs.Glob(Files, "*.up.sql")
	if err != nil {
		return fmt.Errorf("list embedded migrations: %w", err)
	}
	sort.Strings(migrationNames)
	for _, fileName := range migrationNames {
		version := strings.TrimSuffix(fileName, ".up.sql")
		var applied bool
		if err := conn.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`,
			version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			logger.Info("migration already applied", "version", version)
			continue
		}

		if version == "0001_initial_schema" {
			var hasExistingSchema bool
			if err := conn.QueryRowContext(ctx, `SELECT
				to_regclass('public.aws_organization') IS NOT NULL OR
				to_regclass('public.aws_account') IS NOT NULL OR
				to_regclass('public.iam_ticket') IS NOT NULL`,
			).Scan(&hasExistingSchema); err != nil {
				return fmt.Errorf("check for untracked database schema: %w", err)
			}
			if hasExistingSchema {
				return errors.New("database contains application tables but has no migration record; refusing to apply initial migration over existing schema")
			}
		}

		migrationSQL, err := Files.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		transaction, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := transaction.ExecContext(ctx, string(migrationSQL)); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("execute migration %s: %w", version, err)
		}
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`,
			version,
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
		logger.Info("migration applied", "version", version)
	}
	return nil
}
