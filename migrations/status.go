package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Pending returns the embedded migrations that the schema_migrations ledger
// does not record yet, sorted ascending. A database without a ledger (never
// migrated, or an old hand-built schema) reports every migration as pending.
//
// This is the authoritative startup gate: hand-written table/column probes
// silently miss newly added columns (0017 did exactly that), while comparing
// the ledger against the embedded files cannot drift.
func Pending(ctx context.Context, db *sql.DB) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle must not be nil")
	}
	var ledgerExists bool
	if err := db.QueryRowContext(ctx,
		`SELECT to_regclass('public.schema_migrations') IS NOT NULL`,
	).Scan(&ledgerExists); err != nil {
		return nil, fmt.Errorf("check migration ledger: %w", err)
	}
	embedded, err := embeddedVersions()
	if err != nil {
		return nil, err
	}
	if !ledgerExists {
		return embedded, nil
	}

	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()
	applied := make(map[string]bool, len(embedded))
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan migration ledger: %w", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration ledger: %w", err)
	}
	return pendingVersions(embedded, applied), nil
}

// embeddedVersions lists the embedded migration versions in apply order.
func embeddedVersions() ([]string, error) {
	names, err := fs.Glob(Files, "*.up.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	versions := make([]string, 0, len(names))
	for _, name := range names {
		versions = append(versions, strings.TrimSuffix(name, ".up.sql"))
	}
	sort.Strings(versions)
	return versions, nil
}

// pendingVersions is the pure diff used by Pending and by unit tests.
func pendingVersions(embedded []string, applied map[string]bool) []string {
	pending := make([]string, 0, len(embedded))
	for _, version := range embedded {
		if !applied[version] {
			pending = append(pending, version)
		}
	}
	return pending
}
