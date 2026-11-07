package migrations

import "embed"

// Files embeds the versioned SQL migrations for the migration command.
//
//go:embed *.up.sql
var Files embed.FS
