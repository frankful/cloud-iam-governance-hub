package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"

	migrationfiles "github.com/frankful/cloud-iam-governance-hub/migrations"
)

const migrationTimeout = 5 * time.Minute

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("load .env", "error", err)
		os.Exit(1)
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		logger.Error("DATABASE_URL must be configured")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer cancel()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		logger.Error("open PostgreSQL connection", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	// Same engine as the API's startup auto-migration; kept as a standalone
	// CLI for manual runs (CI jobs, one-off repairs, air-gapped upgrades).
	if err := migrationfiles.ApplyAll(ctx, database, logger); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
}
