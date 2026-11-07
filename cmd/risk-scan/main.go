package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		fail(fmt.Errorf("load .env: %w", err))
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fail(errors.New("DATABASE_URL must be configured"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		fail(fmt.Errorf("open PostgreSQL connection: %w", err))
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		fail(fmt.Errorf("connect to PostgreSQL: %w", err))
	}
	scanner, err := service.NewIAMRiskScanner(database)
	if err != nil {
		fail(fmt.Errorf("create IAM risk scanner: %w", err))
	}
	summary, err := scanner.Scan(ctx)
	if err != nil {
		fail(fmt.Errorf("scan persisted IAM assets: %w", err))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		fail(fmt.Errorf("write risk scan summary: %w", err))
	}
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
