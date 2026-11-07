// Command diagsync directly invokes HandleAWSAccountSyncTask to surface the
// real error that the asynq worker may swallow, and to run a pending sync
// run deterministically during development.
//
// Usage: diagsync <sync_run_id> <config_id>
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: diagsync <sync_run_id> <config_id>")
		os.Exit(2)
	}
	runID, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil || runID <= 0 {
		fmt.Fprintln(os.Stderr, "sync_run_id must be a positive integer")
		os.Exit(2)
	}
	configID, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil || configID <= 0 {
		fmt.Fprintln(os.Stderr, "config_id must be a positive integer")
		os.Exit(2)
	}
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		fmt.Println("load .env:", err)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL must be configured")
		os.Exit(1)
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		fmt.Println("open db:", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		fmt.Println("ping db:", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	assetRepository, err := service.NewSQLAWSAssetRepository(db)
	if err != nil {
		fmt.Println("new asset repository:", err)
		os.Exit(1)
	}
	collector, err := service.NewAWSCollectorService(context.Background(), service.AWSCollectorConfig{
		Region:          envOr("AWS_REGION", "us-east-1"),
		Profile:         os.Getenv("AWS_PROFILE"),
		RoleSessionName: envOr("AWS_ROLE_SESSION_NAME", "iam-governance-collector"),
		ExternalID:      os.Getenv("AWS_EXTERNAL_ID"),
	}, assetRepository, logger)
	if err != nil {
		fmt.Println("new collector:", err)
		os.Exit(1)
	}
	configRepository, err := service.NewSQLAWSAccountConfigRepository(db)
	if err != nil {
		fmt.Println("new config repository:", err)
		os.Exit(1)
	}
	runRepository, err := service.NewSQLAWSSyncRunRepository(db)
	if err != nil {
		fmt.Println("new run repository:", err)
		os.Exit(1)
	}
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{Addr: envOr("REDIS_ADDR", "127.0.0.1:6379")})
	defer asynqClient.Close()
	enqueuer, err := service.NewAsynqAWSSyncRunEnqueuer(asynqClient)
	if err != nil {
		fmt.Println("new enqueuer:", err)
		os.Exit(1)
	}
	syncRunService, err := service.NewAWSSyncRunService(
		runRepository, configRepository, enqueuer, collector, logger)
	if err != nil {
		fmt.Println("new sync run service:", err)
		os.Exit(1)
	}

	payload, err := json.Marshal(service.AWSSyncRunTask{SyncRunID: runID, ConfigID: configID})
	if err != nil {
		fmt.Println("marshal payload:", err)
		os.Exit(1)
	}
	task := asynq.NewTask(service.AWSAccountSyncTaskType, payload)
	if err := syncRunService.HandleAWSAccountSyncTask(context.Background(), task); err != nil {
		fmt.Println("HANDLE ERROR:", err)
		os.Exit(1)
	}
	fmt.Println("handler returned nil (success)")
}

func envOr(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}
