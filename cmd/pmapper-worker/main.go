package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("load .env", "error", err)
		os.Exit(1)
	}
	config, err := loadConfig()
	if err != nil {
		logger.Error("load PMapper worker configuration", "error", err)
		os.Exit(1)
	}
	if err := run(config, logger); err != nil {
		logger.Error("PMapper worker stopped", "error", err)
		os.Exit(1)
	}
}

type workerConfig struct {
	databaseURL   string
	redisAddress  string
	redisPassword string
	redisDB       int
	pmapper       service.PMapperConfig
	concurrency   int
}

func loadConfig() (workerConfig, error) {
	config := workerConfig{
		databaseURL:   strings.TrimSpace(os.Getenv("DATABASE_URL")),
		redisAddress:  strings.TrimSpace(os.Getenv("REDIS_ADDR")),
		redisPassword: os.Getenv("REDIS_PASSWORD"),
		pmapper: service.PMapperConfig{
			Binary:     envOrDefault("PMAPPER_BINARY", "pmapper"),
			ImportArgs: splitArgs(envOrDefault("PMAPPER_IMPORT_ARGS", "import --input {input}")),
			ExportArgs: splitArgs(envOrDefault("PMAPPER_EXPORT_ARGS", "graph export --output {output}")),
			TempDir:    os.Getenv("PMAPPER_TEMP_DIR"),
		},
		concurrency: 2,
	}
	if config.databaseURL == "" {
		return workerConfig{}, errors.New("DATABASE_URL must be configured")
	}
	if config.redisAddress == "" {
		config.redisAddress = "127.0.0.1:6379"
	}
	if raw := strings.TrimSpace(os.Getenv("REDIS_DB")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &config.redisDB); err != nil || config.redisDB < 0 {
			return workerConfig{}, errors.New("REDIS_DB must be a non-negative integer")
		}
	}
	if raw := strings.TrimSpace(os.Getenv("PMAPPER_TIMEOUT")); raw != "" {
		timeout, err := time.ParseDuration(raw)
		if err != nil || timeout <= 0 {
			return workerConfig{}, errors.New("PMAPPER_TIMEOUT must be a positive duration")
		}
		config.pmapper.Timeout = timeout
	}
	if raw := strings.TrimSpace(os.Getenv("WORKER_CONCURRENCY")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &config.concurrency); err != nil || config.concurrency < 1 {
			return workerConfig{}, errors.New("WORKER_CONCURRENCY must be a positive integer")
		}
	}
	if config.pmapper.Binary == "" || len(config.pmapper.ImportArgs) == 0 || len(config.pmapper.ExportArgs) == 0 {
		return workerConfig{}, errors.New("PMapper binary and import/export arguments are required")
	}
	return config, nil
}

func run(config workerConfig, logger *slog.Logger) error {
	shutdownTracing, err := oteltrace.Setup(context.Background(), "finops-pmapper-worker")
	if err != nil {
		return fmt.Errorf("set up tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			logger.Warn("flush trace spans", "error", err)
		}
	}()
	logger.Info("OpenTelemetry tracing state", "enabled", oteltrace.Enabled())

	database, err := sql.Open("pgx", config.databaseURL)
	if err != nil {
		return fmt.Errorf("open PostgreSQL connection: %w", err)
	}
	defer database.Close()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	if err := database.PingContext(pingCtx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	repository, err := service.NewSQLIAMRelationshipRepository(database)
	if err != nil {
		return fmt.Errorf("create relationship repository: %w", err)
	}
	graphService, err := service.NewPMapperGraphService(config.pmapper, repository, logger)
	if err != nil {
		return fmt.Errorf("create PMapper graph service: %w", err)
	}
	mux := asynq.NewServeMux()
	if err := service.RegisterPMapperGraphTaskHandler(mux, graphService); err != nil {
		return err
	}
	server := asynq.NewServer(asynq.RedisClientOpt{
		Addr: config.redisAddress, Password: config.redisPassword, DB: config.redisDB,
	}, asynq.Config{
		Concurrency: config.concurrency,
		Queues:      map[string]int{service.PMapperQueueName: 1},
		Logger:      asynqLogger{logger: logger},
	})
	if err := server.Start(mux); err != nil {
		return fmt.Errorf("start Asynq server: %w", err)
	}
	logger.Info("PMapper worker started", "concurrency", config.concurrency, "redis", config.redisAddress)

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-shutdownContext.Done()
	server.Shutdown()
	logger.Info("PMapper worker stopped")
	return nil
}

type asynqLogger struct {
	logger *slog.Logger
}

func (logger asynqLogger) Debug(args ...interface{}) { logger.logger.Debug(fmt.Sprint(args...)) }
func (logger asynqLogger) Info(args ...interface{})  { logger.logger.Info(fmt.Sprint(args...)) }
func (logger asynqLogger) Warn(args ...interface{})  { logger.logger.Warn(fmt.Sprint(args...)) }
func (logger asynqLogger) Error(args ...interface{}) { logger.logger.Error(fmt.Sprint(args...)) }
func (logger asynqLogger) Fatal(args ...interface{}) { logger.logger.Error(fmt.Sprint(args...)) }

func splitArgs(raw string) []string {
	return strings.Fields(strings.TrimSpace(raw))
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
