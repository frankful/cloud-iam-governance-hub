// Command gitstatus-worker polls Git hosting services (GitLab/GitHub) for
// merge request and CI/CD pipeline status updates.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
)

type config struct {
	DatabaseURL      string
	RedisAddr        string
	GitProvider      string
	GitBaseURL       string
	GitToken         string
	GitProjectID     string
	GitTargetBranch  string
	GitTerraformPath string
	Concurrency      int
}

// loadConfig loads configuration from environment variables and .env file.
// It parses .env directly to bypass os.Setenv/os.Getenv issues on Windows.
func loadConfig() (*config, error) {
	// Parse .env file directly
	envVars := parseEnvFile()

	// Helper to get value from envVars map first, then OS environment
	getVal := func(key, defaultValue string) string {
		if v, ok := envVars[key]; ok && v != "" {
			return v
		}
		if v := os.Getenv(key); v != "" {
			return v
		}
		return defaultValue
	}

	// firstNonEmpty returns the first non-empty value.
	firstNonEmpty := func(values ...string) string {
		for _, v := range values {
			if v != "" {
				return v
			}
		}
		return ""
	}

	// Support both GitHub-style (GITHUB_*) and generic (GIT_*) key names,
	// plus PUBLISHER as the provider selector (matching cmd/api).
	gitToken := firstNonEmpty(getVal("GITHUB_TOKEN", ""), getVal("GIT_TOKEN", ""))
	gitProjectID := firstNonEmpty(getVal("GITHUB_REPOSITORY", ""), getVal("GIT_PROJECT_ID", ""))
	gitProvider := strings.ToLower(firstNonEmpty(getVal("PUBLISHER", ""), getVal("GIT_PROVIDER", ""), "github"))
	gitBaseURL := getVal("GIT_BASE_URL", "")
	if gitProvider == "github" && gitBaseURL == "" {
		gitBaseURL = "https://api.github.com"
	}
	gitTargetBranch := firstNonEmpty(getVal("GITHUB_TARGET_BRANCH", ""), getVal("GIT_TARGET_BRANCH", ""), "main")
	gitTerraformPath := firstNonEmpty(getVal("GITHUB_TERRAFORM_PATH", ""), getVal("GIT_TERRAFORM_PATH", ""), "iam")

	slog.Info("loadConfig values",
		"git_provider", gitProvider,
		"git_token_length", len(gitToken),
		"git_project_id_length", len(gitProjectID),
		"git_base_url", gitBaseURL,
		"database_url_length", len(getVal("DATABASE_URL", "")),
	)

	if gitToken == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN (or GIT_TOKEN) environment variable is required")
	}
	if gitProjectID == "" {
		return nil, fmt.Errorf("GITHUB_REPOSITORY (or GIT_PROJECT_ID) environment variable is required")
	}

	return &config{
		DatabaseURL:      getVal("DATABASE_URL", "postgres://localhost:5432/finops?sslmode=disable"),
		RedisAddr:        getVal("REDIS_ADDR", "localhost:6379"),
		GitProvider:      gitProvider,
		GitBaseURL:       gitBaseURL,
		GitToken:         gitToken,
		GitProjectID:     gitProjectID,
		GitTargetBranch:  gitTargetBranch,
		GitTerraformPath: gitTerraformPath,
		Concurrency:      getEnvInt("CONCURRENCY", 5),
	}, nil
}

// parseEnvFile reads and parses .env file from multiple possible paths.
func parseEnvFile() map[string]string {
	result := make(map[string]string)
	envPaths := []string{".env", "../../.env", "../../../.env"}
	for _, envPath := range envPaths {
		if envData, readErr := os.ReadFile(envPath); readErr == nil {
			for _, line := range strings.Split(string(envData), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					// Remove surrounding quotes if present
					if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
						value = value[1 : len(value)-1]
					}
					result[key] = value
				}
			}
			slog.Info("parsed .env file", "path", envPath, "vars_count", len(result))
			break
		}
	}
	return result
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	shutdownTracing, err := oteltrace.Setup(context.Background(), "finops-gitstatus-worker")
	if err != nil {
		logger.Error("failed to set up tracing", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			logger.Warn("flush trace spans", "error", err)
		}
	}()
	logger.Info("OpenTelemetry tracing state", "enabled", oteltrace.Enabled())

	// Open database connection
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to open database connection", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Verify database connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		logger.Error("failed to ping database", "error", err)
		os.Exit(1)
	}

	// Create Git host client
	gitHost, err := githost.NewGitHost(githost.GitHostConfig{
		Provider:      cfg.GitProvider,
		BaseURL:       cfg.GitBaseURL,
		Token:         cfg.GitToken,
		ProjectID:     cfg.GitProjectID,
		TargetBranch:  cfg.GitTargetBranch,
		TerraformPath: cfg.GitTerraformPath,
	})
	if err != nil {
		logger.Error("failed to create Git host client", "error", err)
		os.Exit(1)
	}

	// Create Asynq client
	redisOpt := asynq.RedisClientOpt{Addr: cfg.RedisAddr}
	asynqClient := asynq.NewClient(redisOpt)
	defer asynqClient.Close()

	// Create Redis client for heartbeat
	redisClient := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	defer redisClient.Close()

	// Create Git status repository backed by PostgreSQL
	gitRepo, err := service.NewSQLGitStatusRepository(db)
	if err != nil {
		logger.Error("failed to create git status repository", "error", err)
		os.Exit(1)
	}

	// Create Git status poller
	poller, err := service.NewGitStatusPoller(gitHost, gitRepo, asynqClient, logger,
		// A12⑤：部署已接入 CI apply 回调时（IAM_CI_APPLY_CALLBACK=true），
		// merged 工单等 CI 绿（finops/terraform-apply）才关单。
		service.WithCIApplyCallback(
			strings.EqualFold(strings.TrimSpace(os.Getenv("IAM_CI_APPLY_CALLBACK")), "true")))
	if err != nil {
		logger.Error("failed to create Git status poller", "error", err)
		os.Exit(1)
	}

	// Create Asynq server
	server := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: cfg.Concurrency,
		// Only consume this worker's queue: workers of other task types must
		// never claim (and fail) git status polls.
		Queues: map[string]int{service.GitStatusQueueName: 1},
	})

	// Register task handlers
	mux := asynq.NewServeMux()
	mux.HandleFunc(service.GitStatusPollTaskType, poller.HandleGitStatusPollTask)

	// Re-arm polling for tickets whose remote requests are still open:
	// covers worker restarts and poll schedules that exhausted their
	// attempt budget before a merge happened.
	go func() {
		sweepCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := poller.SweepActivePolls(sweepCtx); err != nil {
			logger.Error("failed to sweep active polls at startup", "error", err)
		}
	}()

	// Start server
	if err := server.Start(mux); err != nil {
		logger.Error("failed to start worker server", "error", err)
		os.Exit(1)
	}

	logger.Info("gitstatus-worker started",
		"provider", cfg.GitProvider,
		"project", cfg.GitProjectID,
		"concurrency", cfg.Concurrency,
	)

	// Start heartbeat goroutine
	heartbeatCtx, heartbeatCancel := context.WithCancel(context.Background())
	defer heartbeatCancel()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				heartbeatKey := "worker:heartbeat:gitstatus"
				if err := redisClient.Set(heartbeatCtx, heartbeatKey, time.Now().Format(time.RFC3339), 30*time.Second).Err(); err != nil {
					logger.Warn("failed to write heartbeat", "error", err)
				}
			}
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down gitstatus-worker...")
	heartbeatCancel()
	server.Shutdown()
	logger.Info("gitstatus-worker stopped")
}
