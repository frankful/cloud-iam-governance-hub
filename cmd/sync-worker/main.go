// Command sync-worker executes background jobs enqueued by the API: AWS
// account synchronization runs (POST /aws/account-configs/:configID/sync) and
// baseline preview jobs. It also reconciles baseline publications with the
// remote PR state (merge detection + branch cleanup). AWS inventory and
// baseline bundle builds never run on the API process; this worker claims each
// task and records the result in the database.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"

	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	migrationfiles "github.com/frankful/cloud-iam-governance-hub/migrations"
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
		logger.Error("load sync worker configuration", "error", err)
		os.Exit(1)
	}
	if err := run(config, logger); err != nil {
		logger.Error("sync worker stopped", "error", err)
		os.Exit(1)
	}
}

type workerConfig struct {
	databaseURL   string
	redisAddress  string
	redisPassword string
	redisDB       int
	region        string
	profile       string
	externalID    string
	roleSession   string
	concurrency   int
	// healthAddress serves /healthz for container/K8s probes. A sync worker
	// has no other HTTP surface, so without it orchestrators can only guess
	// liveness from process state.
	healthAddress string
}

func loadConfig() (workerConfig, error) {
	config := workerConfig{
		databaseURL:   strings.TrimSpace(os.Getenv("DATABASE_URL")),
		redisAddress:  strings.TrimSpace(os.Getenv("REDIS_ADDR")),
		redisPassword: os.Getenv("REDIS_PASSWORD"),
		region:        strings.TrimSpace(os.Getenv("AWS_REGION")),
		profile:       strings.TrimSpace(os.Getenv("AWS_PROFILE")),
		externalID:    strings.TrimSpace(os.Getenv("AWS_EXTERNAL_ID")),
		roleSession:   strings.TrimSpace(os.Getenv("AWS_ROLE_SESSION_NAME")),
		concurrency:   2,
		healthAddress: strings.TrimSpace(os.Getenv("SYNC_WORKER_HEALTH_ADDR")),
	}
	if config.healthAddress == "" {
		config.healthAddress = "127.0.0.1:8081"
	}
	if config.databaseURL == "" {
		return workerConfig{}, errors.New("DATABASE_URL must be configured")
	}
	if config.region == "" {
		return workerConfig{}, errors.New("AWS_REGION must be configured")
	}
	if config.redisAddress == "" {
		config.redisAddress = "127.0.0.1:6379"
	}
	if config.roleSession == "" {
		config.roleSession = "iam-governance-collector"
	}
	if raw := strings.TrimSpace(os.Getenv("REDIS_DB")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &config.redisDB); err != nil || config.redisDB < 0 {
			return workerConfig{}, errors.New("REDIS_DB must be a non-negative integer")
		}
	}
	if raw := strings.TrimSpace(os.Getenv("WORKER_CONCURRENCY")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &config.concurrency); err != nil || config.concurrency < 1 {
			return workerConfig{}, errors.New("WORKER_CONCURRENCY must be a positive integer")
		}
	}
	return config, nil
}

func run(config workerConfig, logger *slog.Logger) error {
	shutdownTracing, err := oteltrace.Setup(context.Background(), "finops-sync-worker")
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
	// 启动门禁：迁移没跑完就别开始消费（0017 缺口此前只在生产 persist 阶段
	// 才以 SQLSTATE 42703 暴露）。
	pending, err := migrationfiles.Pending(pingCtx, database)
	if err != nil {
		return fmt.Errorf("check pending migrations: %w", err)
	}
	if len(pending) > 0 {
		return fmt.Errorf("database schema is out of date (pending migrations: %s); run go run ./cmd/migrate",
			strings.Join(pending, ", "))
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: config.redisAddress, Password: config.redisPassword, DB: config.redisDB,
	})
	defer redisClient.Close()
	// 启动即清一遍上次崩溃遗留的 RUNNING 残留（api 侧另有周期清扫；这里
	// 保证 worker 重启本身就是一次修复）。
	sweepCtx, sweepCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if _, err := service.SweepStaleSyncRuns(sweepCtx, database, logger); err != nil {
		logger.Warn("stale sync-run sweep failed", "error", err)
	}
	sweepCancel()
	stopHeartbeat := service.StartWorkerHeartbeat(
		context.Background(), redisClient, service.SyncWorkerHeartbeatKey, logger)
	defer stopHeartbeat()

	configRepository, err := service.NewSQLAWSAccountConfigRepository(database)
	if err != nil {
		return fmt.Errorf("create AWS account config repository: %w", err)
	}
	runRepository, err := service.NewSQLAWSSyncRunRepository(database)
	if err != nil {
		return fmt.Errorf("create AWS sync run repository: %w", err)
	}
	assetRepository, err := service.NewSQLAWSAssetRepository(database)
	if err != nil {
		return fmt.Errorf("create AWS asset repository: %w", err)
	}
	collector, err := service.NewAWSCollectorService(context.Background(), service.AWSCollectorConfig{
		Region:          config.region,
		Profile:         config.profile,
		RoleSessionName: config.roleSession,
		ExternalID:      config.externalID,
	}, assetRepository, logger)
	if err != nil {
		return fmt.Errorf("create AWS collector: %w", err)
	}
	// 同步顺带采集实例配置文件在用性证据并落库：待清理清单直接读库，
	// 不必每次打开页面都实时调 EC2/EKS（此前串行 7~25 秒）。
	usageStore, err := service.NewProfileUsageEvidenceStore(database)
	if err != nil {
		return fmt.Errorf("create profile usage evidence store: %w", err)
	}
	if err := collector.EnableProfileUsageCollection(usageStore); err != nil {
		return fmt.Errorf("enable profile usage collection: %w", err)
	}
	// The worker never triggers runs, but the service constructor requires an
	// enqueuer; an Asynq client costs nothing here.
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr: config.redisAddress, Password: config.redisPassword, DB: config.redisDB,
	})
	defer asynqClient.Close()
	enqueuer, err := service.NewAsynqAWSSyncRunEnqueuer(asynqClient)
	if err != nil {
		return fmt.Errorf("create AWS sync run enqueuer: %w", err)
	}
	// 漂移判定（phase4 §3）：同步成功后拿刚确认的库存与声明快照比一次。
	// 判定失败只记日志，不影响同步结果。
	declarationService, err := service.NewBaselineDeclarationService(database, logger)
	if err != nil {
		return fmt.Errorf("create baseline declaration service: %w", err)
	}
	driftService, err := service.NewDriftService(database, declarationService, logger)
	if err != nil {
		return fmt.Errorf("create drift service: %w", err)
	}
	syncRunService, err := service.NewAWSSyncRunService(
		runRepository, configRepository, enqueuer, collector, logger,
		service.WithSyncDriftEvaluator(driftService))
	if err != nil {
		return fmt.Errorf("create AWS sync run service: %w", err)
	}

	// 基线链路（B3）：预览 job 的构建 + PR 合并感知都在 worker 执行。
	// 发布器按 PUBLISHER 装配：预览 job 的文件存在性检查（BundleRepoChecker）
	// 与合并感知的分支清理（BaselineBranchCleaner）都依赖它；发布器未配置时
	// checker 为 nil（预览跳过该步）、合并感知只更新台账不删分支。
	publisher := loadPublisherFromEnv(logger)
	var bundleChecker service.BundleRepoChecker
	if publisher != nil {
		bundleChecker, _ = publisher.(service.BundleRepoChecker)
	}
	bundleTerraformPath := loadTerraformPathFromEnv()
	candidateService := service.NewBaselineCandidateService(database)
	bundleService := service.NewBaselineBundleService(database, candidateService, bundleChecker, bundleTerraformPath)
	baselineJobService := service.NewBaselinePreviewJobService(database, bundleService, logger)

	mergeHost, mergeProject := loadGitHostFromEnv(logger)
	var mergeCleaner service.BaselineBranchCleaner
	if publisher != nil {
		mergeCleaner, _ = publisher.(service.BaselineBranchCleaner)
	}
	var mergeService *service.BaselinePublicationMergeService
	if mergeHost != nil {
		mergeService = service.NewBaselinePublicationMergeService(
			database, mergeHost, mergeProject, mergeCleaner, logger)
	}

	server := asynq.NewServer(asynq.RedisClientOpt{
		Addr: config.redisAddress, Password: config.redisPassword, DB: config.redisDB,
	}, asynq.Config{
		Concurrency: config.concurrency,
		Queues: map[string]int{
			service.AWSSyncQueueName:  1,
			service.BaselineQueueName: 1,
		},
		Logger: asynqLogger{logger: logger},
	})
	mux := asynq.NewServeMux()
	mux.HandleFunc(service.AWSAccountSyncTaskType, syncRunService.HandleAWSAccountSyncTask)
	mux.HandleFunc(service.BaselinePreviewJobTaskType, baselineJobService.HandleBaselinePreviewJobTask)
	if err := server.Start(mux); err != nil {
		return fmt.Errorf("start Asynq server: %w", err)
	}
	logger.Info("AWS sync worker started",
		"concurrency", config.concurrency, "redis", config.redisAddress)

	// PR 合并感知：周期查询 PUBLISHED 台账的远端 PR，MERGED → 记台账并按
	// keep_branch 删远端分支。host 未配置时跳过整个循环。
	reconcileCtx, reconcileStop := context.WithCancel(context.Background())
	defer reconcileStop()
	if mergeService != nil {
		service.StartMergeReconcileLoop(reconcileCtx, mergeService, service.BaselineMergeReconcileInterval, logger)
	} else {
		logger.Warn("baseline merge reconcile disabled until publisher is configured")
	}

	healthServer := &http.Server{
		Addr:    config.healthAddress,
		Handler: syncWorkerHealthHandler(database, redisClient),
	}
	go func() {
		logger.Info("sync worker health endpoint started", "address", config.healthAddress)
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("sync worker health endpoint stopped", "error", err)
		}
	}()

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-shutdownContext.Done()
	server.Shutdown()
	healthShutdownCtx, cancelHealthShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHealthShutdown()
	if err := healthServer.Shutdown(healthShutdownCtx); err != nil {
		logger.Warn("shut down sync worker health endpoint", "error", err)
	}
	logger.Info("AWS sync worker stopped")
	return nil
}

// loadPublisherFromEnv reads the same PUBLISHER + token variables as the API
// process and builds the code-host publisher used by the baseline preview job
// (file existence check) and merge reconcile (branch deletion). Returns nil
// (with a warning) when credentials are absent — those features degrade
// instead of blocking collection.
func loadPublisherFromEnv(logger *slog.Logger) service.TicketPublisher {
	publisher := strings.ToLower(strings.TrimSpace(os.Getenv("PUBLISHER")))
	if publisher == "" {
		publisher = "github"
	}
	switch publisher {
	case "gitlab":
		token := strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
		projectID := strings.TrimSpace(os.Getenv("GITLAB_PROJECT_ID"))
		if token == "" || projectID == "" {
			logger.Warn("GitLab publisher not configured; baseline file check and branch cleanup disabled")
			return nil
		}
		gitlabPublisher, err := service.NewGitLabSDKPublisher(service.GitLabConfig{
			BaseURL:       os.Getenv("GITLAB_API_URL"),
			Token:         token,
			ProjectID:     projectID,
			TargetBranch:  os.Getenv("GITLAB_TARGET_BRANCH"),
			TerraformPath: os.Getenv("GITLAB_TERRAFORM_PATH"),
		})
		if err != nil {
			logger.Warn("failed to create GitLab publisher; baseline file check and branch cleanup disabled", "error", err)
			return nil
		}
		return gitlabPublisher
	default:
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
		if token == "" || repository == "" {
			logger.Warn("GitHub publisher not configured; baseline file check and branch cleanup disabled")
			return nil
		}
		githubPublisher, err := service.NewGitHubPublisher(service.GitHubConfig{
			BaseURL:       os.Getenv("GITHUB_API_URL"),
			Token:         token,
			Repository:    repository,
			TargetBranch:  os.Getenv("GITHUB_TARGET_BRANCH"),
			TerraformPath: os.Getenv("GITHUB_TERRAFORM_PATH"),
		})
		if err != nil {
			logger.Warn("failed to create GitHub publisher; baseline file check and branch cleanup disabled", "error", err)
			return nil
		}
		return githubPublisher
	}
}

// loadTerraformPathFromEnv mirrors the API-side directory resolution: the
// publisher's own default ("iam") applies when the variable is unset.
func loadTerraformPathFromEnv() string {
	envVar := "GITHUB_TERRAFORM_PATH"
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PUBLISHER")), "gitlab") {
		envVar = "GITLAB_TERRAFORM_PATH"
	}
	terraformPath := strings.TrimSpace(os.Getenv(envVar))
	if terraformPath == "" {
		return "iam"
	}
	return terraformPath
}

// loadGitHostFromEnv builds the provider-neutral PR state client for merge
// reconcile. Returns (nil, "") when credentials are absent.
func loadGitHostFromEnv(logger *slog.Logger) (githost.GitHost, string) {
	publisher := strings.ToLower(strings.TrimSpace(os.Getenv("PUBLISHER")))
	if publisher == "" {
		publisher = "github"
	}
	config := githost.GitHostConfig{Provider: publisher}
	switch publisher {
	case "gitlab":
		config.Token = strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
		config.ProjectID = strings.TrimSpace(os.Getenv("GITLAB_PROJECT_ID"))
		config.BaseURL = strings.TrimSpace(os.Getenv("GITLAB_API_URL"))
		if config.BaseURL == "" {
			config.BaseURL = "https://gitlab.com/api/v4"
		}
	default:
		config.Provider = "github"
		config.Token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		config.ProjectID = strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
		config.BaseURL = strings.TrimSpace(os.Getenv("GITHUB_API_URL"))
		if config.BaseURL == "" {
			config.BaseURL = "https://api.github.com"
		}
	}
	if config.Token == "" || config.ProjectID == "" {
		return nil, ""
	}
	host, err := githost.NewGitHost(config)
	if err != nil {
		logger.Warn("failed to create git host client; merge reconcile disabled", "error", err)
		return nil, ""
	}
	return host, config.ProjectID
}

// syncWorkerHealthHandler serves /healthz: the worker's only HTTP surface, so
// container orchestrators get a real dependency probe instead of guessing.
func syncWorkerHealthHandler(database *sql.DB, redisClient *redis.Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		status := http.StatusOK
		payload := map[string]string{"status": "ok"}
		if err := database.PingContext(ctx); err != nil {
			status = http.StatusServiceUnavailable
			payload = map[string]string{"status": "unavailable", "error": "postgres: " + err.Error()}
		} else if err := redisClient.Ping(ctx).Err(); err != nil {
			status = http.StatusServiceUnavailable
			payload = map[string]string{"status": "unavailable", "error": "redis: " + err.Error()}
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		if err := json.NewEncoder(writer).Encode(payload); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	})
	return mux
}

type asynqLogger struct {
	logger *slog.Logger
}

func (logger asynqLogger) Debug(args ...interface{}) { logger.logger.Debug(fmt.Sprint(args...)) }
func (logger asynqLogger) Info(args ...interface{})  { logger.logger.Info(fmt.Sprint(args...)) }
func (logger asynqLogger) Warn(args ...interface{})  { logger.logger.Warn(fmt.Sprint(args...)) }
func (logger asynqLogger) Error(args ...interface{}) { logger.logger.Error(fmt.Sprint(args...)) }
func (logger asynqLogger) Fatal(args ...interface{}) { logger.logger.Error(fmt.Sprint(args...)) }
