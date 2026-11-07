package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	abstracthandler "github.com/frankful/cloud-iam-governance-hub/api/handler"
	frontend "github.com/frankful/cloud-iam-governance-hub/frontend"
	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	v1 "github.com/frankful/cloud-iam-governance-hub/internal/handler/http/v1"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	migrationfiles "github.com/frankful/cloud-iam-governance-hub/migrations"
	awsadapter "github.com/frankful/cloud-iam-governance-hub/pkg/adapter/aws"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

const (
	defaultDatabaseURL = "postgres://finops:finops@127.0.0.1:5432/finops?sslmode=disable"
	defaultRedisAddr   = "127.0.0.1:6379"
	defaultAPIAddr     = "127.0.0.1:8080"
	startupTimeout     = 10 * time.Second
	shutdownTimeout    = 10 * time.Second
)

// version is injected at build time:
//
//	go build -ldflags "-X main.version=v1.0.9" ./cmd/api
//
// It stays "dev" for local builds. Audit records need to say which platform
// version produced them, so the value is exposed on GET /version.
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("load .env", "error", err)
		os.Exit(1)
	}
	if err := run(logger); err != nil {
		logger.Error("API server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}
	if config.authMode != "development" && config.authMode != "api-token" {
		return errors.New("AUTH_MODE must be set explicitly to development or api-token")
	}
	if !isLoopbackAddress(config.apiAddress) {
		// 容器化部署（docker compose / K8s）必须绑定 0.0.0.0 才能被端口映射
		// 访问；默认仍然拒绝非回环地址，只有显式 opt-in 才放行。
		if !strings.EqualFold(strings.TrimSpace(os.Getenv("API_ALLOW_NON_LOOPBACK")), "true") {
			return errors.New("API_ADDR must bind to loopback; terminate TLS at a trusted local reverse proxy before remote access (set API_ALLOW_NON_LOOPBACK=true for container deployments)")
		}
		logger.Warn("API_ADDR binds to a non-loopback address; ensure TLS is terminated by a trusted reverse proxy before remote access")
	}

	shutdownTracing, err := oteltrace.Setup(context.Background(), "finops-api")
	if err != nil {
		return fmt.Errorf("setup tracing: %w", err)
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
	database.SetMaxOpenConns(20)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(30 * time.Minute)

	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.redisAddress,
		Password: config.redisPassword,
		DB:       config.redisDB,
	})
	defer redisClient.Close()

	startupCtx, startupCancel := context.WithTimeout(context.Background(), startupTimeout)
	defer startupCancel()
	if err := database.PingContext(startupCtx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	// 启动时自动应用内嵌迁移（幂等 + advisory lock 串行化），替代独立的
	// migrate 容器：新装环境一次 up 即可用，已迁移的库只是多一次台账比对。
	// 手动入口仍是 go run ./cmd/migrate（同一实现）。
	if err := migrationfiles.ApplyAll(startupCtx, database, logger); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}
	if err := checkSchema(startupCtx, database); err != nil {
		return err
	}
	accountConfigRepository, err := service.NewSQLAWSAccountConfigRepository(database)
	if err != nil {
		return fmt.Errorf("create AWS account config repository: %w", err)
	}
	accountConnectivity, err := service.NewAWSAccountConnectivityService(startupCtx, service.AWSAccountConnectivityConfig{
		Region:      config.awsRegion,
		Profile:     config.awsProfile,
		ExternalID:  config.awsExternalID,
		MaxAttempts: 3,
	})
	if err != nil {
		return fmt.Errorf("create AWS account connectivity validator: %w", err)
	}
	accountConfigService, err := service.NewAWSAccountConfigService(accountConfigRepository, accountConnectivity, logger)
	if err != nil {
		return fmt.Errorf("create AWS account config service: %w", err)
	}
	accountConfigHandler, err := v1.NewAWSAccountConfigHandler(accountConfigService)
	if err != nil {
		return fmt.Errorf("create AWS account config handler: %w", err)
	}
	accountQueryService, err := service.NewAWSAccountQueryService(database)
	if err != nil {
		return fmt.Errorf("create AWS account query service: %w", err)
	}
	accountQueryHandler, err := v1.NewAWSAccountQueryHandler(accountQueryService)
	if err != nil {
		return fmt.Errorf("create AWS account query handler: %w", err)
	}
	accountApproverService, err := service.NewAccountApproverService(database)
	if err != nil {
		return fmt.Errorf("create account approver service: %w", err)
	}
	accountApproverHandler, err := v1.NewAWSAccountApproverHandler(accountApproverService)
	if err != nil {
		return fmt.Errorf("create account approver handler: %w", err)
	}
	inventoryService, err := service.NewIAMInventoryService(database)
	if err != nil {
		return fmt.Errorf("create IAM inventory service: %w", err)
	}
	inventoryHandler, err := v1.NewIAMInventoryHandler(inventoryService)
	if err != nil {
		return fmt.Errorf("create IAM inventory handler: %w", err)
	}
	baselineRepository, err := service.NewSQLIAMBaselineRepository(database)
	if err != nil {
		return fmt.Errorf("create IAM baseline repository: %w", err)
	}
	baselineService, err := service.NewIAMBaselineService(baselineRepository)
	if err != nil {
		return fmt.Errorf("create IAM baseline service: %w", err)
	}
	baselineHandler, err := v1.NewIAMBaselineHandler(baselineService)
	if err != nil {
		return fmt.Errorf("create IAM baseline handler: %w", err)
	}
	// 待清理清单复用基线候选集判定：两条链路不能各自演化出相反的归属结论。
	candidateService := service.NewBaselineCandidateService(database)
	// EKS/EC2 实例配置文件引用解析：把 eks-<uuid> 孤儿从「需确认」算准成
	// 「可直接执行」。复用采集链路的同一套 AWS 环境变量；失败自动退回 review 档。
	var profileResolver service.ProfileUsageResolver
	if config.awsRegion != "" {
		liveResolver, err := service.NewEKSProfileUsageResolver(
			database,
			config.awsRegion,
			config.awsProfile,
			strings.TrimSpace(os.Getenv("AWS_ROLE_SESSION_NAME")),
			config.awsExternalID,
		)
		if err != nil {
			return fmt.Errorf("create profile usage resolver: %w", err)
		}
		// 优先读同步落库的在用性证据快照；没有快照的账号实时回源并回写。
		usageStore, err := service.NewProfileUsageEvidenceStore(database)
		if err != nil {
			return fmt.Errorf("create profile usage evidence store: %w", err)
		}
		profileResolver, err = service.NewStoredProfileUsageResolver(usageStore, liveResolver, logger)
		if err != nil {
			return fmt.Errorf("create stored profile usage resolver: %w", err)
		}
	}
	cleanupService, err := service.NewCleanupService(database, candidateService, profileResolver)
	if err != nil {
		return fmt.Errorf("create cleanup service: %w", err)
	}
	cleanupHandler, err := v1.NewCleanupHandler(cleanupService)
	if err != nil {
		return fmt.Errorf("create cleanup handler: %w", err)
	}
	tokenRepository, err := service.NewSQLPlatformTokenRepository(database)
	if err != nil {
		return fmt.Errorf("create platform token repository: %w", err)
	}
	tokenService, err := service.NewPlatformTokenService(tokenRepository)
	if err != nil {
		return fmt.Errorf("create platform token service: %w", err)
	}
	platformUserRepository, err := service.NewSQLPlatformUserRepository(database)
	if err != nil {
		return fmt.Errorf("create platform user repository: %w", err)
	}
	platformUserService, err := service.NewPlatformUserService(platformUserRepository, tokenService)
	if err != nil {
		return fmt.Errorf("create platform user service: %w", err)
	}
	authHandler, err := v1.NewAuthHandler(config.authMode)
	if err != nil {
		return fmt.Errorf("create auth handler: %w", err)
	}
	if config.authMode == "api-token" {
		if err := checkPlatformAuthSchema(startupCtx, database); err != nil {
			return err
		}
		// 首次启动自举：没有任何可用管理员时，自动建/激活 admin、授
		// platform_admin 并把第一枚 token 写到本地文件。之后的每次启动都是
		// no-op（有 active admin 就跳过），不会重复铸造凭证。
		if err := bootstrapFirstAdmin(startupCtx, database, tokenService, logger); err != nil {
			return err
		}
	}
	// env 种子账号：BOOTSTRAP_AWS_ACCOUNT_ID 配置时自动接入 AWS 账号（幂等，
	// 走与手工 POST /aws/account-configs 相同的 Create 路径）。连通性失败只
	// WARN 不阻断启动——清库/新装环境不必再手工录账号。
	if err := service.BootstrapAWSAccountFromEnv(startupCtx, accountConfigService, os.Getenv, logger); err != nil {
		return err
	}
	if err := redisClient.Ping(startupCtx).Err(); err != nil {
		return fmt.Errorf("connect to Redis: %w", err)
	}

	publisher, err := configuredPublisher(config, logger)
	if err != nil {
		return err
	}
	// B2 基线预览：候选集 → 多文件 bundle（含 import 块）→ 冲突检测 → job 落库。
	// 文件存在性检查是只读远端 API，GitHub 与 GitLab 发布器都实现了
	// BundleRepoChecker。目录公式与发布器一致。
	bundleChecker, _ := publisher.(service.BundleRepoChecker)
	bundleTerraformPath := os.Getenv("GITHUB_TERRAFORM_PATH")
	if config.publisher == "gitlab" {
		bundleTerraformPath = os.Getenv("GITLAB_TERRAFORM_PATH")
	}
	bundleTerraformPath = strings.TrimSpace(bundleTerraformPath)
	if bundleTerraformPath == "" {
		bundleTerraformPath = "iam" // 与发布器的默认值保持一致
	}
	bundleService := service.NewBaselineBundleService(database, candidateService, bundleChecker, bundleTerraformPath)
	baselineJobService := service.NewBaselinePreviewJobService(database, bundleService, logger)
	// B3 基线发布（D7 拍板）：一账号一短分支一 PR，幂等键 = 账号 + 快照 run；
	// BASELINE_KEEP_BRANCH 开启则合并后保留分支作审计痕迹（默认合并即删）。
	// 仓库发布器不可用时整个发布面降级下线（预览仍可用）。
	var baselinePublicationHandler *v1.BaselinePublicationHandler
	// 漂移「接受现状」要重发基线，需要同一个发布服务实例；仓库发布器不可用
	// 时保持 nil，收敛入口降级为只读提示（不假装能发）。
	var baselinePublishService *service.BaselinePublishService
	if branchPublisher, ok := publisher.(service.BaselineBranchPublisher); ok {
		baselineKeepBranch := strings.EqualFold(strings.TrimSpace(os.Getenv("BASELINE_KEEP_BRANCH")), "true")
		baselinePublishService = service.NewBaselinePublishService(
			database, bundleService, branchPublisher, baselineKeepBranch, logger)
		baselinePublicationHandler, err = v1.NewBaselinePublicationHandler(baselinePublishService, logger)
		if err != nil {
			return fmt.Errorf("create baseline publication handler: %w", err)
		}
		if stalePubs, err := baselinePublishService.SweepStale(startupCtx); err != nil {
			logger.Warn("failed to sweep stale baseline publications", "error", err)
		} else if stalePubs > 0 {
			logger.Info("swept stale baseline publications", "count", stalePubs)
		}
	}
	baselineJobHandler, err := v1.NewBaselineJobHandler(baselineJobService, logger)
	if err != nil {
		return fmt.Errorf("create baseline job handler: %w", err)
	}
	if staleCount, err := baselineJobService.SweepStale(startupCtx); err != nil {
		logger.Warn("failed to sweep stale baseline preview jobs", "error", err)
	} else if staleCount > 0 {
		logger.Info("swept stale baseline preview jobs", "count", staleCount)
	}
	repository, err := service.NewSQLTicketRepository(database)
	if err != nil {
		return fmt.Errorf("create ticket repository: %w", err)
	}
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     config.redisAddress,
		Password: config.redisPassword,
		DB:       config.redisDB,
	})
	defer asynqClient.Close()
	pollEnqueuer, err := service.NewAsynqGitStatusPollEnqueuer(asynqClient)
	if err != nil {
		return fmt.Errorf("create git status poll enqueuer: %w", err)
	}
	syncRunRepository, err := service.NewSQLAWSSyncRunRepository(database)
	if err != nil {
		return fmt.Errorf("create AWS sync run repository: %w", err)
	}
	syncRunEnqueuer, err := service.NewAsynqAWSSyncRunEnqueuer(asynqClient)
	if err != nil {
		return fmt.Errorf("create AWS sync run enqueuer: %w", err)
	}
	// 预览 job 入队给 sync-worker 构建（与 AWS 采集同一 worker 生命周期），
	// API 进程只落 PENDING 行；入队执行面未装配时 handler 回退进程内 goroutine。
	baselinePreviewEnqueuer, err := service.NewAsynqBaselinePreviewJobEnqueuer(asynqClient)
	if err != nil {
		return fmt.Errorf("create baseline preview job enqueuer: %w", err)
	}
	baselineJobService.SetEnqueuer(baselinePreviewEnqueuer)
	// The API process only triggers and lists runs; the collector lives in
	// cmd/sync-worker so AWS inventory never blocks an HTTP thread.
	syncRunService, err := service.NewAWSSyncRunService(
		syncRunRepository, accountConfigRepository, syncRunEnqueuer, nil, logger)
	if err != nil {
		return fmt.Errorf("create AWS sync run service: %w", err)
	}
	workerStatusService, err := service.NewAWSSyncWorkerStatusService(redisClient)
	if err != nil {
		return fmt.Errorf("create AWS sync worker status service: %w", err)
	}
	syncRunHandler, err := v1.NewAWSSyncRunHandler(syncRunService, workerStatusService)
	if err != nil {
		return fmt.Errorf("create AWS sync run handler: %w", err)
	}
	// PR 状态查询客户端：废弃工单前校验 PR 已关闭，
	// 防止「PR 后来被合并但工单已废弃」的错位。
	mrFetcher, err := configuredGitHost(config, logger)
	if err != nil {
		return fmt.Errorf("create git host client: %w", err)
	}
	// 文件级发布预约（phase4 §4）：同一账号同一文件至多一个开放 PR 源。
	publishReservations, err := service.NewPublishReservationService(database, logger)
	if err != nil {
		return fmt.Errorf("create publish reservation service: %w", err)
	}
	// 声明快照（phase4 §5）：基线声明 + 工单声明构成漂移基准。工单侧在
	// 发布成功后从发布内容反解落库，废弃关单时作废。
	declarationService, err := service.NewBaselineDeclarationService(database, logger)
	if err != nil {
		return fmt.Errorf("create baseline declaration service: %w", err)
	}
	ticketService, err := service.NewTicketService(
		repository, publisher, logger,
		service.WithCandidateRiskMode(config.candidateRiskMode),
		service.WithGitStatusPollEnqueuer(pollEnqueuer),
		service.WithMergeRequestFetcher(mrFetcher),
		// 人工关单勾选「触发同步」时复用自动关单的延迟同步链路。
		service.WithClosureSyncTrigger(syncRunService),
		service.WithPublishReservations(publishReservations),
		service.WithBaselineDeclarations(declarationService),
	)
	if err != nil {
		return fmt.Errorf("create ticket service: %w", err)
	}

	// Start embedded git status worker (polls GitHub/GitLab PR status).
	// Git 凭证未配置时降级跳过而不是阻断启动：PR 状态轮询是增强功能，
	// 与 sync-worker 对 publisher 未配置的降级策略保持一致。
	// Stop() 是 nil 安全的，跳过时 defer 依旧成立。
	gitToken := os.Getenv("GITHUB_TOKEN")
	if strings.EqualFold(config.publisher, "gitlab") {
		gitToken = os.Getenv("GITLAB_TOKEN")
	}
	gitProjectID := os.Getenv("GITHUB_REPOSITORY")
	if strings.EqualFold(config.publisher, "gitlab") {
		gitProjectID = os.Getenv("GITLAB_PROJECT_ID")
	}
	var gitWorker *service.GitStatusWorker
	if gitToken == "" || gitProjectID == "" {
		logger.Warn("embedded gitstatus worker disabled until git credentials are configured",
			"publisher", config.publisher)
	} else {
		gitWorker, err = service.RunGitStatusWorker(context.Background(), service.GitStatusWorkerConfig{
			DB:               database,
			RedisAddr:        config.redisAddress,
			RedisPassword:    config.redisPassword,
			RedisDB:          config.redisDB,
			GitProvider:      config.publisher,
			GitBaseURL:       configuredGitBaseURL(config.publisher),
			GitToken:         gitToken,
			GitProjectID:     gitProjectID,
			GitTargetBranch:  os.Getenv("GITHUB_TARGET_BRANCH"),
			GitTerraformPath: os.Getenv("GITHUB_TERRAFORM_PATH"),
			Concurrency:      5,
			Logger:           logger,
			// 自动关单（merged + CI 成功）后立即同步该账号，让清单反映变更。
			ClosureSync: syncRunService,
			// PR 合并时工单预约转 MERGED 态，等同步确认后释放（phase4 §4.2）。
			Reservations: publishReservations,
			// A12⑤：部署已接入 CI apply 回调（finops/terraform-apply），
			// merged 工单等 CI 绿才关单，不再 merge 即关单。
			CIApplyCallback: strings.EqualFold(strings.TrimSpace(os.Getenv("IAM_CI_APPLY_CALLBACK")), "true"),
		})
		if err != nil {
			return fmt.Errorf("start gitstatus worker: %w", err)
		}
	}
	defer gitWorker.Stop()

	ticketHandler, err := v1.NewTicketHandler(ticketService)
	if err != nil {
		return fmt.Errorf("create ticket handler: %w", err)
	}
	policyDerivedGrantRepository, err := service.NewSQLPolicyDerivedGrantRepository(database)
	if err != nil {
		return fmt.Errorf("create policy-derived grants repository: %w", err)
	}
	policyDerivedGrantService, err := service.NewPolicyDerivedGrantService(policyDerivedGrantRepository)
	if err != nil {
		return fmt.Errorf("create policy-derived grants service: %w", err)
	}
	policyDerivedGrantHandler, err := v1.NewPolicyDerivedGrantsHandler(policyDerivedGrantService)
	if err != nil {
		return fmt.Errorf("create policy-derived grants handler: %w", err)
	}
	platformTokenHandler, err := v1.NewPlatformTokenHandler(tokenService)
	if err != nil {
		return fmt.Errorf("create platform token handler: %w", err)
	}
	platformUserHandler, err := v1.NewPlatformUserHandler(platformUserService)
	if err != nil {
		return fmt.Errorf("create platform user handler: %w", err)
	}
	ownershipRepository, err := service.NewSQLIAMOwnershipRepository(database)
	if err != nil {
		return fmt.Errorf("create IAM ownership repository: %w", err)
	}
	ownershipService, err := service.NewIAMOwnershipService(ownershipRepository)
	if err != nil {
		return fmt.Errorf("create IAM ownership service: %w", err)
	}
	ownershipHandler, err := v1.NewIAMOwnershipHandler(ownershipService)
	if err != nil {
		return fmt.Errorf("create IAM ownership handler: %w", err)
	}
	auditRepository, err := service.NewSQLAuditRepository(database)
	if err != nil {
		return fmt.Errorf("create audit repository: %w", err)
	}
	auditQueryService, err := service.NewAuditQueryService(database, auditRepository)
	if err != nil {
		return fmt.Errorf("create audit query service: %w", err)
	}
	auditHandler, err := v1.NewAuditHandler(auditQueryService)
	if err != nil {
		return fmt.Errorf("create audit handler: %w", err)
	}
	dashboardService, err := service.NewDashboardService(database)
	if err != nil {
		return fmt.Errorf("create dashboard service: %w", err)
	}
	dashboardHandler, err := v1.NewDashboardHandler(dashboardService)
	if err != nil {
		return fmt.Errorf("create dashboard handler: %w", err)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	if oteltrace.Enabled() {
		// HTTP server spans must wrap every other middleware (audit, auth).
		router.Use(otelgin.Middleware("finops-api"))
	}
	router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		logger.Error("panic recovered", "panic", recovered, "stack", string(debug.Stack()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"code":    "INTERNAL_ERROR",
			"message": "internal server error",
			"details": gin.H{},
		})
	}))
	router.Use(v1.RequestAuditMiddleware(auditWriterAdapter{repository: auditRepository}, logger))
	abstractPolicyHandler, err := abstracthandler.NewAbstractPolicyHandler(&awsadapter.AwsAdapter{})
	if err != nil {
		return fmt.Errorf("create abstract policy handler: %w", err)
	}
	router.GET("/healthz", func(ginContext *gin.Context) {
		checkCtx, cancel := context.WithTimeout(ginContext.Request.Context(), startupTimeout)
		defer cancel()
		if err := database.PingContext(checkCtx); err != nil {
			ginContext.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable", "dependency": "postgres"})
			return
		}
		if err := redisClient.Ping(checkCtx).Err(); err != nil {
			ginContext.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable", "dependency": "redis"})
			return
		}
		ginContext.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/readyz", func(ginContext *gin.Context) {
		checkCtx, cancel := context.WithTimeout(ginContext.Request.Context(), startupTimeout)
		defer cancel()
		readinessService, err := service.NewReadinessService(database, redisClient)
		if err != nil {
			ginContext.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "error": err.Error()})
			return
		}
		status := readinessService.CheckReadiness(checkCtx)
		if status.Status != "ready" {
			ginContext.JSON(http.StatusServiceUnavailable, status)
			return
		}
		ginContext.JSON(http.StatusOK, status)
	})
	router.GET("/version", func(ginContext *gin.Context) {
		ginContext.JSON(http.StatusOK, gin.H{"version": version})
	})
	router.GET("/metrics", func(ginContext *gin.Context) {
		// Prometheus output exposes ticket/sync/queue volumes. Keep it
		// internal by default: loopback only, or any caller presenting
		// METRICS_TOKEN as a bearer token.
		if !metricsRequestAllowed(ginContext) {
			ginContext.JSON(http.StatusForbidden, gin.H{"error": "metrics are not exposed to this caller"})
			return
		}
		checkCtx, cancel := context.WithTimeout(ginContext.Request.Context(), startupTimeout)
		defer cancel()
		metricsService, err := service.NewMetricsService(database, redisClient)
		if err != nil {
			ginContext.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		metrics, err := metricsService.RenderMetrics(checkCtx)
		if err != nil {
			ginContext.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		ginContext.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		ginContext.String(http.StatusOK, metrics)
	})
	api := router.Group("/api/v1")
	// Auth config is deliberately public: the SPA must know whether to show
	// the development-user switch or the bearer-token login form.
	router.GET("/api/v1/auth/config", authHandler.Config)
	if config.authMode == "development" {
		api.Use(developmentAuthentication())
	} else {
		api.Use(v1.PlatformTokenAuthentication(tokenService))
	}
	api.GET("/auth/me", authHandler.Me)
	abstracthandler.RegisterAbstractPolicyRoutes(api, abstractPolicyHandler)
	v1.RegisterAWSAccountConfigRoutes(api, accountConfigHandler)
	v1.RegisterAWSAccountQueryRoutes(api, accountQueryHandler)
	v1.RegisterAWSAccountApproverRoutes(api, accountApproverHandler)
	v1.RegisterAWSSyncRunRoutes(api, syncRunHandler)
	v1.RegisterIAMInventoryRoutes(api, inventoryHandler)
	v1.RegisterAuditRoutes(api, auditHandler)
	v1.RegisterDashboardRoutes(api, dashboardHandler)
	v1.RegisterIAMBaselineRoutes(api, baselineHandler)
	v1.RegisterTicketRoutes(api, ticketHandler)
	v1.RegisterPolicyDerivedGrantsRoutes(api, policyDerivedGrantHandler)
	v1.RegisterPlatformTokenRoutes(api, platformTokenHandler)
	v1.RegisterPlatformUserRoutes(api, platformUserHandler)
	provisionHandler, err := v1.NewPlatformProvisionHandler(ticketService)
	if err != nil {
		return fmt.Errorf("create platform provision handler: %w", err)
	}
	v1.RegisterPlatformProvisionRoutes(api, provisionHandler)
	v1.RegisterIAMOwnershipRoutes(api, ownershipHandler)
	v1.RegisterCleanupRoutes(api, cleanupHandler)
	v1.RegisterBaselineJobRoutes(api, baselineJobHandler)
	if baselinePublicationHandler != nil {
		v1.RegisterBaselinePublicationRoutes(api, baselinePublicationHandler)
	}
	// 预约表运维面：列出「谁占着哪个文件」+ 管理员手动释放挂死的预约。
	publishReservationHandler, err := v1.NewPublishReservationHandler(publishReservations, logger)
	if err != nil {
		return fmt.Errorf("create publish reservation handler: %w", err)
	}
	v1.RegisterPublishReservationRoutes(api, publishReservationHandler)
	// 声明快照运维面（phase4 §4.6）：看漂移基准由哪些声明构成、哪些已过期
	// （main 上的 tf 被绕过平台改过），以及手动触发一次新鲜度核对。
	declarationHandler, err := v1.NewBaselineDeclarationHandler(
		declarationService, bundleChecker, bundleTerraformPath, logger)
	if err != nil {
		return fmt.Errorf("create baseline declaration handler: %w", err)
	}
	v1.RegisterBaselineDeclarationRoutes(api, declarationHandler)
	// 漂移发现（phase4 §3/§8）：读取对所有登录角色开放，处置与「立即检测」
	// 限管理员。判定由同步结束点触发，这里的检测是运维兜底。
	// DRIFT_WEBHOOK_URL 配置即用（phase4 §8）：新发现/升级时一条 JSON POST。
	// 未配置时判定照跑，只是不往外推。
	driftNotifier := service.NewDriftNotifier(os.Getenv("DRIFT_WEBHOOK_URL"), logger)
	driftService, err := service.NewDriftService(database, declarationService, logger,
		service.WithDriftNotifier(driftNotifier))
	if err != nil {
		return fmt.Errorf("create drift service: %w", err)
	}
	if driftNotifier != nil {
		logger.Info("drift webhook enabled")
	}
	// 发布冲突升级为 file_conflict 发现（phase4 §6 场景 B）：没有发布器就
	// 没有冲突可记，跳过。
	if baselinePublishService != nil {
		baselinePublishService.SetDriftRecorder(driftService)
	}
	// CI apply 回调可带 publication_id（phase4 §8）：工单 PR 与基线 PR 可能
	// 在同一次 main 提交里一起被 apply。
	if baselinePublishService != nil {
		ticketHandler.SetPublicationReporter(baselinePublishService)
	}
	// 收敛双路（phase4 §7）：只在发布器可用时开放——没有发布器时「接受现状」
	// 无处可发，按钮留着只会骗人。
	driftHandlerOptions := []v1.DriftHandlerOption{}
	if baselinePublishService != nil {
		driftRemediationService, remediationErr := service.NewDriftRemediationService(
			driftService, declarationService, ticketService, baselinePublishService, logger)
		if remediationErr != nil {
			return fmt.Errorf("create drift remediation service: %w", remediationErr)
		}
		driftHandlerOptions = append(driftHandlerOptions,
			v1.WithDriftRemediation(driftRemediationService, baselinePublishService))
	}
	driftHandler, err := v1.NewDriftHandler(driftService, logger, driftHandlerOptions...)
	if err != nil {
		return fmt.Errorf("create drift handler: %w", err)
	}
	v1.RegisterDriftRoutes(api, driftHandler)

	// Git status query
	gitStatusQueryService, err := service.NewGitStatusQueryService(database)
	if err != nil {
		return fmt.Errorf("create git status query service: %w", err)
	}
	gitStatusHandler, err := v1.NewGitStatusHandler(gitStatusQueryService)
	if err != nil {
		return fmt.Errorf("create git status handler: %w", err)
	}
	v1.RegisterGitStatusRoutes(api, gitStatusHandler)

	// Serve the embedded SPA (frontend/dist). API routes above take
	// precedence; unknown non-API paths fall back to index.html so
	// client-side routing (react-router) works on refresh/deep-link.
	distFS, err := fs.Sub(frontend.FS, "dist")
	if err != nil {
		return fmt.Errorf("open embedded frontend dist: %w", err)
	}
	fileServer := http.FileServer(http.FS(distFS))
	spaHandler := func(ginContext *gin.Context) {
		path := strings.TrimPrefix(ginContext.Request.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, statErr := fs.Stat(distFS, path); statErr != nil {
			index, readErr := fs.ReadFile(distFS, "index.html")
			if readErr != nil {
				ginContext.JSON(http.StatusNotFound, gin.H{
					"code": "NOT_FOUND", "message": "frontend not built",
				})
				return
			}
			ginContext.Data(http.StatusOK, "text/html; charset=utf-8", index)
			return
		}
		fileServer.ServeHTTP(ginContext.Writer, ginContext.Request)
	}
	router.GET("/", spaHandler)
	router.NoRoute(func(ginContext *gin.Context) {
		if strings.HasPrefix(ginContext.Request.URL.Path, "/api/") {
			ginContext.JSON(http.StatusNotFound, gin.H{
				"code": "NOT_FOUND", "message": "API endpoint not found",
			})
			return
		}
		if ginContext.Request.Method == http.MethodGet {
			spaHandler(ginContext)
			return
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"code": "NOT_FOUND", "message": "not found",
		})
	})

	server := &http.Server{
		Addr:              config.apiAddress,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("starting IAM governance API",
			"address", config.apiAddress,
			"publisher", config.publisher,
			"auth_mode", config.authMode,
			"iam_candidate_risk_mode", config.candidateRiskMode,
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("serve HTTP: %w", err)
		}
		close(serverErrors)
	}()

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// 陈旧同步清扫：worker 进程崩溃（kill/OOM）后无人写入终态，且 asynq
	// MaxRetry(0) 下任务直接归档不重投。api 是常驻组件，由它周期清理。
	service.StartStaleSyncRunSweeper(shutdownCtx, database, time.Minute, logger)
	select {
	case err := <-serverErrors:
		if err != nil {
			return err
		}
	case <-shutdownCtx.Done():
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	return nil
}

type appConfig struct {
	databaseURL       string
	redisAddress      string
	redisPassword     string
	redisDB           int
	apiAddress        string
	authMode          string
	publisher         string
	awsRegion         string
	awsProfile        string
	awsExternalID     string
	candidateRiskMode service.CandidateRiskMode
}

func loadConfig() (appConfig, error) {
	redisDB := 0
	if raw := strings.TrimSpace(os.Getenv("REDIS_DB")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &redisDB); err != nil || redisDB < 0 {
			return appConfig{}, errors.New("REDIS_DB must be a non-negative integer")
		}
	}
	config := appConfig{
		databaseURL:   strings.TrimSpace(envOrDefault("DATABASE_URL", defaultDatabaseURL)),
		redisAddress:  strings.TrimSpace(envOrDefault("REDIS_ADDR", defaultRedisAddr)),
		redisPassword: os.Getenv("REDIS_PASSWORD"),
		redisDB:       redisDB,
		apiAddress:    strings.TrimSpace(envOrDefault("API_ADDR", defaultAPIAddr)),
		// No implicit development default: a missing AUTH_MODE must fail closed
		// rather than silently enabling the X-User-ID development middleware.
		authMode:      strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_MODE"))),
		publisher:     strings.ToLower(strings.TrimSpace(envOrDefault("PUBLISHER", "github"))),
		awsRegion:     strings.TrimSpace(os.Getenv("AWS_REGION")),
		awsProfile:    strings.TrimSpace(os.Getenv("AWS_PROFILE")),
		awsExternalID: strings.TrimSpace(os.Getenv("AWS_EXTERNAL_ID")),
	}
	candidateRiskMode, err := service.ParseCandidateRiskMode(os.Getenv("IAM_CANDIDATE_RISK_MODE"))
	if err != nil {
		return appConfig{}, err
	}
	config.candidateRiskMode = candidateRiskMode
	if config.databaseURL == "" {
		return appConfig{}, errors.New("DATABASE_URL must not be empty")
	}
	if config.redisAddress == "" {
		return appConfig{}, errors.New("REDIS_ADDR must not be empty")
	}
	if config.apiAddress == "" {
		return appConfig{}, errors.New("API_ADDR must not be empty")
	}
	if config.publisher != "github" && config.publisher != "gitlab" {
		return appConfig{}, errors.New("PUBLISHER must be github or gitlab")
	}
	if config.awsRegion == "" {
		return appConfig{}, errors.New("AWS_REGION is required for AWS account configuration connectivity validation")
	}
	return config, nil
}

// configuredGitHost builds the code-host client used to
// query PR state. Returns (nil, nil) when the publisher is
// unavailable so the abandon guard is skipped rather than
// blocking ticket operations.
func configuredGitHost(config appConfig, logger *slog.Logger) (githost.GitHost, error) {
	switch config.publisher {
	case "github":
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
		if token == "" || repository == "" {
			logger.Warn("PR state guard disabled until GITHUB_TOKEN and GITHUB_REPOSITORY are configured")
			return nil, nil
		}
		// 与 cmd/gitstatus-worker 一致：未配置 GITHUB_API_URL
		// 时回退到 GitHub 公共 API。
		baseURL := strings.TrimSpace(os.Getenv("GITHUB_API_URL"))
		if baseURL == "" {
			baseURL = "https://api.github.com"
		}
		return githost.NewGitHost(githost.GitHostConfig{
			Provider:     "github",
			BaseURL:      baseURL,
			Token:        token,
			ProjectID:    repository,
			TargetBranch: os.Getenv("GITHUB_TARGET_BRANCH"),
		})
	case "gitlab":
		token := strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
		projectID := strings.TrimSpace(os.Getenv("GITLAB_PROJECT_ID"))
		if token == "" || projectID == "" {
			logger.Warn("PR state guard disabled until GITLAB_TOKEN and GITLAB_PROJECT_ID are configured")
			return nil, nil
		}
		baseURL := strings.TrimSpace(os.Getenv("GITLAB_API_URL"))
		if baseURL == "" {
			baseURL = "https://gitlab.com/api/v4"
		}
		return githost.NewGitHost(githost.GitHostConfig{
			Provider:     "gitlab",
			BaseURL:      baseURL,
			Token:        token,
			ProjectID:    projectID,
			TargetBranch: os.Getenv("GITLAB_TARGET_BRANCH"),
		})
	default:
		return nil, nil
	}
}

// configuredGitBaseURL resolves the code-host API base URL for the
// configured publisher: it honors the matching environment variable and
// falls back to the provider's public API, mirroring cmd/gitstatus-worker
// before it was embedded into the API process (gitlab reads
// GITLAB_API_URL, not GITHUB_API_URL).
func configuredGitBaseURL(publisher string) string {
	envVar, fallback := "GITHUB_API_URL", "https://api.github.com"
	if publisher == "gitlab" {
		envVar, fallback = "GITLAB_API_URL", "https://gitlab.com/api/v4"
	}
	if baseURL := strings.TrimSpace(os.Getenv(envVar)); baseURL != "" {
		return baseURL
	}
	return fallback
}

func configuredPublisher(config appConfig, logger *slog.Logger) (service.TicketPublisher, error) {
	switch config.publisher {
	case "github":
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
		if token == "" {
			logger.Warn("GitHub publishing is disabled until GITHUB_TOKEN is configured")
			return unavailablePublisher{provider: "GitHub"}, nil
		}
		return service.NewGitHubPublisher(service.GitHubConfig{
			BaseURL:       os.Getenv("GITHUB_API_URL"),
			Token:         token,
			Repository:    repository,
			TargetBranch:  os.Getenv("GITHUB_TARGET_BRANCH"),
			TerraformPath: os.Getenv("GITHUB_TERRAFORM_PATH"),
		})
	case "gitlab":
		token := strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
		projectID := strings.TrimSpace(os.Getenv("GITLAB_PROJECT_ID"))
		if token == "" && projectID == "" {
			logger.Warn("GitLab publishing is disabled until GITLAB_TOKEN and GITLAB_PROJECT_ID are configured")
			return unavailablePublisher{provider: "GitLab"}, nil
		}
		return service.NewGitLabSDKPublisher(service.GitLabConfig{
			BaseURL:       os.Getenv("GITLAB_API_URL"),
			Token:         token,
			ProjectID:     projectID,
			TargetBranch:  os.Getenv("GITLAB_TARGET_BRANCH"),
			TerraformPath: os.Getenv("GITLAB_TERRAFORM_PATH"),
		})
	default:
		return nil, fmt.Errorf("unsupported publisher %q", config.publisher)
	}
}

type unavailablePublisher struct {
	provider string
}

type auditWriterAdapter struct {
	repository *service.SQLAuditRepository
}

func (writer auditWriterAdapter) WriteAuditEvent(ctx context.Context, record v1.AuditRecord) error {
	return writer.repository.WriteAuditEvent(ctx, service.AuditEvent{
		RequestID:    record.RequestID,
		ActorID:      record.ActorID,
		Action:       record.Action,
		ResourceType: record.ResourceType,
		ResourceID:   record.ResourceID,
		Outcome:      record.Outcome,
		HTTPStatus:   record.HTTPStatus,
		Metadata:     record.Metadata,
		OccurredAt:   record.OccurredAt,
	})
}

func (publisher unavailablePublisher) Publish(
	context.Context,
	model.IAMTicket,
	service.CreateIAMTicketRequest,
	string,
) (*service.TicketPublishResult, error) {
	return nil, fmt.Errorf("%s publishing is not configured", publisher.provider)
}

func (publisher unavailablePublisher) PublishBundle(
	context.Context,
	model.IAMTicket,
	service.CreateIAMTicketRequest,
	[]service.TerraformBundleFile,
) (*service.TicketPublishResult, error) {
	return nil, fmt.Errorf("%s publishing is not configured", publisher.provider)
}

func (publisher unavailablePublisher) FetchTerraformFile(
	context.Context,
	model.IAMTicket,
	service.CreateIAMTicketRequest,
) (string, error) {
	// No code host to ask: report the file as absent so the wild-role path
	// still generates a fresh file (pre-fetch behavior); the sourced path
	// fails loudly with the same "not configured" message as Publish.
	return "", fmt.Errorf("%w: %s publishing is not configured",
		service.ErrTerraformFileNotFound, publisher.provider)
}

func developmentAuthentication() gin.HandlerFunc {
	return func(context *gin.Context) {
		userID := strings.TrimSpace(context.GetHeader("X-User-ID"))
		if userID == "" {
			context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    "UNAUTHORIZED",
				"message": "X-User-ID is required in local development mode",
				"details": gin.H{},
			})
			return
		}
		context.Set(v1.AuthenticatedUserContextKey, userID)
		context.Set(v1.AuthenticatedRolesContextKey, []string{"platform_admin"})
		context.Next()
	}
}

func checkPlatformAuthSchema(ctx context.Context, database *sql.DB) error {
	var available bool
	err := database.QueryRowContext(ctx, `SELECT
		to_regclass('public.platform_role') IS NOT NULL AND
		to_regclass('public.user_role_mapping') IS NOT NULL AND
		to_regclass('public.platform_token') IS NOT NULL`,
	).Scan(&available)
	if err != nil {
		return fmt.Errorf("check platform authentication schema: %w", err)
	}
	if !available {
		return errors.New("platform token/RBAC schema is incomplete; run go run ./cmd/migrate")
	}
	return nil
}

// bootstrapFirstAdmin runs the first-start admin bootstrap. Configuration via
// environment (all optional):
//
//	BOOTSTRAP_ADMIN_USER_ID    default admin
//	BOOTSTRAP_ADMIN_TOKEN_TTL  Go duration, default 2880h (120 days)
//	BOOTSTRAP_ADMIN_TOKEN_FILE path of the token file; empty disables the file
//
// The plaintext token only ever lands in the file; the log records the path
// and the token prefix so the file can be told apart without leaking it.
func bootstrapFirstAdmin(
	ctx context.Context,
	database *sql.DB,
	tokenService *service.PlatformTokenService,
	logger *slog.Logger,
) error {
	store, err := service.NewSQLBootstrapAdminStore(database)
	if err != nil {
		return err
	}
	options := service.BootstrapAdminOptions{
		UserID: strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER_ID")),
	}
	if raw, ok := os.LookupEnv("BOOTSTRAP_ADMIN_TOKEN_TTL"); ok {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return errors.New("BOOTSTRAP_ADMIN_TOKEN_TTL is set but empty")
		}
		ttl, err := time.ParseDuration(raw)
		if err != nil || ttl <= 0 {
			return fmt.Errorf("BOOTSTRAP_ADMIN_TOKEN_TTL %q is not a positive duration: %w", raw, err)
		}
		options.TTL = ttl
	}
	if raw, ok := os.LookupEnv("BOOTSTRAP_ADMIN_TOKEN_FILE"); ok {
		options.TokenFile = strings.TrimSpace(raw)
	} else {
		options.TokenFile = service.BootstrapAdminTokenFileName
	}
	result, err := service.BootstrapAdmin(ctx, store, tokenService, options)
	if err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	if result.Skipped {
		logger.Info("bootstrap admin skipped", "reason", result.Reason, "user", result.UserID)
		return nil
	}
	logger.Info("bootstrap admin token issued",
		"user", result.UserID,
		"token_file", result.TokenFile,
		"token_prefix", result.Token.Prefix,
		"expires_at", result.Token.ExpiresAt,
		"hint", "log in with the token in the file, then revoke it and delete the file",
	)
	return nil
}

func checkSchema(ctx context.Context, database *sql.DB) error {
	var ticketTable, approvalTable, platformUserTable, accountTable, auditTable, accountConfigTable bool
	var baselineTable, validationTable bool
	var groupTable, groupMembershipTable, groupPolicyTable, inventorySnapshotColumns bool
	err := database.QueryRowContext(ctx, `SELECT
		to_regclass('public.iam_ticket') IS NOT NULL,
		to_regclass('public.ticket_approval') IS NOT NULL,
		to_regclass('public.platform_user') IS NOT NULL,
		to_regclass('public.aws_account') IS NOT NULL,
		to_regclass('public.iam_audit_event') IS NOT NULL,
		to_regclass('public.aws_account_config') IS NOT NULL,
		to_regclass('public.iam_baseline') IS NOT NULL,
		to_regclass('public.ticket_validation_record') IS NOT NULL,
		to_regclass('public.iam_group') IS NOT NULL,
		to_regclass('public.iam_group_membership') IS NOT NULL,
		to_regclass('public.iam_group_policy') IS NOT NULL,
		EXISTS (SELECT 1 FROM pg_attribute
			WHERE attrelid = 'public.iam_principal'::regclass
			  AND attname = 'is_deleted' AND NOT attisdropped)`,
	).Scan(
		&ticketTable, &approvalTable, &platformUserTable, &accountTable, &auditTable, &accountConfigTable,
		&baselineTable, &validationTable,
		&groupTable, &groupMembershipTable, &groupPolicyTable, &inventorySnapshotColumns,
	)
	if err != nil {
		return fmt.Errorf("check database schema: %w", err)
	}
	if !ticketTable || !approvalTable || !platformUserTable || !accountTable || !accountConfigTable ||
		!baselineTable || !validationTable ||
		!auditTable || !groupTable || !groupMembershipTable || !groupPolicyTable ||
		!inventorySnapshotColumns {
		return errors.New("database schema is incomplete; run go run ./cmd/migrate to apply pending migrations")
	}
	// 账本比对是权威兜底：手写表/列探针每次迁移都可能漏补（0017 就是），
	// 而嵌入迁移与 schema_migrations 的差集不会漂移。
	pending, err := migrationfiles.Pending(ctx, database)
	if err != nil {
		return fmt.Errorf("check pending migrations: %w", err)
	}
	if len(pending) > 0 {
		return fmt.Errorf("database schema is out of date (pending migrations: %s); run go run ./cmd/migrate",
			strings.Join(pending, ", "))
	}
	return nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// metricsRequestAllowed gates GET /metrics. With METRICS_TOKEN set, the caller
// must present it as a bearer token (constant-time compare). Without a token,
// only loopback scrapers are served, which covers the default single-host
// deployment and keeps the endpoint out of a public listener.
func metricsRequestAllowed(ginContext *gin.Context) bool {
	token := strings.TrimSpace(os.Getenv("METRICS_TOKEN"))
	if token != "" {
		presented := strings.TrimSpace(strings.TrimPrefix(ginContext.GetHeader("Authorization"), "Bearer "))
		return subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1
	}
	return isLoopbackAddress(ginContext.Request.RemoteAddr)
}

func envOrDefault(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}
