package v1

import (
	stdcontext "context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

// baselineJobRunner 是 job 服务的执行面：handler 创建 job 后驱动执行（入队给
// sync-worker 或进程内 goroutine），HTTP 请求不等构建完成（bundle 可能上百
// 个文件，且文件存在性检查走远端 API）。
type baselineJobRunner interface {
	Create(ctx stdcontext.Context, accountRef, requestedBy string) (*service.BaselinePreviewJob, error)
	Enqueuer() service.BaselinePreviewJobEnqueuer
	Fail(ctx stdcontext.Context, jobID int64, cause error) error
	Run(ctx stdcontext.Context, jobID int64) error
	List(ctx stdcontext.Context, accountRef string, limit int) ([]service.BaselinePreviewJob, error)
	Get(ctx stdcontext.Context, jobID int64) (*service.BaselinePreviewJob, error)
}

// BaselineJobHandler 暴露基线预览 job：创建（异步执行）、列表、详情。
// 预览是发布（B3）的前置审查材料，写操作收敛在平台管理员；列表与详情
// 同样收管理员——bundle 内容等于全账号 IAM 现状，不进普通用户的视野。
type BaselineJobHandler struct {
	service baselineJobRunner
	logger  *slog.Logger
}

func NewBaselineJobHandler(baselineJobService baselineJobRunner, logger *slog.Logger) (*BaselineJobHandler, error) {
	if baselineJobService == nil {
		return nil, errors.New("baseline preview job service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BaselineJobHandler{service: baselineJobService, logger: logger}, nil
}

func RegisterBaselineJobRoutes(router gin.IRoutes, handler *BaselineJobHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(
		http.MethodPost,
		"/aws/accounts/:accountID/baseline-jobs",
		append(admin, handler.Create)...,
	)
	router.Handle(
		http.MethodGet,
		"/aws/accounts/:accountID/baseline-jobs",
		append(admin, handler.List)...,
	)
	router.Handle(
		http.MethodGet,
		"/baseline-jobs/:jobID",
		append(admin, handler.Get)...,
	)
}

// Create 落一条 PENDING job 并立即在后台执行。返回 202：结果要看详情，
// 前端轮询列表/详情直到终态。
func (handler *BaselineJobHandler) Create(context *gin.Context) {
	accountRef := strings.TrimSpace(context.Param("accountID"))
	if accountRef == "" {
		writeError(context, http.StatusBadRequest, "accountID must not be empty")
		return
	}
	requestedBy := strings.TrimSpace(context.GetString(AuthenticatedUserContextKey))
	job, err := handler.service.Create(context.Request.Context(), accountRef, requestedBy)
	if err != nil {
		if errors.Is(err, service.ErrBaselineAccountNotFound) {
			writeError(context, http.StatusNotFound, err.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to create baseline preview job")
		return
	}
	// 执行面二选一：注入了队列执行面时入队给 sync-worker（API 进程不背构建），
	// 否则回退进程内后台 goroutine（单进程模式 / 测试）。两种方式的失败都会
	// 写进 job 行；panic 也兜住——构建代码的一次意外不能带崩整个进程，卡在
	// RUNNING 的 job 由 SweepStale 收尾。入队失败直接把 job 落 FAILED，避免
	// 永远停在 PENDING。
	if enqueuer := handler.service.Enqueuer(); enqueuer != nil {
		if enqueueErr := enqueuer.EnqueuePreviewJob(stdcontext.Background(), job.ID); enqueueErr != nil {
			handler.logger.Error("failed to enqueue baseline preview job",
				"job_id", job.ID, "error", enqueueErr)
			_ = handler.service.Fail(stdcontext.Background(), job.ID,
				fmt.Errorf("enqueue failed: %w", enqueueErr))
			writeError(context, http.StatusInternalServerError, "failed to enqueue baseline preview job")
			return
		}
		context.JSON(http.StatusAccepted, gin.H{"job": job})
		return
	}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				handler.logger.Error("baseline preview job worker panicked",
					"job_id", job.ID, "panic", recovered)
			}
		}()
		if runErr := handler.service.Run(stdcontext.Background(), job.ID); runErr != nil {
			handler.logger.Warn("baseline preview job finished with error",
				"job_id", job.ID, "error", runErr)
		}
	}()
	context.JSON(http.StatusAccepted, gin.H{"job": job})
}

func (handler *BaselineJobHandler) List(context *gin.Context) {
	accountRef := strings.TrimSpace(context.Param("accountID"))
	if accountRef == "" {
		writeError(context, http.StatusBadRequest, "accountID must not be empty")
		return
	}
	limit := 20
	if raw := strings.TrimSpace(context.Query("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	jobs, err := handler.service.List(context.Request.Context(), accountRef, limit)
	if err != nil {
		if errors.Is(err, service.ErrBaselineAccountNotFound) {
			writeError(context, http.StatusNotFound, err.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to list baseline preview jobs")
		return
	}
	context.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

func (handler *BaselineJobHandler) Get(context *gin.Context) {
	jobID, err := strconv.ParseInt(strings.TrimSpace(context.Param("jobID")), 10, 64)
	if err != nil || jobID <= 0 {
		writeError(context, http.StatusBadRequest, "jobID must be a positive integer")
		return
	}
	job, err := handler.service.Get(context.Request.Context(), jobID)
	if err != nil {
		if errors.Is(err, service.ErrBaselineJobNotFound) {
			writeError(context, http.StatusNotFound, err.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to load baseline preview job")
		return
	}
	context.JSON(http.StatusOK, gin.H{"job": job})
}
