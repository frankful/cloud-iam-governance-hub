package v1

import (
	stdcontext "context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

// baselinePublicationService 是发布服务的执行面：handler 创建台账后在后台
// 驱动，HTTP 请求不等「构建 bundle + 数百次 contents API 提交」完成。
type baselinePublicationService interface {
	Create(ctx stdcontext.Context, accountRef, requestedBy string) (*service.BaselinePublication, bool, error)
	CreateBatch(ctx stdcontext.Context, accountRefs []string, requestedBy string) ([]service.BaselineBatchOutcome, error)
	Run(ctx stdcontext.Context, publicationID int64) error
	RunBatch(ctx stdcontext.Context, publicationIDs []int64, aggregate bool) error
	List(ctx stdcontext.Context, accountRef string, limit int) ([]service.BaselinePublication, error)
	Get(ctx stdcontext.Context, publicationID int64) (*service.BaselinePublication, error)
	RecordApplyResult(ctx stdcontext.Context, publicationID int64, actor string,
		result service.BaselineApplyResult) (*service.BaselinePublication, error)
	// Preview 只构建 bundle 并与 main 比对，不落台账：确认框里的差异数
	// 必须与实际发布会算的那一套一致（台账 C10）。
	Preview(ctx stdcontext.Context, accountRef string) (service.BaselinePublishPreview, error)
}

// BaselinePublicationHandler 暴露基线发布（B3）：创建（异步执行）、批量
// （可聚合）、列表、详情。写操作收敛在平台管理员——发布就是向 IaC 仓库
// 推送全账号基线，与预览 job 同一权限档。
type BaselinePublicationHandler struct {
	service baselinePublicationService
	logger  *slog.Logger
}

func NewBaselinePublicationHandler(
	baselinePublishService baselinePublicationService,
	logger *slog.Logger,
) (*BaselinePublicationHandler, error) {
	if baselinePublishService == nil {
		return nil, errors.New("baseline publication service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BaselinePublicationHandler{service: baselinePublishService, logger: logger}, nil
}

func RegisterBaselinePublicationRoutes(router gin.IRoutes, handler *BaselinePublicationHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(
		http.MethodPost,
		"/aws/accounts/:accountID/baseline-publications",
		append(admin, handler.Create)...,
	)
	router.Handle(
		http.MethodGet,
		"/aws/accounts/:accountID/baseline-preview",
		append(admin, handler.Preview)...,
	)
	router.Handle(
		http.MethodPost,
		"/aws/baseline-publications/batch",
		append(admin, handler.CreateBatch)...,
	)
	router.Handle(
		http.MethodGet,
		"/aws/accounts/:accountID/baseline-publications",
		append(admin, handler.List)...,
	)
	router.Handle(
		http.MethodGet,
		"/baseline-publications/:publicationID",
		append(admin, handler.Get)...,
	)
	// CI apply 回调（phase4 §8）：基线发布没有工单号，必须能按 publication 回
	// 报「这份文件到底 apply 了没有」。与工单侧 apply-result 同一套状态值。
	router.Handle(
		http.MethodPost,
		"/aws/baseline-publications/:publicationID/apply-result",
		append(admin, handler.RecordApplyResult)...,
	)
}

// Create 落一条 PUBLISHING 台账并立即在后台发布。202 返回：已发布（幂等
// 命中）时 already_published=true 且直接带既有记录；进行中/新建则前端轮询
// 列表/详情直到 PUBLISHED / FAILED。
func (handler *BaselinePublicationHandler) Create(context *gin.Context) {
	accountRef := strings.TrimSpace(context.Param("accountID"))
	if accountRef == "" {
		writeError(context, http.StatusBadRequest, "accountID must not be empty")
		return
	}
	requestedBy := strings.TrimSpace(context.GetString(AuthenticatedUserContextKey))
	publication, alreadyPublished, err := handler.service.Create(
		context.Request.Context(), accountRef, requestedBy)
	if err != nil {
		handler.writeCreateError(context, err)
		return
	}
	if alreadyPublished {
		// 幂等命中（D4：同 run 不重发）：返回 200 + 既有记录，不开新分支。
		context.JSON(http.StatusOK, gin.H{
			"publication":       publication,
			"already_published": true,
		})
		return
	}
	// 已有发布在跑（in_flight）时只返回台账，不再驱动一次：Run 的领取不是
	// 原子的，两个 goroutine 同时提交同一分支会以 409（contents API 的 sha
	// 冲突）收场，用户看到的是「发布失败」而不是「已在发布中」。
	if !publication.InFlight {
		handler.spawnRun(publication.ID, false)
	}
	context.JSON(http.StatusAccepted, gin.H{
		"publication":       publication,
		"already_published": false,
	})
}

// Preview 返回「点发布之前」的差异概览（台账 C10）：多少个文件、其中多少
// 已在 main 上一致、多少个会被推送、多少属于冲突。只读：构建 bundle 并比对，
// 不落台账、不占预约——预约是真实发布时才做的事，预览承诺不了。
func (handler *BaselinePublicationHandler) Preview(context *gin.Context) {
	accountRef := strings.TrimSpace(context.Param("accountID"))
	if accountRef == "" {
		writeError(context, http.StatusBadRequest, "accountID must not be empty")
		return
	}
	preview, err := handler.service.Preview(context.Request.Context(), accountRef)
	if err != nil {
		handler.writeCreateError(context, err)
		return
	}
	context.JSON(http.StatusOK, preview)
}

type baselineBatchCreateRequest struct {
	AccountRefs []string `json:"account_refs"`
	// Aggregate=true 时同一快照 run 的多账号文件进同一分支开一个 PR
	//（D7 批量选项）；默认 false = 逐账号独立分支与 PR。
	Aggregate bool `json:"aggregate"`
}

// CreateBatch 批量发布。每个账号独立台账（幂等键不变）；聚合模式下各行
// 共享批次分支与 PR。部分账号失败不影响其余账号。
func (handler *BaselinePublicationHandler) CreateBatch(context *gin.Context) {
	var request baselineBatchCreateRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	refs := make([]string, 0, len(request.AccountRefs))
	seen := map[string]bool{}
	for _, ref := range request.AccountRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		writeError(context, http.StatusBadRequest, "account_refs must not be empty")
		return
	}
	requestedBy := strings.TrimSpace(context.GetString(AuthenticatedUserContextKey))
	outcomes, err := handler.service.CreateBatch(
		context.Request.Context(), refs, requestedBy)
	if err != nil {
		handler.writeCreateError(context, err)
		return
	}

	// 收集需要执行的台账：已发布/失败解析的账号原样返回，不进执行队列。
	ids := make([]int64, 0, len(outcomes))
	publishable := 0
	for _, outcome := range outcomes {
		if outcome.Publication != nil && !outcome.AlreadyPublished &&
			!outcome.Publication.InFlight &&
			outcome.Publication.Status == service.BaselinePublicationStatusPublishing {
			ids = append(ids, outcome.Publication.ID)
			publishable++
		}
	}
	if publishable > 0 {
		handler.spawnRunBatch(ids, request.Aggregate)
	}
	context.JSON(http.StatusAccepted, gin.H{"outcomes": outcomes})
}

func (handler *BaselinePublicationHandler) List(context *gin.Context) {
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
	publications, err := handler.service.List(context.Request.Context(), accountRef, limit)
	if err != nil {
		writeError(context, http.StatusInternalServerError, "failed to list baseline publications")
		return
	}
	context.JSON(http.StatusOK, gin.H{"publications": publications})
}

func (handler *BaselinePublicationHandler) Get(context *gin.Context) {
	publicationID, err := strconv.ParseInt(strings.TrimSpace(context.Param("publicationID")), 10, 64)
	if err != nil || publicationID <= 0 {
		writeError(context, http.StatusBadRequest, "publicationID must be a positive integer")
		return
	}
	publication, err := handler.service.Get(context.Request.Context(), publicationID)
	if err != nil {
		if errors.Is(err, service.ErrBaselinePublicationNotFound) {
			writeError(context, http.StatusNotFound, err.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to load baseline publication")
		return
	}
	context.JSON(http.StatusOK, gin.H{"publication": publication})
}

func (handler *BaselinePublicationHandler) writeCreateError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrBaselineAccountNotFound):
		writeError(context, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrBaselineNoSyncRun):
		// 幂等键依赖快照 run：没有成功同步就没有基线代次，先同步再发布。
		writeError(context, http.StatusConflict, err.Error())
	default:
		writeError(context, http.StatusInternalServerError, "failed to create baseline publication")
	}
}

// spawnRun / spawnRunBatch 与预览 job 相同的后台模式：上下文与请求解耦，
// panic 兜底，卡住的行由 SweepStale 收尾。
func (handler *BaselinePublicationHandler) spawnRun(publicationID int64, _ bool) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				handler.logger.Error("baseline publication worker panicked",
					"publication_id", publicationID, "panic", recovered)
			}
		}()
		if runErr := handler.service.Run(stdcontext.Background(), publicationID); runErr != nil {
			handler.logger.Warn("baseline publication finished with error",
				"publication_id", publicationID, "error", runErr)
		}
	}()
}

func (handler *BaselinePublicationHandler) spawnRunBatch(publicationIDs []int64, aggregate bool) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				handler.logger.Error("baseline batch publication worker panicked",
					"publications", publicationIDs, "panic", recovered)
			}
		}()
		if runErr := handler.service.RunBatch(stdcontext.Background(), publicationIDs, aggregate); runErr != nil {
			handler.logger.Warn("baseline batch publication finished with error",
				"publications", publicationIDs, "error", runErr)
		}
	}()
}

type baselineApplyResultRequest struct {
	Status    string `json:"status"`
	CommitSHA string `json:"commit_sha"`
	CIURL     string `json:"ci_url"`
	Note      string `json:"note"`
}

// RecordApplyResult handles POST /aws/baseline-publications/:publicationID/apply-result
//
// 与工单侧 apply-result 同一套状态值（succeeded / failed），区别只是这里没有
// 工单可关：成功只把发布标记为「已应用」，失败只记日志。合并 ≠ 生效——这条
// 回调是平台知道「基线真的落地了」的唯一途径。
func (handler *BaselinePublicationHandler) RecordApplyResult(context *gin.Context) {
	publicationID, err := strconv.ParseInt(strings.TrimSpace(context.Param("publicationID")), 10, 64)
	if err != nil || publicationID <= 0 {
		writeError(context, http.StatusBadRequest, "publication id must be a positive integer")
		return
	}
	var request baselineApplyResultRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	actor := strings.TrimSpace(context.GetString(AuthenticatedUserContextKey))
	publication, err := handler.service.RecordApplyResult(
		context.Request.Context(), publicationID, actor, service.BaselineApplyResult{
			Status:    strings.ToLower(strings.TrimSpace(request.Status)),
			CommitSHA: request.CommitSHA,
			CIURL:     request.CIURL,
			Note:      request.Note,
		})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrBaselinePublicationNotFound):
			writeError(context, http.StatusNotFound, err.Error())
		case isValidationError(err):
			writeError(context, http.StatusBadRequest, err.Error())
		default:
			handler.logger.Error("failed to record baseline apply result",
				"publication_id", publicationID, "error", err)
			writeError(context, http.StatusInternalServerError, "failed to record apply result")
		}
		return
	}
	context.JSON(http.StatusOK, gin.H{"publication": publication})
}
