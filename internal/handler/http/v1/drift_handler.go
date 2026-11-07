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

// driftService 是漂移发现的读写面（phase4 §8）。读取对所有登录角色开放：
// 漂移是给人看的，不是管理员内部信息。
type driftService interface {
	List(ctx stdcontext.Context, filter service.DriftFilter) (service.DriftFindingPage, error)
	GetFinding(ctx stdcontext.Context, id int64) (service.DriftFinding, error)
	ApplyAction(ctx stdcontext.Context, id int64, action, actor string) (service.DriftFinding, error)
	SummarizeAccounts(ctx stdcontext.Context, awsAccountID string) ([]service.DriftAccountSummary, error)
	EvaluateAccount(ctx stdcontext.Context, accountDBID int64) (service.DriftEvaluation, error)
	IngestCIReport(ctx stdcontext.Context, report service.CIReport) (service.CIReportResult, error)
}

// DriftHandler 暴露漂移发现。判定本身由同步结束点触发，这里的「立即检测」
// 只是运维兜底：判定会覆盖该账号全部声明，代价是一次全量库存读取。
type DriftHandler struct {
	service      driftService
	remediation  driftRemediationService
	publications driftPublicationRunner
	logger       *slog.Logger
}

// driftRemediationService 是收敛双路（phase4 §7）的执行面：追认 = 重发基线，
// 回滚 = 按声明快照建一张 UPDATE_* 草稿。
type driftRemediationService interface {
	Acknowledge(ctx stdcontext.Context, findingID int64, actor string) (service.DriftRemediation, error)
	Rollback(ctx stdcontext.Context, findingID int64, actor string) (service.DriftRemediation, error)
}

// driftPublicationRunner 让「接受现状」复用基线发布的后台执行：Create 只落
// 台账，真正的 bundling / 推分支由这里 spawn。
type driftPublicationRunner interface {
	Run(ctx stdcontext.Context, publicationID int64) error
}

// DriftHandlerOption 让收敛双路按需装配：只读部署（或单测）不配也能起服务，
// 此时 remediate 明确回 501，而不是假装成功。
type DriftHandlerOption func(*DriftHandler) error

func WithDriftRemediation(
	remediation driftRemediationService,
	publications driftPublicationRunner,
) DriftHandlerOption {
	return func(handler *DriftHandler) error {
		if remediation == nil {
			return errors.New("drift remediation service must not be nil")
		}
		if publications == nil {
			return errors.New("baseline publication runner must not be nil")
		}
		handler.remediation = remediation
		handler.publications = publications
		return nil
	}
}

func NewDriftHandler(
	drift driftService,
	logger *slog.Logger,
	options ...DriftHandlerOption,
) (*DriftHandler, error) {
	if drift == nil {
		return nil, errors.New("drift service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	handler := &DriftHandler{service: drift, logger: logger}
	for _, option := range options {
		if err := option(handler); err != nil {
			return nil, err
		}
	}
	return handler, nil
}

func RegisterDriftRoutes(router gin.IRoutes, handler *DriftHandler) {
	readers := []gin.HandlerFunc{RequireRoles("platform_admin", "approval_admin", "standard_user")}
	admins := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodGet, "/drift-findings", append(readers, handler.List)...)
	router.Handle(http.MethodGet, "/drift-findings/summary", append(readers, handler.Summary)...)
	router.Handle(http.MethodGet, "/drift-findings/:id", append(readers, handler.Get)...)
	// 处置改变的是「要不要处理」这一判断，不是配置本身；仍收敛在管理员，
	// 避免忽略动作变成绕过审计的静音按钮。
	router.Handle(http.MethodPost, "/drift-findings/:id/ignore", append(admins, handler.Ignore)...)
	router.Handle(http.MethodPost, "/drift-findings/:id/reopen", append(admins, handler.Reopen)...)
	router.Handle(http.MethodPost, "/drift-findings/:id/resolve", append(admins, handler.Resolve)...)
	// 收敛双路：追认要往 IaC 仓库推全账号基线，回滚要开变更工单，都与
	// 「忽略」不在一个量级，同样收敛在平台管理员。
	router.Handle(http.MethodPost, "/drift-findings/:id/remediate", append(admins, handler.Remedy)...)
	router.Handle(http.MethodPost, "/drift-findings/check", append(admins, handler.Check)...)
	// CI plan-only 上报（phase4 §8）。用 CI runner 的专用 platform token 调用，
	// 与 apply-result 同一个信任级别：它能写发现表，但改不了配置与工单。
	router.Handle(http.MethodPost, "/aws/drift-reports", append(admins, handler.ReportCI)...)
}

// List handles GET /drift-findings?account_id=&status=&severity=&change_type=&include_resolved=&page=&page_size=
func (handler *DriftHandler) List(context *gin.Context) {
	filter := service.DriftFilter{
		AWSAccountID: strings.TrimSpace(context.Query("account_id")),
		Status:       strings.ToUpper(strings.TrimSpace(context.Query("status"))),
		Severity:     strings.ToUpper(strings.TrimSpace(context.Query("severity"))),
		ChangeType:   strings.TrimSpace(context.Query("change_type")),
	}
	filter.IncludeResolved = strings.EqualFold(context.Query("include_resolved"), "true")
	if raw := strings.TrimSpace(context.Query("page")); raw != "" {
		page, err := strconv.Atoi(raw)
		if err != nil || page <= 0 {
			writeError(context, http.StatusBadRequest, "page must be a positive integer")
			return
		}
		filter.Page = page
	}
	if raw := strings.TrimSpace(context.Query("page_size")); raw != "" {
		size, err := strconv.Atoi(raw)
		if err != nil || size <= 0 || size > 200 {
			writeError(context, http.StatusBadRequest, "page_size must be between 1 and 200")
			return
		}
		filter.PageSize = size
	}
	if filter.Status != "" && !isDriftStatus(filter.Status) {
		writeError(context, http.StatusBadRequest,
			"status must be one of: SUSPECT, OPEN, PENDING, PENDING_REBASELINE, IGNORED")
		return
	}

	page, err := handler.service.List(context.Request.Context(), filter)
	if err != nil {
		handler.logger.Error("failed to list drift findings", "error", err)
		writeError(context, http.StatusInternalServerError, "failed to list drift findings")
		return
	}
	context.JSON(http.StatusOK, page)
}

// Get handles GET /drift-findings/:id
func (handler *DriftHandler) Get(context *gin.Context) {
	id, ok := driftFindingID(context)
	if !ok {
		return
	}
	finding, err := handler.service.GetFinding(context.Request.Context(), id)
	if err != nil {
		handler.writeLookupError(context, id, err)
		return
	}
	context.JSON(http.StatusOK, finding)
}

// Summary handles GET /drift-findings/summary?account_id=
// 返回每个账号的声明覆盖、未解决计数与心跳：0 条漂移和「从未检测」在页面上
// 必须是两种不同的样子。
func (handler *DriftHandler) Summary(context *gin.Context) {
	summaries, err := handler.service.SummarizeAccounts(
		context.Request.Context(), strings.TrimSpace(context.Query("account_id")))
	if err != nil {
		handler.logger.Error("failed to summarize drift accounts", "error", err)
		writeError(context, http.StatusInternalServerError, "failed to summarize drift accounts")
		return
	}
	context.JSON(http.StatusOK, gin.H{"accounts": summaries, "total": len(summaries)})
}

func (handler *DriftHandler) Ignore(context *gin.Context) {
	handler.applyAction(context, service.DriftActionIgnore)
}

func (handler *DriftHandler) Reopen(context *gin.Context) {
	handler.applyAction(context, service.DriftActionReopen)
}

func (handler *DriftHandler) Resolve(context *gin.Context) {
	handler.applyAction(context, service.DriftActionResolve)
}

func (handler *DriftHandler) applyAction(context *gin.Context, action string) {
	id, ok := driftFindingID(context)
	if !ok {
		return
	}
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	finding, err := handler.service.ApplyAction(context.Request.Context(), id, action, actorID)
	if err != nil {
		handler.writeLookupError(context, id, err)
		return
	}
	context.JSON(http.StatusOK, finding)
}

type driftCheckRequest struct {
	AccountID int64 `json:"account_id"`
}

// Check handles POST /drift-findings/check
// body: {"account_id": 12}
func (handler *DriftHandler) Check(context *gin.Context) {
	var request driftCheckRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if request.AccountID <= 0 {
		writeError(context, http.StatusBadRequest, "account_id must be a positive integer")
		return
	}
	evaluation, err := handler.service.EvaluateAccount(context.Request.Context(), request.AccountID)
	if err != nil {
		handler.logger.Error("failed to evaluate drift", "account_id", request.AccountID, "error", err)
		writeError(context, http.StatusInternalServerError, "failed to evaluate drift")
		return
	}
	context.JSON(http.StatusOK, evaluation)
}

// ReportCI handles POST /aws/drift-reports
// body: {"account_id":"123456789012","commit_sha":"...","ci_url":"...",
//
//	"findings":[{"resource_address":"aws_iam_role.foo","change_type":"attribute",...}]}
//
// 一次上报 = 一次完整 plan 的结果，语义是替换：本轮没报的 ci 发现会被关闭。
// 空 findings 是合法输入，表示 plan 干净——这是这条链路最有价值的信号。
func (handler *DriftHandler) ReportCI(context *gin.Context) {
	var report service.CIReport
	if err := context.ShouldBindJSON(&report); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	actorID, _ := authenticatedUser(context)
	result, err := handler.service.IngestCIReport(context.Request.Context(), report)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDriftAccountNotFound):
			writeError(context, http.StatusNotFound, err.Error())
		case isValidationError(err):
			writeError(context, http.StatusBadRequest, err.Error())
		default:
			handler.logger.Error("failed to ingest CI drift report",
				"account_id", report.AWSAccountID, "actor", actorID, "error", err)
			writeError(context, http.StatusInternalServerError, "failed to ingest drift report")
		}
		return
	}
	context.JSON(http.StatusOK, result)
}

type driftRemediateRequest struct {
	Route string `json:"route"`
}

// Remedy handles POST /drift-findings/:id/remediate
// body: {"route": "acknowledge" | "rollback"}
//
// 两条路都不替人做决定：追认只是重发基线（把现状写成代码），回滚只生成一张
// 待提交的草稿。真正的变更仍然要过审批与 apply。
func (handler *DriftHandler) Remedy(context *gin.Context) {
	id, ok := driftFindingID(context)
	if !ok {
		return
	}
	if handler.remediation == nil {
		writeError(context, http.StatusNotImplemented, "drift remediation is not configured")
		return
	}
	var request driftRemediateRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	route := strings.ToLower(strings.TrimSpace(request.Route))
	var (
		plan service.DriftRemediation
		err  error
	)
	switch route {
	case service.DriftRouteAcknowledge:
		plan, err = handler.remediation.Acknowledge(context.Request.Context(), id, actorID)
		// 幂等命中（同一次同步已发过）或在途（已经有人在跑）都不再 spawn；
		// 只有新建出来的台账才需要驱动。
		if err == nil && plan.Publication != nil && !plan.AlreadyPublished && !plan.InFlight {
			handler.spawnPublicationRun(plan.Publication.ID)
		}
	case service.DriftRouteRollback:
		plan, err = handler.remediation.Rollback(context.Request.Context(), id, actorID)
	default:
		writeError(context, http.StatusBadRequest, "route must be acknowledge or rollback")
		return
	}
	if err != nil {
		handler.writeRemediationError(context, id, err)
		return
	}
	context.JSON(http.StatusOK, plan)
}

// spawnPublicationRun 与基线发布 handler 同款：HTTP 不等 bundling 与推分支，
// 失败只记日志（台账里已有 FAILED 状态，页面看得到）。
func (handler *DriftHandler) spawnPublicationRun(publicationID int64) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				handler.logger.Error("drift acknowledge publication panicked",
					"publication_id", publicationID, "panic", recovered)
			}
		}()
		if runErr := handler.publications.Run(stdcontext.Background(), publicationID); runErr != nil {
			handler.logger.Warn("drift acknowledge publication finished with error",
				"publication_id", publicationID, "error", runErr)
		}
	}()
}

func (handler *DriftHandler) writeRemediationError(context *gin.Context, id int64, err error) {
	switch {
	case errors.Is(err, service.ErrDriftFindingNotFound):
		writeError(context, http.StatusNotFound, "drift finding not found")
	case isValidationError(err):
		// 草稿被工单校验拒（在途工单冲突、角色不在库存等）：把原因原样
		// 交给页面，运维才知道是「改不了」还是「现在不能改」。
		writeError(context, http.StatusBadRequest, err.Error())
	default:
		handler.logger.Error("drift remediation failed", "id", id, "error", err)
		writeError(context, http.StatusInternalServerError, "drift remediation failed")
	}
}

func (handler *DriftHandler) writeLookupError(context *gin.Context, id int64, err error) {
	if errors.Is(err, service.ErrDriftFindingNotFound) {
		writeError(context, http.StatusNotFound, "drift finding not found")
		return
	}
	handler.logger.Error("drift finding operation failed", "id", id, "error", err)
	writeError(context, http.StatusInternalServerError, "drift finding operation failed")
}

func driftFindingID(context *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(context.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		writeError(context, http.StatusBadRequest, "drift finding id must be a positive integer")
		return 0, false
	}
	return id, true
}

func isDriftStatus(status string) bool {
	switch strings.ToUpper(status) {
	case service.DriftStatusSuspect, service.DriftStatusOpen, service.DriftStatusPending,
		service.DriftStatusPendingRebaseline, service.DriftStatusIgnored:
		return true
	default:
		return false
	}
}
