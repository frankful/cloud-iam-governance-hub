package v1

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

const AuthenticatedUserContextKey = "authenticated_user"

type ticketService interface {
	CreateTicket(ctx context.Context, submitter string, request service.CreateIAMTicketRequest) (model.IAMTicket, error)
	CreateDraft(ctx context.Context, submitter string, request service.CreateIAMTicketRequest) (model.IAMTicket, error)
	SubmitTicket(ctx context.Context, ticketNo, actorID string, roles []string) (model.IAMTicket, error)
	GetTicket(ctx context.Context, ticketNo string) (model.IAMTicket, error)
	GetTicketForActor(ctx context.Context, ticketNo, actorID string, roles []string) (model.IAMTicket, error)
	PreviewTicketTerraform(ctx context.Context, ticketNo, actorID string, roles []string) (string, error)
	GetApprovalInfo(ctx context.Context, ticketNo string) (model.TicketApprovalInfo, error)
	ListAvailableApprovers(ctx context.Context, accountID *int64) ([]model.PlatformUser, error)
	ListTickets(ctx context.Context, filter service.TicketListFilter) ([]model.IAMTicket, int64, error)
	PreviewValidation(ctx context.Context, submitter string, request service.CreateIAMTicketRequest) (service.TicketValidationSnapshot, error)
	Decide(ctx context.Context, ticketNo, approver string, decision service.TicketDecision) (model.IAMTicket, error)
	RetryPublication(ctx context.Context, ticketNo string) (model.IAMTicket, error)
	RearmPolling(ctx context.Context, ticketNo string) error
	CloseTicket(ctx context.Context, ticketNo, actorID, reason, comment string, triggerSync bool) (model.IAMTicket, error)
	RecordCIApplyResult(ctx context.Context, ticketNo, actorID string, result service.CIApplyResult) (model.IAMTicket, bool, error)
}

// publicationApplyReporter 是 apply 回调里「把基线发布标记为已应用」的最小
// 依赖。工单 PR 与基线 PR 可能在同一批 main 提交里一起被 apply，CI 带上
// publication_id 就能把两边对上。
type publicationApplyReporter interface {
	Get(ctx context.Context, publicationID int64) (*service.BaselinePublication, error)
	RecordApplyResult(ctx context.Context, publicationID int64, actor string,
		result service.BaselineApplyResult) (*service.BaselinePublication, error)
}

type TicketHandler struct {
	service      ticketService
	publications publicationApplyReporter
}

// TicketHandlerOption 按需装配外围依赖：只读或单测环境不配 publication 也能
// 起服务，此时带 publication_id 的回调明确回 501。
type TicketHandlerOption func(*TicketHandler) error

func WithTicketPublicationReporter(reporter publicationApplyReporter) TicketHandlerOption {
	return func(handler *TicketHandler) error {
		if reporter == nil {
			return errors.New("publication apply reporter must not be nil")
		}
		handler.publications = reporter
		return nil
	}
}

// SetPublicationReporter 在装配后期注入（发布服务在工单服务之后构造）。
// 未注入时带 publication_id 的回调回 501，其余行为不变。
func (handler *TicketHandler) SetPublicationReporter(reporter publicationApplyReporter) {
	handler.publications = reporter
}

func NewTicketHandler(ticketService ticketService, options ...TicketHandlerOption) (*TicketHandler, error) {
	if ticketService == nil {
		return nil, errors.New("ticket service must not be nil")
	}
	handler := &TicketHandler{service: ticketService}
	for _, option := range options {
		if err := option(handler); err != nil {
			return nil, err
		}
	}
	return handler, nil
}

// RegisterTicketRoutes registers the IAM ticket API routes. Authentication
// middleware must set AuthenticatedUserContextKey on the Gin context.
func RegisterTicketRoutes(router gin.IRoutes, handler *TicketHandler) {
	router.GET("/tickets", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.List)
	router.POST("/tickets", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.Create)
	router.POST("/tickets/validate", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.Validate)
	router.POST("/tickets/:ticketNo/submit", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.Submit)
	router.GET("/tickets/:ticketNo", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.Get)
	router.GET("/tickets/:ticketNo/terraform", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.TerraformPreview)
	router.GET("/tickets/:ticketNo/approval", RequireRoles("platform_admin", "approval_admin"), handler.GetApprovalInfo)
	router.POST("/tickets/:ticketNo/decision", RequireRoles("platform_admin", "approval_admin"), handler.Decide)
	router.POST("/tickets/:ticketNo/publish", RequireRoles("platform_admin"), handler.RetryPublication)
	router.POST("/tickets/:ticketNo/poll", RequireRoles("platform_admin"), handler.RearmPoll)
	router.POST("/tickets/:ticketNo/close", RequireRoles("platform_admin"), handler.Close)
	// 预留：CI 自动 apply 后的回调入口（A1）。当前默认流程不变（合并后
	// 延迟关单同步）；CI 接入后改调本接口，立即关单并触发同步。
	// 认证使用为 CI runner 签发的专用 platform token（platform_admin）。
	router.POST("/tickets/:ticketNo/apply-result", RequireRoles("platform_admin"), handler.RecordCIApplyResult)
	router.GET("/approvers", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.ListApprovers)
}

func (handler *TicketHandler) Create(context *gin.Context) {
	submitter, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}

	var request service.CreateIAMTicketRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	if !requirePolicyPayload(context, request) {
		return
	}

	ticket, err := handler.service.CreateDraft(context.Request.Context(), submitter, request)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusCreated, gin.H{"ticket": ticket})
}

// List handles GET /tickets — paged, filtered ticket list for the list page
// and dashboards. Query parameters: status (comma separated), account_id,
// submitter, ticket_type, q (ticket_no/principal keyword), limit, offset.
func (handler *TicketHandler) List(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	filter := service.TicketListFilter{
		Submitter:  strings.TrimSpace(context.Query("submitter")),
		TicketType: strings.TrimSpace(context.Query("ticket_type")),
		Keyword:    strings.TrimSpace(context.Query("q")),
		Limit:      20,
	}
	// Standard users may only page through their own tickets. Admins retain
	// the ability to filter by any submitter (or leave it empty for all).
	if !hasAnyRole(authenticatedRoles(context), "platform_admin", "approval_admin") {
		filter.Submitter = actorID
	}
	if raw := strings.TrimSpace(context.Query("status")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			if status := strings.TrimSpace(part); status != "" {
				filter.Statuses = append(filter.Statuses, status)
			}
		}
	}
	if raw := strings.TrimSpace(context.Query("account_id")); raw != "" {
		accountID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || accountID <= 0 {
			writeError(context, http.StatusBadRequest, "account_id must be a positive integer")
			return
		}
		filter.AccountID = &accountID
	}
	if raw := strings.TrimSpace(context.Query("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			writeError(context, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		filter.Limit = limit
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if raw := strings.TrimSpace(context.Query("offset")); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			writeError(context, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		filter.Offset = offset
	}
	tickets, total, err := handler.service.ListTickets(context.Request.Context(), filter)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	if tickets == nil {
		tickets = []model.IAMTicket{}
	}
	context.JSON(http.StatusOK, gin.H{
		"tickets": tickets,
		"total":   total,
		"limit":   filter.Limit,
		"offset":  filter.Offset,
	})
}

// Validate handles POST /tickets/validate — realtime DSL pre-validation that
// runs the same checks as submit without persisting anything. Returns the
// validation snapshot on success; baseline violations and blocking risk
// findings come back as 422 with structured details.
func (handler *TicketHandler) Validate(context *gin.Context) {
	submitter, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	var request service.CreateIAMTicketRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	if !requirePolicyPayload(context, request) {
		return
	}
	snapshot, err := handler.service.PreviewValidation(context.Request.Context(), submitter, request)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"validation": snapshot})
}

// requirePolicyPayload writes a 400 when a ticket needs a policy payload but
// carries neither request_policy nor abstract_policy. Resource-creation
// tickets carry their policy data in type-specific configuration instead.
func requirePolicyPayload(context *gin.Context, request service.CreateIAMTicketRequest) bool {
	if request.TicketType == service.TicketTypeAttachUserPolicy ||
		request.TicketType == service.TicketTypeRollback ||
		request.TicketType == service.TicketTypeUpdateRole ||
		request.TicketType == service.TicketTypeUpdateManagedPolicy ||
		request.TicketType == service.TicketTypeUpdateGroupInlinePolicy ||
		request.TicketType == service.TicketTypeUpdateGroupMembership {
		return true
	}
	if request.TicketType == service.TicketTypeAdoptRoleInlinePolicies &&
		strings.TrimSpace(request.PrincipalName) != "" {
		// Batch adoption snapshots the policy documents from inventory on the
		// server, so it intentionally has no request_policy/abstract_policy.
		return true
	}
	switch request.TicketType {
	case service.TicketTypeCreateRole:
		if strings.TrimSpace(request.Role.Name) != "" && len(request.Role.TrustPolicy) > 0 {
			return true
		}
	case service.TicketTypeCreateManagedPolicy:
		if request.CreatePolicy != nil {
			return true
		}
	case service.TicketTypeCreateUser:
		if request.CreateUser != nil {
			return true
		}
	case service.TicketTypeCreateGroup:
		if request.CreateGroup != nil {
			return true
		}
	}
	if request.AbstractPolicy != nil || request.Permission.Principal.Name != "" {
		return true
	}
	writeError(context, http.StatusBadRequest, "either request_policy or abstract_policy must be provided")
	return false
}

func (handler *TicketHandler) Submit(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	value, _ := context.Get(AuthenticatedRolesContextKey)
	roles, _ := value.([]string)
	ticket, err := handler.service.SubmitTicket(
		context.Request.Context(), strings.TrimSpace(context.Param("ticketNo")), actorID, roles,
	)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

func (handler *TicketHandler) Get(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	ticketNo := strings.TrimSpace(context.Param("ticketNo"))
	value, _ := context.Get(AuthenticatedRolesContextKey)
	roles, _ := value.([]string)
	ticket, err := handler.service.GetTicketForActor(context.Request.Context(), ticketNo, actorID, roles)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

// TerraformPreview handles GET /tickets/:ticketNo/terraform: the Terraform file
// content the ticket would publish. Published tickets return the stored file;
// unpublished tickets render on demand so submitters and approvers can review
// the exact HCL before it reaches the Git host.
func (handler *TicketHandler) TerraformPreview(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	ticketNo := strings.TrimSpace(context.Param("ticketNo"))
	value, _ := context.Get(AuthenticatedRolesContextKey)
	roles, _ := value.([]string)
	code, err := handler.service.PreviewTicketTerraform(context.Request.Context(), ticketNo, actorID, roles)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"terraform_preview": code})
}

func (handler *TicketHandler) GetApprovalInfo(context *gin.Context) {
	if _, ok := authenticatedUser(context); !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	info, err := handler.service.GetApprovalInfo(
		context.Request.Context(),
		strings.TrimSpace(context.Param("ticketNo")),
	)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"approval": info})
}

func (handler *TicketHandler) ListApprovers(context *gin.Context) {
	if _, ok := authenticatedUser(context); !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	var accountID *int64
	if rawAccountID := strings.TrimSpace(context.Query("account_id")); rawAccountID != "" {
		parsed, err := strconv.ParseInt(rawAccountID, 10, 64)
		if err != nil || parsed <= 0 {
			writeError(context, http.StatusBadRequest, "account_id must be a positive integer")
			return
		}
		accountID = &parsed
	}
	users, err := handler.service.ListAvailableApprovers(context.Request.Context(), accountID)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"approvers": users})
}

func (handler *TicketHandler) Decide(context *gin.Context) {
	approver, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}

	var decision service.TicketDecision
	if err := context.ShouldBindJSON(&decision); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	ticket, err := handler.service.Decide(
		context.Request.Context(),
		strings.TrimSpace(context.Param("ticketNo")),
		approver,
		decision,
	)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

func (handler *TicketHandler) RetryPublication(context *gin.Context) {
	if _, ok := authenticatedUser(context); !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	ticket, err := handler.service.RetryPublication(
		context.Request.Context(),
		strings.TrimSpace(context.Param("ticketNo")),
	)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

// RearmPoll handles POST /tickets/:ticketNo/poll: restarts the Git
// status observation window of a published ticket whose poll budget
// was exhausted while the remote request stayed open.
func (handler *TicketHandler) RearmPoll(context *gin.Context) {
	if _, ok := authenticatedUser(context); !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	if err := handler.service.RearmPolling(
		context.Request.Context(),
		strings.TrimSpace(context.Param("ticketNo")),
	); err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"poll_rearmed": true})
}

// Close handles POST /tickets/:ticketNo/close
func (handler *TicketHandler) Close(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}

	var request struct {
		Reason      string `json:"reason"`
		Comment     string `json:"comment"`
		TriggerSync *bool  `json:"trigger_sync"`
	}
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}

	// 人工关单默认不触发同步（人工无法证明变更已应用）；
	// 前端「标记为已应用」弹窗里由操作者显式勾选。
	triggerSync := request.TriggerSync != nil && *request.TriggerSync
	ticket, err := handler.service.CloseTicket(
		context.Request.Context(),
		strings.TrimSpace(context.Param("ticketNo")),
		actorID,
		request.Reason,
		request.Comment,
		triggerSync,
	)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

// RecordCIApplyResult handles POST /tickets/:ticketNo/apply-result — the
// reserved CI apply callback (A1). CI reports succeeded/failed; succeeded
// closes the ticket as APPLIED and triggers an immediate inventory sync.
func (handler *TicketHandler) RecordCIApplyResult(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}

	var request struct {
		Status    string `json:"status"`
		CommitSHA string `json:"commit_sha"`
		CIURL     string `json:"ci_url"`
		Note      string `json:"note"`
		// PublicationID 是可选的基线发布归属：同一次 main 提交可能同时应用
		// 了工单 PR 与基线 PR，带上它就让「合并 ≠ 生效」那条缝闭合。
		PublicationID int64 `json:"publication_id"`
	}
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}

	ticketNo := strings.TrimSpace(context.Param("ticketNo"))
	var publication *service.BaselinePublication
	if request.PublicationID > 0 {
		var ok bool
		publication, ok = handler.linkPublication(context, ticketNo, request.PublicationID)
		if !ok {
			return
		}
	}

	ticket, closed, err := handler.service.RecordCIApplyResult(
		context.Request.Context(),
		ticketNo,
		actorID,
		service.CIApplyResult{
			Status:        request.Status,
			CommitSHA:     request.CommitSHA,
			CIURL:         request.CIURL,
			Note:          request.Note,
			PublicationID: request.PublicationID,
		},
	)
	if err != nil {
		writeServiceError(context, err)
		return
	}
	// 关单成功后再标记发布已应用：两步都是幂等的，CI 重试安全。标记失败只
	// 记日志——工单已经关了，把 500 返回给 CI 只会让它重试同样的事。
	if publication != nil && strings.EqualFold(strings.TrimSpace(request.Status), "succeeded") {
		if _, applyErr := handler.publications.RecordApplyResult(
			context.Request.Context(), publication.ID, actorID,
			service.BaselineApplyResult{
				Status:    service.BaselineApplyStatusSucceeded,
				CommitSHA: request.CommitSHA,
				CIURL:     request.CIURL,
				Note:      request.Note,
			}); applyErr != nil {
			slog.Default().Warn("failed to mark baseline publication applied from ticket callback",
				"publication_id", publication.ID, "ticket_no", ticketNo, "error", applyErr)
		}
	}
	context.JSON(http.StatusOK, gin.H{"ticket": ticket, "closed": closed, "publication": publication})
}

// linkPublication 校验 publication_id 与工单属于同一账号。归属不符时返回
// false：先关单再发现「应用的是别的账号」是最难收拾的顺序。
func (handler *TicketHandler) linkPublication(
	context *gin.Context, ticketNo string, publicationID int64,
) (*service.BaselinePublication, bool) {
	if handler.publications == nil {
		writeError(context, http.StatusNotImplemented, "publication apply reporting is not configured")
		return nil, false
	}
	publication, err := handler.publications.Get(context.Request.Context(), publicationID)
	if err != nil {
		if errors.Is(err, service.ErrBaselinePublicationNotFound) {
			writeError(context, http.StatusNotFound, "baseline publication not found")
			return nil, false
		}
		writeError(context, http.StatusInternalServerError, "failed to load baseline publication")
		return nil, false
	}
	ticket, err := handler.service.GetTicket(context.Request.Context(), ticketNo)
	if err != nil {
		writeServiceError(context, err)
		return nil, false
	}
	if ticket.AccountID == nil || *ticket.AccountID != publication.AccountDBID {
		writeError(context, http.StatusBadRequest,
			"publication does not belong to the ticket's account")
		return nil, false
	}
	return publication, true
}

func authenticatedUser(context *gin.Context) (string, bool) {
	value, exists := context.Get(AuthenticatedUserContextKey)
	if !exists {
		return "", false
	}
	user, ok := value.(string)
	user = strings.TrimSpace(user)
	return user, ok && user != ""
}

func writeServiceError(context *gin.Context, err error) {
	var complianceError *service.IAMBaselineComplianceError
	if errors.As(err, &complianceError) {
		writeErrorEnvelope(context, http.StatusUnprocessableEntity, "BASELINE_VIOLATION",
			complianceError.Error(), gin.H{"violations": complianceError.Violations})
		return
	}
	var riskError *service.CandidatePolicyRiskError
	if errors.As(err, &riskError) {
		writeErrorEnvelope(context, http.StatusUnprocessableEntity, "RISK_BLOCKED",
			riskError.Error(), gin.H{"findings": riskError.Findings})
		return
	}
	var publicationError *service.PublicationFailedError
	if errors.As(err, &publicationError) {
		writeError(context, http.StatusBadGateway, publicationError.Error())
		return
	}
	var baselineValidationError *service.IAMBaselineValidationError
	if errors.As(err, &baselineValidationError) {
		writeError(context, http.StatusBadRequest, baselineValidationError.Error())
		return
	}
	var trustPolicyError *service.TrustPolicyChangeError
	if errors.As(err, &trustPolicyError) {
		writeErrorEnvelope(context, http.StatusUnprocessableEntity, "TRUST_POLICY_CHANGE",
			trustPolicyError.Error(), gin.H{"role_name": trustPolicyError.RoleName})
		return
	}
	var attachmentConflictError *service.AttachmentConflictError
	if errors.As(err, &attachmentConflictError) {
		writeErrorEnvelope(context, http.StatusConflict, "ATTACHMENT_CONFLICT",
			attachmentConflictError.Error(), gin.H{
				"principal_type":   attachmentConflictError.PrincipalType,
				"principal_name":   attachmentConflictError.PrincipalName,
				"policy_arn":       attachmentConflictError.PolicyARN,
				"source_ticket_no": attachmentConflictError.SourceTicketNo,
				"baseline_owned":   attachmentConflictError.BaselineOwned,
			})
		return
	}
	var wildAttachmentError *service.WildAttachmentError
	if errors.As(err, &wildAttachmentError) {
		writeErrorEnvelope(context, http.StatusUnprocessableEntity, "WILD_ATTACHMENT",
			wildAttachmentError.Error(), gin.H{
				"principal_type": wildAttachmentError.PrincipalType,
				"principal_name": wildAttachmentError.PrincipalName,
				"policy_arn":     wildAttachmentError.PolicyARN,
			})
		return
	}
	var abandonGuardError *service.AbandonGuardError
	if errors.As(err, &abandonGuardError) {
		writeError(context, http.StatusBadRequest, abandonGuardError.Error())
		return
	}
	switch {
	case errors.Is(err, service.ErrTicketNotFound):
		writeError(context, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrNotDesignatedApprover):
		writeError(context, http.StatusForbidden, err.Error())
	case errors.Is(err, service.ErrTicketAccessDenied):
		writeError(context, http.StatusForbidden, err.Error())
	case errors.Is(err, service.ErrApprovalAlreadySet),
		errors.Is(err, service.ErrInvalidTicketState):
		writeError(context, http.StatusConflict, err.Error())
	case isValidationError(err):
		writeError(context, http.StatusBadRequest, err.Error())
	default:
		// 未归类错误：必须留痕，否则 500 无法定位（此前吞错，靠二分 payload 排查）。
		slog.Error("ticket request failed",
			"error", err, "method", context.Request.Method, "path", context.Request.URL.Path)
		writeError(context, http.StatusInternalServerError, "internal server error")
	}
}

func isValidationError(err error) bool {
	// 结构化判定优先：service 层用 apperr.Validation/Validationf 标记的
	// 校验错误，按类型归类 400，与文案内容无关（四次白名单漏配事故的
	// 结构性修复）。
	if apperr.IsValidationError(err) {
		return true
	}
	// legacy 兜底：尚未迁移到 apperr 的存量路径（部分 adapter 层错误）。
	// 新增用户可读校验文案一律用 apperr.Validation/Validationf，禁止再往
	// 本清单加条目。
	message := err.Error()
	for _, prefix := range []string{
		"submitter ",
		"unsupported ticket type",
		"account_id ",
		"principal_name ",
		"role.name ",
		"role.trust_policy", // 字符串形态 trust_policy 解包失败（400 而非 500）
		"role.policy_arns: ",
		"create_user.policy_arns: ",
		"create_group.policy_arns: ",
		"abstract_policy.", // validateAbstractPolicyStructure 返回的错误（带点）
		"abstract_policy ", // "abstract_policy must contain..." 等（带空格）
		"request_policy.principal.",
		"approval_mode ",
		"at least one approver_id ",
		"approver_ids ",
		"approver_id ",
		"no active approvers",
		// 曾经的中文用户可读校验文案（在途工单冲突等）已统一改为英文并走
		// apperr.Validation，这里不再保留中文前缀：文案语言统一后，靠语言文字
		// 猜分类的入口越少越好（台账 C16）。
		"submitter cannot",
		"validate requested IAM policy:",
		"approver ",
		"approval result ",
		"approval reason ",
		"ticket number ",
		"either request_policy or abstract_policy",
		"update_role config",
		"update_role is identical",
		"update_role.inline_policies is no longer supported",
		"update_role.managed_policy_arns is no longer supported",
		"role ",
		"principal_type ",
		"managed_policy_arn: ",
		"load existing ",
		"user \"",
		"IAM user ",  // CREATE_USER 查重/导入校验（清单已存在或不存在）
		"IAM group ", // CREATE_GROUP 同上
		"group \"",
		"validate role update terraform:",
		"validate policy update terraform:",
		"update_policy ",
		"update_policy.",
		"update_membership",
		"operation ",
		"AWS-managed policies cannot",
		"inline policy ",
		"policy \"",
		"policy arn:",
		"locate source attach ticket",
		"fetch role Terraform file",
		"fetch source Terraform file",
		"load managed policy",
		"load group inline policy",
		"check active update-policy tickets",
		"rollback target ",
		"update_policy config missing",
	} {
		if strings.HasPrefix(message, prefix) {
			return true
		}
	}
	return false
}

// writeError writes the unified API error envelope:
// {"code": <stable_code>, "message": <human readable>, "details": {}}.
func writeError(context *gin.Context, status int, message string) {
	writeErrorEnvelope(context, status, errorCodeForStatus(status), message, nil)
}

// writeErrorEnvelope writes an error response with a semantic code and a
// details object. Structured failures (baseline violations, risk findings)
// carry their payload in details so clients branch on code, not message text.
func writeErrorEnvelope(context *gin.Context, status int, code, message string, details gin.H) {
	if details == nil {
		details = gin.H{}
	}
	context.JSON(status, gin.H{"code": code, "message": message, "details": details})
}

// errorCodeForStatus maps HTTP statuses to stable machine-readable codes.
func errorCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "INVALID_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusUnprocessableEntity:
		return "VALIDATION_FAILED"
	case http.StatusInternalServerError:
		return "INTERNAL_ERROR"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	default:
		return "ERROR"
	}
}
