package v1

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

type accountApproverService interface {
	ListBindings(ctx context.Context, accountID int64) ([]service.AccountApproverBinding, error)
	ListCandidates(ctx context.Context, accountID int64) ([]service.AccountApproverCandidate, error)
	SetBindings(ctx context.Context, accountID int64, userIDs []string) ([]service.AccountApproverBinding, error)
	ListAccountsForApprover(ctx context.Context, userID string) ([]service.ApproverAccountSummary, error)
	SetAccountsForApprover(ctx context.Context, userID string, accountIDs []int64) ([]service.ApproverAccountSummary, error)
}

// AWSAccountApproverHandler manages the per-account approver bindings that
// AUTO approval resolves and the MANUAL approver picker reads. Without this
// write path every newly onboarded account was locked out of the ticket flow
// (A9).
type AWSAccountApproverHandler struct {
	service accountApproverService
}

// NewAWSAccountApproverHandler creates an AWSAccountApproverHandler.
func NewAWSAccountApproverHandler(approverService accountApproverService) (*AWSAccountApproverHandler, error) {
	if approverService == nil {
		return nil, errors.New("account approver service must not be nil")
	}
	return &AWSAccountApproverHandler{service: approverService}, nil
}

// RegisterAWSAccountApproverRoutes registers the binding endpoints. Bindings
// decide who can approve tickets, so only platform_admin may manage them.
func RegisterAWSAccountApproverRoutes(router gin.IRoutes, handler *AWSAccountApproverHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodGet, "/aws/accounts/:accountID/approvers", append(admin, handler.List)...)
	router.Handle(http.MethodPut, "/aws/accounts/:accountID/approvers", append(admin, handler.Replace)...)
	router.Handle(http.MethodGet, "/aws/accounts/:accountID/approver-candidates", append(admin, handler.Candidates)...)
	// A9③乙：停用/降级平台用户前，反查其审批人绑定（用户管理页确认框数据源）。
	router.Handle(http.MethodGet, "/aws/approver-bindings/:userID", append(admin, handler.ApproverAccounts)...)
	// 反向写路径：用户管理页按「此人审批哪些账号」整体替换绑定。
	router.Handle(http.MethodPut, "/aws/approver-bindings/:userID", append(admin, handler.SetApproverAccounts)...)
}

// List handles GET /aws/accounts/:accountID/approvers.
func (handler *AWSAccountApproverHandler) List(context *gin.Context) {
	accountID, ok := parseAccountApproverID(context)
	if !ok {
		return
	}
	bindings, err := handler.service.ListBindings(context.Request.Context(), accountID)
	if err != nil {
		writeAccountApproverError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"approvers": bindings})
}

// Replace handles PUT /aws/accounts/:accountID/approvers with a full
// replacement list, returning the resulting bindings.
func (handler *AWSAccountApproverHandler) Replace(context *gin.Context) {
	accountID, ok := parseAccountApproverID(context)
	if !ok {
		return
	}
	var payload struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := context.ShouldBindJSON(&payload); err != nil {
		writeError(context, http.StatusBadRequest, "request body must be {\"user_ids\": [...]}")
		return
	}
	bindings, err := handler.service.SetBindings(context.Request.Context(), accountID, payload.UserIDs)
	if err != nil {
		writeAccountApproverError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"approvers": bindings})
}

// Candidates handles GET /aws/accounts/:accountID/approver-candidates: every
// eligible user plus the bound flag, for the settings picker.
func (handler *AWSAccountApproverHandler) Candidates(context *gin.Context) {
	accountID, ok := parseAccountApproverID(context)
	if !ok {
		return
	}
	candidates, err := handler.service.ListCandidates(context.Request.Context(), accountID)
	if err != nil {
		writeAccountApproverError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"candidates": candidates})
}

// ApproverAccounts handles GET /aws/approver-bindings/:userID: every account
// where the user is still bound as an approver, used to warn the operator
// before deactivating or demoting the user (A9③乙).
func (handler *AWSAccountApproverHandler) ApproverAccounts(context *gin.Context) {
	userID := strings.TrimSpace(context.Param("userID"))
	if userID == "" {
		writeError(context, http.StatusBadRequest, "user id must not be empty")
		return
	}
	accounts, err := handler.service.ListAccountsForApprover(context.Request.Context(), userID)
	if err != nil {
		writeAccountApproverError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"accounts": accounts})
}

// SetApproverAccounts handles PUT /aws/approver-bindings/:userID with a full
// replacement of the accounts the user approves. The user-management page
// edits bindings from the user's side; the account-side picker in Sync
// Management keeps working and hits the same table.
func (handler *AWSAccountApproverHandler) SetApproverAccounts(context *gin.Context) {
	userID := strings.TrimSpace(context.Param("userID"))
	if userID == "" {
		writeError(context, http.StatusBadRequest, "user id must not be empty")
		return
	}
	var payload struct {
		AccountIDs []int64 `json:"account_ids"`
	}
	if err := context.ShouldBindJSON(&payload); err != nil {
		writeError(context, http.StatusBadRequest, "request body must be {\"account_ids\": [...]}")
		return
	}
	for _, accountID := range payload.AccountIDs {
		if accountID <= 0 {
			writeError(context, http.StatusBadRequest, "account ids must be positive integers")
			return
		}
	}
	accounts, err := handler.service.SetAccountsForApprover(
		context.Request.Context(), userID, payload.AccountIDs)
	if err != nil {
		writeAccountApproverError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"accounts": accounts})
}

func parseAccountApproverID(context *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(context.Param("accountID"), 10, 64)
	if err != nil || id <= 0 {
		writeError(context, http.StatusBadRequest, "account id must be a positive integer")
		return 0, false
	}
	return id, true
}

func writeAccountApproverError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrAccountApproverAccountNotFound):
		writeError(context, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrAccountApproverInvalidUser):
		// 422: the request is well-formed but the referenced users can never
		// approve a ticket.
		writeError(context, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(context, http.StatusInternalServerError, "failed to manage account approvers")
	}
}
