package v1

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type iamOwnershipService interface {
	SetOwnership(ctx context.Context, accountDBID int64, key, managedBy, reviewedBy string) error
	ListOwnership(ctx context.Context, accountDBID int64, kind, managedBy string) ([]service.ResourceOwnership, error)
}

// IAMOwnershipHandler serves the administrator-facing ownership marks: which
// inventoried resources the platform declares in Terraform and which ones
// belong to another system. Only platform administrators may set them — the
// marks decide what a full baseline is allowed to touch.
type IAMOwnershipHandler struct {
	service iamOwnershipService
}

func NewIAMOwnershipHandler(ownershipService iamOwnershipService) (*IAMOwnershipHandler, error) {
	if ownershipService == nil {
		return nil, errors.New("IAM ownership service must not be nil")
	}
	return &IAMOwnershipHandler{service: ownershipService}, nil
}

func RegisterIAMOwnershipRoutes(router gin.IRoutes, handler *IAMOwnershipHandler) {
	admin := RequireRoles("platform_admin")
	router.GET("/aws/ownership", admin, handler.List)
	router.PUT("/aws/ownership/:key", admin, handler.Set)
}

// List returns the ownership marks of one account.
func (handler *IAMOwnershipHandler) List(context *gin.Context) {
	accountID, _ := strconv.ParseInt(strings.TrimSpace(context.Query("account_id")), 10, 64)
	ownership, err := handler.service.ListOwnership(
		context.Request.Context(),
		accountID,
		strings.TrimSpace(context.Query("kind")),
		strings.TrimSpace(context.Query("managed_by")),
	)
	if err != nil {
		writeError(context, http.StatusBadRequest, err.Error())
		return
	}
	context.JSON(http.StatusOK, gin.H{"ownership": ownership})
}

// Set marks one resource as platform-managed, externally managed or undecided.
func (handler *IAMOwnershipHandler) Set(context *gin.Context) {
	key := strings.TrimSpace(context.Param("key"))
	if key == "" {
		writeError(context, http.StatusBadRequest, "resource key is required")
		return
	}
	var body struct {
		AccountID int64  `json:"account_id"`
		ManagedBy string `json:"managed_by"`
	}
	if err := context.ShouldBindJSON(&body); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	// 归属决定基线能不能动资源，必须能追溯到操作人；API token 模式下身份来自
	// 认证中间件，dev 模式下来自 X-User-ID。
	err := handler.service.SetOwnership(
		context.Request.Context(),
		body.AccountID,
		key,
		body.ManagedBy,
		context.GetString(AuthenticatedUserContextKey),
	)
	if errors.Is(err, service.ErrOwnershipNotFound) {
		writeError(context, http.StatusNotFound, "resource not found in the account inventory")
		return
	}
	if err != nil {
		writeError(context, http.StatusBadRequest, err.Error())
		return
	}
	context.JSON(http.StatusOK, gin.H{"key": key, "managed_by": strings.TrimSpace(body.ManagedBy)})
}
