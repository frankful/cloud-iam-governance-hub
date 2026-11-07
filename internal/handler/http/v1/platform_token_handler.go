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

type platformTokenService interface {
	RevokeToken(ctx context.Context, tokenID int64, actor service.AuthenticatedIdentity) error
}

type PlatformTokenHandler struct {
	service platformTokenService
}

func NewPlatformTokenHandler(tokenService platformTokenService) (*PlatformTokenHandler, error) {
	if tokenService == nil {
		return nil, errors.New("platform token service must not be nil")
	}
	return &PlatformTokenHandler{service: tokenService}, nil
}

func RegisterPlatformTokenRoutes(router gin.IRoutes, handler *PlatformTokenHandler) {
	router.POST("/platform/tokens/:tokenID/revoke", RequireRoles(
		"platform_admin", "approval_admin", "standard_user",
	), handler.Revoke)
}

func (handler *PlatformTokenHandler) Revoke(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	tokenID, err := strconv.ParseInt(strings.TrimSpace(context.Param("tokenID")), 10, 64)
	if err != nil || tokenID <= 0 {
		writeError(context, http.StatusBadRequest, "tokenID must be a positive integer")
		return
	}
	roles, _ := context.Get(AuthenticatedRolesContextKey)
	userRoles, _ := roles.([]string)
	err = handler.service.RevokeToken(context.Request.Context(), tokenID, service.AuthenticatedIdentity{
		UserID: actorID,
		Roles:  userRoles,
	})
	if errors.Is(err, service.ErrInvalidPlatformToken) {
		writeError(context, http.StatusNotFound, "token not found or already revoked")
		return
	}
	if err != nil {
		writeError(context, http.StatusInternalServerError, "failed to revoke token")
		return
	}
	context.Status(http.StatusNoContent)
}
