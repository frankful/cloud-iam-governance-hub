package v1

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type platformUserService interface {
	ListUsers(ctx context.Context) ([]service.PlatformUser, error)
	UpsertUser(ctx context.Context, user service.UpsertPlatformUser, actorID string) error
	IssueToken(ctx context.Context, actorID, userID, name string, expiresAt *time.Time) (service.IssuedPlatformToken, error)
	ListTokens(ctx context.Context, userID string) ([]service.PlatformTokenInfo, error)
}

// PlatformUserHandler serves the administrator-facing user and token
// management endpoints. Every route is platform_admin only: managing people
// and handing out login tokens is the most privileged operation on the
// platform.
type PlatformUserHandler struct {
	service platformUserService
}

func NewPlatformUserHandler(userService platformUserService) (*PlatformUserHandler, error) {
	if userService == nil {
		return nil, errors.New("platform user service must not be nil")
	}
	return &PlatformUserHandler{service: userService}, nil
}

func RegisterPlatformUserRoutes(router gin.IRoutes, handler *PlatformUserHandler) {
	admin := RequireRoles("platform_admin")
	router.GET("/platform/users", admin, handler.List)
	router.PUT("/platform/users/:userID", admin, handler.Upsert)
	router.GET("/platform/tokens", admin, handler.ListTokens)
	router.POST("/platform/users/:userID/tokens", admin, handler.IssueToken)
}

// List returns every platform user with its roles.
func (handler *PlatformUserHandler) List(context *gin.Context) {
	users, err := handler.service.ListUsers(context.Request.Context())
	if err != nil {
		writeError(context, http.StatusInternalServerError, "failed to list platform users")
		return
	}
	context.JSON(http.StatusOK, gin.H{"users": users})
}

// Upsert creates a platform user or replaces its display name, e-mail, active
// flag and roles.
func (handler *PlatformUserHandler) Upsert(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	var body struct {
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		IsActive    *bool    `json:"is_active"`
		Roles       []string `json:"roles"`
	}
	if err := context.ShouldBindJSON(&body); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	userID := strings.TrimSpace(context.Param("userID"))
	if userID == "" {
		writeError(context, http.StatusBadRequest, "userID is required")
		return
	}
	err := handler.service.UpsertUser(context.Request.Context(), service.UpsertPlatformUser{
		UserID:      userID,
		DisplayName: body.DisplayName,
		Email:       body.Email,
		IsActive:    body.IsActive,
		Roles:       body.Roles,
	}, actorID)
	if err != nil {
		writeError(context, http.StatusBadRequest, err.Error())
		return
	}
	context.JSON(http.StatusOK, gin.H{"user_id": userID})
}

// ListTokens returns token metadata (never a secret) for all users or for one.
func (handler *PlatformUserHandler) ListTokens(context *gin.Context) {
	userID := strings.TrimSpace(context.Query("user_id"))
	tokens, err := handler.service.ListTokens(context.Request.Context(), userID)
	if err != nil {
		writeError(context, http.StatusInternalServerError, "failed to list platform tokens")
		return
	}
	context.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// IssueToken issues a login token for a user. The secret is returned exactly
// once — only its digest is stored.
func (handler *PlatformUserHandler) IssueToken(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	userID := strings.TrimSpace(context.Param("userID"))
	if userID == "" {
		writeError(context, http.StatusBadRequest, "userID is required")
		return
	}
	var body struct {
		Name             string `json:"name"`
		ExpiresInHours   int    `json:"expires_in_hours"`
	}
	if err := context.ShouldBindJSON(&body); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "issued from the admin console"
	}
	var expiresAt *time.Time
	if body.ExpiresInHours > 0 {
		deadline := time.Now().Add(time.Duration(body.ExpiresInHours) * time.Hour)
		expiresAt = &deadline
	}
	issued, err := handler.service.IssueToken(context.Request.Context(), actorID, userID, name, expiresAt)
	if errors.Is(err, service.ErrInvalidPlatformUser) {
		writeError(context, http.StatusNotFound, "platform user not found or inactive")
		return
	}
	if errors.Is(err, service.ErrPlatformUserNoRole) {
		writeError(context, http.StatusBadRequest,
			"platform user "+userID+" has no platform role; assign at least one role (user management) before issuing a login token")
		return
	}
	if err != nil {
		writeError(context, http.StatusBadRequest, err.Error())
		return
	}
	context.JSON(http.StatusCreated, gin.H{
		"id": issued.ID, "user_id": issued.UserID, "name": issued.Name,
		"prefix": issued.Prefix, "token": issued.Token, "expires_at": issued.ExpiresAt,
	})
}
