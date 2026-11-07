package v1

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type awsAccountConfigService interface {
	Create(context.Context, service.AWSAccountConfigInput, string) (model.AWSAccountConfig, error)
	Update(context.Context, int64, service.AWSAccountConfigInput, string) (model.AWSAccountConfig, error)
	Get(context.Context, int64) (model.AWSAccountConfig, error)
	List(context.Context, int, int) ([]model.AWSAccountConfig, error)
	SetSyncEnabled(context.Context, int64, bool, string) (model.AWSAccountConfig, error)
	TestConnection(context.Context, int64, string) (service.AWSAccountConnectionIdentity, error)
}

type AWSAccountConfigHandler struct {
	service awsAccountConfigService
}

func NewAWSAccountConfigHandler(accountConfigService awsAccountConfigService) (*AWSAccountConfigHandler, error) {
	if accountConfigService == nil {
		return nil, errors.New("AWS account config service must not be nil")
	}
	return &AWSAccountConfigHandler{service: accountConfigService}, nil
}

func RegisterAWSAccountConfigRoutes(router gin.IRoutes, handler *AWSAccountConfigHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodPost, "/aws/account-configs", append(admin, handler.Create)...)
	router.Handle(http.MethodGet, "/aws/account-configs", append(admin, handler.List)...)
	router.Handle(http.MethodGet, "/aws/account-configs/:configID", append(admin, handler.Get)...)
	router.Handle(http.MethodPut, "/aws/account-configs/:configID", append(admin, handler.Update)...)
	router.Handle(http.MethodPatch, "/aws/account-configs/:configID/sync-enabled", append(admin, handler.SetSyncEnabled)...)
	router.Handle(http.MethodPost, "/aws/account-configs/:configID/test-connection", append(admin, handler.TestConnection)...)
}

func (handler *AWSAccountConfigHandler) Create(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	var input service.AWSAccountConfigInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	config, err := handler.service.Create(context.Request.Context(), input, actorID)
	if err != nil {
		writeAWSAccountConfigError(context, err)
		return
	}
	context.JSON(http.StatusCreated, gin.H{"config": newAWSAccountConfigResponse(config)})
}

func (handler *AWSAccountConfigHandler) Update(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	id, ok := parseAWSAccountConfigID(context)
	if !ok {
		return
	}
	var input service.AWSAccountConfigInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	config, err := handler.service.Update(context.Request.Context(), id, input, actorID)
	if err != nil {
		writeAWSAccountConfigError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"config": newAWSAccountConfigResponse(config)})
}

func (handler *AWSAccountConfigHandler) Get(context *gin.Context) {
	id, ok := parseAWSAccountConfigID(context)
	if !ok {
		return
	}
	config, err := handler.service.Get(context.Request.Context(), id)
	if err != nil {
		writeAWSAccountConfigError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"config": newAWSAccountConfigResponse(config)})
}

func (handler *AWSAccountConfigHandler) List(context *gin.Context) {
	limit, offset := 50, 0
	if raw := strings.TrimSpace(context.Query("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(context, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		limit = parsed
	}
	if raw := strings.TrimSpace(context.Query("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(context, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = parsed
	}
	configs, err := handler.service.List(context.Request.Context(), limit, offset)
	if err != nil {
		writeAWSAccountConfigError(context, err)
		return
	}
	response := make([]awsAccountConfigResponse, 0, len(configs))
	for _, config := range configs {
		response = append(response, newAWSAccountConfigResponse(config))
	}
	context.JSON(http.StatusOK, gin.H{"configs": response, "limit": limit, "offset": offset})
}

func (handler *AWSAccountConfigHandler) SetSyncEnabled(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	id, ok := parseAWSAccountConfigID(context)
	if !ok {
		return
	}
	var request struct {
		Enabled *bool `json:"sync_enabled"`
	}
	if err := context.ShouldBindJSON(&request); err != nil || request.Enabled == nil {
		writeError(context, http.StatusBadRequest, "sync_enabled boolean is required")
		return
	}
	config, err := handler.service.SetSyncEnabled(context.Request.Context(), id, *request.Enabled, actorID)
	if err != nil {
		writeAWSAccountConfigError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"config": newAWSAccountConfigResponse(config)})
}

func (handler *AWSAccountConfigHandler) TestConnection(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	id, ok := parseAWSAccountConfigID(context)
	if !ok {
		return
	}
	identity, err := handler.service.TestConnection(context.Request.Context(), id, actorID)
	if err != nil {
		writeAWSAccountConfigError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"identity": identity})
}

func parseAWSAccountConfigID(context *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(context.Param("configID")), 10, 64)
	if err != nil || id <= 0 {
		writeError(context, http.StatusBadRequest, "configID must be a positive integer")
		return 0, false
	}
	return id, true
}

func writeAWSAccountConfigError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrAWSAccountConfigNotFound):
		writeError(context, http.StatusNotFound, "AWS account configuration not found")
	case errors.Is(err, service.ErrAWSAccountConfigConflict):
		writeError(context, http.StatusConflict, "AWS account configuration already exists")
	case errors.Is(err, service.ErrAWSAccountConfigChanged):
		writeError(context, http.StatusConflict, "AWS account configuration changed; retry the operation")
	case errors.Is(err, service.ErrAWSAccountConnectivity):
		writeError(context, http.StatusUnprocessableEntity, "AWS account connectivity validation failed")
	default:
		var validationError *service.AWSAccountConfigValidationError
		if errors.As(err, &validationError) {
			writeError(context, http.StatusBadRequest, validationError.Error())
			return
		}
		slog.Error("AWS account config request failed",
			"error", err, "method", context.Request.Method, "path", context.Request.URL.Path)
		writeError(context, http.StatusInternalServerError, "failed to process AWS account configuration")
	}
}

type awsAccountConfigResponse struct {
	ID                   int64       `json:"id"`
	AWSAccountID         string      `json:"aws_account_id"`
	AWSAccountDBID       *int64      `json:"aws_account_db_id,omitempty"`
	OrganizationDBID     *int64      `json:"organization_db_id,omitempty"`
	DisplayName          string      `json:"display_name"`
	ReadOnlyRoleARN      *string     `json:"read_only_role_arn,omitempty"`
	SyncMode             string      `json:"sync_mode"`
	SyncEnabled          bool        `json:"sync_enabled"`
	Tags                 model.JSONB `json:"tags"`
	SyncStatus           string      `json:"sync_status"`
	LastSyncAttemptAt    *time.Time  `json:"last_sync_attempt_at,omitempty"`
	LastSuccessfulSyncAt *time.Time  `json:"last_successful_sync_at,omitempty"`
	CreatedAt            time.Time   `json:"created_at"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

func newAWSAccountConfigResponse(config model.AWSAccountConfig) awsAccountConfigResponse {
	return awsAccountConfigResponse{
		ID: config.ID, AWSAccountID: config.AWSAccountID,
		AWSAccountDBID: config.AWSAccountDBID, OrganizationDBID: config.OrganizationDBID,
		DisplayName: config.DisplayName, ReadOnlyRoleARN: config.ReadOnlyRoleARN,
		SyncMode: config.SyncMode, SyncEnabled: config.SyncEnabled,
		Tags: config.Tags, SyncStatus: config.SyncStatus,
		LastSyncAttemptAt:    config.LastSyncAttemptAt,
		LastSuccessfulSyncAt: config.LastSuccessfulSyncAt,
		CreatedAt:            config.CreatedAt, UpdatedAt: config.UpdatedAt,
	}
}
