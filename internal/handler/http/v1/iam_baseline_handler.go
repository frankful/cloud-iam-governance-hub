package v1

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

type iamBaselineService interface {
	Create(context.Context, int64, abstractiam.AbstractPolicy, bool, string) (model.IAMBaseline, error)
	List(context.Context, int64) ([]model.IAMBaseline, error)
	SetEnabled(context.Context, int64, int64, bool, string) (model.IAMBaseline, error)
}

type IAMBaselineHandler struct {
	service iamBaselineService
}

func NewIAMBaselineHandler(baselineService iamBaselineService) (*IAMBaselineHandler, error) {
	if baselineService == nil {
		return nil, errors.New("IAM baseline service must not be nil")
	}
	return &IAMBaselineHandler{service: baselineService}, nil
}

func RegisterIAMBaselineRoutes(router gin.IRoutes, handler *IAMBaselineHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodPost, "/aws/accounts/:accountID/baselines", append(admin, handler.Create)...)
	router.Handle(http.MethodGet, "/aws/accounts/:accountID/baselines", append(admin, handler.List)...)
	router.Handle(http.MethodPut, "/aws/accounts/:accountID/baselines/:baselineID", append(admin, handler.SetEnabled)...)
}

func (handler *IAMBaselineHandler) Create(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	accountID, ok := parseBaselinePathID(context, "accountID")
	if !ok {
		return
	}
	var request struct {
		Policy  abstractiam.AbstractPolicy `json:"abstract_policy"`
		Enabled bool                       `json:"enabled"`
	}
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	baseline, err := handler.service.Create(
		context.Request.Context(), accountID, request.Policy, request.Enabled, actorID,
	)
	if err != nil {
		writeIAMBaselineError(context, err)
		return
	}
	context.JSON(http.StatusCreated, gin.H{"baseline": baseline})
}

func (handler *IAMBaselineHandler) List(context *gin.Context) {
	accountID, ok := parseBaselinePathID(context, "accountID")
	if !ok {
		return
	}
	baselines, err := handler.service.List(context.Request.Context(), accountID)
	if err != nil {
		writeIAMBaselineError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"baselines": baselines})
}

func (handler *IAMBaselineHandler) SetEnabled(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	accountID, ok := parseBaselinePathID(context, "accountID")
	if !ok {
		return
	}
	baselineID, ok := parseBaselinePathID(context, "baselineID")
	if !ok {
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if err := context.ShouldBindJSON(&request); err != nil || request.Enabled == nil {
		writeError(context, http.StatusBadRequest, "enabled boolean is required")
		return
	}
	baseline, err := handler.service.SetEnabled(
		context.Request.Context(), accountID, baselineID, *request.Enabled, actorID,
	)
	if err != nil {
		writeIAMBaselineError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"baseline": baseline})
}

func parseBaselinePathID(context *gin.Context, parameter string) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(context.Param(parameter)), 10, 64)
	if err != nil || id <= 0 {
		writeError(context, http.StatusBadRequest, parameter+" must be a positive integer")
		return 0, false
	}
	return id, true
}

func writeIAMBaselineError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrIAMBaselineNotFound), errors.Is(err, service.ErrIAMBaselineAccountNotFound):
		writeError(context, http.StatusNotFound, err.Error())
	default:
		var validationError *service.IAMBaselineValidationError
		if errors.As(err, &validationError) {
			writeError(context, http.StatusBadRequest, validationError.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to process IAM baseline")
	}
}
