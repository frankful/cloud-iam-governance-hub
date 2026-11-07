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

type policyDerivedGrantService interface {
	Get(context.Context, int64, int64) (service.PolicyDerivedGrants, error)
}

type PolicyDerivedGrantsHandler struct {
	service policyDerivedGrantService
}

func NewPolicyDerivedGrantsHandler(grantsService policyDerivedGrantService) (*PolicyDerivedGrantsHandler, error) {
	if grantsService == nil {
		return nil, errors.New("policy-derived grants service must not be nil")
	}
	return &PolicyDerivedGrantsHandler{service: grantsService}, nil
}

func RegisterPolicyDerivedGrantsRoutes(router gin.IRoutes, handler *PolicyDerivedGrantsHandler) {
	router.GET(
		"/aws/accounts/:accountID/principals/:principalID/policy-derived-grants",
		RequireRoles("platform_admin", "approval_admin", "standard_user"),
		handler.Get,
	)
}

func (handler *PolicyDerivedGrantsHandler) Get(context *gin.Context) {
	accountID, ok := parsePolicyDerivedID(context, "accountID")
	if !ok {
		return
	}
	principalID, ok := parsePolicyDerivedID(context, "principalID")
	if !ok {
		return
	}
	result, err := handler.service.Get(context.Request.Context(), accountID, principalID)
	if err != nil {
		if errors.Is(err, service.ErrPolicyDerivedPrincipalNotFound) {
			writeError(context, http.StatusNotFound, "IAM principal not found in AWS account")
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to derive principal policy grants")
		return
	}
	context.JSON(http.StatusOK, gin.H{"policy_derived_grants": result})
}

func parsePolicyDerivedID(context *gin.Context, parameter string) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(context.Param(parameter)), 10, 64)
	if err != nil || id <= 0 {
		writeError(context, http.StatusBadRequest, parameter+" must be a positive integer")
		return 0, false
	}
	return id, true
}
