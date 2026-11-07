package v1

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type awsAccountQueryService interface {
	ListAccounts(context.Context) ([]service.AWSAccountRef, error)
}

// AWSAccountQueryHandler serves the account reference list.
type AWSAccountQueryHandler struct {
	service awsAccountQueryService
}

// NewAWSAccountQueryHandler creates an AWSAccountQueryHandler.
func NewAWSAccountQueryHandler(accountService awsAccountQueryService) (*AWSAccountQueryHandler, error) {
	if accountService == nil {
		return nil, errors.New("AWS account query service must not be nil")
	}
	return &AWSAccountQueryHandler{service: accountService}, nil
}

// RegisterAWSAccountQueryRoutes registers the account reference endpoint.
func RegisterAWSAccountQueryRoutes(router gin.IRoutes, handler *AWSAccountQueryHandler) {
	router.GET(
		"/aws/accounts",
		RequireRoles("platform_admin", "approval_admin", "standard_user"),
		handler.List,
	)
}

// List handles GET /aws/accounts.
func (handler *AWSAccountQueryHandler) List(context *gin.Context) {
	accounts, err := handler.service.ListAccounts(context.Request.Context())
	if err != nil {
		writeError(context, http.StatusInternalServerError, "failed to list AWS accounts")
		return
	}
	context.JSON(http.StatusOK, gin.H{"accounts": accounts})
}
