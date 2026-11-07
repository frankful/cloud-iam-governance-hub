package v1

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type dashboardService interface {
	Summary(context.Context) (service.DashboardSummary, error)
}

// DashboardHandler serves the aggregated dashboard overview.
type DashboardHandler struct {
	service dashboardService
}

// NewDashboardHandler creates a DashboardHandler.
func NewDashboardHandler(dashboardService dashboardService) (*DashboardHandler, error) {
	if dashboardService == nil {
		return nil, errors.New("dashboard service must not be nil")
	}
	return &DashboardHandler{service: dashboardService}, nil
}

// RegisterDashboardRoutes registers the dashboard summary endpoint.
func RegisterDashboardRoutes(router gin.IRoutes, handler *DashboardHandler) {
	router.GET(
		"/dashboard/summary",
		RequireRoles("platform_admin", "approval_admin"),
		handler.Summary,
	)
}

// Summary handles GET /dashboard/summary.
func (handler *DashboardHandler) Summary(context *gin.Context) {
	summary, err := handler.service.Summary(context.Request.Context())
	if err != nil {
		writeError(context, http.StatusInternalServerError, "failed to build dashboard summary")
		return
	}
	context.JSON(http.StatusOK, gin.H{"summary": summary})
}
