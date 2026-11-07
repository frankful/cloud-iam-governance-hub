package v1

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

// GitStatusHandler handles Git status query API requests.
type GitStatusHandler struct {
	queryService *service.GitStatusQueryService
}

// NewGitStatusHandler creates a new GitStatusHandler.
func NewGitStatusHandler(queryService *service.GitStatusQueryService) (*GitStatusHandler, error) {
	if queryService == nil {
		return nil, errors.New("git status query service must not be nil")
	}
	return &GitStatusHandler{queryService: queryService}, nil
}

// RegisterGitStatusRoutes registers the Git status query API routes.
func RegisterGitStatusRoutes(router gin.IRoutes, handler *GitStatusHandler) {
	router.GET("/tickets/:ticketNo/git-status", RequireRoles("platform_admin", "approval_admin", "standard_user"), handler.GetTicketGitStatus)
	router.GET("/tickets/:ticketNo/execution-records", RequireRoles("platform_admin", "approval_admin"), handler.ListExecutionRecords)
}

// GetTicketGitStatus handles GET /tickets/:ticketNo/git-status
func (handler *GitStatusHandler) GetTicketGitStatus(context *gin.Context) {
	ticketNo := strings.TrimSpace(context.Param("ticketNo"))
	if ticketNo == "" {
		writeError(context, http.StatusBadRequest, "ticket number must not be empty")
		return
	}

	status, err := handler.queryService.GetTicketGitStatus(context.Request.Context(), ticketNo)
	if err != nil {
		writeServiceError(context, err)
		return
	}

	context.JSON(http.StatusOK, gin.H{"git_status": status})
}

// ListExecutionRecords handles GET /tickets/:ticketNo/execution-records
func (handler *GitStatusHandler) ListExecutionRecords(context *gin.Context) {
	ticketNo := strings.TrimSpace(context.Param("ticketNo"))
	if ticketNo == "" {
		writeError(context, http.StatusBadRequest, "ticket number must not be empty")
		return
	}

	limit := 20
	if rawLimit := strings.TrimSpace(context.Query("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			writeError(context, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	records, err := handler.queryService.ListExecutionRecords(context.Request.Context(), ticketNo, limit)
	if err != nil {
		writeServiceError(context, err)
		return
	}

	context.JSON(http.StatusOK, gin.H{"execution_records": records})
}
