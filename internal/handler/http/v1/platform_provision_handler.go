package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

// PlatformProvisionHandler turns platform users into cloud IAM users via
// CREATE_USER tickets (one per target account).
type PlatformProvisionHandler struct {
	tickets *service.TicketService
}

func NewPlatformProvisionHandler(tickets *service.TicketService) (*PlatformProvisionHandler, error) {
	if tickets == nil {
		return nil, errors.New("ticket service must not be nil")
	}
	return &PlatformProvisionHandler{tickets: tickets}, nil
}

func RegisterPlatformProvisionRoutes(router gin.IRoutes, handler *PlatformProvisionHandler) {
	router.POST("/platform/users/:userID/provision",
		RequireRoles("platform_admin"), handler.Provision)
}

// Provision handles POST /platform/users/:userID/provision. The response is
// always 201 with per-account results: failures are inline (error field), so
// a partial batch is visible without retrying the whole request.
func (handler *PlatformProvisionHandler) Provision(context *gin.Context) {
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
	var body service.ProvisionUserRequest
	if err := context.ShouldBindJSON(&body); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body")
		return
	}
	results, err := handler.tickets.ProvisionUser(context.Request.Context(), actorID, userID, body)
	if err != nil {
		writeError(context, http.StatusBadRequest, err.Error())
		return
	}
	context.JSON(http.StatusCreated, gin.H{"results": results})
}
