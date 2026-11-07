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

type auditQueryService interface {
	ListAuditEvents(context.Context, service.AuditEventFilter) ([]service.AuditEventView, int, error)
	ExportAuditEvents(context.Context, service.AuditEventFilter, string) ([]service.AuditEventView, error)
}

// AuditHandler serves the append-only audit log (platform_admin only).
type AuditHandler struct {
	service auditQueryService
}

// NewAuditHandler creates an AuditHandler.
func NewAuditHandler(auditService auditQueryService) (*AuditHandler, error) {
	if auditService == nil {
		return nil, errors.New("audit query service must not be nil")
	}
	return &AuditHandler{service: auditService}, nil
}

// RegisterAuditRoutes registers the audit query and export endpoints.
func RegisterAuditRoutes(router gin.IRoutes, handler *AuditHandler) {
	admin := RequireRoles("platform_admin")
	router.GET("/audit/events", admin, handler.List)
	router.GET("/audit/events/export", admin, handler.Export)
}

// List handles GET /audit/events.
func (handler *AuditHandler) List(context *gin.Context) {
	filter, ok := parseAuditEventFilter(context)
	if !ok {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	events, total, err := handler.service.ListAuditEvents(context.Request.Context(), filter)
	if err != nil {
		writeAuditError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"events": events, "total": total, "limit": limit, "offset": offset,
	})
}

// Export handles GET /audit/events/export: bounded, synchronous JSON download.
// Every export is itself recorded as an AUDIT_EVENTS_EXPORTED audit event.
func (handler *AuditHandler) Export(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	filter, ok := parseAuditEventFilter(context)
	if !ok {
		return
	}
	events, err := handler.service.ExportAuditEvents(context.Request.Context(), filter, actorID)
	if err != nil {
		writeAuditError(context, err)
		return
	}
	context.Header("Content-Disposition", `attachment; filename="audit-events.json"`)
	context.JSON(http.StatusOK, gin.H{"events": events, "count": len(events)})
}

// parseAuditEventFilter parses the shared audit query parameters. It returns
// ok=false after writing a 400 for malformed values.
func parseAuditEventFilter(context *gin.Context) (service.AuditEventFilter, bool) {
	filter := service.AuditEventFilter{
		ActorID:      strings.TrimSpace(context.Query("actor_id")),
		Action:       strings.TrimSpace(context.Query("action")),
		ResourceType: strings.TrimSpace(context.Query("resource_type")),
		ResourceID:   strings.TrimSpace(context.Query("resource_id")),
		Outcome:      strings.TrimSpace(context.Query("outcome")),
	}
	from, ok := parseOptionalAuditTime(context, "from")
	if !ok {
		return filter, false
	}
	to, ok := parseOptionalAuditTime(context, "to")
	if !ok {
		return filter, false
	}
	filter.From, filter.To = from, to
	if from != nil && to != nil && from.After(*to) {
		writeError(context, http.StatusBadRequest, "from must not be after to")
		return filter, false
	}
	return filter, true
}

func parseOptionalAuditTime(context *gin.Context, name string) (*time.Time, bool) {
	raw := strings.TrimSpace(context.Query(name))
	if raw == "" {
		return nil, true
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeError(context, http.StatusBadRequest, name+" must be an RFC3339 timestamp")
		return nil, false
	}
	return &parsed, true
}

func writeAuditError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidAuditOutcome):
		writeError(context, http.StatusBadRequest, err.Error())
	default:
		writeError(context, http.StatusInternalServerError, "failed to query audit events")
	}
}
