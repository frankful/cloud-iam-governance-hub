package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuditEventFilter filters the audit event listing. All filters are optional;
// From/To bound occurred_at (inclusive). Limit/Offset paginate.
type AuditEventFilter struct {
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Outcome      string // SUCCESS | FAILURE
	From         *time.Time
	To           *time.Time
	Limit        int
	Offset       int
}

// AuditEventView is one recorded audit event as read back from the
// append-only iam_audit_event table (nullable columns are pointers).
type AuditEventView struct {
	ID           int64           `json:"id"`
	RequestID    *string         `json:"request_id,omitempty"`
	ActorID      *string         `json:"actor_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Outcome      string          `json:"outcome"`
	HTTPStatus   *int            `json:"http_status,omitempty"`
	Metadata     json.RawMessage `json:"metadata"`
	OccurredAt   time.Time       `json:"occurred_at"`
}

// ErrInvalidAuditOutcome rejects unknown outcome filter values.
var ErrInvalidAuditOutcome = errors.New("outcome must be SUCCESS or FAILURE")

// AuditQueryService reads the append-only audit log. ExportAuditEvents records
// every export through the same AuditWriter the request middleware uses, so
// "who exported the audit log" is itself audited.
type AuditQueryService struct {
	db          *sql.DB
	auditEvents AuditWriter
}

// NewAuditQueryService creates an AuditQueryService.
func NewAuditQueryService(database *sql.DB, auditEvents AuditWriter) (*AuditQueryService, error) {
	if database == nil {
		return nil, errors.New("database connection must not be nil")
	}
	if auditEvents == nil {
		return nil, errors.New("audit event writer must not be nil")
	}
	return &AuditQueryService{db: database, auditEvents: auditEvents}, nil
}

func buildAuditEventConditions(filter AuditEventFilter, addArg func(any) string) ([]string, error) {
	conditions := []string{"TRUE"}
	if actor := strings.TrimSpace(filter.ActorID); actor != "" {
		conditions = append(conditions, "actor_id = "+addArg(actor))
	}
	if action := strings.TrimSpace(filter.Action); action != "" {
		conditions = append(conditions, "action = "+addArg(action))
	}
	if resourceType := strings.TrimSpace(filter.ResourceType); resourceType != "" {
		conditions = append(conditions, "resource_type = "+addArg(resourceType))
	}
	if resourceID := strings.TrimSpace(filter.ResourceID); resourceID != "" {
		conditions = append(conditions, "resource_id = "+addArg(resourceID))
	}
	switch outcome := strings.TrimSpace(filter.Outcome); outcome {
	case "":
	case "SUCCESS", "FAILURE":
		conditions = append(conditions, "outcome = "+addArg(outcome))
	default:
		return nil, ErrInvalidAuditOutcome
	}
	if filter.From != nil {
		conditions = append(conditions, "occurred_at >= "+addArg(*filter.From))
	}
	if filter.To != nil {
		conditions = append(conditions, "occurred_at <= "+addArg(*filter.To))
	}
	return conditions, nil
}

const auditEventSelectColumns = `SELECT id, request_id, actor_id, action, resource_type,
	resource_id, outcome, http_status, metadata, occurred_at FROM iam_audit_event`

// ListAuditEvents lists audit events with total count, newest first.
func (service *AuditQueryService) ListAuditEvents(
	ctx context.Context,
	filter AuditEventFilter,
) ([]AuditEventView, int, error) {
	args := make([]any, 0, 7)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	conditions, err := buildAuditEventConditions(filter, addArg)
	if err != nil {
		return nil, 0, err
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := service.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iam_audit_event"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []AuditEventView{}, total, nil
	}

	query := auditEventSelectColumns + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT %s OFFSET %s",
			addArg(filter.Limit), addArg(filter.Offset))
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	events, err := scanAuditEventViews(rows)
	if err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

// maxAuditExportRows bounds one export so a single request can never dump an
// unbounded audit log.
const maxAuditExportRows = 1000

// ExportAuditEvents returns a bounded slice of matching events (oldest-first
// within the window so re-exports are stable) and records who exported what.
func (service *AuditQueryService) ExportAuditEvents(
	ctx context.Context,
	filter AuditEventFilter,
	exportedBy string,
) ([]AuditEventView, error) {
	if strings.TrimSpace(exportedBy) == "" {
		return nil, errors.New("exporting actor must not be empty")
	}
	if filter.Limit <= 0 || filter.Limit > maxAuditExportRows {
		filter.Limit = maxAuditExportRows
	}
	filter.Offset = 0

	args := make([]any, 0, 7)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	conditions, err := buildAuditEventConditions(filter, addArg)
	if err != nil {
		return nil, err
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	query := auditEventSelectColumns + where +
		fmt.Sprintf(" ORDER BY occurred_at, id LIMIT %s", addArg(filter.Limit))
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("export audit events: %w", err)
	}
	defer rows.Close()
	events, err := scanAuditEventViews(rows)
	if err != nil {
		return nil, err
	}

	metadata, err := json.Marshal(map[string]any{
		"exported_by": exportedBy,
		"row_count":   len(events),
		"limit":       filter.Limit,
		"filter":      filterSummaryForAudit(filter),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal export audit metadata: %w", err)
	}
	if err := service.auditEvents.WriteAuditEvent(ctx, AuditEvent{
		ActorID:      exportedBy,
		Action:       "AUDIT_EVENTS_EXPORTED",
		ResourceType: "iam_audit_event",
		Outcome:      "SUCCESS",
		Metadata:     metadata,
	}); err != nil {
		return nil, fmt.Errorf("record audit export event: %w", err)
	}
	return events, nil
}

func filterSummaryForAudit(filter AuditEventFilter) map[string]any {
	summary := map[string]any{}
	if value := strings.TrimSpace(filter.ActorID); value != "" {
		summary["actor_id"] = value
	}
	if value := strings.TrimSpace(filter.Action); value != "" {
		summary["action"] = value
	}
	if value := strings.TrimSpace(filter.ResourceType); value != "" {
		summary["resource_type"] = value
	}
	if value := strings.TrimSpace(filter.ResourceID); value != "" {
		summary["resource_id"] = value
	}
	if value := strings.TrimSpace(filter.Outcome); value != "" {
		summary["outcome"] = value
	}
	if filter.From != nil {
		summary["from"] = filter.From.UTC().Format(time.RFC3339)
	}
	if filter.To != nil {
		summary["to"] = filter.To.UTC().Format(time.RFC3339)
	}
	return summary
}

func scanAuditEventViews(rows *sql.Rows) ([]AuditEventView, error) {
	events := make([]AuditEventView, 0)
	for rows.Next() {
		var event AuditEventView
		var metadata []byte
		if err := rows.Scan(&event.ID, &event.RequestID, &event.ActorID, &event.Action,
			&event.ResourceType, &event.ResourceID, &event.Outcome, &event.HTTPStatus,
			&metadata, &event.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		event.Metadata = json.RawMessage(metadata)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}
