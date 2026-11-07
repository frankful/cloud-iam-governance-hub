package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AuditEvent is a minimal, secret-free record of a platform operation.
type AuditEvent struct {
	RequestID    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Outcome      string
	HTTPStatus   int
	Metadata     json.RawMessage
	OccurredAt   time.Time
}

type AuditWriter interface {
	WriteAuditEvent(context.Context, AuditEvent) error
}

type SQLAuditRepository struct {
	db *sql.DB
}

func NewSQLAuditRepository(db *sql.DB) (*SQLAuditRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLAuditRepository{db: db}, nil
}

func (repository *SQLAuditRepository) WriteAuditEvent(ctx context.Context, event AuditEvent) error {
	if event.Action == "" || event.ResourceType == "" {
		return errors.New("audit action and resource type must not be empty")
	}
	if event.Outcome != "SUCCESS" && event.Outcome != "FAILURE" {
		return errors.New("audit outcome must be SUCCESS or FAILURE")
	}
	metadata := event.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	if !json.Valid(metadata) {
		return errors.New("audit metadata must be valid JSON")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	_, err := repository.db.ExecContext(ctx, `INSERT INTO iam_audit_event
		(request_id, actor_id, action, resource_type, resource_id, outcome, http_status, metadata, occurred_at)
		VALUES (NULLIF($1, ''), NULLIF($2, ''), $3, $4, NULLIF($5, ''), $6, NULLIF($7, 0), $8::jsonb, $9)`,
		event.RequestID, event.ActorID, event.Action, event.ResourceType, event.ResourceID,
		event.Outcome, event.HTTPStatus, string(metadata), event.OccurredAt,
	)
	if err != nil {
		return fmt.Errorf("insert platform audit event: %w", err)
	}
	return nil
}
