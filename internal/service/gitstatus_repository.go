package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// SQLGitStatusRepository implements GitStatusRepository using PostgreSQL.
type SQLGitStatusRepository struct {
	db *sql.DB
}

// NewSQLGitStatusRepository creates a new SQLGitStatusRepository.
func NewSQLGitStatusRepository(db *sql.DB) (*SQLGitStatusRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection must not be nil")
	}
	return &SQLGitStatusRepository{db: db}, nil
}

// ListPollableTickets returns active tickets whose remote request still
// needs polling.
//
// 轮询终点有两类：CLOSED（对端关闭，无后续）与 CI 已出终态（SUCCEEDED →
// 关单；FAILED/CANCELED → 挂起留人工）。**MERGED 本身不再是终点**——CI
// apply 回调开启后，merged 工单还要等 `finops/terraform-apply` 的 commit
// status，轮询在 merge 之后才进入关键阶段。若把 MERGED 一律排除，worker
// 重启时 sweep 捡不到「已 merge、正等 CI」的工单，轮询线程静默死亡（只剩
// 主动回调一条活路）；因此此处放行 merged + CI 未定（NULL/PENDING/
// RUNNING/UNKNOWN）的工单。预算耗尽（poll_attempt_count >= 上限）的工单
// 仍然停住，只有管理员显式 re-arm 才会继续。
func (r *SQLGitStatusRepository) ListPollableTickets(ctx context.Context) ([]PollableTicket, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT ticket_no, LOWER(git_provider), git_repository, remote_request_number
		FROM iam_ticket
		WHERE status IN ($1, $2, $3)
			AND poll_attempt_count < $4
			AND remote_request_number IS NOT NULL AND remote_request_number <> ''
			AND git_repository IS NOT NULL AND git_repository <> ''
			AND git_provider IS NOT NULL AND git_provider <> ''
			AND (git_merge_state IS NULL
				OR git_merge_state NOT IN ('MERGED', 'CLOSED')
				OR (git_merge_state = 'MERGED'
					AND (git_ci_state IS NULL
						OR git_ci_state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELED'))))`,
		TicketStatusApproved, TicketStatusPublishing, TicketStatusPublishFailed, MaxPollAttempts,
	)
	if err != nil {
		return nil, fmt.Errorf("query pollable tickets: %w", err)
	}
	defer rows.Close()

	tickets := make([]PollableTicket, 0)
	for rows.Next() {
		var ticket PollableTicket
		if err := rows.Scan(&ticket.TicketNo, &ticket.Provider, &ticket.Project, &ticket.RemoteRequestNumber); err != nil {
			return nil, fmt.Errorf("scan pollable ticket: %w", err)
		}
		tickets = append(tickets, ticket)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pollable tickets: %w", err)
	}
	return tickets, nil
}

// SaveExecutionRecord persists an IAC execution record.
func (r *SQLGitStatusRepository) SaveExecutionRecord(ctx context.Context, ticketNo string, record model.IACExecutionRecord) error {
	// Resolve ticket ID from ticket number
	var ticketID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM iam_ticket WHERE ticket_no = $1`,
		ticketNo,
	).Scan(&ticketID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("ticket not found: %s", ticketNo)
		}
		return fmt.Errorf("resolve ticket ID: %w", err)
	}

	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `INSERT INTO iac_execution_record
		(ticket_id, provider, repository, remote_request_number, remote_url, commit_sha,
		 pipeline_id, merge_state, ci_state, apply_result, attempt, idempotency_key,
		 sanitized_error, metadata, observed_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, NOW())
		ON CONFLICT (idempotency_key) DO NOTHING`,
		ticketID, strings.ToUpper(record.Provider), record.Repository, record.RemoteRequestNumber,
		record.RemoteURL, record.CommitSHA, record.PipelineID, record.MergeState,
		record.CIState, record.ApplyResult, record.Attempt, record.IdempotencyKey,
		record.SanitizedError, metadataJSON, record.ObservedAt,
	)
	if err != nil {
		return fmt.Errorf("insert execution record: %w", err)
	}

	return nil
}

// UpdateTicketGitStatus updates the Git-related status fields of a ticket.
func (r *SQLGitStatusRepository) UpdateTicketGitStatus(ctx context.Context, ticketNo string, status GitTicketStatus) error {
	result, err := r.db.ExecContext(ctx, `UPDATE iam_ticket
		SET git_merge_state = $1,
			git_ci_state = $2,
			git_apply_result = $3,
			poll_attempt_count = $4,
			next_poll_at = $5,
			last_status_poll_at = $6,
			updated_at = NOW()
		WHERE ticket_no = $7`,
		status.MergeState, status.CIState, status.ApplyResult,
		status.PollAttemptCount, status.NextPollAt, status.LastStatusPollAt,
		ticketNo,
	)
	if err != nil {
		return fmt.Errorf("update ticket git status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check update result: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ticket %s not found", ticketNo)
	}

	return nil
}

// GetTicket retrieves a ticket by ticket number.
func (r *SQLGitStatusRepository) GetTicket(ctx context.Context, ticketNo string) (model.IAMTicket, error) {
	var ticket model.IAMTicket
	var requestPolicy []byte
	var approverIDs []byte

	err := r.db.QueryRowContext(ctx, `SELECT
		id, ticket_no, ticket_type, account_id, principal_name, request_policy,
		approval_mode, approver_ids, terraform_code, git_pr_url, git_provider,
		git_repository, remote_request_number, git_commit_sha, status, submitter,
		created_at, updated_at
		FROM iam_ticket WHERE ticket_no = $1`, ticketNo,
	).Scan(
		&ticket.ID, &ticket.TicketNo, &ticket.TicketType, &ticket.AccountID,
		&ticket.PrincipalName, &requestPolicy, &ticket.ApprovalMode, &approverIDs,
		&ticket.TerraformCode, &ticket.GitPRURL, &ticket.GitProvider,
		&ticket.GitRepository, &ticket.RemoteRequestNumber, &ticket.GitCommitSHA,
		&ticket.Status, &ticket.Submitter, &ticket.CreatedAt, &ticket.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.IAMTicket{}, ErrTicketNotFound
		}
		return model.IAMTicket{}, fmt.Errorf("get ticket: %w", err)
	}

	ticket.RequestPolicy = model.JSONB(requestPolicy)
	ticket.ApproverIDs = model.JSONB(approverIDs)

	return ticket, nil
}

// GetTicketByNumber retrieves a ticket by ticket number (helper for poller).
func (r *SQLGitStatusRepository) GetTicketByNumber(ctx context.Context, ticketNo string) (*model.IAMTicket, error) {
	ticket, err := r.GetTicket(ctx, ticketNo)
	if err != nil {
		return nil, err
	}
	return &ticket, nil
}

// MarkTicketPublishFailed marks a ticket as PUBLISH_FAILED with an error message.
func (r *SQLGitStatusRepository) MarkTicketPublishFailed(ctx context.Context, ticketNo, errorMessage string) error {
	result, err := r.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, updated_at = NOW()
		WHERE ticket_no = $2 AND status IN ($3, $4, $5)`,
		TicketStatusPublishFailed, ticketNo, TicketStatusApproved, TicketStatusPublishing, TicketStatusPublishFailed,
	)
	if err != nil {
		return fmt.Errorf("mark ticket publish failed: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check mark publish failed result: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ticket %s was not marked as PUBLISH_FAILED (may already be in terminal state)", ticketNo)
	}

	return nil
}

// RestoreTicketStatus moves a PUBLISH_FAILED ticket back to APPROVED once a
// poll proves the remote request exists. Tickets in any other state are left
// untouched, so the call is safe to repeat on every successful poll.
func (r *SQLGitStatusRepository) RestoreTicketStatus(ctx context.Context, ticketNo string) error {
	result, err := r.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, updated_at = NOW()
		WHERE ticket_no = $2 AND status = $3`,
		TicketStatusApproved, ticketNo, TicketStatusPublishFailed,
	)
	if err != nil {
		return fmt.Errorf("restore ticket status: %w", err)
	}
	if _, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("check restore ticket status result: %w", err)
	}
	return nil
}

// CloseTicket closes a ticket with the specified reason.
func (r *SQLGitStatusRepository) CloseTicket(ctx context.Context, ticketNo, actorID, reason string) (model.IAMTicket, error) {
	ticket, err := r.GetTicket(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, err
	}

	if ticket.Status == nil {
		return model.IAMTicket{}, fmt.Errorf("ticket %s has no status", ticketNo)
	}

	// Only allow closing from states a merged request makes terminal
	if *ticket.Status != TicketStatusApproved &&
		*ticket.Status != TicketStatusPublishing &&
		*ticket.Status != TicketStatusPublishFailed {
		return model.IAMTicket{}, fmt.Errorf("ticket %s cannot be closed from state %s", ticketNo, *ticket.Status)
	}

	result, err := r.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, closed_at = NOW(), closed_by = $2, closure_reason = $3, updated_at = NOW()
		WHERE ticket_no = $4`,
		"CLOSED", actorID, reason, ticketNo,
	)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("close ticket: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("check close ticket result: %w", err)
	}
	if rowsAffected == 0 {
		return model.IAMTicket{}, fmt.Errorf("ticket %s was not closed", ticketNo)
	}

	ticket.Status = stringPointer("CLOSED")
	closedBy := actorID
	ticket.ClosedBy = &closedBy
	closedAt := time.Now()
	ticket.ClosedAt = &closedAt
	closureReason := reason
	ticket.ClosureReason = &closureReason

	return ticket, nil
}

// UpdateTicketPollStatus updates the poll status fields of a ticket.
func (r *SQLGitStatusRepository) UpdateTicketPollStatus(ctx context.Context, ticketNo string, pollAttemptCount int, nextPollAt, lastStatusPollAt *time.Time) error {
	result, err := r.db.ExecContext(ctx, `UPDATE iam_ticket
		SET poll_attempt_count = $1,
			next_poll_at = $2,
			last_status_poll_at = $3,
			updated_at = NOW()
		WHERE ticket_no = $4`,
		pollAttemptCount, nextPollAt, lastStatusPollAt, ticketNo,
	)
	if err != nil {
		return fmt.Errorf("update ticket poll status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check update result: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ticket %s not found", ticketNo)
	}

	return nil
}
