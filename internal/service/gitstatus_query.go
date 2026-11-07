package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// GitStatusQueryService provides query methods for Git status and execution records.
type GitStatusQueryService struct {
	db *sql.DB
}

// NewGitStatusQueryService creates a new GitStatusQueryService.
func NewGitStatusQueryService(db *sql.DB) (*GitStatusQueryService, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection must not be nil")
	}
	return &GitStatusQueryService{db: db}, nil
}

// TicketGitStatus represents the Git status of a ticket.
type TicketGitStatus struct {
	TicketNo            string  `json:"ticket_no"`
	GitPRURL            *string `json:"git_pr_url,omitempty"`
	GitProvider         *string `json:"git_provider,omitempty"`
	GitRepository       *string `json:"git_repository,omitempty"`
	RemoteRequestNumber *string `json:"remote_request_number,omitempty"`
	GitCommitSHA        *string `json:"git_commit_sha,omitempty"`
	PollAttemptCount    int     `json:"poll_attempt_count"`
	NextPollAt          *string `json:"next_poll_at,omitempty"`
	LastStatusPollAt    *string `json:"last_status_poll_at,omitempty"`
}

// GetTicketGitStatus retrieves the Git status of a ticket.
func (s *GitStatusQueryService) GetTicketGitStatus(ctx context.Context, ticketNo string) (*TicketGitStatus, error) {
	var status TicketGitStatus
	var nextPollAt, lastStatusPollAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `SELECT
		ticket_no, git_pr_url, git_provider, git_repository,
		remote_request_number, git_commit_sha, poll_attempt_count,
		next_poll_at, last_status_poll_at
		FROM iam_ticket WHERE ticket_no = $1`, ticketNo,
	).Scan(
		&status.TicketNo, &status.GitPRURL, &status.GitProvider,
		&status.GitRepository, &status.RemoteRequestNumber, &status.GitCommitSHA,
		&status.PollAttemptCount, &nextPollAt, &lastStatusPollAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTicketNotFound
		}
		return nil, fmt.Errorf("get ticket git status: %w", err)
	}

	if nextPollAt.Valid {
		t := nextPollAt.Time.Format("2006-01-02T15:04:05Z07:00")
		status.NextPollAt = &t
	}
	if lastStatusPollAt.Valid {
		t := lastStatusPollAt.Time.Format("2006-01-02T15:04:05Z07:00")
		status.LastStatusPollAt = &t
	}

	return &status, nil
}

// ExecutionRecord represents an IAC execution record for API responses.
type ExecutionRecord struct {
	ID                  int64  `json:"id"`
	TicketNo            string `json:"ticket_no"`
	Provider            string `json:"provider"`
	Repository          string `json:"repository"`
	RemoteRequestNumber string `json:"remote_request_number,omitempty"`
	RemoteURL           string `json:"remote_url,omitempty"`
	CommitSHA           string `json:"commit_sha,omitempty"`
	MergeState          string `json:"merge_state"`
	CIState             string `json:"ci_state"`
	ApplyResult         string `json:"apply_result"`
	Attempt             int    `json:"attempt"`
	ObservedAt          string `json:"observed_at"`
}

// ListExecutionRecords retrieves execution records for a ticket.
func (s *GitStatusQueryService) ListExecutionRecords(ctx context.Context, ticketNo string, limit int) ([]ExecutionRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `SELECT
		record.id, ticket.ticket_no, record.provider, record.repository,
		record.remote_request_number, record.remote_url, record.commit_sha,
		record.merge_state, record.ci_state, record.apply_result, record.attempt, record.observed_at
		FROM iac_execution_record record
		JOIN iam_ticket ticket ON ticket.id = record.ticket_id
		WHERE ticket.ticket_no = $1
		ORDER BY record.observed_at DESC
		LIMIT $2`, ticketNo, limit)
	if err != nil {
		return nil, fmt.Errorf("list execution records: %w", err)
	}
	defer rows.Close()

	records := make([]ExecutionRecord, 0)
	for rows.Next() {
		var record ExecutionRecord
		var remoteRequestNumber, remoteURL, commitSHA sql.NullString
		var observedAt sql.NullTime

		if err := rows.Scan(
			&record.ID, &record.TicketNo, &record.Provider, &record.Repository,
			&remoteRequestNumber, &remoteURL, &commitSHA,
			&record.MergeState, &record.CIState, &record.ApplyResult,
			&record.Attempt, &observedAt,
		); err != nil {
			return nil, fmt.Errorf("scan execution record: %w", err)
		}

		if remoteRequestNumber.Valid {
			record.RemoteRequestNumber = remoteRequestNumber.String
		}
		if remoteURL.Valid {
			record.RemoteURL = remoteURL.String
		}
		if commitSHA.Valid {
			record.CommitSHA = commitSHA.String
		}
		if observedAt.Valid {
			record.ObservedAt = observedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		}

		records = append(records, record)
	}

	return records, nil
}

// ListTicketExecutionRecords retrieves execution records for a ticket by ticket number.
func (s *GitStatusQueryService) ListTicketExecutionRecords(ctx context.Context, ticketNo string) ([]model.IACExecutionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		record.id, ticket.ticket_no, record.provider, record.repository,
		record.remote_request_number, record.remote_url, record.commit_sha,
		record.merge_state, record.ci_state, record.apply_result, record.attempt, record.observed_at
		FROM iac_execution_record record
		JOIN iam_ticket ticket ON ticket.id = record.ticket_id
		WHERE ticket.ticket_no = $1
		ORDER BY record.observed_at DESC
		LIMIT 50`, ticketNo)
	if err != nil {
		return nil, fmt.Errorf("list ticket execution records: %w", err)
	}
	defer rows.Close()

	records := make([]model.IACExecutionRecord, 0)
	for rows.Next() {
		var record model.IACExecutionRecord
		var ticketNo string
		var remoteRequestNumber, remoteURL, commitSHA sql.NullString
		var observedAt sql.NullTime

		if err := rows.Scan(
			&record.ID, &ticketNo, &record.Provider, &record.Repository,
			&remoteRequestNumber, &remoteURL, &record.CommitSHA,
			&record.MergeState, &record.CIState, &record.ApplyResult,
			&record.Attempt, &observedAt,
		); err != nil {
			return nil, fmt.Errorf("scan execution record: %w", err)
		}

		if remoteRequestNumber.Valid {
			record.RemoteRequestNumber = &remoteRequestNumber.String
		}
		if remoteURL.Valid {
			record.RemoteURL = &remoteURL.String
		}
		if commitSHA.Valid {
			record.CommitSHA = &commitSHA.String
		}
		if observedAt.Valid {
			record.ObservedAt = observedAt.Time
		}

		records = append(records, record)
	}

	return records, nil
}
