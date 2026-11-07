package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AWSAccountRef is the lightweight account reference the frontend needs to
// build account pickers (ticket forms, inventory filters). It exposes the
// database id because ticket/inventory APIs are keyed by it.
type AWSAccountRef struct {
	ID              int64   `json:"id"`
	AWSAccountID    string  `json:"aws_account_id"`
	AccountName     *string `json:"account_name,omitempty"`
	ReadOnlyRoleARN *string `json:"read_only_role_arn,omitempty"`
	// SyncEnabled is false for accounts without an onboarding config or
	// whose sync was disabled by an administrator. Clients use it to keep
	// unavailable accounts out of provisioning/ticket target pickers.
	SyncEnabled bool `json:"sync_enabled"`
}

// AWSAccountQueryService lists known AWS accounts.
type AWSAccountQueryService struct {
	db *sql.DB
}

// NewAWSAccountQueryService creates an AWSAccountQueryService.
func NewAWSAccountQueryService(database *sql.DB) (*AWSAccountQueryService, error) {
	if database == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &AWSAccountQueryService{db: database}, nil
}

// ListAccounts returns all known AWS accounts ordered by account id, each
// annotated with whether it is available for provisioning (has an onboarding
// config with sync enabled).
func (service *AWSAccountQueryService) ListAccounts(ctx context.Context) ([]AWSAccountRef, error) {
	rows, err := service.db.QueryContext(ctx, `SELECT a.id, a.account_id, a.account_name,
		a.read_only_role_arn, COALESCE(bool_or(c.sync_enabled), FALSE)
		FROM aws_account a
		LEFT JOIN aws_account_config c
			ON c.aws_account_db_id = a.id
			OR (c.aws_account_db_id IS NULL AND c.aws_account_id = a.account_id)
		GROUP BY a.id, a.account_id, a.account_name, a.read_only_role_arn
		ORDER BY a.account_id, a.id`)
	if err != nil {
		return nil, fmt.Errorf("list AWS accounts: %w", err)
	}
	defer rows.Close()
	accounts := make([]AWSAccountRef, 0)
	for rows.Next() {
		var account AWSAccountRef
		if err := rows.Scan(&account.ID, &account.AWSAccountID, &account.AccountName,
			&account.ReadOnlyRoleARN, &account.SyncEnabled); err != nil {
			return nil, fmt.Errorf("scan AWS account: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate AWS accounts: %w", err)
	}
	return accounts, nil
}
