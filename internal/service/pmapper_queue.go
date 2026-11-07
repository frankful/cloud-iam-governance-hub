package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/hibiken/asynq"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

var ErrNoPMapperPrincipals = errors.New("no persisted IAM principals")

// LoadPMapperPrincipalsForAccount returns persisted principals, including the
// database IDs required to associate PMapper graph edges with their records.
func LoadPMapperPrincipalsForAccount(
	ctx context.Context,
	db *sql.DB,
	accountID int64,
) ([]model.IAMPrincipal, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	if accountID <= 0 {
		return nil, errors.New("account database ID must be positive")
	}

	const query = `SELECT id, account_id, principal_type, principal_name, arn,
		trust_policy, description, last_used_at, created_at, updated_at
		FROM iam_principal WHERE account_id = $1 AND is_deleted = FALSE ORDER BY id`
	rows, err := db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("load persisted IAM principals for account %d: %w", accountID, err)
	}
	defer rows.Close()

	principals := make([]model.IAMPrincipal, 0)
	for rows.Next() {
		var principal model.IAMPrincipal
		var persistedAccountID sql.NullInt64
		var trustPolicy sql.NullString
		var description sql.NullString
		var lastUsedAt sql.NullTime
		if err := rows.Scan(
			&principal.ID,
			&persistedAccountID,
			&principal.PrincipalType,
			&principal.PrincipalName,
			&principal.ARN,
			&trustPolicy,
			&description,
			&lastUsedAt,
			&principal.CreatedAt,
			&principal.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan persisted IAM principal for account %d: %w", accountID, err)
		}
		if persistedAccountID.Valid {
			principal.AccountID = &persistedAccountID.Int64
		}
		if trustPolicy.Valid {
			principal.TrustPolicy = model.JSONB(trustPolicy.String)
		}
		if description.Valid {
			principal.Description = &description.String
		}
		if lastUsedAt.Valid {
			principal.LastUsedAt = &lastUsedAt.Time
		}
		if principal.ID <= 0 || strings.TrimSpace(principal.ARN) == "" {
			return nil, fmt.Errorf("persisted IAM principal for account %d has an invalid ID or ARN", accountID)
		}
		principals = append(principals, principal)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted IAM principals for account %d: %w", accountID, err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close persisted IAM principal rows for account %d: %w", accountID, err)
	}
	if len(principals) == 0 {
		return nil, fmt.Errorf("%w found for account %d", ErrNoPMapperPrincipals, accountID)
	}

	policyRows, err := db.QueryContext(ctx, `WITH effective_policy AS (
		SELECT principal_id, policy_id FROM iam_principal_policy
		UNION
		SELECT membership.user_principal_id, group_policy.policy_id
		FROM iam_group_membership AS membership
		JOIN iam_group_policy AS group_policy ON group_policy.group_id = membership.group_id
	)
	SELECT effective_policy.principal_id, policy.id, policy.policy_arn, policy.policy_name,
	       policy.policy_type, policy.policy_document, policy.risk_score
	FROM effective_policy
	JOIN iam_policy AS policy ON policy.id = effective_policy.policy_id
	JOIN iam_principal AS principal ON principal.id = effective_policy.principal_id
	WHERE principal.account_id = $1 AND principal.is_deleted = FALSE
	ORDER BY effective_policy.principal_id, policy.id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("load persisted effective IAM policies for account %d: %w", accountID, err)
	}
	principalByID := make(map[int64]int, len(principals))
	for index := range principals {
		principalByID[principals[index].ID] = index
	}
	for policyRows.Next() {
		var principalID int64
		var policy model.IAMPolicy
		var policyARN, policyName, policyType sql.NullString
		var policyDocument []byte
		if err := policyRows.Scan(
			&principalID, &policy.ID, &policyARN, &policyName, &policyType,
			&policyDocument, &policy.RiskScore,
		); err != nil {
			policyRows.Close()
			return nil, fmt.Errorf("scan effective IAM policy for account %d: %w", accountID, err)
		}
		index, exists := principalByID[principalID]
		if !exists {
			policyRows.Close()
			return nil, fmt.Errorf("effective IAM policy references unknown principal %d", principalID)
		}
		if policyARN.Valid {
			policy.PolicyARN = &policyARN.String
		}
		if policyName.Valid {
			policy.PolicyName = &policyName.String
		}
		if policyType.Valid {
			policy.PolicyType = &policyType.String
		}
		policy.PolicyDocument = model.JSONB(policyDocument)
		principals[index].Policies = append(principals[index].Policies, policy)
	}
	if err := policyRows.Err(); err != nil {
		policyRows.Close()
		return nil, fmt.Errorf("iterate effective IAM policies for account %d: %w", accountID, err)
	}
	if err := policyRows.Close(); err != nil {
		return nil, fmt.Errorf("close effective IAM policy rows for account %d: %w", accountID, err)
	}
	return principals, nil
}

// EnqueuePMapperGraphBuildForAccount queues a graph build using the persisted
// principal rows for an AWS account.
func EnqueuePMapperGraphBuildForAccount(
	ctx context.Context,
	client *asynq.Client,
	db *sql.DB,
	accountID int64,
	options ...asynq.Option,
) (*asynq.TaskInfo, error) {
	principals, err := LoadPMapperPrincipalsForAccount(ctx, db, accountID)
	if err != nil {
		return nil, err
	}
	return EnqueuePMapperGraphBuild(ctx, client, principals, options...)
}
