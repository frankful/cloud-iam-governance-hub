package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/pkg/adapter/aws"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

var ErrPolicyDerivedPrincipalNotFound = errors.New("IAM principal not found in AWS account")

type PolicyDerivedGrantOrigin struct {
	PolicyID   int64   `json:"policy_id"`
	PolicyName *string `json:"policy_name,omitempty"`
	PolicyARN  *string `json:"policy_arn,omitempty"`
	PolicyType *string `json:"policy_type,omitempty"`
	Source     string  `json:"source"`
	GroupID    *int64  `json:"group_id,omitempty"`
	GroupName  *string `json:"group_name,omitempty"`
}

type PolicyDerivedStatement struct {
	Statement abstractiam.AbstractStatement `json:"statement"`
	Origins   []PolicyDerivedGrantOrigin    `json:"origins"`
}

type PolicyDerivedGrants struct {
	AccountID     int64                      `json:"account_id"`
	PrincipalID   int64                      `json:"principal_id"`
	Principal     string                     `json:"principal_name"`
	PrincipalType string                     `json:"principal_type"`
	Policy        abstractiam.AbstractPolicy `json:"abstract_policy"`
	Statements    []PolicyDerivedStatement   `json:"statements"`
	Warnings      []string                   `json:"warnings"`
	SnapshotAt    *time.Time                 `json:"snapshot_at,omitempty"`
	Limitations   []string                   `json:"limitations"`
}

type PolicyDerivedGrantRepository interface {
	GetPolicyDerivedGrants(context.Context, int64, int64) (PolicyDerivedGrants, error)
}

type PolicyDerivedGrantService struct {
	repository PolicyDerivedGrantRepository
}

func NewPolicyDerivedGrantService(repository PolicyDerivedGrantRepository) (*PolicyDerivedGrantService, error) {
	if repository == nil {
		return nil, errors.New("policy-derived grant repository must not be nil")
	}
	return &PolicyDerivedGrantService{repository: repository}, nil
}

func (service *PolicyDerivedGrantService) Get(
	ctx context.Context,
	accountID, principalID int64,
) (PolicyDerivedGrants, error) {
	if accountID <= 0 || principalID <= 0 {
		return PolicyDerivedGrants{}, errors.New("account and principal database IDs must be positive")
	}
	result, err := service.repository.GetPolicyDerivedGrants(ctx, accountID, principalID)
	if err != nil {
		return PolicyDerivedGrants{}, fmt.Errorf("get policy-derived grants: %w", err)
	}
	return result, nil
}

type SQLPolicyDerivedGrantRepository struct {
	db      *sql.DB
	adapter *aws.AwsAdapter
}

func NewSQLPolicyDerivedGrantRepository(db *sql.DB) (*SQLPolicyDerivedGrantRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLPolicyDerivedGrantRepository{db: db, adapter: &aws.AwsAdapter{}}, nil
}

type policyGrantRow struct {
	policyID   int64
	policyName sql.NullString
	policyARN  sql.NullString
	policyType sql.NullString
	document   []byte
	source     string
	groupID    sql.NullInt64
	groupName  sql.NullString
}

func (repository *SQLPolicyDerivedGrantRepository) GetPolicyDerivedGrants(
	ctx context.Context,
	accountID, principalID int64,
) (PolicyDerivedGrants, error) {
	var result PolicyDerivedGrants
	var lastSeen sql.NullTime
	err := repository.db.QueryRowContext(ctx, `SELECT id, principal_name, principal_type, last_seen_at
		FROM iam_principal
		WHERE account_id = $1 AND id = $2 AND is_deleted = FALSE`,
		accountID, principalID,
	).Scan(&result.PrincipalID, &result.Principal, &result.PrincipalType, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyDerivedGrants{}, ErrPolicyDerivedPrincipalNotFound
	}
	if err != nil {
		return PolicyDerivedGrants{}, fmt.Errorf("load IAM principal: %w", err)
	}
	result.AccountID = accountID
	if lastSeen.Valid {
		observed := lastSeen.Time.UTC()
		result.SnapshotAt = &observed
	}

	rows, err := repository.db.QueryContext(ctx, `
		WITH effective_policy AS (
			SELECT principal_policy.principal_id, principal_policy.policy_id,
				'DIRECT'::text AS source, NULL::bigint AS group_id, NULL::text AS group_name
			FROM iam_principal_policy AS principal_policy
			WHERE principal_policy.principal_id = $2
			UNION
			SELECT membership.user_principal_id, group_policy.policy_id,
				'GROUP'::text AS source, group_record.id AS group_id, group_record.group_name AS group_name
			FROM iam_group_membership AS membership
			JOIN iam_group AS group_record ON group_record.id = membership.group_id
			JOIN iam_group_policy AS group_policy ON group_policy.group_id = group_record.id
			WHERE membership.user_principal_id = $2 AND group_record.account_id = $1
		)
		SELECT policy.id, policy.policy_name, policy.policy_arn, policy.policy_type,
			policy.policy_document, effective_policy.source,
			effective_policy.group_id, effective_policy.group_name
		FROM effective_policy
		JOIN iam_principal AS principal
			ON principal.id = effective_policy.principal_id
			AND principal.account_id = $1
			AND principal.is_deleted = FALSE
		JOIN iam_policy AS policy ON policy.id = effective_policy.policy_id
		ORDER BY policy.id, effective_policy.source, effective_policy.group_id`,
		accountID, principalID,
	)
	if err != nil {
		return PolicyDerivedGrants{}, fmt.Errorf("query principal attached policies: %w", err)
	}
	defer rows.Close()

	policyRows := make([]policyGrantRow, 0)
	for rows.Next() {
		var row policyGrantRow
		if err := rows.Scan(
			&row.policyID, &row.policyName, &row.policyARN, &row.policyType,
			&row.document, &row.source, &row.groupID, &row.groupName,
		); err != nil {
			return PolicyDerivedGrants{}, fmt.Errorf("scan principal attached policy: %w", err)
		}
		policyRows = append(policyRows, row)
	}
	if err := rows.Err(); err != nil {
		return PolicyDerivedGrants{}, fmt.Errorf("iterate principal attached policies: %w", err)
	}
	statements, warnings, err := normalizePolicyGrantRows(repository.adapter, result.Principal, policyRows)
	if err != nil {
		return PolicyDerivedGrants{}, err
	}
	result.Statements = statements
	result.Warnings = warnings
	result.Policy = abstractiam.AbstractPolicy{
		Name:        "policy-derived grants for " + result.Principal,
		Description: "Best-effort normalized grants from collected IAM policies; not AWS effective permissions",
		Statements:  make([]abstractiam.AbstractStatement, 0, len(result.Statements)),
	}
	for _, statement := range result.Statements {
		result.Policy.Statements = append(result.Policy.Statements, statement.Statement)
	}
	result.Limitations = []string{
		"Derived from collected managed and inline identity policies; does not evaluate AWS authorization.",
		"Does not include SCPs, permission boundaries, session policies, resource policies, or runtime request context.",
		"Unsupported AWS policy fields or condition values may be omitted; inspect warnings before relying on results.",
	}
	return result, nil
}

func normalizePolicyGrantRows(
	policyAdapter *aws.AwsAdapter,
	principalName string,
	policyRows []policyGrantRow,
) ([]PolicyDerivedStatement, []string, error) {
	statements := make([]PolicyDerivedStatement, 0)
	warnings := make([]string, 0)
	statementIndex := make(map[string]int)
	warningSet := make(map[string]struct{})
	for _, row := range policyRows {
		policy, parseStatus, warning, err := policyAdapter.FromCloudPolicy(row.document)
		if err != nil {
			return nil, nil, fmt.Errorf("parse IAM policy %d: %w", row.policyID, err)
		}
		if parseStatus != aws.ParseStatusSuccess {
			warningSet[fmt.Sprintf("policy %d (%s): %s", row.policyID, nullableString(row.policyName), warning)] = struct{}{}
		}
		for _, statement := range policy.Statements {
			encoded, err := json.Marshal(statement)
			if err != nil {
				return nil, nil, fmt.Errorf("normalize policy %d statement: %w", row.policyID, err)
			}
			digest := sha256.Sum256(encoded)
			key := hex.EncodeToString(digest[:])
			index, exists := statementIndex[key]
			if !exists {
				index = len(statements)
				statementIndex[key] = index
				statements = append(statements, PolicyDerivedStatement{Statement: statement})
			}
			origin := PolicyDerivedGrantOrigin{
				PolicyID: row.policyID, PolicyName: nullStringPointer(row.policyName),
				PolicyARN: nullStringPointer(row.policyARN), PolicyType: nullStringPointer(row.policyType),
				Source: row.source, GroupID: nullInt64Pointer(row.groupID),
				GroupName: nullStringPointer(row.groupName),
			}
			statements[index].Origins = append(statements[index].Origins, origin)
		}
	}
	for warning := range warningSet {
		warnings = append(warnings, warning)
	}
	sort.Strings(warnings)
	sort.Slice(statements, func(i, j int) bool {
		left, _ := json.Marshal(statements[i].Statement)
		right, _ := json.Marshal(statements[j].Statement)
		return strings.Compare(string(left), string(right)) < 0
	})
	return statements, warnings, nil
}

func nullableString(value sql.NullString) string {
	if !value.Valid {
		return "unnamed policy"
	}
	return value.String
}

func nullStringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

func nullInt64Pointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

var _ PolicyDerivedGrantRepository = (*SQLPolicyDerivedGrantRepository)(nil)
