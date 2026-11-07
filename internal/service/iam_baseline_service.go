package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

var (
	ErrIAMBaselineNotFound        = errors.New("IAM baseline not found")
	ErrIAMBaselineAccountNotFound = errors.New("AWS account not found")
	baselineIDPattern             = regexp.MustCompile(`^[A-Za-z0-9:_*?./-]{1,512}$`)
)

type IAMBaselineRepository interface {
	CreateVersion(ctx context.Context, accountID int64, policy abstractiam.AbstractPolicy, enabled bool, actorID string) (model.IAMBaseline, error)
	List(ctx context.Context, accountID int64) ([]model.IAMBaseline, error)
	SetEnabled(ctx context.Context, accountID, baselineID int64, enabled bool, actorID string) (model.IAMBaseline, error)
}

type IAMBaselineService struct {
	repository IAMBaselineRepository
}

func NewIAMBaselineService(repository IAMBaselineRepository) (*IAMBaselineService, error) {
	if repository == nil {
		return nil, errors.New("IAM baseline repository must not be nil")
	}
	return &IAMBaselineService{repository: repository}, nil
}

func (service *IAMBaselineService) Create(
	ctx context.Context,
	accountID int64,
	policy abstractiam.AbstractPolicy,
	enabled bool,
	actorID string,
) (model.IAMBaseline, error) {
	if accountID <= 0 {
		return model.IAMBaseline{}, &IAMBaselineValidationError{Message: "account ID must be positive"}
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" || len(actorID) > 128 {
		return model.IAMBaseline{}, &IAMBaselineValidationError{Message: "authenticated actor ID is invalid"}
	}
	if err := ValidateIAMBaseline(policy); err != nil {
		return model.IAMBaseline{}, err
	}
	baseline, err := service.repository.CreateVersion(ctx, accountID, policy, enabled, actorID)
	if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("create IAM baseline version: %w", err)
	}
	return baseline, nil
}

func (service *IAMBaselineService) List(ctx context.Context, accountID int64) ([]model.IAMBaseline, error) {
	if accountID <= 0 {
		return nil, &IAMBaselineValidationError{Message: "account ID must be positive"}
	}
	return service.repository.List(ctx, accountID)
}

func (service *IAMBaselineService) SetEnabled(
	ctx context.Context,
	accountID, baselineID int64,
	enabled bool,
	actorID string,
) (model.IAMBaseline, error) {
	if accountID <= 0 || baselineID <= 0 {
		return model.IAMBaseline{}, &IAMBaselineValidationError{Message: "account and baseline IDs must be positive"}
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" || len(actorID) > 128 {
		return model.IAMBaseline{}, &IAMBaselineValidationError{Message: "authenticated actor ID is invalid"}
	}
	baseline, err := service.repository.SetEnabled(ctx, accountID, baselineID, enabled, actorID)
	if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("set IAM baseline enabled state: %w", err)
	}
	return baseline, nil
}

type IAMBaselineValidationError struct {
	Message string
}

func (validationError *IAMBaselineValidationError) Error() string {
	return validationError.Message
}

type IAMBaselineViolation struct {
	Code           string `json:"code"`
	StatementIndex int    `json:"statement_index"`
	Action         string `json:"action,omitempty"`
	Resource       string `json:"resource,omitempty"`
	ConditionKey   string `json:"condition_key,omitempty"`
	Description    string `json:"description"`
}

type IAMBaselineComplianceError struct {
	Violations []IAMBaselineViolation `json:"violations"`
}

func (complianceError *IAMBaselineComplianceError) Error() string {
	return fmt.Sprintf("requested policy violates account baseline (%d violation(s))", len(complianceError.Violations))
}

// ValidateIAMBaseline limits Phase 1 baselines to allow-only positive
// selectors, with a deliberately small set of required condition operators.
func ValidateIAMBaseline(policy abstractiam.AbstractPolicy) error {
	if len(policy.Statements) == 0 {
		return &IAMBaselineValidationError{Message: "baseline must contain at least one statement"}
	}
	for statementIndex, statement := range policy.Statements {
		if statement.Effect != "Allow" {
			return &IAMBaselineValidationError{Message: fmt.Sprintf(
				"baseline statement %d must use Effect Allow", statementIndex)}
		}
		if len(statement.NotActions) > 0 || len(statement.NotResources) > 0 {
			return &IAMBaselineValidationError{Message: fmt.Sprintf(
				"baseline statement %d cannot use NotActions or NotResources", statementIndex)}
		}
		if len(statement.Actions) == 0 || len(statement.Resources) == 0 {
			return &IAMBaselineValidationError{Message: fmt.Sprintf(
				"baseline statement %d requires actions and resources", statementIndex)}
		}
		for _, action := range statement.Actions {
			if !baselineIDPattern.MatchString(action) || strings.Count(action, ":") != 1 ||
				strings.HasPrefix(action, ":") || strings.HasSuffix(action, ":") {
				return &IAMBaselineValidationError{Message: fmt.Sprintf(
					"baseline statement %d has invalid abstract action %q", statementIndex, action)}
			}
		}
		for _, resource := range statement.Resources {
			if !baselineIDPattern.MatchString(resource) {
				return &IAMBaselineValidationError{Message: fmt.Sprintf(
					"baseline statement %d has invalid resource pattern %q", statementIndex, resource)}
			}
		}
		for _, condition := range statement.Conditions {
			if condition.Key == "" || len(condition.Values) == 0 {
				return &IAMBaselineValidationError{Message: fmt.Sprintf(
					"baseline statement %d contains an incomplete required condition", statementIndex)}
			}
			if condition.Operator != "StringEquals" && condition.Operator != "StringLike" {
				return &IAMBaselineValidationError{Message: fmt.Sprintf(
					"baseline statement %d uses unsupported condition operator %q", statementIndex, condition.Operator)}
			}
			for _, value := range condition.Values {
				if _, ok := value.(string); !ok {
					return &IAMBaselineValidationError{Message: fmt.Sprintf(
						"baseline statement %d condition values must be strings", statementIndex)}
				}
			}
		}
	}
	return nil
}

// CheckAbstractPolicyAgainstBaseline verifies each explicit allow grant is
// provably covered by at least one baseline statement. It is not a policy
// simulator; ambiguous wildcard containment is conservatively blocked.
func CheckAbstractPolicyAgainstBaseline(
	request abstractiam.AbstractPolicy,
	baseline abstractiam.AbstractPolicy,
) []IAMBaselineViolation {
	violations := make([]IAMBaselineViolation, 0)
	for requestIndex, requestStatement := range request.Statements {
		if requestStatement.Effect != "Allow" || len(requestStatement.NotActions) > 0 ||
			len(requestStatement.NotResources) > 0 {
			violations = append(violations, IAMBaselineViolation{
				Code: "UNSUPPORTED_REQUEST_STATEMENT", StatementIndex: requestIndex,
				Description: "request statements must use Allow with positive actions and resources",
			})
			continue
		}
		if len(requestStatement.Actions) == 0 || len(requestStatement.Resources) == 0 {
			violations = append(violations, IAMBaselineViolation{
				Code: "EMPTY_REQUEST_SELECTOR", StatementIndex: requestIndex,
				Description: "request statement must specify actions and resources",
			})
			continue
		}
		for _, action := range requestStatement.Actions {
			for _, resource := range requestStatement.Resources {
				matched := false
				for _, allowed := range baseline.Statements {
					if allowed.Effect != "Allow" ||
						!anyPatternContains(allowed.Actions, action) ||
						!anyPatternContains(allowed.Resources, resource) {
						continue
					}
					if !requestConditionsMeetBaseline(requestStatement.Conditions, allowed.Conditions) {
						continue
					}
					matched = true
					break
				}
				if !matched {
					violations = append(violations, IAMBaselineViolation{
						Code: "GRANT_OUTSIDE_BASELINE", StatementIndex: requestIndex,
						Action: action, Resource: resource,
						Description: "requested action/resource is not provably covered by an enabled baseline rule",
					})
				}
			}
		}
	}
	return violations
}

func AbstractPolicyFromLegacyPermission(permission model.AbstractPermission) (abstractiam.AbstractPolicy, error) {
	policy := abstractiam.AbstractPolicy{
		Name: permission.Principal.Name, Description: permission.Description,
		Statements: make([]abstractiam.AbstractStatement, 0, len(permission.Permissions)),
	}
	for grantIndex, grant := range permission.Permissions {
		resource, err := canonicalLegacyResource(grant.Resource)
		if err != nil {
			return abstractiam.AbstractPolicy{}, &IAMBaselineValidationError{
				Message: fmt.Sprintf("request permission %d resource cannot be converted to the canonical DSL: %v",
					grantIndex, err),
			}
		}
		statement := abstractiam.AbstractStatement{
			Effect: "Allow", Actions: []string{grant.Action}, Resources: []string{resource},
		}
		if len(grant.Conditions) != 0 {
			operators := make([]string, 0, len(grant.Conditions))
			for operator := range grant.Conditions {
				operators = append(operators, operator)
			}
			sort.Strings(operators)
			for _, operator := range operators {
				conditions, ok := grant.Conditions[operator].(map[string]interface{})
				if !ok {
					return abstractiam.AbstractPolicy{}, &IAMBaselineValidationError{
						Message: fmt.Sprintf("request permission %d has an unsupported condition structure", grantIndex),
					}
				}
				keys := make([]string, 0, len(conditions))
				for key := range conditions {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					values, err := legacyConditionValues(conditions[key])
					if err != nil {
						return abstractiam.AbstractPolicy{}, &IAMBaselineValidationError{
							Message: fmt.Sprintf("request permission %d condition %q: %v", grantIndex, key, err),
						}
					}
					statement.Conditions = append(statement.Conditions, abstractiam.AbstractCondition{
						Key: key, Operator: operator, Values: values,
					})
				}
			}
		}
		policy.Statements = append(policy.Statements, statement)
	}
	return policy, nil
}

func canonicalLegacyResource(resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if strings.HasPrefix(resource, "storage://") {
		location := strings.TrimPrefix(resource, "storage://")
		if location == "" || strings.HasPrefix(location, "/") {
			return "", errors.New("storage resource must include a bucket path")
		}
		bucket, key, hasKey := strings.Cut(location, "/")
		if bucket == "" {
			return "", errors.New("storage resource must include a bucket name")
		}
		canonical := "//storage/bucket/" + bucket
		if hasKey {
			canonical += "/" + key
		}
		return canonical, nil
	}
	if strings.Contains(resource, "://") && !strings.HasPrefix(resource, "//") {
		return "", errors.New("unsupported legacy resource URI")
	}
	if strings.HasPrefix(resource, "arn:") {
		return "", errors.New("AWS ARN is not a cloud-neutral abstract resource")
	}
	if resource == "" {
		return "", errors.New("resource must not be empty")
	}
	return resource, nil
}

func legacyConditionValues(value interface{}) ([]interface{}, error) {
	switch value := value.(type) {
	case string:
		return []interface{}{value}, nil
	case []string:
		values := make([]interface{}, len(value))
		for index, item := range value {
			values[index] = item
		}
		return values, nil
	case []interface{}:
		for _, item := range value {
			if _, ok := item.(string); !ok {
				return nil, errors.New("condition values must be strings")
			}
		}
		return value, nil
	default:
		return nil, errors.New("condition values must be a string or string array")
	}
}

func anyPatternContains(patterns []string, request string) bool {
	for _, pattern := range patterns {
		if patternContains(pattern, request) {
			return true
		}
	}
	return false
}

func patternContains(allowed, request string) bool {
	if allowed == request || allowed == "*" {
		return true
	}
	if !strings.ContainsAny(request, "*?") {
		matched, err := simpleGlobMatch(allowed, request)
		return err == nil && matched
	}
	if strings.Count(allowed, "*") == 1 && strings.HasSuffix(allowed, "*") &&
		!strings.Contains(allowed, "?") &&
		strings.Count(request, "*") == 1 && strings.HasSuffix(request, "*") &&
		!strings.Contains(request, "?") {
		return strings.HasPrefix(strings.TrimSuffix(request, "*"), strings.TrimSuffix(allowed, "*"))
	}
	return false
}

func simpleGlobMatch(pattern, value string) (bool, error) {
	var expression strings.Builder
	expression.WriteByte('^')
	for _, character := range pattern {
		switch character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteByte('$')
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return false, err
	}
	return compiled.MatchString(value), nil
}

func requestConditionsMeetBaseline(
	requestConditions []abstractiam.AbstractCondition,
	requiredConditions []abstractiam.AbstractCondition,
) bool {
	for _, required := range requiredConditions {
		found := false
		for _, requested := range requestConditions {
			if requested.Key != required.Key || requested.Operator != required.Operator {
				continue
			}
			for _, requiredValue := range required.Values {
				requiredString, ok := requiredValue.(string)
				if !ok {
					continue
				}
				for _, requestedValue := range requested.Values {
					requestedString, ok := requestedValue.(string)
					if !ok {
						continue
					}
					if required.Operator == "StringEquals" && requestedString == requiredString {
						found = true
					}
					if required.Operator == "StringLike" {
						if patternContains(requiredString, requestedString) {
							found = true
						}
					}
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type SQLIAMBaselineRepository struct {
	db *sql.DB
}

func NewSQLIAMBaselineRepository(db *sql.DB) (*SQLIAMBaselineRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLIAMBaselineRepository{db: db}, nil
}

func (repository *SQLIAMBaselineRepository) CreateVersion(
	ctx context.Context,
	accountID int64,
	policy abstractiam.AbstractPolicy,
	enabled bool,
	actorID string,
) (model.IAMBaseline, error) {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("marshal baseline policy: %w", err)
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("begin IAM baseline creation: %w", err)
	}
	defer tx.Rollback()
	var lockedAccountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM aws_account WHERE id = $1 FOR UPDATE`, accountID).
		Scan(&lockedAccountID); errors.Is(err, sql.ErrNoRows) {
		return model.IAMBaseline{}, ErrIAMBaselineAccountNotFound
	} else if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("lock AWS account for baseline version: %w", err)
	}
	var version int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM iam_baseline WHERE account_id = $1`, accountID,
	).Scan(&version); err != nil {
		return model.IAMBaseline{}, fmt.Errorf("allocate IAM baseline version: %w", err)
	}
	if enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE iam_baseline SET enabled = FALSE
			WHERE account_id = $1 AND enabled = TRUE`, accountID); err != nil {
			return model.IAMBaseline{}, fmt.Errorf("disable previous IAM baseline: %w", err)
		}
	}
	baseline, err := scanIAMBaseline(tx.QueryRowContext(ctx, `INSERT INTO iam_baseline
		(account_id, version, abstract_policy, enabled, created_by, created_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, NOW())
		RETURNING id, account_id, version, abstract_policy, enabled, created_by, created_at`,
		accountID, version, string(policyJSON), enabled, actorID,
	))
	if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("insert IAM baseline version: %w", err)
	}
	if err := insertBaselineAudit(ctx, tx, actorID, "IAM_BASELINE_CREATED", baseline, map[string]interface{}{
		"version": baseline.Version, "enabled": baseline.Enabled,
	}); err != nil {
		return model.IAMBaseline{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.IAMBaseline{}, fmt.Errorf("commit IAM baseline creation: %w", err)
	}
	return baseline, nil
}

func (repository *SQLIAMBaselineRepository) List(
	ctx context.Context,
	accountID int64,
) ([]model.IAMBaseline, error) {
	var accountExists bool
	if err := repository.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM aws_account WHERE id = $1)`, accountID,
	).Scan(&accountExists); err != nil {
		return nil, fmt.Errorf("check AWS account for IAM baselines: %w", err)
	}
	if !accountExists {
		return nil, ErrIAMBaselineAccountNotFound
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT id, account_id, version,
		abstract_policy, enabled, created_by, created_at
		FROM iam_baseline WHERE account_id = $1 ORDER BY version DESC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list IAM baselines: %w", err)
	}
	defer rows.Close()
	baselines := make([]model.IAMBaseline, 0)
	for rows.Next() {
		baseline, err := scanIAMBaseline(rows)
		if err != nil {
			return nil, fmt.Errorf("scan IAM baseline: %w", err)
		}
		baselines = append(baselines, baseline)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate IAM baselines: %w", err)
	}
	return baselines, nil
}

func (repository *SQLIAMBaselineRepository) SetEnabled(
	ctx context.Context,
	accountID, baselineID int64,
	enabled bool,
	actorID string,
) (model.IAMBaseline, error) {
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("begin IAM baseline activation: %w", err)
	}
	defer tx.Rollback()
	var lockedAccountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM aws_account WHERE id = $1 FOR UPDATE`, accountID).
		Scan(&lockedAccountID); errors.Is(err, sql.ErrNoRows) {
		return model.IAMBaseline{}, ErrIAMBaselineAccountNotFound
	} else if err != nil {
		return model.IAMBaseline{}, fmt.Errorf("lock AWS account for baseline activation: %w", err)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM iam_baseline WHERE id = $1 AND account_id = $2
	)`, baselineID, accountID).Scan(&exists); err != nil {
		return model.IAMBaseline{}, fmt.Errorf("check IAM baseline ownership: %w", err)
	}
	if !exists {
		return model.IAMBaseline{}, ErrIAMBaselineNotFound
	}
	if enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE iam_baseline SET enabled = FALSE
			WHERE account_id = $1 AND enabled = TRUE`, accountID); err != nil {
			return model.IAMBaseline{}, fmt.Errorf("disable active IAM baseline: %w", err)
		}
	}
	baseline, err := scanIAMBaseline(tx.QueryRowContext(ctx, `UPDATE iam_baseline
		SET enabled = $3
		WHERE id = $1 AND account_id = $2
		RETURNING id, account_id, version, abstract_policy, enabled, created_by, created_at`,
		baselineID, accountID, enabled,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.IAMBaseline{}, ErrIAMBaselineNotFound
		}
		return model.IAMBaseline{}, fmt.Errorf("update IAM baseline enabled state: %w", err)
	}
	if err := insertBaselineAudit(ctx, tx, actorID, "IAM_BASELINE_ENABLED_CHANGED", baseline,
		map[string]interface{}{"version": baseline.Version, "enabled": enabled}); err != nil {
		return model.IAMBaseline{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.IAMBaseline{}, fmt.Errorf("commit IAM baseline activation: %w", err)
	}
	return baseline, nil
}

type baselineRowScanner interface {
	Scan(...interface{}) error
}

func scanIAMBaseline(row baselineRowScanner) (model.IAMBaseline, error) {
	var baseline model.IAMBaseline
	var createdBy sql.NullString
	err := row.Scan(
		&baseline.ID, &baseline.AccountID, &baseline.Version, &baseline.AbstractPolicy,
		&baseline.Enabled, &createdBy, &baseline.CreatedAt,
	)
	if err != nil {
		return model.IAMBaseline{}, err
	}
	if createdBy.Valid {
		baseline.CreatedBy = &createdBy.String
	}
	return baseline, nil
}

func insertBaselineAudit(
	ctx context.Context,
	tx *sql.Tx,
	actorID, action string,
	baseline model.IAMBaseline,
	metadata map[string]interface{},
) error {
	metadata = cloneBaselineAuditMetadata(metadata)
	metadata["account_db_id"] = baseline.AccountID
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal IAM baseline audit metadata: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO iam_audit_event
		(actor_id, action, resource_type, resource_id, outcome, metadata, occurred_at)
		VALUES ($1, $2, 'iam_baseline', $3, 'SUCCESS', $4::jsonb, NOW())`,
		actorID, action, fmt.Sprint(baseline.ID), string(encoded),
	); err != nil {
		return fmt.Errorf("insert IAM baseline audit event: %w", err)
	}
	return nil
}

func cloneBaselineAuditMetadata(metadata map[string]interface{}) map[string]interface{} {
	cloned := make(map[string]interface{}, len(metadata)+1)
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

var _ IAMBaselineRepository = (*SQLIAMBaselineRepository)(nil)
