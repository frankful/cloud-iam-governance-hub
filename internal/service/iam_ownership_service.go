package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Ownership values for inventoried IAM resources. They answer one question:
// does Terraform declare this resource, or does somebody else own it?
const (
	// OwnershipPlatform means the platform declares the resource in Terraform.
	OwnershipPlatform = "platform"
	// OwnershipExternal means another system owns it (CloudFormation, eksctl,
	// another team's Terraform) — the platform only observes it.
	OwnershipExternal = "external"
	// OwnershipUnknown means nobody has decided yet; the baseline difference
	// list surfaces those for an administrator to assign.
	OwnershipUnknown = "unknown"
)

// Resource key prefixes. They mirror the Terraform file layout, so an
// administrator talks about "role-otel-collector" in both places.
const (
	OwnershipKindRole   = "role"
	OwnershipKindUser   = "user"
	OwnershipKindGroup  = "group"
	OwnershipKindPolicy = "policy"
)

// ErrOwnershipNotFound marks a resource key that does not exist in the
// inventory of the given account.
var ErrOwnershipNotFound = errors.New("resource not found in inventory")

// ResourceOwnership is one inventoried resource with its ownership mark.
type ResourceOwnership struct {
	Key       string `json:"key"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	ManagedBy string `json:"managed_by"`
	AccountID int64  `json:"account_db_id"`
}

// IAMOwnershipRepository stores and reads the ownership marks.
type IAMOwnershipRepository interface {
	// SetOwnership writes the mark plus the audit trail (reviewedBy may be
	// empty for system-driven calls, but the human path must supply it —
	// ownership decides what a baseline may touch).
	SetOwnership(ctx context.Context, accountDBID int64, kind, name, managedBy, reviewedBy string) error
	ListOwnership(ctx context.Context, accountDBID int64, kind, managedBy string) ([]ResourceOwnership, error)
}

// IAMOwnershipService manages the ownership marks of inventoried resources.
type IAMOwnershipService struct {
	repository IAMOwnershipRepository
}

func NewIAMOwnershipService(repository IAMOwnershipRepository) (*IAMOwnershipService, error) {
	if repository == nil {
		return nil, errors.New("IAM ownership repository must not be nil")
	}
	return &IAMOwnershipService{repository: repository}, nil
}

// SetOwnership marks one resource as platform-managed, externally managed or
// undecided. The resource is addressed by its key ("role-<name>",
// "user-<name>", "group-<name>", "policy-<name>") — the same key the
// Terraform file layout uses, so the boundary and the files never drift apart.
// reviewedBy records who made the decision; ownership gates what the baseline
// is allowed to touch, so it must be traceable to a person.
func (service *IAMOwnershipService) SetOwnership(
	ctx context.Context,
	accountDBID int64,
	key string,
	managedBy string,
	reviewedBy string,
) error {
	if service == nil || service.repository == nil {
		return errors.New("IAM ownership service is not configured")
	}
	kind, name, err := ParseOwnershipKey(key)
	if err != nil {
		return err
	}
	managedBy = strings.TrimSpace(managedBy)
	if !IsOwnershipValue(managedBy) {
		return fmt.Errorf("managed_by must be one of %s, %s, %s",
			OwnershipPlatform, OwnershipExternal, OwnershipUnknown)
	}
	if accountDBID <= 0 {
		return errors.New("account_id must be positive")
	}
	return service.repository.SetOwnership(ctx, accountDBID, kind, name, managedBy, strings.TrimSpace(reviewedBy))
}

// ListOwnership returns the ownership marks of one account, optionally
// narrowed by kind and by mark.
func (service *IAMOwnershipService) ListOwnership(
	ctx context.Context,
	accountDBID int64,
	kind string,
	managedBy string,
) ([]ResourceOwnership, error) {
	if service == nil || service.repository == nil {
		return nil, errors.New("IAM ownership service is not configured")
	}
	kind = strings.TrimSpace(kind)
	if kind != "" && !IsOwnershipKind(kind) {
		return nil, fmt.Errorf("unknown resource kind %q", kind)
	}
	managedBy = strings.TrimSpace(managedBy)
	if managedBy != "" && !IsOwnershipValue(managedBy) {
		return nil, fmt.Errorf("managed_by must be one of %s, %s, %s",
			OwnershipPlatform, OwnershipExternal, OwnershipUnknown)
	}
	return service.repository.ListOwnership(ctx, accountDBID, kind, managedBy)
}

// ParseOwnershipKey splits a resource key into its kind and name:
// "role-otel-collector" → ("role", "otel-collector"). Only the first dash
// separates them, so names may contain dashes themselves. The kind prefix is
// case-insensitive, but the name keeps its original case: AWS resource names
// are case-sensitive and a lowercased name silently matches zero rows.
func ParseOwnershipKey(key string) (kind string, name string, err error) {
	key = strings.TrimSpace(key)
	separator := strings.Index(key, "-")
	if separator <= 0 || separator == len(key)-1 {
		return "", "", fmt.Errorf("resource key %q must look like role-<name>, user-<name>, group-<name> or policy-<name>", key)
	}
	kind = strings.ToLower(key[:separator])
	name = key[separator+1:]
	if !IsOwnershipKind(kind) {
		return "", "", fmt.Errorf("unknown resource kind %q in key %q", kind, key)
	}
	return kind, name, nil
}

// IsOwnershipKind reports whether kind is a resource kind the platform owns.
func IsOwnershipKind(kind string) bool {
	switch kind {
	case OwnershipKindRole, OwnershipKindUser, OwnershipKindGroup, OwnershipKindPolicy:
		return true
	default:
		return false
	}
}

// IsOwnershipValue reports whether value is a valid ownership mark.
func IsOwnershipValue(value string) bool {
	switch value {
	case OwnershipPlatform, OwnershipExternal, OwnershipUnknown:
		return true
	default:
		return false
	}
}

// SQLIAMOwnershipRepository stores ownership marks in PostgreSQL.
type SQLIAMOwnershipRepository struct {
	db *sql.DB
}

func NewSQLIAMOwnershipRepository(db *sql.DB) (*SQLIAMOwnershipRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLIAMOwnershipRepository{db: db}, nil
}

func (repository *SQLIAMOwnershipRepository) SetOwnership(
	ctx context.Context,
	accountDBID int64,
	kind, name, managedBy, reviewedBy string,
) error {
	if repository == nil || repository.db == nil {
		return errors.New("IAM ownership database must not be nil")
	}
	// 审计字段只在这里写：采集器不碰归属，标注记录是谁做的决定。
	// 各分支参数个数不同，审计占位符按分支各自编号。
	auditSet := func(reviewedByParam int) string {
		return fmt.Sprintf(`, managed_by_reviewed_at = NOW(),
		                    managed_by_reviewed_by = NULLIF($%d, '')`, reviewedByParam)
	}
	var result sql.Result
	var err error
	switch kind {
	case OwnershipKindRole, OwnershipKindUser:
		result, err = repository.db.ExecContext(ctx,
			`UPDATE iam_principal SET managed_by = $1`+auditSet(5)+`
			 WHERE account_id = $2 AND principal_name = $3 AND principal_type = $4`,
			managedBy, accountDBID, name, strings.Title(kind), reviewedBy)
	case OwnershipKindGroup:
		result, err = repository.db.ExecContext(ctx,
			`UPDATE iam_group SET managed_by = $1`+auditSet(4)+`
			 WHERE account_id = $2 AND group_name = $3`,
			managedBy, accountDBID, name, reviewedBy)
	case OwnershipKindPolicy:
		// 0021 之前这里只按 policy_name 匹配：policy_arn 全局唯一但 policy_name
		// 不是——改一个账号的归属会把所有账号同名策略一起改掉。customer-managed
		// 策略行已带 account_id（AWS 托管策略为 NULL，本就不该被标注）。
		result, err = repository.db.ExecContext(ctx,
			`UPDATE iam_policy SET managed_by = $1`+auditSet(4)+`
			 WHERE account_id = $2 AND policy_name = $3 AND policy_type = 'managed'`,
			managedBy, accountDBID, name, reviewedBy)
	default:
		return fmt.Errorf("unknown resource kind %q", kind)
	}
	if err != nil {
		return fmt.Errorf("update ownership of %s-%s: %w", kind, name, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update ownership of %s-%s: %w", kind, name, err)
	}
	if affected == 0 {
		return ErrOwnershipNotFound
	}
	return nil
}

func (repository *SQLIAMOwnershipRepository) ListOwnership(
	ctx context.Context,
	accountDBID int64,
	kind, managedBy string,
) ([]ResourceOwnership, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("IAM ownership database must not be nil")
	}
	rows := make([]ResourceOwnership, 0)
	appendRows := func(query string, args ...any) error {
		result, err := repository.db.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list ownership: %w", err)
		}
		defer result.Close()
		for result.Next() {
			var ownership ResourceOwnership
			if err := result.Scan(&ownership.Key, &ownership.Kind, &ownership.Name,
				&ownership.ManagedBy, &ownership.AccountID); err != nil {
				return fmt.Errorf("scan ownership: %w", err)
			}
			rows = append(rows, ownership)
		}
		return result.Err()
	}
	accountCondition := ""
	args := make([]any, 0, 3)
	if accountDBID > 0 {
		accountCondition = " AND account_id = $1"
		args = append(args, accountDBID)
	}
	managedCondition := ""
	if managedBy != "" {
		args = append(args, managedBy)
		managedCondition = fmt.Sprintf(" AND managed_by = $%d", len(args))
	}
	switch kind {
	case "":
		err := appendRows(`SELECT 'role-' || principal_name AS key, 'role' AS kind,
				principal_name AS name, managed_by, account_id
			FROM iam_principal WHERE principal_type = 'Role'`+accountCondition+managedCondition, args...)
		if err != nil {
			return nil, err
		}
		err = appendRows(`SELECT 'user-' || principal_name AS key, 'user' AS kind,
				principal_name AS name, managed_by, account_id
			FROM iam_principal WHERE principal_type = 'User'`+accountCondition+managedCondition, args...)
		if err != nil {
			return nil, err
		}
		err = appendRows(`SELECT 'group-' || group_name AS key, 'group' AS kind,
				group_name AS name, managed_by, account_id
			FROM iam_group WHERE TRUE`+accountCondition+managedCondition, args...)
		if err != nil {
			return nil, err
		}
		// AWS 托管策略本体（account_id 为 NULL）不属于任何账号，也不可标注，
		// 不进归属清单——否则清零账号过滤时会列出一堆没法操作的行。
		err = appendRows(`SELECT 'policy-' || policy_name AS key, 'policy' AS kind,
				policy_name AS name, managed_by, COALESCE(account_id, 0) AS account_id
			FROM iam_policy
			WHERE policy_type = 'managed' AND account_id IS NOT NULL`+accountCondition+managedCondition, args...)
		if err != nil {
			return nil, err
		}
	case OwnershipKindRole:
		if err := appendRows(`SELECT 'role-' || principal_name AS key, 'role' AS kind,
				principal_name AS name, managed_by, account_id
			FROM iam_principal WHERE principal_type = 'Role'`+accountCondition+managedCondition, args...); err != nil {
			return nil, err
		}
	case OwnershipKindUser:
		if err := appendRows(`SELECT 'user-' || principal_name AS key, 'user' AS kind,
				principal_name AS name, managed_by, account_id
			FROM iam_principal WHERE principal_type = 'User'`+accountCondition+managedCondition, args...); err != nil {
			return nil, err
		}
	case OwnershipKindGroup:
		if err := appendRows(`SELECT 'group-' || group_name AS key, 'group' AS kind,
				group_name AS name, managed_by, account_id
			FROM iam_group`+accountCondition+managedCondition, args...); err != nil {
			return nil, err
		}
	case OwnershipKindPolicy:
		if err := appendRows(`SELECT 'policy-' || policy_name AS key, 'policy' AS kind,
				policy_name AS name, managed_by, COALESCE(account_id, 0) AS account_id
			FROM iam_policy
			WHERE policy_type = 'managed' AND account_id IS NOT NULL`+accountCondition+managedCondition, args...); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

var _ IAMOwnershipRepository = (*SQLIAMOwnershipRepository)(nil)
