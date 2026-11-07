package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// PrincipalListFilter filters the principal inventory listing. AccountID zero
// searches every account; Type is "User" or "Role"; Q matches name or ARN.
// AWS narrows by the AWS-owned mark ("true" only AWS-created roles, "false"
// only the rest; empty means both).
type PrincipalListFilter struct {
	AccountID int64
	Type      string
	Q         string
	// ManagedBy narrows the listing to one ownership mark.
	ManagedBy string
	// AWS filters by the AWS-owned classification (see AWSOwnedPrincipalSQL).
	AWS   string
	Limit int
	// Offset skips the first Offset rows.
	Offset int
}

// GroupListFilter filters the group inventory listing.
type GroupListFilter struct {
	AccountID int64
	Q         string
	ManagedBy string
	Limit     int
	Offset    int
}

// ManagedPolicyFilter filters the managed-policy inventory listing. Q matches
// policy name or ARN. Policies are not account-scoped in the inventory
// (AWS-managed policies have no owning account; customer-managed policies
// carry the account inside the ARN). AWS narrows by the AWS-managed mark
// ("true" only arn:aws:iam::aws:policy/ entries, "false" only customer ones).
type ManagedPolicyFilter struct {
	Q         string
	ManagedBy string
	AWS       string
	// AccountID 为库内 aws_account.id；0 表示不过滤（跨账号清单）。
	// 工单表单与资产页必须带上：托管策略按账号隔离，跨账号下拉会泄漏别家资源。
	AccountID int64
	Limit     int
	Offset    int
}

// ManagedPolicySummary is the list view of one inventoried managed policy.
type ManagedPolicySummary struct {
	ID         int64   `json:"id"`
	PolicyName string  `json:"policy_name"`
	PolicyARN  *string `json:"policy_arn,omitempty"`
	PolicyType *string `json:"policy_type,omitempty"`
	ManagedBy  string  `json:"managed_by"`
	// AWSManaged marks AWS-managed policies (arn:aws:iam::aws:policy/):
	// they are read-only references here and can never be edited via tickets.
	AWSManaged bool `json:"aws_managed"`
}

// ManagedPolicyDetail is the detail view of one inventoried managed policy:
// identity fields, the current policy document (to prefill the update-policy
// editor) and reference counts (how many principals and groups attach it,
// shown as a change-risk hint).
type ManagedPolicyDetail struct {
	ManagedPolicySummary
	PolicyDocument *model.JSONB `json:"policy_document,omitempty"`
	// AttachedPrincipals counts direct user/role attachments.
	AttachedPrincipals int `json:"attached_principals"`
	// AttachedGroups counts group attachments (managed policies) or the
	// owning groups of an inline policy.
	AttachedGroups int `json:"attached_groups"`
	// GroupReferences counts groups holding an inline policy of this name.
	GroupReferences int `json:"group_references"`
}

// PrincipalSummary is the list view of an inventoried IAM principal.
type PrincipalSummary struct {
	ID            int64      `json:"id"`
	AccountID     int64      `json:"account_db_id"`
	AWSAccountID  string     `json:"aws_account_id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalName string     `json:"principal_name"`
	ARN           string     `json:"arn"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
	// ManagedBy marks who owns the resource: platform (Terraform declares
	// it), external (another system owns it) or unknown (undecided).
	ManagedBy string `json:"managed_by"`
	// AWSLifecycle marks principals whose lifecycle is in AWS's hands
	// (service-linked roles, SSM Quick Setup roles, AWS automation-created
	// roles): listed for visibility but never ticket-modifiable.
	AWSLifecycle bool `json:"aws_lifecycle"`
}

// AttachedPolicy is one managed policy attached to a principal or group.
type AttachedPolicy struct {
	PolicyID   int64   `json:"policy_id"`
	PolicyName *string `json:"policy_name,omitempty"`
	PolicyType *string `json:"policy_type,omitempty"`
	PolicyARN  *string `json:"policy_arn,omitempty"`
}

// GroupRef is a lightweight group reference used inside principal detail.
type GroupRef struct {
	ID        int64  `json:"id"`
	GroupName string `json:"group_name"`
	ARN       string `json:"arn"`
}

// PrincipalDetail is the detail view of an IAM principal: identity fields
// plus directly attached policies and group memberships.
type PrincipalDetail struct {
	PrincipalSummary
	Description *string           `json:"description,omitempty"`
	TrustPolicy *model.JSONB      `json:"trust_policy,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Policies    []AttachedPolicy  `json:"policies"`
	Groups      []GroupRef        `json:"groups"`
}

// GroupSummary is the list view of an IAM group.
type GroupSummary struct {
	ID           int64     `json:"id"`
	AccountID    int64     `json:"account_db_id"`
	AWSAccountID string    `json:"aws_account_id"`
	GroupName    string    `json:"group_name"`
	ARN          string    `json:"arn"`
	Path         string    `json:"path"`
	MemberCount  int       `json:"member_count"`
	UpdatedAt    time.Time `json:"updated_at"`
	ManagedBy    string    `json:"managed_by"`
}

// PrincipalRef is a lightweight principal reference used inside group detail.
type PrincipalRef struct {
	ID            int64  `json:"id"`
	PrincipalName string `json:"principal_name"`
	ARN           string `json:"arn"`
}

// GroupDetail is the detail view of an IAM group: members and policies.
type GroupDetail struct {
	GroupSummary
	Members  []PrincipalRef   `json:"members"`
	Policies []AttachedPolicy `json:"policies"`
}

// ErrIAMPrincipalNotFound is returned when a principal ID does not exist.
var ErrIAMPrincipalNotFound = errors.New("IAM principal not found")

// ErrInvalidInventoryAWSFilter is returned when the aws filter is not one of
// the accepted values (empty, "true", "false").
var ErrInvalidInventoryAWSFilter = errors.New("aws filter must be true or false")

// AWSOwnedPrincipalSQL is the SQL mirror of awsLifecycleReason plus the
// service-linked mark: roles whose lifecycle sits in AWS's hands. Same three
// evidence classes as the baseline classifier — SSM Quick Setup naming
// namespace, service-linked roles, and the "Created By: AWS ... Automation"
// tag combined with an AWS-reserved name prefix — evaluated in SQL so the
// listing stays paginated server-side.
const AWSOwnedPrincipalSQL = `(%[1]s.principal_type = 'Role' AND (
	lower(%[1]s.principal_name) LIKE 'aws-quicksetup-%%'
	OR lower(%[1]s.principal_name) LIKE 'awsquicksetup%%'
	OR %[1]s.principal_name LIKE 'AWSServiceRoleFor%%'
	OR (%[1]s.tags ->> 'Created By' ILIKE '%%aws%%'
		AND %[1]s.tags ->> 'Created By' ILIKE '%%automation%%'
		AND (%[1]s.principal_name LIKE 'Amazon%%' OR %[1]s.principal_name LIKE 'AWS%%'))
))`

// AWSManagedPolicySQL marks AWS-managed policy rows by their account-less ARN.
const AWSManagedPolicySQL = `(%[1]s.policy_arn LIKE 'arn:aws:iam::aws:policy/%%')`

// applyInventoryAWSFilter translates the aws query parameter into a WHERE
// condition. Returns (condition, ok); ok=false means the value was invalid
// and the request must be rejected.
func applyInventoryAWSFilter(value, condition string) (string, string, bool) {
	switch strings.TrimSpace(value) {
	case "":
		return "", "", true
	case "true":
		return condition, "", true
	case "false":
		return "NOT " + condition, "", true
	default:
		return "", "", false
	}
}

// ErrIAMGroupNotFound is returned when a group ID does not exist.
var ErrIAMGroupNotFound = errors.New("IAM group not found")

// ErrIAMPolicyNotFound is returned when a managed policy ID does not exist.
var ErrIAMPolicyNotFound = errors.New("IAM managed policy not found")

// IAMInventoryService reads the inventoried IAM principals and groups.
type IAMInventoryService struct {
	db *sql.DB
}

// NewIAMInventoryService creates an IAMInventoryService.
func NewIAMInventoryService(database *sql.DB) (*IAMInventoryService, error) {
	if database == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &IAMInventoryService{db: database}, nil
}

// ListPrincipals lists inventoried principals with total count.
func (service *IAMInventoryService) ListPrincipals(
	ctx context.Context,
	filter PrincipalListFilter,
) ([]PrincipalSummary, int, error) {
	conditions := []string{"p.is_deleted = FALSE"}
	args := make([]any, 0, 4)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if filter.AccountID > 0 {
		conditions = append(conditions, "p.account_id = "+addArg(filter.AccountID))
	}
	switch filter.Type {
	case "":
	case "User", "Role":
		conditions = append(conditions, "p.principal_type = "+addArg(filter.Type))
	default:
		return nil, 0, ErrInvalidPrincipalType
	}
	if q := strings.TrimSpace(filter.Q); q != "" {
		pattern := addArg("%" + q + "%")
		conditions = append(conditions,
			"(p.principal_name ILIKE "+pattern+" OR p.arn ILIKE "+pattern+")")
	}
	if managedBy := strings.TrimSpace(filter.ManagedBy); managedBy != "" {
		conditions = append(conditions, "p.managed_by = "+addArg(managedBy))
	}
	switch awsCondition, _, ok := applyInventoryAWSFilter(filter.AWS, fmt.Sprintf(AWSOwnedPrincipalSQL, "p")); {
	case !ok:
		return nil, 0, ErrInvalidInventoryAWSFilter
	case awsCondition != "":
		conditions = append(conditions, awsCondition)
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := service.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iam_principal p"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count IAM principals: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []PrincipalSummary{}, total, nil
	}

	query := `SELECT p.id, p.account_id, a.account_id, p.principal_type,
			p.principal_name, p.arn, p.last_seen_at, p.updated_at, p.managed_by,
			COALESCE(` + fmt.Sprintf(AWSOwnedPrincipalSQL, "p") + `, FALSE) AS aws_lifecycle
		FROM iam_principal p
		JOIN aws_account a ON a.id = p.account_id` +
		where + fmt.Sprintf(" ORDER BY p.principal_name, p.id LIMIT %s OFFSET %s",
		addArg(filter.Limit), addArg(filter.Offset))
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list IAM principals: %w", err)
	}
	defer rows.Close()
	principals := make([]PrincipalSummary, 0, filter.Limit)
	for rows.Next() {
		var summary PrincipalSummary
		if err := rows.Scan(&summary.ID, &summary.AccountID, &summary.AWSAccountID,
			&summary.PrincipalType, &summary.PrincipalName, &summary.ARN,
			&summary.LastSeenAt, &summary.UpdatedAt, &summary.ManagedBy,
			&summary.AWSLifecycle); err != nil {
			return nil, 0, fmt.Errorf("scan IAM principal: %w", err)
		}
		principals = append(principals, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate IAM principals: %w", err)
	}
	return principals, total, nil
}

// GetPrincipal returns the detail view of one principal.
func (service *IAMInventoryService) GetPrincipal(ctx context.Context, principalID int64) (PrincipalDetail, error) {
	var detail PrincipalDetail
	var tagsJSON []byte
	err := service.db.QueryRowContext(ctx, `SELECT p.id, p.account_id, a.account_id,
			p.principal_type, p.principal_name, p.arn, p.last_seen_at, p.updated_at,
			p.managed_by, p.description, p.trust_policy, p.tags
		FROM iam_principal p
		JOIN aws_account a ON a.id = p.account_id
		WHERE p.id = $1 AND p.is_deleted = FALSE`, principalID,
	).Scan(&detail.ID, &detail.AccountID, &detail.AWSAccountID,
		&detail.PrincipalType, &detail.PrincipalName, &detail.ARN,
		&detail.LastSeenAt, &detail.UpdatedAt,
		&detail.ManagedBy, &detail.Description, &detail.TrustPolicy, &tagsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return PrincipalDetail{}, ErrIAMPrincipalNotFound
	}
	if err != nil {
		return PrincipalDetail{}, fmt.Errorf("get IAM principal: %w", err)
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &detail.Tags); err != nil {
			return PrincipalDetail{}, fmt.Errorf("decode tags for IAM principal %d: %w", principalID, err)
		}
	}

	detail.Policies = make([]AttachedPolicy, 0)
	policyRows, err := service.db.QueryContext(ctx, `SELECT pol.id, pol.policy_name, pol.policy_type, pol.policy_arn
		FROM iam_principal_policy pp
		JOIN iam_policy pol ON pol.id = pp.policy_id
		WHERE pp.principal_id = $1
		ORDER BY pol.policy_name`, principalID)
	if err != nil {
		return PrincipalDetail{}, fmt.Errorf("list IAM principal policies: %w", err)
	}
	defer policyRows.Close()
	for policyRows.Next() {
		var policy AttachedPolicy
		if err := policyRows.Scan(&policy.PolicyID, &policy.PolicyName, &policy.PolicyType, &policy.PolicyARN); err != nil {
			return PrincipalDetail{}, fmt.Errorf("scan IAM principal policy: %w", err)
		}
		detail.Policies = append(detail.Policies, policy)
	}
	if err := policyRows.Err(); err != nil {
		return PrincipalDetail{}, fmt.Errorf("iterate IAM principal policies: %w", err)
	}

	detail.Groups = make([]GroupRef, 0)
	groupRows, err := service.db.QueryContext(ctx, `SELECT g.id, g.group_name, g.arn
		FROM iam_group_membership gm
		JOIN iam_group g ON g.id = gm.group_id
		WHERE gm.user_principal_id = $1
		ORDER BY g.group_name`, principalID)
	if err != nil {
		return PrincipalDetail{}, fmt.Errorf("list IAM principal groups: %w", err)
	}
	defer groupRows.Close()
	for groupRows.Next() {
		var group GroupRef
		if err := groupRows.Scan(&group.ID, &group.GroupName, &group.ARN); err != nil {
			return PrincipalDetail{}, fmt.Errorf("scan IAM principal group: %w", err)
		}
		detail.Groups = append(detail.Groups, group)
	}
	if err := groupRows.Err(); err != nil {
		return PrincipalDetail{}, fmt.Errorf("iterate IAM principal groups: %w", err)
	}
	return detail, nil
}

// ListGroups lists inventoried groups with member counts and total count.
func (service *IAMInventoryService) ListGroups(
	ctx context.Context,
	filter GroupListFilter,
) ([]GroupSummary, int, error) {
	conditions := []string{"TRUE"}
	args := make([]any, 0, 3)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if filter.AccountID > 0 {
		conditions = append(conditions, "g.account_id = "+addArg(filter.AccountID))
	}
	if q := strings.TrimSpace(filter.Q); q != "" {
		pattern := addArg("%" + q + "%")
		conditions = append(conditions,
			"(g.group_name ILIKE "+pattern+" OR g.arn ILIKE "+pattern+")")
	}
	if managedBy := strings.TrimSpace(filter.ManagedBy); managedBy != "" {
		conditions = append(conditions, "g.managed_by = "+addArg(managedBy))
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := service.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iam_group g"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count IAM groups: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []GroupSummary{}, total, nil
	}

	query := `SELECT g.id, g.account_id, a.account_id, g.group_name, g.arn, g.path,
			COALESCE(m.member_count, 0), g.updated_at, g.managed_by
		FROM iam_group g
		JOIN aws_account a ON a.id = g.account_id
		LEFT JOIN (
			SELECT gm.group_id, COUNT(*) AS member_count
			FROM iam_group_membership gm GROUP BY gm.group_id
		) m ON m.group_id = g.id` +
		where + fmt.Sprintf(" ORDER BY g.group_name, g.id LIMIT %s OFFSET %s",
		addArg(filter.Limit), addArg(filter.Offset))
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list IAM groups: %w", err)
	}
	defer rows.Close()
	groups := make([]GroupSummary, 0, filter.Limit)
	for rows.Next() {
		var summary GroupSummary
		if err := rows.Scan(&summary.ID, &summary.AccountID, &summary.AWSAccountID,
			&summary.GroupName, &summary.ARN, &summary.Path,
			&summary.MemberCount, &summary.UpdatedAt, &summary.ManagedBy); err != nil {
			return nil, 0, fmt.Errorf("scan IAM group: %w", err)
		}
		groups = append(groups, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate IAM groups: %w", err)
	}
	return groups, total, nil
}

// ListManagedPolicies lists inventoried managed policies (type "managed",
// both AWS-managed and customer-managed) with total count.
func (service *IAMInventoryService) ListManagedPolicies(
	ctx context.Context,
	filter ManagedPolicyFilter,
) ([]ManagedPolicySummary, int, error) {
	conditions := []string{`pol.policy_type = 'managed'`}
	args := make([]any, 0, 3)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if q := strings.TrimSpace(filter.Q); q != "" {
		pattern := addArg("%" + q + "%")
		conditions = append(conditions,
			"(pol.policy_name ILIKE "+pattern+" OR pol.policy_arn ILIKE "+pattern+")")
	}
	if managedBy := strings.TrimSpace(filter.ManagedBy); managedBy != "" {
		conditions = append(conditions, "pol.managed_by = "+addArg(managedBy))
	}
	if filter.AccountID > 0 {
		// AWS-managed policies have no owning account (account_id IS NULL):
		// they are global references, so they stay visible in every
		// account-scoped picker. Customer-managed policies remain isolated to
		// their account — that was the A11 cross-account leak fix.
		conditions = append(conditions, "(pol.account_id = "+addArg(filter.AccountID)+
			" OR "+fmt.Sprintf(AWSManagedPolicySQL, "pol")+")")
	}
	switch awsCondition, _, ok := applyInventoryAWSFilter(filter.AWS, fmt.Sprintf(AWSManagedPolicySQL, "pol")); {
	case !ok:
		return nil, 0, ErrInvalidInventoryAWSFilter
	case awsCondition != "":
		conditions = append(conditions, awsCondition)
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := service.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iam_policy pol"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count managed policies: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []ManagedPolicySummary{}, total, nil
	}

	query := `SELECT pol.id, pol.policy_name, pol.policy_arn, pol.policy_type, pol.managed_by,
			` + fmt.Sprintf(AWSManagedPolicySQL, "pol") + ` AS aws_managed
		FROM iam_policy pol` +
		// 账号自管策略排前面：AWS 托管目录有上千条，按名称混排会把本账号的
		// 策略挤出 limit=100 的默认列表；带 q 搜索时仍按名称匹配。
		where + fmt.Sprintf(" ORDER BY (pol.account_id IS NULL), pol.policy_name, pol.id LIMIT %s OFFSET %s",
		addArg(filter.Limit), addArg(filter.Offset))
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list managed policies: %w", err)
	}
	defer rows.Close()
	policies := make([]ManagedPolicySummary, 0, filter.Limit)
	for rows.Next() {
		var summary ManagedPolicySummary
		if err := rows.Scan(&summary.ID, &summary.PolicyName,
			&summary.PolicyARN, &summary.PolicyType, &summary.ManagedBy,
			&summary.AWSManaged); err != nil {
			return nil, 0, fmt.Errorf("scan managed policy: %w", err)
		}
		policies = append(policies, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate managed policies: %w", err)
	}
	return policies, total, nil
}

// GetManagedPolicy returns the detail view of one managed policy: identity
// fields, the current policy document (used to prefill the update-policy
// editor) and reference counts (users/roles and groups attaching it — the
// change-risk hint shown next to the update action).
func (service *IAMInventoryService) GetManagedPolicy(
	ctx context.Context,
	policyID int64,
) (ManagedPolicyDetail, error) {
	var detail ManagedPolicyDetail
	var document []byte
	// aws_managed is computed the same way as in the list query: the detail
	// drawer hides the edit action for AWS-managed policies, so leaving this
	// at its zero value would offer an edit that can never be applied.
	err := service.db.QueryRowContext(ctx, `SELECT pol.id, pol.policy_name,
			pol.policy_arn, pol.policy_type, `+fmt.Sprintf(AWSManagedPolicySQL, "pol")+` AS aws_managed,
			pol.policy_document
		FROM iam_policy pol WHERE pol.id = $1`, policyID,
	).Scan(&detail.ID, &detail.PolicyName, &detail.PolicyARN,
		&detail.PolicyType, &detail.AWSManaged, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedPolicyDetail{}, ErrIAMPolicyNotFound
	}
	if err != nil {
		return ManagedPolicyDetail{}, fmt.Errorf("get managed policy: %w", err)
	}
	// Catalog-only AWS-managed rows have a NULL document: they are known to
	// exist but their document has not been fetched yet. Leave PolicyDocument
	// nil instead of exposing an empty object that would read as "no
	// permissions".
	if len(document) > 0 {
		parsed := model.JSONB(document)
		detail.PolicyDocument = &parsed
	}

	// Direct attachments: iam_principal_policy (user/role) and
	// iam_group_policy (group). Inline policies attach no principal directly;
	// they are referenced by iam_group_policy rows through the group join.
	if err := service.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT ipp.principal_id), COUNT(DISTINCT gp.group_id)
		FROM iam_policy pol
		LEFT JOIN iam_principal_policy ipp ON ipp.policy_id = pol.id
		LEFT JOIN iam_group_policy gp ON gp.policy_id = pol.id
		WHERE pol.id = $1`, policyID,
	).Scan(&detail.AttachedPrincipals, &detail.AttachedGroups); err != nil {
		return ManagedPolicyDetail{}, fmt.Errorf("count managed policy references: %w", err)
	}
	return detail, nil
}

// GetGroup returns the detail view of one group: members and attached policies.
func (service *IAMInventoryService) GetGroup(ctx context.Context, groupID int64) (GroupDetail, error) {
	var detail GroupDetail
	err := service.db.QueryRowContext(ctx, `SELECT g.id, g.account_id, a.account_id,
			g.group_name, g.arn, g.path, g.updated_at,
			COALESCE(m.member_count, 0), g.managed_by
		FROM iam_group g
		JOIN aws_account a ON a.id = g.account_id
		LEFT JOIN (
			SELECT gm.group_id, COUNT(*) AS member_count
			FROM iam_group_membership gm GROUP BY gm.group_id
		) m ON m.group_id = g.id
		WHERE g.id = $1`, groupID,
	).Scan(&detail.ID, &detail.AccountID, &detail.AWSAccountID,
		&detail.GroupName, &detail.ARN, &detail.Path, &detail.UpdatedAt,
		&detail.MemberCount, &detail.ManagedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return GroupDetail{}, ErrIAMGroupNotFound
	}
	if err != nil {
		return GroupDetail{}, fmt.Errorf("get IAM group: %w", err)
	}

	detail.Members = make([]PrincipalRef, 0)
	memberRows, err := service.db.QueryContext(ctx, `SELECT p.id, p.principal_name, p.arn
		FROM iam_group_membership gm
		JOIN iam_principal p ON p.id = gm.user_principal_id
		WHERE gm.group_id = $1 AND p.is_deleted = FALSE
		ORDER BY p.principal_name`, groupID)
	if err != nil {
		return GroupDetail{}, fmt.Errorf("list IAM group members: %w", err)
	}
	defer memberRows.Close()
	for memberRows.Next() {
		var member PrincipalRef
		if err := memberRows.Scan(&member.ID, &member.PrincipalName, &member.ARN); err != nil {
			return GroupDetail{}, fmt.Errorf("scan IAM group member: %w", err)
		}
		detail.Members = append(detail.Members, member)
	}
	if err := memberRows.Err(); err != nil {
		return GroupDetail{}, fmt.Errorf("iterate IAM group members: %w", err)
	}

	detail.Policies = make([]AttachedPolicy, 0)
	policyRows, err := service.db.QueryContext(ctx, `SELECT pol.id, pol.policy_name, pol.policy_type, pol.policy_arn
		FROM iam_group_policy gp
		JOIN iam_policy pol ON pol.id = gp.policy_id
		WHERE gp.group_id = $1
		ORDER BY pol.policy_name`, groupID)
	if err != nil {
		return GroupDetail{}, fmt.Errorf("list IAM group policies: %w", err)
	}
	defer policyRows.Close()
	for policyRows.Next() {
		var policy AttachedPolicy
		if err := policyRows.Scan(&policy.PolicyID, &policy.PolicyName, &policy.PolicyType, &policy.PolicyARN); err != nil {
			return GroupDetail{}, fmt.Errorf("scan IAM group policy: %w", err)
		}
		detail.Policies = append(detail.Policies, policy)
	}
	if err := policyRows.Err(); err != nil {
		return GroupDetail{}, fmt.Errorf("iterate IAM group policies: %w", err)
	}
	return detail, nil
}

// GetRoleInlinePolicy returns the current document of a role inline policy
// by role name + inline policy name. Used by inventory detail view.
func (service *IAMInventoryService) GetRoleInlinePolicy(
	ctx context.Context,
	accountDatabaseID int64,
	roleName, inlinePolicyName string,
) (json.RawMessage, bool, error) {
	var document []byte
	err := service.db.QueryRowContext(ctx, `
		SELECT p.policy_document FROM iam_policy p
		JOIN iam_principal_policy pp ON pp.policy_id = p.id
		JOIN iam_principal r ON r.id = pp.principal_id
		WHERE r.account_id = $1 AND r.principal_type = 'Role'
			AND r.principal_name = $2 AND p.policy_name = $3
			AND p.policy_type = 'inline' AND r.is_deleted = FALSE`,
		accountDatabaseID, roleName, inlinePolicyName,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("query role inline policy %s on role %s: %w",
			inlinePolicyName, roleName, err)
	}
	return document, true, nil
}

// GetGroupInlinePolicy returns the current document of a group inline policy
// by group name + inline policy name. Used by inventory detail view.
func (service *IAMInventoryService) GetGroupInlinePolicy(
	ctx context.Context,
	accountDatabaseID int64,
	groupName, inlinePolicyName string,
) (json.RawMessage, bool, error) {
	var document []byte
	err := service.db.QueryRowContext(ctx, `
		SELECT p.policy_document FROM iam_policy p
		JOIN iam_principal_policy pp ON pp.policy_id = p.id
		JOIN iam_principal r ON r.id = pp.principal_id
		WHERE r.account_id = $1 AND r.principal_type = 'Group'
			AND r.principal_name = $2 AND p.policy_name = $3
			AND p.policy_type = 'inline' AND r.is_deleted = FALSE`,
		accountDatabaseID, groupName, inlinePolicyName,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("query group inline policy %s on group %s: %w",
			inlinePolicyName, groupName, err)
	}
	return document, true, nil
}

// InlinePolicyListFilter filters the inline-policy inventory listing.
// AccountID zero searches every account; Q matches the policy or owner name;
// AWS narrows by the owner's AWS-owned mark ("true"/"false", empty both).
type InlinePolicyListFilter struct {
	AccountID int64
	Q         string
	AWS       string
	Limit     int
	Offset    int
}

// InlinePolicySummary is the list view of one inline policy with its owning
// principal. Inline policies carry no ARN of their own (account_id is always
// NULL on the policy row), so the account label comes from the owner.
type InlinePolicySummary struct {
	// PolicyID is the iam_policy row of the inline policy document.
	PolicyID     int64  `json:"policy_id"`
	AccountID    int64  `json:"account_db_id"`
	AWSAccountID string `json:"aws_account_id"`
	PolicyName   string `json:"policy_name"`
	OwnerKind    string `json:"owner_kind"`
	OwnerName    string `json:"owner_name"`
	OwnerARN     string `json:"owner_arn"`
	// AWSManaged mirrors the owner: an inline policy on a service-linked or
	// AWS automation-created role is AWS's, not ticket-modifiable.
	AWSManaged bool       `json:"aws_managed"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// InstanceProfileListFilter filters the instance-profile inventory listing.
type InstanceProfileListFilter struct {
	AccountID int64
	Q         string
	Limit     int
	Offset    int
}

// InstanceProfileSummary is the list view of one inventoried instance
// profile. Instance profiles cannot be changed through tickets at all (no
// ticket type touches them); EKSManaged additionally marks the
// `eks-<uuid>` profiles that managed node groups create and rewrite.
type InstanceProfileSummary struct {
	ID                  int64      `json:"id"`
	AccountID           int64      `json:"account_db_id"`
	AWSAccountID        string     `json:"aws_account_id"`
	InstanceProfileName string     `json:"instance_profile_name"`
	ARN                 string     `json:"arn"`
	Path                string     `json:"path"`
	RoleARN             *string    `json:"role_arn,omitempty"`
	RoleName            string     `json:"role_name"`
	EKSManaged          bool       `json:"eks_managed"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
}

// ListInlinePolicies lists inline policies with their owning principal and
// total count. Three-way union mirrors loadInlinePolicies: role/user rows
// live in iam_principal_policy, group rows in iam_group_policy. The owner's
// account provides the account label (the policy row itself has none).
func (service *IAMInventoryService) ListInlinePolicies(
	ctx context.Context,
	filter InlinePolicyListFilter,
) ([]InlinePolicySummary, int, error) {
	awsOwned, ok := parseAWSFilter(filter.AWS)
	if !ok {
		return nil, 0, ErrInvalidInventoryAWSFilter
	}
	args := make([]any, 0, 6)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	q := strings.TrimSpace(filter.Q)
	// qPattern binds the search pattern once per branch (policy name + owner
	// name); empty q contributes nothing.
	qPattern := ""
	if q != "" {
		qPattern = addArg("%" + q + "%")
	}
	accountValue := ""
	if filter.AccountID > 0 {
		accountValue = addArg(filter.AccountID)
	}
	searchCondition := func(ownerColumn string) string {
		if qPattern == "" {
			return ""
		}
		return fmt.Sprintf(
			" AND (pol.policy_name ILIKE %s OR %s ILIKE %s)", qPattern, ownerColumn, qPattern,
		)
	}
	accountCondition := func(column string) string {
		if accountValue == "" {
			return ""
		}
		return " AND " + column + " = " + accountValue
	}
	roleAWSOwned := fmt.Sprintf(AWSOwnedPrincipalSQL, "p")
	union := `
		SELECT pol.id AS policy_id, p.account_id, a.account_id AS aws_account_id,
		       pol.policy_name, 'role' AS owner_kind,
		       p.principal_name AS owner_name, p.arn AS owner_arn,
		       (p.principal_type = 'Role' AND ` + roleAWSOwned + `) AS aws_managed,
		       p.last_seen_at
		FROM iam_policy pol
		JOIN iam_principal_policy pp ON pp.policy_id = pol.id
		JOIN iam_principal p ON p.id = pp.principal_id
		JOIN aws_account a ON a.id = p.account_id
		WHERE pol.policy_type = 'inline' AND p.is_deleted = FALSE
		  AND p.principal_type IN ('Role','User')` +
		searchCondition("p.principal_name") + accountCondition("p.account_id") + `
		UNION ALL
		SELECT pol.id, g.account_id, a.account_id,
		       pol.policy_name, 'group', g.group_name, g.arn,
		       FALSE, NULL
		FROM iam_policy pol
		JOIN iam_group_policy gp ON gp.policy_id = pol.id
		JOIN iam_group g ON g.id = gp.group_id
		JOIN aws_account a ON a.id = g.account_id
		WHERE pol.policy_type = 'inline'` +
		searchCondition("g.group_name") + accountCondition("g.account_id")

	if awsOwned != "" {
		union = "SELECT * FROM (" + union + ") inline WHERE aws_managed = " + awsOwned
	} else {
		union = "SELECT * FROM (" + union + ") inline WHERE TRUE"
	}

	var total int
	if err := service.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ("+union+") counted", args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count inline policies: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []InlinePolicySummary{}, total, nil
	}
	query := union + fmt.Sprintf(
		" ORDER BY owner_kind, owner_name, policy_name LIMIT %d OFFSET %d",
		filter.Limit, filter.Offset)
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list inline policies: %w", err)
	}
	defer rows.Close()
	policies := make([]InlinePolicySummary, 0, filter.Limit)
	for rows.Next() {
		var summary InlinePolicySummary
		if err := rows.Scan(&summary.PolicyID, &summary.AccountID, &summary.AWSAccountID,
			&summary.PolicyName, &summary.OwnerKind, &summary.OwnerName, &summary.OwnerARN,
			&summary.AWSManaged, &summary.LastSeenAt); err != nil {
			return nil, 0, fmt.Errorf("scan inline policy: %w", err)
		}
		policies = append(policies, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate inline policies: %w", err)
	}
	return policies, total, nil
}

// ListInstanceProfiles lists inventoried instance profiles with total count.
func (service *IAMInventoryService) ListInstanceProfiles(
	ctx context.Context,
	filter InstanceProfileListFilter,
) ([]InstanceProfileSummary, int, error) {
	conditions := []string{"ip.is_deleted = FALSE"}
	args := make([]any, 0, 2)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if filter.AccountID > 0 {
		conditions = append(conditions, "ip.account_id = "+addArg(filter.AccountID))
	}
	if q := strings.TrimSpace(filter.Q); q != "" {
		pattern := addArg("%" + q + "%")
		conditions = append(conditions,
			"(ip.instance_profile_name ILIKE "+pattern+" OR ip.arn ILIKE "+
				pattern+" OR COALESCE(ip.role_arn, '') ILIKE "+pattern+")")
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := service.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iam_instance_profile ip"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count instance profiles: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []InstanceProfileSummary{}, total, nil
	}

	query := `SELECT ip.id, ip.account_id, a.account_id, ip.instance_profile_name,
			ip.arn, ip.path, ip.role_arn, ip.last_seen_at
		FROM iam_instance_profile ip
		JOIN aws_account a ON a.id = ip.account_id` +
		where + fmt.Sprintf(" ORDER BY ip.instance_profile_name, ip.id LIMIT %s OFFSET %s",
		addArg(filter.Limit), addArg(filter.Offset))
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list instance profiles: %w", err)
	}
	defer rows.Close()
	profiles := make([]InstanceProfileSummary, 0, filter.Limit)
	for rows.Next() {
		var summary InstanceProfileSummary
		if err := rows.Scan(&summary.ID, &summary.AccountID, &summary.AWSAccountID,
			&summary.InstanceProfileName, &summary.ARN, &summary.Path,
			&summary.RoleARN, &summary.LastSeenAt); err != nil {
			return nil, 0, fmt.Errorf("scan instance profile: %w", err)
		}
		if summary.RoleARN != nil {
			summary.RoleName = roleNameFromARN(*summary.RoleARN)
		}
		summary.EKSManaged = isEKSManagedInstanceProfileName(
			strings.ToLower(strings.TrimSpace(summary.InstanceProfileName)))
		profiles = append(profiles, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate instance profiles: %w", err)
	}
	return profiles, total, nil
}

// parseAWSFilter normalises the aws query value: "" means no narrowing,
// "true"/"false" map to their SQL literal, anything else is invalid.
func parseAWSFilter(value string) (string, bool) {
	switch strings.TrimSpace(value) {
	case "":
		return "", true
	case "true":
		return "TRUE", true
	case "false":
		return "FALSE", true
	default:
		return "", false
	}
}

// roleNameFromARN extracts the role name from a role ARN
// (arn:aws:iam::<account>:role/<path><name>).
func roleNameFromARN(arn string) string {
	const marker = ":role/"
	index := strings.Index(arn, marker)
	if index < 0 {
		return ""
	}
	name := arn[index+len(marker):]
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return name
}

// ErrIAMInstanceProfileNotFound is returned when an instance profile ID does
// not exist.
var ErrIAMInstanceProfileNotFound = errors.New("IAM instance profile not found")

// InlinePolicyDetail is the detail view of one inline policy: identity and
// owner fields plus the current document (to prefill the update editor or
// simply to inspect it).
type InlinePolicyDetail struct {
	InlinePolicySummary
	PolicyDocument *model.JSONB `json:"policy_document,omitempty"`
}

// GetInlinePolicy returns the detail view of one inline policy by its
// iam_policy row ID. Inline policies attach through two different link
// tables (principal vs group), so the lookup tries both: principal rows
// first, then group rows. Neither hit means the policy does not exist (or is
// not inline).
func (service *IAMInventoryService) GetInlinePolicy(
	ctx context.Context,
	policyID int64,
) (InlinePolicyDetail, error) {
	var detail InlinePolicyDetail
	var document []byte
	var ownerType string
	roleAWSOwned := fmt.Sprintf(AWSOwnedPrincipalSQL, "p")
	err := service.db.QueryRowContext(ctx, `
		SELECT pol.policy_name, pol.policy_document,
		       p.account_id, a.account_id, p.principal_type,
		       p.principal_name, p.arn, p.last_seen_at,
		       (p.principal_type = 'Role' AND `+roleAWSOwned+`)
		FROM iam_policy pol
		JOIN iam_principal_policy pp ON pp.policy_id = pol.id
		JOIN iam_principal p ON p.id = pp.principal_id
		JOIN aws_account a ON a.id = p.account_id
		WHERE pol.id = $1 AND pol.policy_type = 'inline' AND p.is_deleted = FALSE`,
		policyID,
	).Scan(&detail.PolicyName, &document,
		&detail.AccountID, &detail.AWSAccountID, &ownerType,
		&detail.OwnerName, &detail.OwnerARN, &detail.LastSeenAt,
		&detail.AWSManaged)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Fall through to the group branch below.
	case err != nil:
		return InlinePolicyDetail{}, fmt.Errorf("get inline policy %d (principal link): %w", policyID, err)
	default:
		detail.PolicyID = policyID
		detail.OwnerKind = strings.ToLower(ownerType)
		parsed := model.JSONB(document)
		detail.PolicyDocument = &parsed
		return detail, nil
	}

	err = service.db.QueryRowContext(ctx, `
		SELECT pol.policy_name, pol.policy_document,
		       g.account_id, a.account_id, 'Group',
		       g.group_name, g.arn, g.updated_at, FALSE
		FROM iam_policy pol
		JOIN iam_group_policy gp ON gp.policy_id = pol.id
		JOIN iam_group g ON g.id = gp.group_id
		JOIN aws_account a ON a.id = g.account_id
		WHERE pol.id = $1 AND pol.policy_type = 'inline'`, policyID,
	).Scan(&detail.PolicyName, &document,
		&detail.AccountID, &detail.AWSAccountID, &ownerType,
		&detail.OwnerName, &detail.OwnerARN, &detail.LastSeenAt,
		&detail.AWSManaged)
	if errors.Is(err, sql.ErrNoRows) {
		return InlinePolicyDetail{}, ErrIAMPolicyNotFound
	}
	if err != nil {
		return InlinePolicyDetail{}, fmt.Errorf("get inline policy %d (group link): %w", policyID, err)
	}
	detail.PolicyID = policyID
	detail.OwnerKind = "group"
	parsed := model.JSONB(document)
	detail.PolicyDocument = &parsed
	return detail, nil
}

// InstanceProfileDetail is the detail view of one instance profile: the
// summary fields plus its tags (profiles support tags on collect, even
// though IAM instance profiles themselves do not carry them in AWS).
type InstanceProfileDetail struct {
	InstanceProfileSummary
	Tags map[string]string `json:"tags,omitempty"`
}

// GetInstanceProfile returns the detail view of one instance profile.
func (service *IAMInventoryService) GetInstanceProfile(
	ctx context.Context,
	profileID int64,
) (InstanceProfileDetail, error) {
	var detail InstanceProfileDetail
	var tagsJSON []byte
	err := service.db.QueryRowContext(ctx, `SELECT ip.id, ip.account_id, a.account_id,
			ip.instance_profile_name, ip.arn, ip.path, ip.role_arn, ip.last_seen_at, ip.tags
		FROM iam_instance_profile ip
		JOIN aws_account a ON a.id = ip.account_id
		WHERE ip.id = $1 AND ip.is_deleted = FALSE`, profileID,
	).Scan(&detail.ID, &detail.AccountID, &detail.AWSAccountID,
		&detail.InstanceProfileName, &detail.ARN, &detail.Path,
		&detail.RoleARN, &detail.LastSeenAt, &tagsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return InstanceProfileDetail{}, ErrIAMInstanceProfileNotFound
	}
	if err != nil {
		return InstanceProfileDetail{}, fmt.Errorf("get instance profile %d: %w", profileID, err)
	}
	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &detail.Tags); err != nil {
			return InstanceProfileDetail{}, fmt.Errorf("decode tags for instance profile %d: %w", profileID, err)
		}
	}
	if detail.RoleARN != nil {
		detail.RoleName = roleNameFromARN(*detail.RoleARN)
	}
	detail.EKSManaged = isEKSManagedInstanceProfileName(
		strings.ToLower(strings.TrimSpace(detail.InstanceProfileName)))
	return detail, nil
}
