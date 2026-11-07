package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

const (
	defaultAWSMaxAttempts = 5
	defaultSyncTimeout    = 15 * time.Minute
)

type awsOrganizationsAPI interface {
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
}

type awsSTSAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type awsIAMAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	ListGroups(context.Context, *iam.ListGroupsInput, ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
	GetGroup(context.Context, *iam.GetGroupInput, ...func(*iam.Options)) (*iam.GetGroupOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
	GetGroupPolicy(context.Context, *iam.GetGroupPolicyInput, ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
	ListPolicies(context.Context, *iam.ListPoliciesInput, ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListPolicyTags(context.Context, *iam.ListPolicyTagsInput, ...func(*iam.Options)) (*iam.ListPolicyTagsOutput, error)
	ListInstanceProfiles(context.Context, *iam.ListInstanceProfilesInput, ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error)
	ListOpenIDConnectProviders(context.Context, *iam.ListOpenIDConnectProvidersInput, ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error)
	GetOpenIDConnectProvider(context.Context, *iam.GetOpenIDConnectProviderInput, ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error)
	ListSAMLProviders(context.Context, *iam.ListSAMLProvidersInput, ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error)
	GetSAMLProvider(context.Context, *iam.GetSAMLProviderInput, ...func(*iam.Options)) (*iam.GetSAMLProviderOutput, error)
}

type awsIAMFactory func(aws.Config) awsIAMAPI

// ---- C1a：同步阶段指标（阶段耗时 + AWS 请求数） ----

// awsRequestCounter 统计一次同步 run 发出的全部 AWS API HTTP 请求
// （IAM/在用性证据），挂在 aws.Config.HTTPClient 上一处收口——不给 26 个
// 接口方法逐个包装。service.sts 是预注入客户端，不在统计内；每次 run 的
// AssumeRole/GetCallerIdentity 至多 1~2 次，可忽略。
type awsRequestCounter struct {
	next  http.RoundTripper
	count atomic.Int64
}

func newAWSRequestCounter() *awsRequestCounter {
	return &awsRequestCounter{next: http.DefaultTransport}
}

// attach 把计数器挂到一个 SDK 配置上；同一 run 的多个配置（IAM 客户端与
// 在用性证据客户端）可共用同一个 counter。若配置已带自定义 Transport
// （如代理），计数器链在它前面，计数语义不变。
func (counter *awsRequestCounter) attach(cfg aws.Config) aws.Config {
	// aws.Config.HTTPClient 是接口（Do 方法），能拿到 *http.Client 才能链住
	// 它的自定义 Transport；否则保持 DefaultTransport（含代理环境变量语义）。
	if httpClient, ok := cfg.HTTPClient.(*http.Client); ok && httpClient.Transport != nil {
		counter.next = httpClient.Transport
	}
	cfg.HTTPClient = &http.Client{Transport: counter}
	return cfg
}

func (counter *awsRequestCounter) RoundTrip(request *http.Request) (*http.Response, error) {
	counter.count.Add(1)
	return counter.next.RoundTrip(request)
}

func (counter *awsRequestCounter) total() int64 {
	return counter.count.Load()
}

// syncStageMetric 记录单个阶段的墙钟耗时与 AWS 请求增量。
type syncStageMetric struct {
	name     string
	duration time.Duration
	requests int64
}

// syncRunMetrics 是一次同步 run 的阶段序列。子阶段（采集内部的
// roles/users/policies 等）与 run 级阶段共用同一 counter，请求增量按阶段
// 边界切分；请求始终归因到**最细粒度**的阶段——包含子阶段的父阶段
// （如 collect）requests 记 0，全部耗时仍由父阶段计时承载。
type syncRunMetrics struct {
	counter      *awsRequestCounter
	stages       []syncStageMetric
	lastRequests int64
}

func newSyncRunMetrics(counter *awsRequestCounter) *syncRunMetrics {
	return &syncRunMetrics{counter: counter}
}

func (metrics *syncRunMetrics) record(name string, duration time.Duration) {
	var delta int64
	if metrics.counter != nil {
		now := metrics.counter.total()
		delta = now - metrics.lastRequests
		metrics.lastRequests = now
	}
	metrics.stages = append(metrics.stages, syncStageMetric{name: name, duration: duration, requests: delta})
}

// stage 包裹一段同步逻辑，计时并记录请求增量。
func (metrics *syncRunMetrics) stage(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	metrics.record(name, time.Since(start))
	return err
}

// timedResult / timedError 是 nil-safe 的内联计时：metrics 为 nil（测试或
// 不关心指标的调用方）直接执行原逻辑。
func timedResult[T any](metrics *syncRunMetrics, name string, fn func() (T, error)) (T, error) {
	if metrics == nil {
		return fn()
	}
	var value T
	err := metrics.stage(name, func() error {
		var err error
		value, err = fn()
		return err
	})
	return value, err
}

func timedError(metrics *syncRunMetrics, name string, fn func() error) error {
	if metrics == nil {
		return fn()
	}
	return metrics.stage(name, fn)
}

// logFields 输出扁平的 aws_requests_total / stage_<name>_ms /
// stage_<name>_requests 字段，方便日志聚合与 grep。
func (metrics *syncRunMetrics) logFields() []any {
	fields := []any{}
	if metrics == nil {
		return fields
	}
	if metrics.counter != nil {
		fields = append(fields, "aws_requests_total", metrics.counter.total())
	}
	for _, stage := range metrics.stages {
		fields = append(fields,
			"stage_"+stage.name+"_ms", stage.duration.Milliseconds(),
			"stage_"+stage.name+"_requests", stage.requests)
	}
	return fields
}

// AWSCollectorConfig controls AWS retry behavior, collection timeout, and IAM
// role assumption settings.
type AWSCollectorConfig struct {
	Region              string
	Profile             string
	RoleSessionName     string
	ExternalID          string
	MaxAttempts         int
	SyncTimeout         time.Duration
	ManagementAccountID string
}

// AWSCollectorService discovers organization accounts and persists their IAM
// principals, policies, and principal-policy associations.
type AWSCollectorService struct {
	config        AWSCollectorConfig
	organizations awsOrganizationsAPI
	sts           awsSTSAPI
	iamFactory    awsIAMFactory
	repository    AWSAssetRepository
	logger        *slog.Logger
	// 在用性证据采集（可选）：同步时顺带把 EC2 launch template / EKS 节点组
	// 的实例配置文件引用落库，待清理清单就能直接读库而不用实时调 AWS。
	usageStore      *ProfileUsageEvidenceStore
	usageEKSFactory func(aws.Config) eksUsageAPI
	usageEC2Factory func(aws.Config) ec2UsageAPI
}

// AWSAssetRepository is the persistence boundary used by the collector.
type AWSAssetRepository interface {
	UpsertOrganizationAccounts(ctx context.Context, organizationID int64, accounts []model.AWSAccount) error
	EnsureCurrentAccount(ctx context.Context, accountID string) (model.AWSAccount, error)
	GetAccountCollectionInfo(ctx context.Context, accountID string) (model.AWSAccount, error)
	SaveAccountIAM(ctx context.Context, account model.AWSAccount, inventory collectedIAMInventory) error
}

type configuredAWSAssetRepository interface {
	EnsureConfiguredAccount(ctx context.Context, config model.AWSAccountConfig) (model.AWSAccount, error)
	// ListCurrentIAMAssets returns the live (non-deleted) principals and
	// groups of one account so the collector can diff a fresh collection
	// against the platform inventory before overwriting it.
	ListCurrentIAMAssets(ctx context.Context, accountDBID int64) ([]CurrentIAMAsset, error)
}

// CurrentIAMAsset is one live principal or group row used for sync diffs.
type CurrentIAMAsset struct {
	ARN      string
	Name     string
	IsGroup  bool
	Type     string // principal type (USER/ROLE) for principals, empty for groups
	Attached []string
}

// SQLAWSAssetRepository persists collected assets with parameterized SQL.
type SQLAWSAssetRepository struct {
	db *sql.DB
}

func NewSQLAWSAssetRepository(db *sql.DB) (*SQLAWSAssetRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLAWSAssetRepository{db: db}, nil
}

// ListCurrentIAMAssets returns the live principals and groups of one account.
// The collector calls this before SaveAccountIAM overwrites the inventory so
// a sync run can report added/removed assets.
func (repository *SQLAWSAssetRepository) ListCurrentIAMAssets(
	ctx context.Context,
	accountDBID int64,
) ([]CurrentIAMAsset, error) {
	rows, err := repository.db.QueryContext(ctx, `
		SELECT arn, principal_name, FALSE, principal_type
		FROM iam_principal
		WHERE account_id = $1 AND is_deleted = FALSE
		UNION ALL
		SELECT arn, group_name, TRUE, ''
		FROM iam_group
		WHERE account_id = $1`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("list current IAM assets for account %d: %w", accountDBID, err)
	}
	defer rows.Close()

	var assets []CurrentIAMAsset
	for rows.Next() {
		var asset CurrentIAMAsset
		if err := rows.Scan(&asset.ARN, &asset.Name, &asset.IsGroup, &asset.Type); err != nil {
			return nil, fmt.Errorf("scan current IAM asset: %w", err)
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate current IAM assets: %w", err)
	}
	return assets, nil
}

func (repository *SQLAWSAssetRepository) UpsertOrganizationAccounts(
	ctx context.Context,
	organizationID int64,
	accounts []model.AWSAccount,
) error {
	if organizationID <= 0 {
		return errors.New("organization database ID must be positive")
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin account upsert transaction: %w", err)
	}
	defer transaction.Rollback()

	const query = `INSERT INTO aws_account
		(org_id, account_id, account_name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (account_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			account_name = EXCLUDED.account_name,
			status = EXCLUDED.status,
			updated_at = NOW()`
	for _, account := range accounts {
		if _, err := transaction.ExecContext(ctx, query,
			organizationID,
			account.AccountID,
			account.AccountName,
			account.Status,
		); err != nil {
			return fmt.Errorf("upsert AWS account %s: %w", account.AccountID, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit account upsert transaction: %w", err)
	}
	return nil
}

func (repository *SQLAWSAssetRepository) GetAccountCollectionInfo(
	ctx context.Context,
	accountID string,
) (model.AWSAccount, error) {
	var account model.AWSAccount
	err := repository.db.QueryRowContext(ctx,
		`SELECT id, account_id, read_only_role_arn
		 FROM aws_account WHERE account_id = $1`,
		accountID,
	).Scan(&account.ID, &account.AccountID, &account.ReadOnlyRoleARN)
	if err != nil {
		return model.AWSAccount{}, fmt.Errorf("load read-only role for account %s: %w", accountID, err)
	}
	if account.ReadOnlyRoleARN == nil || strings.TrimSpace(*account.ReadOnlyRoleARN) == "" {
		return model.AWSAccount{}, fmt.Errorf("account %s has no read-only role ARN configured", accountID)
	}
	return account, nil
}

func (repository *SQLAWSAssetRepository) EnsureCurrentAccount(
	ctx context.Context,
	accountID string,
) (model.AWSAccount, error) {
	if len(accountID) != 12 {
		return model.AWSAccount{}, fmt.Errorf("invalid AWS account ID %q", accountID)
	}
	var account model.AWSAccount
	err := repository.db.QueryRowContext(ctx, `INSERT INTO aws_account
		(account_id, status, created_at, updated_at)
		VALUES ($1, 'ACTIVE', NOW(), NOW())
		ON CONFLICT (account_id) DO UPDATE SET
			status = 'ACTIVE',
			updated_at = NOW()
		RETURNING id, account_id, read_only_role_arn`,
		accountID,
	).Scan(&account.ID, &account.AccountID, &account.ReadOnlyRoleARN)
	if err != nil {
		return model.AWSAccount{}, fmt.Errorf("register current AWS account %s: %w", accountID, err)
	}
	return account, nil
}

func (repository *SQLAWSAssetRepository) EnsureConfiguredAccount(
	ctx context.Context,
	config model.AWSAccountConfig,
) (model.AWSAccount, error) {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AWSAccount{}, fmt.Errorf("begin configured AWS account registration: %w", err)
	}
	defer transaction.Rollback()

	var account model.AWSAccount
	err = transaction.QueryRowContext(ctx, `INSERT INTO aws_account
		(org_id, account_id, account_name, status, read_only_role_arn, created_at, updated_at)
		VALUES ($1, $2, $3, 'ACTIVE', $4, NOW(), NOW())
		ON CONFLICT (account_id) DO UPDATE SET
			org_id = COALESCE(aws_account.org_id, EXCLUDED.org_id),
			account_name = COALESCE(EXCLUDED.account_name, aws_account.account_name),
			status = COALESCE(aws_account.status, EXCLUDED.status),
			read_only_role_arn = COALESCE(EXCLUDED.read_only_role_arn, aws_account.read_only_role_arn),
			updated_at = NOW()
		RETURNING id, org_id, account_id, account_name, status, read_only_role_arn`,
		config.OrganizationDBID, config.AWSAccountID, config.DisplayName, nullableRoleARN(config.ReadOnlyRoleARN),
	).Scan(&account.ID, &account.OrganizationID, &account.AccountID, &account.AccountName,
		&account.Status, &account.ReadOnlyRoleARN)
	if err != nil {
		return model.AWSAccount{}, fmt.Errorf("register configured AWS account %s: %w", config.AWSAccountID, err)
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE aws_account_config
		SET aws_account_db_id = $2
		WHERE id = $1 AND (aws_account_db_id IS DISTINCT FROM $2)`, config.ID, account.ID); err != nil {
		return model.AWSAccount{}, fmt.Errorf("link configured AWS account %s: %w", config.AWSAccountID, err)
	}
	if err := transaction.Commit(); err != nil {
		return model.AWSAccount{}, fmt.Errorf("commit configured AWS account registration: %w", err)
	}
	return account, nil
}

func (repository *SQLAWSAssetRepository) SaveAccountIAM(
	ctx context.Context,
	account model.AWSAccount,
	inventory collectedIAMInventory,
) error {
	principals := inventory.Principals
	groups := inventory.Groups
	managedPolicies := inventory.ManagedPolicies
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin IAM asset transaction for account %s: %w", account.AccountID, err)
	}
	defer transaction.Rollback()

	for _, policy := range managedPolicies {
		if _, err := upsertPolicy(ctx, transaction, policy, account); err != nil {
			return fmt.Errorf("upsert managed policy %q: %w", aws.ToString(policy.PolicyName), err)
		}
	}
	for _, policy := range inventory.AWSManagedPolicies {
		if err := upsertPolicyCatalogEntry(ctx, transaction, policy); err != nil {
			return fmt.Errorf("upsert AWS-managed policy catalog entry %q: %w", aws.ToString(policy.PolicyName), err)
		}
	}
	if _, err := transaction.ExecContext(ctx,
		`UPDATE iam_principal SET is_deleted = TRUE, updated_at = NOW() WHERE account_id = $1`,
		account.ID,
	); err != nil {
		return fmt.Errorf("mark prior IAM principals stale for account %s: %w", account.AccountID, err)
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM iam_principal_policy
		WHERE principal_id IN (SELECT id FROM iam_principal WHERE account_id = $1)`, account.ID,
	); err != nil {
		return fmt.Errorf("clear prior principal policy associations for account %s: %w", account.AccountID, err)
	}

	for _, principal := range principals {
		var principalID int64
		err := transaction.QueryRowContext(ctx, `INSERT INTO iam_principal
			(account_id, principal_type, principal_name, arn, path,
			 permissions_boundary_arn, permissions_boundary_type,
			 trust_policy, description, max_session_duration, tags,
			 last_used_at, last_seen_at, is_deleted, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), FALSE, NOW(), NOW())
			ON CONFLICT (arn) DO UPDATE SET
				account_id = EXCLUDED.account_id,
				principal_type = EXCLUDED.principal_type,
				principal_name = EXCLUDED.principal_name,
				path = EXCLUDED.path,
				permissions_boundary_arn = EXCLUDED.permissions_boundary_arn,
				permissions_boundary_type = EXCLUDED.permissions_boundary_type,
				trust_policy = EXCLUDED.trust_policy,
				description = EXCLUDED.description,
				max_session_duration = EXCLUDED.max_session_duration,
				tags = EXCLUDED.tags,
				last_used_at = EXCLUDED.last_used_at,
				last_seen_at = NOW(),
				is_deleted = FALSE,
				updated_at = NOW()
			RETURNING id`,
			account.ID,
			principal.Principal.PrincipalType,
			principal.Principal.PrincipalName,
			principal.Principal.ARN,
			normalizedIAMPath(principal.Principal.Path),
			principal.Principal.PermissionsBoundaryARN,
			principal.Principal.PermissionsBoundaryType,
			jsonOrNull(principal.Principal.TrustPolicy),
			principal.Principal.Description,
			int64OrNull(principal.Principal.MaxSessionDuration),
			mapOrNull(principal.Principal.Tags),
			principal.Principal.LastUsedAt,
		).Scan(&principalID)
		if err != nil {
			return fmt.Errorf("upsert IAM principal %s: %w", principal.Principal.ARN, err)
		}

		for _, policy := range principal.Policies {
			policyID, err := upsertPolicy(ctx, transaction, policy, account)
			if err != nil {
				return fmt.Errorf("upsert policy %q for principal %s: %w", aws.ToString(policy.PolicyName), principal.Principal.ARN, err)
			}
			if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_principal_policy
				(principal_id, policy_id) VALUES ($1, $2)
				ON CONFLICT (principal_id, policy_id) DO NOTHING`,
				principalID, policyID,
			); err != nil {
				return fmt.Errorf("associate policy %q with principal %s: %w", aws.ToString(policy.PolicyName), principal.Principal.ARN, err)
			}
		}
	}

	if err := reconcileStaleIAMGroups(ctx, transaction, account.ID, groups); err != nil {
		return fmt.Errorf("reconcile IAM groups for account %s: %w", account.AccountID, err)
	}

	for _, group := range groups {
		var groupID int64
		err := transaction.QueryRowContext(ctx, `INSERT INTO iam_group
			(account_id, group_name, arn, path, created_at, updated_at)
			VALUES ($1, $2, $3, $4, NOW(), NOW())
			ON CONFLICT (arn) DO UPDATE SET
				account_id = EXCLUDED.account_id,
				group_name = EXCLUDED.group_name,
				path = EXCLUDED.path,
				updated_at = NOW()
			RETURNING id`,
			account.ID, group.Group.GroupName, group.Group.ARN, group.Group.Path,
		).Scan(&groupID)
		if err != nil {
			return fmt.Errorf("upsert IAM group %s: %w", group.Group.ARN, err)
		}

		if _, err := transaction.ExecContext(ctx, `DELETE FROM iam_group_membership WHERE group_id = $1`, groupID); err != nil {
			return fmt.Errorf("replace memberships for IAM group %s: %w", group.Group.ARN, err)
		}
		for _, userARN := range group.MemberARNs {
			var userPrincipalID int64
			err := transaction.QueryRowContext(ctx, `SELECT id FROM iam_principal
				WHERE arn = $1 AND principal_type = 'User'`, userARN).Scan(&userPrincipalID)
			if err != nil {
				return fmt.Errorf("find user %s for IAM group %s: %w", userARN, group.Group.ARN, err)
			}
			if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_group_membership
				(group_id, user_principal_id) VALUES ($1, $2)
				ON CONFLICT (group_id, user_principal_id) DO NOTHING`, groupID, userPrincipalID); err != nil {
				return fmt.Errorf("associate user %s with IAM group %s: %w", userARN, group.Group.ARN, err)
			}
		}

		if _, err := transaction.ExecContext(ctx, `DELETE FROM iam_group_policy WHERE group_id = $1`, groupID); err != nil {
			return fmt.Errorf("replace policies for IAM group %s: %w", group.Group.ARN, err)
		}
		for _, policy := range group.Policies {
			policyID, err := upsertPolicy(ctx, transaction, policy, account)
			if err != nil {
				return fmt.Errorf("upsert policy %q for IAM group %s: %w", aws.ToString(policy.PolicyName), group.Group.ARN, err)
			}
			if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_group_policy
				(group_id, policy_id) VALUES ($1, $2)
				ON CONFLICT (group_id, policy_id) DO NOTHING`, groupID, policyID); err != nil {
				return fmt.Errorf("associate policy %q with IAM group %s: %w", aws.ToString(policy.PolicyName), group.Group.ARN, err)
			}
		}
	}

	if _, err := transaction.ExecContext(ctx,
		`UPDATE iam_instance_profile SET is_deleted = TRUE, updated_at = NOW() WHERE account_id = $1`,
		account.ID,
	); err != nil {
		return fmt.Errorf("mark prior IAM instance profiles stale for account %s: %w", account.AccountID, err)
	}
	for _, profile := range inventory.InstanceProfiles {
		if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_instance_profile
			(account_id, instance_profile_name, arn, path, role_arn, tags,
			 last_seen_at, is_deleted, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW(), FALSE, NOW(), NOW())
			ON CONFLICT (arn) DO UPDATE SET
				account_id = EXCLUDED.account_id,
				instance_profile_name = EXCLUDED.instance_profile_name,
				path = EXCLUDED.path,
				role_arn = EXCLUDED.role_arn,
				tags = EXCLUDED.tags,
				last_seen_at = NOW(),
				is_deleted = FALSE,
				updated_at = NOW()`,
			account.ID,
			profile.InstanceProfileName,
			profile.ARN,
			normalizedIAMPath(profile.Path),
			profile.RoleARN,
			mapOrNull(profile.Tags),
		); err != nil {
			return fmt.Errorf("upsert IAM instance profile %s: %w", profile.ARN, err)
		}
	}

	if _, err := transaction.ExecContext(ctx,
		`UPDATE iam_identity_provider SET is_deleted = TRUE, updated_at = NOW() WHERE account_id = $1`,
		account.ID,
	); err != nil {
		return fmt.Errorf("mark prior IAM identity providers stale for account %s: %w", account.AccountID, err)
	}
	for _, provider := range inventory.IdentityProviders {
		if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_identity_provider
			(account_id, provider_type, arn, provider_name, url, client_id_list,
			 thumbprint_list, saml_metadata_document, tags,
			 last_seen_at, is_deleted, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), FALSE, NOW(), NOW())
			ON CONFLICT (arn) DO UPDATE SET
				account_id = EXCLUDED.account_id,
				provider_type = EXCLUDED.provider_type,
				provider_name = EXCLUDED.provider_name,
				url = EXCLUDED.url,
				client_id_list = EXCLUDED.client_id_list,
				thumbprint_list = EXCLUDED.thumbprint_list,
				saml_metadata_document = EXCLUDED.saml_metadata_document,
				tags = EXCLUDED.tags,
				last_seen_at = NOW(),
				is_deleted = FALSE,
				updated_at = NOW()`,
			account.ID,
			provider.ProviderType,
			provider.ARN,
			provider.ProviderName,
			provider.URL,
			stringSliceOrNull(provider.ClientIDList),
			stringSliceOrNull(provider.ThumbprintList),
			provider.SAMLMetadataDocument,
			mapOrNull(provider.Tags),
		); err != nil {
			return fmt.Errorf("upsert IAM identity provider %s: %w", provider.ARN, err)
		}
	}

	if _, err := transaction.ExecContext(ctx,
		`UPDATE aws_account SET last_sync_at = NOW(), updated_at = NOW() WHERE id = $1`,
		account.ID,
	); err != nil {
		return fmt.Errorf("update last sync time for account %s: %w", account.AccountID, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit IAM asset transaction for account %s: %w", account.AccountID, err)
	}
	return nil
}

func reconcileStaleIAMGroups(
	ctx context.Context,
	transaction *sql.Tx,
	accountID int64,
	groups []collectedIAMGroup,
) error {
	query := `DELETE FROM iam_group WHERE account_id = $1`
	args := []interface{}{accountID}
	if len(groups) > 0 {
		query += ` AND arn NOT IN (`
		for i, group := range groups {
			if i > 0 {
				query += `, `
			}
			query += fmt.Sprintf("$%d", i+2)
			args = append(args, group.Group.ARN)
		}
		query += `)`
	}
	_, err := transaction.ExecContext(ctx, query, args...)
	return err
}

// upsertPolicy 写入一条策略。account_id 只在 ARN 属于本账号（customer-managed
// 策略本体）时填写：归属标注按账号过滤策略行，AWS 托管策略与内联策略（无 ARN）
// 不属于任何单一账号，必须留 NULL，否则会被误标。
func upsertPolicy(
	ctx context.Context,
	transaction *sql.Tx,
	policy model.IAMPolicy,
	account model.AWSAccount,
) (int64, error) {
	if policy.PolicyARN != nil {
		var id int64
		err := transaction.QueryRowContext(ctx, `INSERT INTO iam_policy
			(policy_arn, policy_name, policy_type, description, tags, policy_document, risk_score, account_id, created_at, updated_at)
			VALUES ($1, $2, $3, COALESCE($4, ''), $5::jsonb, $6::jsonb, $7, $8, NOW(), NOW())
			ON CONFLICT (policy_arn) DO UPDATE SET
				policy_name = EXCLUDED.policy_name,
				policy_type = EXCLUDED.policy_type,
				description = COALESCE(EXCLUDED.description, ''),
				tags = EXCLUDED.tags,
				policy_document = EXCLUDED.policy_document,
				account_id = EXCLUDED.account_id,
				updated_at = NOW()
			RETURNING id`,
			policy.PolicyARN, policy.PolicyName, policy.PolicyType,
			policy.Description, mapOrNull(policy.Tags),
			string(policy.PolicyDocument), policy.RiskScore,
			policyOwnAccountID(policy.PolicyARN, account),
		).Scan(&id)
		return id, err
	}

	var id int64
	err := transaction.QueryRowContext(ctx, `SELECT id FROM iam_policy
		WHERE policy_arn IS NULL AND policy_name IS NOT DISTINCT FROM $1
			AND policy_type IS NOT DISTINCT FROM $2
			AND policy_document = $3::jsonb
		ORDER BY id LIMIT 1`,
		policy.PolicyName, policy.PolicyType, string(policy.PolicyDocument),
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	err = transaction.QueryRowContext(ctx, `INSERT INTO iam_policy
		(policy_name, policy_type, policy_document, risk_score, created_at, updated_at)
		VALUES ($1, $2, $3::jsonb, $4, NOW(), NOW())
		RETURNING id`,
		policy.PolicyName, policy.PolicyType, string(policy.PolicyDocument), policy.RiskScore,
	).Scan(&id)
	return id, err
}

// upsertPolicyCatalogEntry records an AWS-managed policy as a metadata-only
// catalog row. It never overwrites an existing row: if the policy was already
// attached somewhere, upsertPolicy stored its real document and description,
// and a catalog refresh must not wipe them back to NULL/”.
func upsertPolicyCatalogEntry(
	ctx context.Context,
	transaction *sql.Tx,
	policy model.IAMPolicy,
) error {
	if policy.PolicyARN == nil {
		return errors.New("AWS-managed policy catalog entry has no ARN")
	}
	_, err := transaction.ExecContext(ctx, `INSERT INTO iam_policy
		(policy_arn, policy_name, policy_type, policy_document, risk_score, created_at, updated_at)
		VALUES ($1, $2, 'managed', NULL, 0, NOW(), NOW())
		ON CONFLICT (policy_arn) DO NOTHING`,
		policy.PolicyARN, policy.PolicyName,
	)
	return err
}

// policyOwnAccountID 判断策略 ARN 是否是本账号的 customer-managed 策略本体：
// `arn:aws:iam::<12位账号>:policy/...` 且账号段与当前账号一致。AWS 托管策略
// （arn:aws:iam::aws:policy/...）与跨账号 ARN 返回 nil。
func policyOwnAccountID(arn *string, account model.AWSAccount) any {
	if arn == nil || account.ID <= 0 || len(account.AccountID) != 12 {
		return nil
	}
	const prefix = "arn:aws:iam::"
	value := *arn
	if !strings.HasPrefix(value, prefix) {
		return nil
	}
	rest := value[len(prefix):]
	if len(rest) < 12 || rest[:12] != account.AccountID {
		return nil
	}
	if !strings.HasPrefix(rest[12:], ":policy/") {
		return nil
	}
	return account.ID
}

type collectedIAMPrincipal struct {
	Principal model.IAMPrincipal
	Policies  []model.IAMPolicy
}

type collectedIAMGroup struct {
	Group      model.IAMGroup
	MemberARNs []string
	Policies   []model.IAMPolicy
}

// collectedIAMInventory is one full account snapshot. It is a struct rather
// than a parameter list because the baseline keeps adding declarable resource
// kinds (instance profiles, identity providers) to the same transaction.
type collectedIAMInventory struct {
	Principals      []collectedIAMPrincipal
	Groups          []collectedIAMGroup
	ManagedPolicies []model.IAMPolicy
	// AWSManagedPolicies is the metadata-only catalog of AWS-managed policies
	// (arn:aws:iam::aws:policy/*). They are not declarable and are never
	// edited by tickets, but they must be searchable and attachable, so the
	// catalog is refreshed on every sync. Documents stay NULL until an
	// attachment needs them (see fetchManagedPolicy).
	AWSManagedPolicies []model.IAMPolicy
	InstanceProfiles   []model.IAMInstanceProfile
	IdentityProviders  []model.IAMIdentityProvider
}

// NewAWSCollectorService loads AWS credentials and configures SDK standard
// retries, including retries for AWS throttling responses.
func NewAWSCollectorService(
	ctx context.Context,
	collectorConfig AWSCollectorConfig,
	repository AWSAssetRepository,
	logger *slog.Logger,
) (*AWSCollectorService, error) {
	if collectorConfig.Region == "" {
		return nil, errors.New("AWS region must not be empty")
	}
	if err := ValidateAWSConfig(); err != nil {
		return nil, err
	}
	if collectorConfig.MaxAttempts <= 0 {
		collectorConfig.MaxAttempts = defaultAWSMaxAttempts
	}
	if collectorConfig.SyncTimeout <= 0 {
		collectorConfig.SyncTimeout = defaultSyncTimeout
	}
	if collectorConfig.RoleSessionName == "" {
		collectorConfig.RoleSessionName = "iam-governance-collector"
	}
	if repository == nil {
		return nil, errors.New("AWS asset repository must not be nil")
	}

	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(collectorConfig.Region),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(options *retry.StandardOptions) {
				options.MaxAttempts = collectorConfig.MaxAttempts
			})
		}),
	}
	if profile := strings.TrimSpace(collectorConfig.Profile); profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(profile))
	}
	awsConfig, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK configuration: %w", err)
	}

	iamFactory := func(memberConfig aws.Config) awsIAMAPI {
		accountConfig := awsConfig
		if memberConfig.Credentials != nil {
			accountConfig.Credentials = memberConfig.Credentials
		}
		// C1a：memberConfig 里可能带了请求计数器（HTTPClient），必须透传，
		// 否则同步请求计数恒为 0。
		if memberConfig.HTTPClient != nil {
			accountConfig.HTTPClient = memberConfig.HTTPClient
		}
		return iam.NewFromConfig(accountConfig)
	}

	collector, err := newAWSCollectorService(
		collectorConfig,
		organizations.NewFromConfig(awsConfig),
		sts.NewFromConfig(awsConfig),
		iamFactory,
		repository,
		logger,
	)
	if err != nil {
		return nil, err
	}
	// 在用性证据的默认客户端工厂：与 IAM 同一套基础配置（凭证随 memberConfig
	// 注入），测试可以直接替换这两个字段。
	collector.usageEKSFactory = func(memberConfig aws.Config) eksUsageAPI {
		base := awsConfig
		if memberConfig.Credentials != nil {
			base.Credentials = memberConfig.Credentials
		}
		return eks.NewFromConfig(base)
	}
	collector.usageEC2Factory = func(memberConfig aws.Config) ec2UsageAPI {
		base := awsConfig
		if memberConfig.Credentials != nil {
			base.Credentials = memberConfig.Credentials
		}
		return ec2.NewFromConfig(base)
	}
	return collector, nil
}

func newAWSCollectorService(
	collectorConfig AWSCollectorConfig,
	organizationsClient awsOrganizationsAPI,
	stsClient awsSTSAPI,
	iamClientFactory awsIAMFactory,
	repository AWSAssetRepository,
	logger *slog.Logger,
) (*AWSCollectorService, error) {
	if collectorConfig.MaxAttempts <= 0 {
		collectorConfig.MaxAttempts = defaultAWSMaxAttempts
	}
	if collectorConfig.SyncTimeout <= 0 {
		collectorConfig.SyncTimeout = defaultSyncTimeout
	}
	if collectorConfig.RoleSessionName == "" {
		collectorConfig.RoleSessionName = "iam-governance-collector"
	}
	if organizationsClient == nil || stsClient == nil || iamClientFactory == nil {
		return nil, errors.New("AWS Organizations, STS, and IAM clients are required")
	}
	if repository == nil {
		return nil, errors.New("AWS asset repository must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &AWSCollectorService{
		config:        collectorConfig,
		organizations: organizationsClient,
		sts:           stsClient,
		iamFactory:    iamClientFactory,
		repository:    repository,
		logger:        logger,
	}, nil
}

// EnableProfileUsageCollection 打开「同步时顺带采集在用性证据」：之后每次
// 成功的账号同步都会把 EC2/EKS 实例配置文件引用证据 UPSERT 进数据库，
// 待清理清单即可直接读库。客户端工厂已在构造时配置；store 为 nil 时报错。
func (service *AWSCollectorService) EnableProfileUsageCollection(
	store *ProfileUsageEvidenceStore,
) error {
	if store == nil {
		return errors.New("profile usage evidence store must not be nil")
	}
	service.usageStore = store
	return nil
}

// collectProfileUsageEvidence 是同步链路的尽力而为步骤：失败只记日志、
// 不让同步失败——IAM 库存的价值不依赖于这份补充证据。
func (service *AWSCollectorService) collectProfileUsageEvidence(
	ctx context.Context,
	memberConfig aws.Config,
	awsAccountID string,
) {
	if service.usageStore == nil || service.usageEKSFactory == nil || service.usageEC2Factory == nil {
		return
	}
	result, err := collectProfileUsage(
		ctx, service.usageEKSFactory(memberConfig), service.usageEC2Factory(memberConfig))
	if err != nil {
		service.logger.Warn("profile usage evidence collection failed; cleanup page will fall back to live resolution",
			"account_id", awsAccountID, "error", err)
		return
	}
	if err := service.usageStore.Save(ctx, awsAccountID, result); err != nil {
		service.logger.Warn("persist profile usage evidence failed",
			"account_id", awsAccountID, "error", err)
		return
	}
	service.logger.Info("profile usage evidence stored",
		"account_id", awsAccountID,
		"used_profile_count", len(result.UsedProfiles),
		"role_nodegroup_count", len(result.RoleNodegroups),
		"warnings", len(result.Warnings),
	)
}

// SyncOrganization discovers accounts in the active AWS Organization, records
// their metadata, and collects IAM assets from active member accounts. The
// management account is skipped when ManagementAccountID is configured.
func (service *AWSCollectorService) SyncOrganization(
	ctx context.Context,
	organizationDatabaseID int64,
) error {
	if organizationDatabaseID <= 0 {
		return errors.New("organization database ID must be positive")
	}
	runContext, cancel := context.WithTimeout(ctx, service.config.SyncTimeout)
	defer cancel()

	accounts, err := service.listOrganizationAccounts(runContext)
	if err != nil {
		return err
	}
	if err := service.repository.UpsertOrganizationAccounts(runContext, organizationDatabaseID, accounts); err != nil {
		return fmt.Errorf("save AWS Organizations accounts: %w", err)
	}

	for _, account := range accounts {
		if account.Status == nil || *account.Status != string(orgtypes.AccountStatusActive) {
			continue
		}
		if service.config.ManagementAccountID != "" && account.AccountID == service.config.ManagementAccountID {
			continue
		}
		if err := service.collectAccount(runContext, account.AccountID); err != nil {
			service.logger.Error("AWS account IAM collection failed",
				"account_id", account.AccountID,
				"error", err,
			)
			return fmt.Errorf("collect IAM assets for account %s: %w", account.AccountID, err)
		}
	}
	return nil
}

// SyncCurrentAccount collects IAM inventory using the active SDK credentials
// directly. It does not require Organizations access or call AssumeRole.
func (service *AWSCollectorService) SyncCurrentAccount(ctx context.Context) (model.AWSAccount, error) {
	runContext, cancel := context.WithTimeout(ctx, service.config.SyncTimeout)
	defer cancel()

	identity, err := service.sts.GetCallerIdentity(runContext, &sts.GetCallerIdentityInput{})
	if err != nil {
		return model.AWSAccount{}, fmt.Errorf("identify current AWS credentials: %w", err)
	}
	accountID := aws.ToString(identity.Account)
	if len(accountID) != 12 {
		return model.AWSAccount{}, fmt.Errorf("STS returned invalid AWS account ID %q", accountID)
	}

	account, err := service.repository.EnsureCurrentAccount(runContext, accountID)
	if err != nil {
		return model.AWSAccount{}, err
	}
	requestCounter := newAWSRequestCounter()
	runMetrics := newSyncRunMetrics(requestCounter)
	iamClient := service.iamFactory(requestCounter.attach(aws.Config{Region: service.config.Region}))
	var inventory collectedIAMInventory
	err = runMetrics.stage("collect", func() error {
		var err error
		inventory, err = service.collectIAMAssets(runContext, iamClient, runMetrics)
		if err != nil {
			return fmt.Errorf("collect IAM assets in account %s: %w", accountID, err)
		}
		return nil
	})
	if err != nil {
		return model.AWSAccount{}, err
	}
	err = runMetrics.stage("persist", func() error {
		if err := service.repository.SaveAccountIAM(runContext, account, inventory); err != nil {
			return fmt.Errorf("persist IAM assets for account %s: %w", accountID, err)
		}
		return nil
	})
	if err != nil {
		return model.AWSAccount{}, err
	}
	// 同步顺带采集在用性证据（尽力而为，失败不影响同步结果）。
	err = runMetrics.stage("usage_evidence", func() error {
		service.collectProfileUsageEvidence(runContext, requestCounter.attach(aws.Config{Region: service.config.Region}), accountID)
		return nil
	})
	if err != nil {
		service.logger.Warn("profile usage evidence collection reported an error (non-fatal)",
			"account_id", accountID, "error", err)
	}
	summary := []any{
		"account_id", accountID,
		"principal_count", len(inventory.Principals),
		"group_count", len(inventory.Groups),
		"managed_policy_count", len(inventory.ManagedPolicies),
		"aws_managed_policy_count", len(inventory.AWSManagedPolicies),
		"instance_profile_count", len(inventory.InstanceProfiles),
		"identity_provider_count", len(inventory.IdentityProviders),
	}
	summary = append(summary, runMetrics.logFields()...)
	service.logger.Info("AWS account IAM assets collected", summary...)
	return account, nil
}

// SyncConfiguredAccount collects only the account represented by the supplied
// enabled account configuration. It does not discover or enumerate an AWS
// Organization.
func (service *AWSCollectorService) SyncConfiguredAccount(
	ctx context.Context,
	config model.AWSAccountConfig,
) (model.AWSAccount, *AWSSyncChanges, error) {
	if !config.SyncEnabled {
		return model.AWSAccount{}, nil, fmt.Errorf("AWS account config %d is disabled", config.ID)
	}
	if config.AWSAccountID == "" {
		return model.AWSAccount{}, nil, errors.New("configured AWS account ID must not be empty")
	}
	accountRepository, ok := service.repository.(configuredAWSAssetRepository)
	if !ok {
		return model.AWSAccount{}, nil, errors.New("AWS asset repository does not support configured accounts")
	}
	runContext, cancel := context.WithTimeout(ctx, service.config.SyncTimeout)
	defer cancel()

	requestCounter := newAWSRequestCounter()
	runMetrics := newSyncRunMetrics(requestCounter)

	var account model.AWSAccount
	err := runMetrics.stage("ensure_account", func() error {
		var err error
		account, err = accountRepository.EnsureConfiguredAccount(runContext, config)
		return err
	})
	if err != nil {
		return model.AWSAccount{}, nil, err
	}
	if account.Status != nil && *account.Status != "ACTIVE" {
		return model.AWSAccount{}, nil, fmt.Errorf("AWS account %s is not active (status %s)",
			config.AWSAccountID, *account.Status)
	}

	var iamClient awsIAMAPI
	// usageConfig 带出各分支的凭证上下文，供在用性证据采集复用同一身份。
	var usageConfig aws.Config
	// credentials 阶段的 STS 调用走预注入的 service.sts，不进请求计数。
	err = runMetrics.stage("credentials", func() error {
		switch config.SyncMode {
		case AWSAccountSyncAssumeRole:
			if config.ReadOnlyRoleARN == nil || strings.TrimSpace(*config.ReadOnlyRoleARN) == "" {
				return errors.New("configured read-only role ARN is required")
			}
			assumeInput := &sts.AssumeRoleInput{
				RoleArn:         config.ReadOnlyRoleARN,
				RoleSessionName: aws.String(service.config.RoleSessionName),
			}
			if service.config.ExternalID != "" {
				assumeInput.ExternalId = aws.String(service.config.ExternalID)
			}
			assumedRole, err := service.sts.AssumeRole(runContext, assumeInput)
			if err != nil {
				return fmt.Errorf("assume configured read-only role for account %s: %w",
					config.AWSAccountID, err)
			}
			if assumedRole.Credentials == nil ||
				assumedRole.Credentials.AccessKeyId == nil ||
				assumedRole.Credentials.SecretAccessKey == nil ||
				assumedRole.Credentials.SessionToken == nil {
				return fmt.Errorf("AssumeRole returned incomplete credentials for account %s",
					config.AWSAccountID)
			}
			memberConfig := aws.Config{Region: service.config.Region}
			memberConfig.Credentials = credentials.NewStaticCredentialsProvider(
				*assumedRole.Credentials.AccessKeyId,
				*assumedRole.Credentials.SecretAccessKey,
				*assumedRole.Credentials.SessionToken,
			)
			memberConfig.Retryer = func() aws.Retryer {
				return retry.NewStandard(func(options *retry.StandardOptions) {
					options.MaxAttempts = service.config.MaxAttempts
				})
			}
			iamClient = service.iamFactory(requestCounter.attach(memberConfig))
			usageConfig = requestCounter.attach(memberConfig)
		case AWSAccountSyncCurrentCredentials:
			identity, err := service.sts.GetCallerIdentity(runContext, &sts.GetCallerIdentityInput{})
			if err != nil {
				return fmt.Errorf("identify current AWS credentials: %w", err)
			}
			if identity == nil || aws.ToString(identity.Account) != config.AWSAccountID {
				return fmt.Errorf("configured account ID %s does not match current AWS identity %s",
					config.AWSAccountID, aws.ToString(identity.Account))
			}
			iamClient = service.iamFactory(requestCounter.attach(aws.Config{Region: service.config.Region}))
			usageConfig = requestCounter.attach(aws.Config{Region: service.config.Region})
		default:
			return fmt.Errorf("unsupported configured AWS sync mode %q", config.SyncMode)
		}
		return nil
	})
	if err != nil {
		return model.AWSAccount{}, nil, err
	}

	var previous []CurrentIAMAsset
	err = runMetrics.stage("load_previous", func() error {
		var err error
		previous, err = accountRepository.ListCurrentIAMAssets(runContext, account.ID)
		if err != nil {
			return fmt.Errorf("load current IAM inventory for account %s: %w",
				config.AWSAccountID, err)
		}
		return nil
	})
	if err != nil {
		return model.AWSAccount{}, nil, err
	}

	var inventory collectedIAMInventory
	err = runMetrics.stage("collect", func() error {
		var err error
		inventory, err = service.collectIAMAssets(runContext, iamClient, runMetrics)
		if err != nil {
			return fmt.Errorf("collect IAM assets in account %s: %w", config.AWSAccountID, err)
		}
		return nil
	})
	if err != nil {
		return model.AWSAccount{}, nil, err
	}
	changes := diffIAMAssets(previous, inventory.Principals, inventory.Groups)
	err = runMetrics.stage("persist", func() error {
		if err := service.repository.SaveAccountIAM(runContext, account, inventory); err != nil {
			return fmt.Errorf("persist IAM assets for account %s: %w", config.AWSAccountID, err)
		}
		return nil
	})
	if err != nil {
		return model.AWSAccount{}, nil, err
	}
	// 同步顺带采集在用性证据（尽力而为，失败不影响同步结果）。
	err = runMetrics.stage("usage_evidence", func() error {
		service.collectProfileUsageEvidence(runContext, usageConfig, config.AWSAccountID)
		return nil
	})
	// 在用性证据失败不算同步失败，但阶段耗时/请求增量已经记下。
	if err != nil {
		service.logger.Warn("profile usage evidence collection reported an error (non-fatal)",
			"account_id", config.AWSAccountID, "error", err)
	}
	summary := []any{
		"account_id", config.AWSAccountID,
		"account_db_id", account.ID,
		"principal_count", len(inventory.Principals),
		"group_count", len(inventory.Groups),
		"managed_policy_count", len(inventory.ManagedPolicies),
		"aws_managed_policy_count", len(inventory.AWSManagedPolicies),
		"instance_profile_count", len(inventory.InstanceProfiles),
		"identity_provider_count", len(inventory.IdentityProviders),
	}
	if changes != nil {
		summary = append(summary,
			"principals_added", len(changes.PrincipalsAdded),
			"principals_removed", len(changes.PrincipalsRemoved),
			"groups_added", len(changes.GroupsAdded),
			"groups_removed", len(changes.GroupsRemoved),
		)
	} else {
		summary = append(summary, "inventory_unchanged", true)
	}
	summary = append(summary, runMetrics.logFields()...)
	service.logger.Info("configured AWS account IAM assets collected", summary...)
	return account, changes, nil
}

// diffIAMAssets compares the freshly collected assets against the platform
// inventory snapshot taken before the save. It returns nil when nothing
// changed so runs without movement do not store a diff.
func diffIAMAssets(
	previous []CurrentIAMAsset,
	principals []collectedIAMPrincipal,
	groups []collectedIAMGroup,
) *AWSSyncChanges {
	live := make(map[string]CurrentIAMAsset, len(previous))
	for _, asset := range previous {
		live[asset.ARN] = asset
	}

	changes := &AWSSyncChanges{}
	seen := make(map[string]bool, len(previous))

	for _, principal := range principals {
		arn := principal.Principal.ARN
		seen[arn] = true
		if _, exists := live[arn]; exists {
			continue
		}
		changes.PrincipalsAdded = append(changes.PrincipalsAdded, AWSSyncAssetChange{
			Name: principal.Principal.PrincipalName,
			Type: principal.Principal.PrincipalType,
			ARN:  arn,
		})
	}
	for _, group := range groups {
		arn := group.Group.ARN
		seen[arn] = true
		if _, exists := live[arn]; exists {
			continue
		}
		changes.GroupsAdded = append(changes.GroupsAdded, AWSSyncAssetChange{
			Name: group.Group.GroupName,
			ARN:  arn,
		})
	}
	for _, asset := range previous {
		if seen[asset.ARN] {
			continue
		}
		change := AWSSyncAssetChange{Name: asset.Name, Type: asset.Type, ARN: asset.ARN}
		if asset.IsGroup {
			changes.GroupsRemoved = append(changes.GroupsRemoved, change)
		} else {
			changes.PrincipalsRemoved = append(changes.PrincipalsRemoved, change)
		}
	}

	if len(changes.PrincipalsAdded) == 0 && len(changes.PrincipalsRemoved) == 0 &&
		len(changes.GroupsAdded) == 0 && len(changes.GroupsRemoved) == 0 {
		return nil
	}
	return changes
}

func (service *AWSCollectorService) listOrganizationAccounts(ctx context.Context) ([]model.AWSAccount, error) {
	var accounts []model.AWSAccount
	var nextToken *string
	for {
		output, err := service.organizations.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list AWS Organizations accounts: %w", err)
		}
		for _, account := range output.Accounts {
			if account.Id == nil || strings.TrimSpace(*account.Id) == "" {
				continue
			}
			row := model.AWSAccount{AccountID: *account.Id}
			if account.Name != nil {
				row.AccountName = account.Name
			}
			if account.Status != "" {
				status := string(account.Status)
				row.Status = &status
			}
			accounts = append(accounts, row)
		}
		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		if nextToken != nil && *nextToken == *output.NextToken {
			return nil, fmt.Errorf("AWS Organizations returned a repeated pagination token %q", *output.NextToken)
		}
		nextToken = output.NextToken
	}
	return accounts, nil
}

func (service *AWSCollectorService) collectAccount(ctx context.Context, accountID string) error {
	account, err := service.repository.GetAccountCollectionInfo(ctx, accountID)
	if err != nil {
		return err
	}
	if account.ReadOnlyRoleARN == nil || strings.TrimSpace(*account.ReadOnlyRoleARN) == "" {
		return fmt.Errorf("account %s has no read-only role ARN configured", accountID)
	}
	assumeInput := &sts.AssumeRoleInput{
		RoleArn:         account.ReadOnlyRoleARN,
		RoleSessionName: aws.String(service.config.RoleSessionName),
	}
	if service.config.ExternalID != "" {
		assumeInput.ExternalId = aws.String(service.config.ExternalID)
	}
	assumedRole, err := service.sts.AssumeRole(ctx, assumeInput)
	if err != nil {
		return fmt.Errorf("assume read-only role in account %s: %w", accountID, err)
	}
	if assumedRole.Credentials == nil ||
		assumedRole.Credentials.AccessKeyId == nil ||
		assumedRole.Credentials.SecretAccessKey == nil ||
		assumedRole.Credentials.SessionToken == nil {
		return fmt.Errorf("AssumeRole returned incomplete credentials for account %s", accountID)
	}

	memberConfig := aws.Config{Region: service.config.Region}
	memberConfig.Credentials = credentials.NewStaticCredentialsProvider(
		*assumedRole.Credentials.AccessKeyId,
		*assumedRole.Credentials.SecretAccessKey,
		*assumedRole.Credentials.SessionToken,
	)
	memberConfig.Retryer = func() aws.Retryer {
		return retry.NewStandard(func(options *retry.StandardOptions) {
			options.MaxAttempts = service.config.MaxAttempts
		})
	}
	requestCounter := newAWSRequestCounter()
	runMetrics := newSyncRunMetrics(requestCounter)
	iamClient := service.iamFactory(requestCounter.attach(memberConfig))

	var inventory collectedIAMInventory
	err = runMetrics.stage("collect", func() error {
		var err error
		inventory, err = service.collectIAMAssets(ctx, iamClient, runMetrics)
		if err != nil {
			return fmt.Errorf("collect IAM assets in account %s: %w", accountID, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = runMetrics.stage("persist", func() error {
		if err := service.repository.SaveAccountIAM(ctx, account, inventory); err != nil {
			return fmt.Errorf("persist IAM assets for account %s: %w", accountID, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 同步顺带采集在用性证据（尽力而为，失败不影响同步结果）。
	err = runMetrics.stage("usage_evidence", func() error {
		service.collectProfileUsageEvidence(ctx, requestCounter.attach(memberConfig), accountID)
		return nil
	})
	if err != nil {
		service.logger.Warn("profile usage evidence collection reported an error (non-fatal)",
			"account_id", accountID, "error", err)
	}
	summary := []any{
		"account_id", accountID,
		"principal_count", len(inventory.Principals),
		"group_count", len(inventory.Groups),
		"managed_policy_count", len(inventory.ManagedPolicies),
		"aws_managed_policy_count", len(inventory.AWSManagedPolicies),
		"instance_profile_count", len(inventory.InstanceProfiles),
		"identity_provider_count", len(inventory.IdentityProviders),
	}
	summary = append(summary, runMetrics.logFields()...)
	service.logger.Info("AWS account IAM assets collected", summary...)
	return nil
}

func (service *AWSCollectorService) collectIAMAssets(
	ctx context.Context,
	client awsIAMAPI,
	metrics *syncRunMetrics,
) (collectedIAMInventory, error) {
	managedPolicies, err := timedResult(metrics, "collect.managed_policies", func() (map[string]model.IAMPolicy, error) {
		return service.collectManagedPolicies(ctx, client)
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}

	var inventory collectedIAMInventory
	// roles 阶段含逐 role 的 ListAttachedRolePolicies/GetRolePolicy 等，
	// 是整轮同步里请求量最大的部分之一。
	err = timedError(metrics, "collect.roles", func() error {
		var roleMarker *string
		for {
			output, err := client.ListRoles(ctx, &iam.ListRolesInput{Marker: roleMarker})
			if err != nil {
				return fmt.Errorf("list IAM roles: %w", err)
			}
			for _, role := range output.Roles {
				principal, err := service.collectRole(ctx, client, role, managedPolicies)
				if err != nil {
					return err
				}
				inventory.Principals = append(inventory.Principals, principal)
			}
			if !output.IsTruncated {
				break
			}
			if output.Marker == nil || *output.Marker == "" {
				return errors.New("IAM ListRoles response is truncated without a marker")
			}
			roleMarker = output.Marker
		}
		return nil
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}

	err = timedError(metrics, "collect.users", func() error {
		var userMarker *string
		for {
			output, err := client.ListUsers(ctx, &iam.ListUsersInput{Marker: userMarker})
			if err != nil {
				return fmt.Errorf("list IAM users: %w", err)
			}
			for _, user := range output.Users {
				principal, err := service.collectUser(ctx, client, user, managedPolicies)
				if err != nil {
					return err
				}
				inventory.Principals = append(inventory.Principals, principal)
			}
			if !output.IsTruncated {
				break
			}
			if output.Marker == nil || *output.Marker == "" {
				return errors.New("IAM ListUsers response is truncated without a marker")
			}
			userMarker = output.Marker
		}
		return nil
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}

	groups, err := timedResult(metrics, "collect.groups", func() ([]collectedIAMGroup, error) {
		return service.collectGroups(ctx, client, managedPolicies)
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}
	inventory.Groups = groups
	inventory.ManagedPolicies = make([]model.IAMPolicy, 0, len(managedPolicies))
	for _, policy := range managedPolicies {
		inventory.ManagedPolicies = append(inventory.ManagedPolicies, policy)
	}

	instanceProfiles, err := timedResult(metrics, "collect.instance_profiles", func() ([]model.IAMInstanceProfile, error) {
		return service.collectInstanceProfiles(ctx, client)
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}
	inventory.InstanceProfiles = instanceProfiles

	// C2: refresh the AWS-managed policy catalog so AdministratorAccess and
	// friends are searchable and attachable. Metadata only — see the field
	// comment on collectedIAMInventory.
	awsManagedPolicies, err := timedResult(metrics, "collect.aws_policy_catalog", func() ([]model.IAMPolicy, error) {
		return service.collectAWSManagedPolicyCatalog(ctx, client)
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}
	inventory.AWSManagedPolicies = awsManagedPolicies

	identityProviders, err := timedResult(metrics, "collect.identity_providers", func() ([]model.IAMIdentityProvider, error) {
		return service.collectIdentityProviders(ctx, client)
	})
	if err != nil {
		return collectedIAMInventory{}, err
	}
	inventory.IdentityProviders = identityProviders
	return inventory, nil
}

// collectAWSManagedPolicyCatalog lists the AWS-managed policy catalog
// (Scope=AWS). It deliberately skips GetPolicy/GetPolicyVersion/ListPolicyTags:
// the catalog has ~1100 entries and their documents are only needed when one
// is actually attached, which fetchManagedPolicy already handles on demand.
func (service *AWSCollectorService) collectAWSManagedPolicyCatalog(
	ctx context.Context,
	client awsIAMAPI,
) ([]model.IAMPolicy, error) {
	var policies []model.IAMPolicy
	var marker *string
	for {
		output, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
			Scope:  iamtypes.PolicyScopeTypeAws,
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list AWS-managed policies: %w", err)
		}
		for _, listedPolicy := range output.Policies {
			if listedPolicy.Arn == nil {
				continue
			}
			arn := *listedPolicy.Arn
			name := aws.ToString(listedPolicy.PolicyName)
			policyType := "managed"
			policies = append(policies, model.IAMPolicy{
				PolicyARN:  &arn,
				PolicyName: &name,
				PolicyType: &policyType,
				// PolicyDocument stays nil: NULL in iam_policy means
				// "known to exist, document not fetched yet".
			})
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, errors.New("IAM ListPolicies (AWS scope) response is truncated without a marker")
		}
		marker = output.Marker
	}
	return policies, nil
}

// collectInstanceProfiles lists every instance profile and the role it
// carries. The baseline needs the binding so a role rebuild cannot detach
// running EC2 instances.
func (service *AWSCollectorService) collectInstanceProfiles(
	ctx context.Context,
	client awsIAMAPI,
) ([]model.IAMInstanceProfile, error) {
	var profiles []model.IAMInstanceProfile
	var marker *string
	for {
		output, err := client.ListInstanceProfiles(ctx, &iam.ListInstanceProfilesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list IAM instance profiles: %w", err)
		}
		for _, profile := range output.InstanceProfiles {
			if profile.Arn == nil || profile.InstanceProfileName == nil {
				return nil, errors.New("AWS returned instance profile without name or ARN")
			}
			collected := model.IAMInstanceProfile{
				InstanceProfileName: *profile.InstanceProfileName,
				ARN:                 *profile.Arn,
				Path:                normalizedIAMPath(aws.ToString(profile.Path)),
				Tags:                iamTagsToMap(profile.Tags),
			}
			if len(profile.Roles) > 0 && profile.Roles[0].Arn != nil {
				collected.RoleARN = profile.Roles[0].Arn
			}
			profiles = append(profiles, collected)
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, errors.New("IAM ListInstanceProfiles response is truncated without a marker")
		}
		marker = output.Marker
	}
	return profiles, nil
}

// collectIdentityProviders lists OIDC and SAML providers with the attributes
// the Terraform resources require (URL/client IDs/thumbprints or metadata).
func (service *AWSCollectorService) collectIdentityProviders(
	ctx context.Context,
	client awsIAMAPI,
) ([]model.IAMIdentityProvider, error) {
	var providers []model.IAMIdentityProvider

	oidcList, err := client.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, fmt.Errorf("list IAM OIDC providers: %w", err)
	}
	for _, entry := range oidcList.OpenIDConnectProviderList {
		if entry.Arn == nil {
			return nil, errors.New("AWS returned OIDC provider without ARN")
		}
		details, err := client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: entry.Arn,
		})
		if err != nil {
			return nil, fmt.Errorf("get IAM OIDC provider %s: %w", *entry.Arn, err)
		}
		providers = append(providers, model.IAMIdentityProvider{
			ProviderType:   "OIDC",
			ARN:            *entry.Arn,
			ProviderName:   iamResourceName(*entry.Arn),
			URL:            details.Url,
			ClientIDList:   details.ClientIDList,
			ThumbprintList: details.ThumbprintList,
			Tags:           iamTagsToMap(details.Tags),
		})
	}

	samlList, err := client.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil, fmt.Errorf("list IAM SAML providers: %w", err)
	}
	for _, entry := range samlList.SAMLProviderList {
		if entry.Arn == nil {
			return nil, errors.New("AWS returned SAML provider without ARN")
		}
		details, err := client.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{
			SAMLProviderArn: entry.Arn,
		})
		if err != nil {
			return nil, fmt.Errorf("get IAM SAML provider %s: %w", *entry.Arn, err)
		}
		providers = append(providers, model.IAMIdentityProvider{
			ProviderType:         "SAML",
			ARN:                  *entry.Arn,
			ProviderName:         iamResourceName(*entry.Arn),
			SAMLMetadataDocument: details.SAMLMetadataDocument,
			Tags:                 iamTagsToMap(details.Tags),
		})
	}
	return providers, nil
}

// iamResourceName extracts the IAM resource name from an ARN. It must not use
// the last path segment: an OIDC provider ARN is
// arn:aws:iam::123:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE
// and the provider name — which the Terraform resource derives its URL from —
// is everything after the resource type, slashes included.
func iamResourceName(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return arn
	}
	resource := parts[5]
	if index := strings.Index(resource, "/"); index >= 0 && index+1 < len(resource) {
		return resource[index+1:]
	}
	return resource
}

func (service *AWSCollectorService) collectGroups(
	ctx context.Context,
	client awsIAMAPI,
	managedPolicies map[string]model.IAMPolicy,
) ([]collectedIAMGroup, error) {
	var groups []collectedIAMGroup
	var marker *string
	for {
		output, err := client.ListGroups(ctx, &iam.ListGroupsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list IAM groups: %w", err)
		}
		for _, listed := range output.Groups {
			if listed.GroupName == nil || listed.Arn == nil {
				return nil, errors.New("AWS returned group without name or ARN")
			}
			group := collectedIAMGroup{
				Group: model.IAMGroup{
					GroupName: *listed.GroupName,
					ARN:       *listed.Arn,
					Path:      aws.ToString(listed.Path),
				},
			}
			if group.Group.Path == "" {
				group.Group.Path = "/"
			}
			var groupMarker *string
			for {
				details, err := client.GetGroup(ctx, &iam.GetGroupInput{
					GroupName: listed.GroupName,
					Marker:    groupMarker,
				})
				if err != nil {
					return nil, fmt.Errorf("get IAM group %s: %w", *listed.GroupName, err)
				}
				if details.Group != nil {
					if details.Group.Path != nil {
						group.Group.Path = *details.Group.Path
					}
				}
				for _, user := range details.Users {
					if user.Arn != nil {
						group.MemberARNs = append(group.MemberARNs, *user.Arn)
					}
				}
				if !details.IsTruncated {
					break
				}
				if details.Marker == nil || *details.Marker == "" {
					return nil, fmt.Errorf("IAM GetGroup response for %s is truncated without a marker", *listed.GroupName)
				}
				groupMarker = details.Marker
			}
			policies, err := service.collectGroupPolicies(ctx, client, *listed.GroupName, managedPolicies)
			if err != nil {
				return nil, fmt.Errorf("collect policies for IAM group %s: %w", *listed.GroupName, err)
			}
			group.Policies = policies
			groups = append(groups, group)
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, errors.New("IAM ListGroups response is truncated without a marker")
		}
		marker = output.Marker
	}
	return groups, nil
}

func (service *AWSCollectorService) collectGroupPolicies(
	ctx context.Context,
	client awsIAMAPI,
	groupName string,
	managedPolicies map[string]model.IAMPolicy,
) ([]model.IAMPolicy, error) {
	attached := make(map[string]struct{})
	var policies []model.IAMPolicy
	var marker *string
	for {
		output, err := client.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{
			GroupName: aws.String(groupName),
			Marker:    marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list attached managed policies: %w", err)
		}
		for _, attachedPolicy := range output.AttachedPolicies {
			if attachedPolicy.PolicyArn == nil {
				continue
			}
			arn := *attachedPolicy.PolicyArn
			if _, exists := attached[arn]; exists {
				continue
			}
			policy, exists := managedPolicies[arn]
			if !exists {
				policy, err = service.fetchManagedPolicy(ctx, client, arn, aws.ToString(attachedPolicy.PolicyName))
				if err != nil {
					return nil, err
				}
				managedPolicies[arn] = policy
			}
			attached[arn] = struct{}{}
			policies = append(policies, policy)
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, errors.New("IAM attached group-policy response is truncated without a marker")
		}
		marker = output.Marker
	}

	marker = nil
	for {
		output, err := client.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{
			GroupName: aws.String(groupName),
			Marker:    marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list inline policies: %w", err)
		}
		for _, policyName := range output.PolicyNames {
			details, err := client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
				GroupName:  aws.String(groupName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				return nil, fmt.Errorf("get inline policy %s: %w", policyName, err)
			}
			if details.PolicyDocument == nil {
				return nil, fmt.Errorf("AWS returned no document for inline policy %s", policyName)
			}
			document, err := decodeIAMPolicyDocument(*details.PolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("decode inline policy %s: %w", policyName, err)
			}
			nameCopy, typeCopy := policyName, "inline"
			policies = append(policies, model.IAMPolicy{
				PolicyName:     &nameCopy,
				PolicyType:     &typeCopy,
				PolicyDocument: model.JSONB(document),
			})
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, errors.New("IAM inline group-policy response is truncated without a marker")
		}
		marker = output.Marker
	}
	return policies, nil
}

func (service *AWSCollectorService) collectRole(
	ctx context.Context,
	client awsIAMAPI,
	role iamtypes.Role,
	managedPolicies map[string]model.IAMPolicy,
) (collectedIAMPrincipal, error) {
	if role.RoleName == nil || role.Arn == nil {
		return collectedIAMPrincipal{}, errors.New("AWS returned role without name or ARN")
	}
	details, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: role.RoleName})
	if err != nil {
		return collectedIAMPrincipal{}, fmt.Errorf("get IAM role %s: %w", *role.RoleName, err)
	}

	principal := model.IAMPrincipal{
		PrincipalType: "Role",
		PrincipalName: *role.RoleName,
		ARN:           *role.Arn,
	}
	if details.Role != nil {
		if details.Role.AssumeRolePolicyDocument != nil {
			document, err := decodeIAMPolicyDocument(*details.Role.AssumeRolePolicyDocument)
			if err != nil {
				return collectedIAMPrincipal{}, fmt.Errorf("decode trust policy for role %s: %w", *role.RoleName, err)
			}
			principal.TrustPolicy = model.JSONB(document)
		}
		principal.Description = details.Role.Description
		principal.Path = normalizedIAMPath(aws.ToString(details.Role.Path))
		if boundary := details.Role.PermissionsBoundary; boundary != nil {
			principal.PermissionsBoundaryARN = boundary.PermissionsBoundaryArn
			if boundary.PermissionsBoundaryType != "" {
				boundaryType := string(boundary.PermissionsBoundaryType)
				principal.PermissionsBoundaryType = &boundaryType
			}
		}
		if details.Role.MaxSessionDuration != nil {
			maxSessionDuration := int64(*details.Role.MaxSessionDuration)
			principal.MaxSessionDuration = &maxSessionDuration
		}
		if tags := iamTagsToMap(details.Role.Tags); len(tags) > 0 {
			principal.Tags = tags
		}
		if details.Role.RoleLastUsed != nil {
			principal.LastUsedAt = details.Role.RoleLastUsed.LastUsedDate
		}
	}

	policies, err := service.collectPrincipalPolicies(ctx, client, *role.RoleName, true, managedPolicies)
	if err != nil {
		return collectedIAMPrincipal{}, fmt.Errorf("collect policies for role %s: %w", *role.RoleName, err)
	}
	return collectedIAMPrincipal{Principal: principal, Policies: policies}, nil
}

func (service *AWSCollectorService) collectUser(
	ctx context.Context,
	client awsIAMAPI,
	user iamtypes.User,
	managedPolicies map[string]model.IAMPolicy,
) (collectedIAMPrincipal, error) {
	if user.UserName == nil || user.Arn == nil {
		return collectedIAMPrincipal{}, errors.New("AWS returned user without name or ARN")
	}
	details, err := client.GetUser(ctx, &iam.GetUserInput{UserName: user.UserName})
	if err != nil {
		return collectedIAMPrincipal{}, fmt.Errorf("get IAM user %s: %w", *user.UserName, err)
	}

	principal := model.IAMPrincipal{
		PrincipalType: "User",
		PrincipalName: *user.UserName,
		ARN:           *user.Arn,
	}
	if details.User != nil {
		principal.LastUsedAt = details.User.PasswordLastUsed
		principal.Path = normalizedIAMPath(aws.ToString(details.User.Path))
		if boundary := details.User.PermissionsBoundary; boundary != nil {
			principal.PermissionsBoundaryARN = boundary.PermissionsBoundaryArn
			if boundary.PermissionsBoundaryType != "" {
				boundaryType := string(boundary.PermissionsBoundaryType)
				principal.PermissionsBoundaryType = &boundaryType
			}
		}
		if tags := iamTagsToMap(details.User.Tags); len(tags) > 0 {
			principal.Tags = tags
		}
	}

	policies, err := service.collectPrincipalPolicies(ctx, client, *user.UserName, false, managedPolicies)
	if err != nil {
		return collectedIAMPrincipal{}, fmt.Errorf("collect policies for user %s: %w", *user.UserName, err)
	}
	return collectedIAMPrincipal{Principal: principal, Policies: policies}, nil
}

func (service *AWSCollectorService) collectPrincipalPolicies(
	ctx context.Context,
	client awsIAMAPI,
	name string,
	isRole bool,
	managedPolicies map[string]model.IAMPolicy,
) ([]model.IAMPolicy, error) {
	attached := make(map[string]struct{})
	var policies []model.IAMPolicy
	var marker *string
	for {
		var outputAttached []iamtypes.AttachedPolicy
		var truncated bool
		var nextMarker *string
		var err error
		if isRole {
			output, callErr := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(name), Marker: marker})
			err = callErr
			if output != nil {
				outputAttached, truncated, nextMarker = output.AttachedPolicies, output.IsTruncated, output.Marker
			}
		} else {
			output, callErr := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(name), Marker: marker})
			err = callErr
			if output != nil {
				outputAttached, truncated, nextMarker = output.AttachedPolicies, output.IsTruncated, output.Marker
			}
		}
		if err != nil {
			return nil, fmt.Errorf("list attached managed policies: %w", err)
		}
		for _, attachedPolicy := range outputAttached {
			if attachedPolicy.PolicyArn == nil {
				continue
			}
			arn := *attachedPolicy.PolicyArn
			if _, exists := attached[arn]; exists {
				continue
			}
			policy, exists := managedPolicies[arn]
			if !exists {
				var err error
				policy, err = service.fetchManagedPolicy(ctx, client, arn, aws.ToString(attachedPolicy.PolicyName))
				if err != nil {
					return nil, err
				}
				managedPolicies[arn] = policy
			}
			attached[arn] = struct{}{}
			policies = append(policies, policy)
		}
		if !truncated {
			break
		}
		if nextMarker == nil || *nextMarker == "" {
			return nil, errors.New("IAM attached-policy response is truncated without a marker")
		}
		marker = nextMarker
	}

	marker = nil
	for {
		var names []string
		var truncated bool
		var nextMarker *string
		var err error
		if isRole {
			output, callErr := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(name), Marker: marker})
			err = callErr
			if output != nil {
				names, truncated, nextMarker = output.PolicyNames, output.IsTruncated, output.Marker
			}
		} else {
			output, callErr := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(name), Marker: marker})
			err = callErr
			if output != nil {
				names, truncated, nextMarker = output.PolicyNames, output.IsTruncated, output.Marker
			}
		}
		if err != nil {
			return nil, fmt.Errorf("list inline policies: %w", err)
		}
		for _, policyName := range names {
			var document *string
			if isRole {
				output, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
					RoleName: aws.String(name), PolicyName: aws.String(policyName),
				})
				if err == nil {
					document = output.PolicyDocument
				}
			} else {
				output, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName: aws.String(name), PolicyName: aws.String(policyName),
				})
				if err == nil {
					document = output.PolicyDocument
				}
			}
			if err != nil {
				return nil, fmt.Errorf("get inline policy %s: %w", policyName, err)
			}
			if document == nil {
				return nil, fmt.Errorf("AWS returned no document for inline policy %s", policyName)
			}
			decoded, err := decodeIAMPolicyDocument(*document)
			if err != nil {
				return nil, fmt.Errorf("decode inline policy %s: %w", policyName, err)
			}
			nameCopy, typeCopy := policyName, "inline"
			policies = append(policies, model.IAMPolicy{
				PolicyName:     &nameCopy,
				PolicyType:     &typeCopy,
				PolicyDocument: model.JSONB(decoded),
			})
		}
		if !truncated {
			break
		}
		if nextMarker == nil || *nextMarker == "" {
			return nil, errors.New("IAM inline-policy response is truncated without a marker")
		}
		marker = nextMarker
	}
	return policies, nil
}

func (service *AWSCollectorService) fetchManagedPolicy(
	ctx context.Context,
	client awsIAMAPI,
	arn string,
	name string,
) (model.IAMPolicy, error) {
	policyOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return model.IAMPolicy{}, fmt.Errorf("get attached managed policy %s: %w", arn, err)
	}
	if policyOutput.Policy == nil || policyOutput.Policy.DefaultVersionId == nil {
		return model.IAMPolicy{}, fmt.Errorf("AWS returned no default version for managed policy %s", arn)
	}
	versionOutput, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: policyOutput.Policy.DefaultVersionId,
	})
	if err != nil {
		return model.IAMPolicy{}, fmt.Errorf("get default version for attached policy %s: %w", arn, err)
	}
	if versionOutput.PolicyVersion == nil || versionOutput.PolicyVersion.Document == nil {
		return model.IAMPolicy{}, fmt.Errorf("AWS returned no document for managed policy %s", arn)
	}
	document, err := decodeIAMPolicyDocument(*versionOutput.PolicyVersion.Document)
	if err != nil {
		return model.IAMPolicy{}, fmt.Errorf("decode managed policy %s: %w", arn, err)
	}
	policyName := name
	if policyOutput.Policy.PolicyName != nil {
		policyName = *policyOutput.Policy.PolicyName
	}
	policyType := "managed"
	tags, err := fetchPolicyTags(ctx, client, arn)
	if err != nil {
		return model.IAMPolicy{}, err
	}
	return model.IAMPolicy{
		PolicyARN:      &arn,
		PolicyName:     &policyName,
		PolicyType:     &policyType,
		Description:    policyOutput.Policy.Description,
		Tags:           tags,
		PolicyDocument: model.JSONB(document),
	}, nil
}

// fetchPolicyTags paginates ListPolicyTags for a managed policy. The
// permission has been verified in the target account; a denial here means the
// sync role lost iam:ListPolicyTags, which would silently produce tag-less
// baseline declarations and wipe real tags on apply — surface it loudly.
func fetchPolicyTags(ctx context.Context, client awsIAMAPI, arn string) (map[string]string, error) {
	tags := make(map[string]string)
	var marker *string
	for {
		output, err := client.ListPolicyTags(ctx, &iam.ListPolicyTagsInput{
			PolicyArn: aws.String(arn),
			Marker:    marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list tags for managed policy %s: %w", arn, err)
		}
		for _, tag := range output.Tags {
			if tag.Key == nil || tag.Value == nil {
				continue
			}
			tags[*tag.Key] = *tag.Value
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, fmt.Errorf("IAM ListPolicyTags response for %s is truncated without a marker", arn)
		}
		marker = output.Marker
	}
	return tags, nil
}

func (service *AWSCollectorService) collectManagedPolicies(
	ctx context.Context,
	client awsIAMAPI,
) (map[string]model.IAMPolicy, error) {
	policies := make(map[string]model.IAMPolicy)
	var marker *string
	for {
		output, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
			Scope:  iamtypes.PolicyScopeTypeLocal,
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list local managed policies: %w", err)
		}
		for _, listedPolicy := range output.Policies {
			if listedPolicy.Arn == nil || listedPolicy.DefaultVersionId == nil {
				continue
			}
			policyOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: listedPolicy.Arn})
			if err != nil {
				return nil, fmt.Errorf("get managed policy %s: %w", *listedPolicy.Arn, err)
			}
			if policyOutput.Policy == nil || policyOutput.Policy.DefaultVersionId == nil {
				continue
			}
			versionOutput, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: listedPolicy.Arn,
				VersionId: policyOutput.Policy.DefaultVersionId,
			})
			if err != nil {
				return nil, fmt.Errorf("get default version for policy %s: %w", *listedPolicy.Arn, err)
			}
			if versionOutput.PolicyVersion == nil || versionOutput.PolicyVersion.Document == nil {
				return nil, fmt.Errorf("AWS returned no document for managed policy %s", *listedPolicy.Arn)
			}
			document, err := decodeIAMPolicyDocument(*versionOutput.PolicyVersion.Document)
			if err != nil {
				return nil, fmt.Errorf("decode managed policy %s: %w", *listedPolicy.Arn, err)
			}
			arn := *listedPolicy.Arn
			name := aws.ToString(listedPolicy.PolicyName)
			policyType := "managed"
			tags, err := fetchPolicyTags(ctx, client, arn)
			if err != nil {
				return nil, err
			}
			// Description 只在 GetPolicy 响应里出现：ListPolicies 恒为空
			// （实测 CLI 证实），漏了这一步会把实态 description 采成空串，
			// 基线声明漏写 ForceNew 属性，apply 时销毁重建策略。
			policies[arn] = model.IAMPolicy{
				PolicyARN:      &arn,
				PolicyName:     &name,
				PolicyType:     &policyType,
				Description:    policyOutput.Policy.Description,
				Tags:           tags,
				PolicyDocument: model.JSONB(document),
			}
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || *output.Marker == "" {
			return nil, errors.New("IAM ListPolicies response is truncated without a marker")
		}
		marker = output.Marker
	}
	return policies, nil
}

func decodeIAMPolicyDocument(document string) ([]byte, error) {
	decoded := document
	if !json.Valid([]byte(decoded)) {
		unescaped, err := url.QueryUnescape(decoded)
		if err != nil {
			return nil, fmt.Errorf("URL-decode IAM policy document: %w", err)
		}
		decoded = unescaped
	}
	if !json.Valid([]byte(decoded)) {
		return nil, errors.New("IAM policy document is not valid JSON")
	}
	var compact json.RawMessage
	if err := json.Unmarshal([]byte(decoded), &compact); err != nil {
		return nil, fmt.Errorf("decode IAM policy JSON: %w", err)
	}
	return compact, nil
}

func jsonOrNull(value model.JSONB) interface{} {
	if len(value) == 0 {
		return nil
	}
	return string(value)
}

// mapOrNull encodes a string map for a JSONB column; NULL when empty so the
// collector clears stale attributes on re-sync.
func mapOrNull(value map[string]string) interface{} {
	if len(value) == 0 {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return string(raw)
}

// stringSliceOrNull encodes a string slice for a JSONB column; NULL when
// empty so clearing a provider's client IDs is reflected on re-sync.
func stringSliceOrNull(value []string) interface{} {
	if len(value) == 0 {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return string(raw)
}

// normalizedIAMPath keeps the schema's NOT NULL path invariant: AWS always
// returns a path, but a zero value must still land as "/" rather than "".
func normalizedIAMPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "/"
	}
	return path
}

// iamTagsToMap converts the SDK tag list to the inventory's string map.
func iamTagsToMap(tags []iamtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			result[*tag.Key] = *tag.Value
		}
	}
	return result
}

func int64OrNull(value *int64) interface{} {
	if value == nil {
		return nil
	}
	return *value
}

var _ awsOrganizationsAPI = (*organizations.Client)(nil)
var _ awsSTSAPI = (*sts.Client)(nil)
var _ awsIAMAPI = (*iam.Client)(nil)
var _ AWSAssetRepository = (*SQLAWSAssetRepository)(nil)
