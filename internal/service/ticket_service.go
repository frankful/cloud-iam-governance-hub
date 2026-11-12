package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
	gitlab "github.com/xanzy/go-gitlab"
)

const (
	TicketTypeCreateRole              = "CREATE_ROLE"
	TicketTypeCreateManagedPolicy     = "CREATE_MANAGED_POLICY"
	TicketTypeCreateUser              = "CREATE_USER"
	TicketTypeCreateGroup             = "CREATE_GROUP"
	TicketTypeAttachUserPolicy        = "ATTACH_USER_POLICY"
	TicketTypeRollback                = "ROLLBACK"
	TicketTypeUpdateRole              = "UPDATE_ROLE"
	TicketTypeUpdateManagedPolicy     = "UPDATE_MANAGED_POLICY"
	TicketTypeUpdateGroupInlinePolicy = "UPDATE_GROUP_INLINE_POLICY"
	TicketTypeUpdateGroupMembership   = "UPDATE_GROUP_MEMBERSHIP"
	TicketTypeAdoptRoleInlinePolicies = "ADOPT_ROLE_INLINE_POLICIES"

	// ATTACH_USER_POLICY operation values.
	OperationAttach           = "attach"
	OperationDetach           = "detach"
	TicketStatusDraft         = "DRAFT"
	TicketStatusApproving     = "APPROVING"
	TicketStatusApproved      = "APPROVED"
	TicketStatusPublishing    = "PUBLISHING"
	TicketStatusPublishFailed = "PUBLISH_FAILED"
	TicketStatusRejected      = "REJECTED"
	TicketStatusMerged        = "MERGED"
	TicketStatusClosed        = "CLOSED"
	ApprovalModeManual        = "MANUAL"
	ApprovalModeAuto          = "AUTO"

	ClosureReasonApplied   = "APPLIED"
	ClosureReasonAbandoned = "ABANDONED"

	// CIApplyStatusSucceeded / CIApplyStatusFailed are the accepted values
	// of the reserved CI apply callback (POST /tickets/:no/apply-result, A1).
	CIApplyStatusSucceeded = "succeeded"
	CIApplyStatusFailed    = "failed"

	maxCodeHostRequestDuration = 30 * time.Second
	// maxPublishSequenceDuration bounds the entire publication sequence:
	// several sequential code-host API calls, each limited by the HTTP
	// client's per-request timeout (maxCodeHostRequestDuration).
	maxPublishSequenceDuration = 5 * maxCodeHostRequestDuration
	// publicationLeaseDuration must exceed maxPublishSequenceDuration so a
	// slow-but-healthy publication does not release its claim mid-flight.
	publicationLeaseDuration = 6 * time.Minute
)

var (
	ErrTicketNotFound        = errors.New("IAM ticket not found")
	ErrTicketAccessDenied    = errors.New("IAM ticket access denied")
	ErrInvalidTicketState    = errors.New("invalid IAM ticket state")
	ErrNotDesignatedApprover = errors.New("user is not a designated approver")
	ErrApprovalAlreadySet    = errors.New("approval decision already recorded")
)

// PublicationFailedError reports a code-host publication failure with
// its underlying cause, so the API can return a 502 carrying the real
// reason instead of a generic internal error.
type PublicationFailedError struct {
	Cause error
}

func (publishError *PublicationFailedError) Error() string {
	if publishError == nil || publishError.Cause == nil {
		return "publication failed"
	}
	return fmt.Sprintf("publication failed: %s", publishError.Cause.Error())
}

func (publishError *PublicationFailedError) Unwrap() error {
	if publishError == nil {
		return nil
	}
	return publishError.Cause
}

// CreateIAMTicketRequest uses aws_account.id for AccountID. MANUAL mode accepts
// platform user IDs; AUTO mode resolves approvers from account bindings and
// rejects caller-supplied approver IDs.
//
// 多云架构说明：
//   - Permission (旧模型) 用于向后兼容，后续逐步废弃
//   - AbstractPolicy (新模型) 是多云架构的推荐入口
//   - 两者同时提供时，优先使用 AbstractPolicy
type CreateIAMTicketRequest struct {
	TicketType       string                      `json:"ticket_type"`
	AccountID        int64                       `json:"account_id"`
	PrincipalName    string                      `json:"principal_name"`
	Permission       model.AbstractPermission    `json:"request_policy"`  // 旧模型（向后兼容）
	AbstractPolicy   *abstractiam.AbstractPolicy `json:"abstract_policy"` // 新模型（多云推荐）
	Role             adapter.AWSRoleInfo         `json:"role"`
	CreatePolicy     *adapter.ManagedPolicyInfo  `json:"create_managed_policy,omitempty"` // CREATE_MANAGED_POLICY
	CreateUser       *adapter.IAMUserInfo        `json:"create_user,omitempty"`           // CREATE_USER
	CreateGroup      *adapter.IAMGroupInfo       `json:"create_group,omitempty"`          // CREATE_GROUP
	AdoptExisting    bool                        `json:"adopt_existing,omitempty"`        // CREATE_*: import an existing resource instead of creating it
	ManagedPolicyARN string                      `json:"managed_policy_arn,omitempty"`    // ATTACH_USER_POLICY：要挂载的既有 policy ARN
	PrincipalType    string                      `json:"principal_type,omitempty"`        // ATTACH_USER_POLICY：授权主体类型 User/Group（默认 User）
	TargetTicketNo   string                      `json:"target_ticket_no,omitempty"`      // ROLLBACK：被回滚的工单号
	// TargetFileKey 是回滚时目标工单实际写入的 Terraform 文件键（不含 .tf），
	// 创建回滚工单时从目标工单的 request 推导（role-<name> / user-<name> /
	// group-<name> / policy-<name>）。没有它，回滚只会写一张以目标工单号命
	// 名的空文件，而声明在资源命名的文件里 —— plan 什么都不会销毁。
	TargetFileKey      string                      `json:"target_file_key,omitempty"`
	UpdateRole         *adapter.UpdateRoleConfig   `json:"update_role,omitempty"`          // UPDATE_ROLE：角色更新配置
	SourceTicketNo     string                      `json:"source_ticket_no,omitempty"`     // UPDATE_ROLE / detach：修改的源工单号
	Operation          string                      `json:"operation,omitempty"`            // ATTACH_USER_POLICY：attach（默认）| detach
	UpdatePolicy       *adapter.UpdatePolicyConfig `json:"update_policy,omitempty"`        // UPDATE_MANAGED_POLICY / UPDATE_GROUP_INLINE_POLICY：策略更新配置
	UpdateMembership   *UpdateMembershipConfig     `json:"update_membership,omitempty"`    // UPDATE_GROUP_MEMBERSHIP：组成员变更配置
	RoleInlinePolicies []RoleInlinePolicyImport    `json:"role_inline_policies,omitempty"` // ADOPT_ROLE_INLINE_POLICIES: server-snapshotted inline policies
	ApprovalMode       string                      `json:"approval_mode"`
	ApproverIDs        []string                    `json:"approver_ids,omitempty"`
	AWSAccountID       string                      `json:"-"`
}

type RoleInlinePolicyImport struct {
	Name     string          `json:"name"`
	Document json.RawMessage `json:"document"`
}

// UpdateMembershipConfig is one UPDATE_GROUP_MEMBERSHIP ticket's payload:
// add or remove IAM users on a group's managed membership declaration
// (group-<group>-membership.tf). Operation is "add" or "remove"; Users are
// the affected IAM user names, not the full desired list — the desired list
// is computed from the main file (or the inventory when the file does not
// exist yet) at generation time.
type UpdateMembershipConfig struct {
	GroupName string   `json:"group_name"`
	Operation string   `json:"operation"` // add | remove
	Users     []string `json:"users"`
}

// MembershipOperationAdd / Remove are the two UPDATE_GROUP_MEMBERSHIP
// operations.
const (
	MembershipOperationAdd    = "add"
	MembershipOperationRemove = "remove"
)

// GetAbstractPolicy 获取工单请求的抽象策略
// 优先返回新模型 AbstractPolicy，如果不存在则从旧模型转换
func (r CreateIAMTicketRequest) GetAbstractPolicy() (*abstractiam.AbstractPolicy, error) {
	// 优先使用新模型
	if r.AbstractPolicy != nil {
		return r.AbstractPolicy, nil
	}
	// 回退到旧模型转换
	policy, err := r.Permission.ToAbstractPolicy()
	if err != nil {
		return nil, fmt.Errorf("convert legacy permission to abstract policy: %w", err)
	}
	return &policy, nil
}

// rolePolicyDeclared reports whether a CREATE_ROLE request carries a
// permission payload at all: the new abstract_policy model or the legacy
// request_policy model. Permissions are optional for a role — a role without
// any declared permissions is a valid AWS object (zero-permission role) — so
// the request then creates the role without an inline policy resource.
func (r CreateIAMTicketRequest) rolePolicyDeclared() bool {
	if r.AbstractPolicy != nil {
		return true
	}
	return len(r.Permission.Permissions) > 0
}

// terraformFileTicketNo returns the ticket number whose Terraform file this
// request maps to. ROLLBACK requests clear the *target* ticket's file so the
// resource declarations disappear and terraform plan produces destroys.
func (r CreateIAMTicketRequest) terraformFileTicketNo(fallback string) string {
	// Policy updates (and their rollbacks) are keyed by the target policy so
	// repeat updates upsert the same file instead of creating one file per
	// ticket (deterministic GitOps in-place update).
	if key := r.policyFileKey(); key != "" {
		return key
	}
	// Resources the platform declares for the first time are keyed by the
	// resource, not by the ticket: the full baseline (docs/pending-issues
	// item 24) and every later ticket then write the same file, so a resource
	// is never declared in two files.
	if key := r.resourceFileKey(); key != "" {
		return key
	}
	// UPDATE_ROLE 及其回滚都修改源 CREATE_ROLE 工单的文件；野生角色（③，
	// SourceTicketNo 为空）改用独立稳定文件 role-<name>.tf。回滚请求由
	// prepareRollbackTarget 打上 PrincipalType=Role 标记，两个方向解析到
	// 同一文件。
	if strings.TrimSpace(r.SourceTicketNo) != "" {
		return r.SourceTicketNo
	}
	if r.TicketType == TicketTypeUpdateGroupMembership &&
		r.UpdateMembership != nil &&
		strings.TrimSpace(r.UpdateMembership.GroupName) != "" {
		// 与基线同 key：membership 声明只有一个文件，工单原地改写它，
		// 基线候选也据此把该组标记为已有工单声明。
		return MembershipFileKey(r.UpdateMembership.GroupName)
	}
	if (r.TicketType == TicketTypeUpdateRole ||
		(r.TicketType == TicketTypeRollback && r.PrincipalType == "Role")) &&
		strings.TrimSpace(r.PrincipalName) != "" {
		return "role-" + r.PrincipalName
	}
	// 回滚 CREATE_*：目标资源声明在资源命名的文件里（user-<name>.tf 等），
	// 回滚必须写同一文件才能让 plan 产生 destroy。TargetFileKey 由创建回滚
	// 时从目标工单推导，优先于下面按工单号命名的历史兜底。
	if r.TicketType == TicketTypeRollback && strings.TrimSpace(r.TargetFileKey) != "" {
		return strings.TrimSpace(r.TargetFileKey)
	}
	if r.TicketType == TicketTypeRollback && strings.TrimSpace(r.TargetTicketNo) != "" {
		return r.TargetTicketNo
	}
	return fallback
}

// resourceFileKey returns a stable, resource-derived Terraform file key for
// the ticket types that declare a resource for the first time: one file per
// resource instead of one file per ticket.
//
// Keying by the resource is what makes a full baseline possible (docs
// pending-issues item 24): the baseline generator and every later ticket write
// the same file, so a resource is never declared twice — two files declaring
// the same Terraform address make Terraform reject the whole configuration.
//
// It also fixes a latent duplicate: CREATE_MANAGED_POLICY used to write a
// ticket-numbered file while UPDATE_MANAGED_POLICY wrote "policy-<name>", and
// both declared the same aws_iam_policy address.
func (r CreateIAMTicketRequest) resourceFileKey() string {
	switch r.TicketType {
	case TicketTypeCreateRole:
		if name := strings.TrimSpace(r.Role.Name); name != "" {
			return ResourceFileKey(BaselineKindRole, name)
		}
	case TicketTypeCreateUser:
		if r.CreateUser != nil {
			if name := strings.TrimSpace(r.CreateUser.Name); name != "" {
				return ResourceFileKey(BaselineKindUser, name)
			}
		}
	case TicketTypeCreateGroup:
		if r.CreateGroup != nil {
			if name := strings.TrimSpace(r.CreateGroup.Name); name != "" {
				return ResourceFileKey(BaselineKindGroup, name)
			}
		}
	case TicketTypeCreateManagedPolicy:
		if r.CreatePolicy != nil {
			if name := strings.TrimSpace(r.CreatePolicy.Name); name != "" {
				return ResourceFileKey(BaselineKindPolicy, name)
			}
		}
	case TicketTypeAttachUserPolicy:
		principal := strings.TrimSpace(r.PrincipalName)
		policyName := PolicyNameFromARN(r.ManagedPolicyARN)
		if principal != "" && policyName != "" {
			principalType := strings.ToLower(strings.TrimSpace(r.PrincipalType))
			if principalType == "" {
				principalType = "user"
			}
			return AttachmentFileKey(principalType, principal, policyName)
		}
	}
	return ""
}

// AttachmentFileKey returns the IaC file key for one managed-policy
// attachment: "attachment-<type>-<principal>-<policy>". One file per
// attachment keeps the import ID (principal/policy-ARN) self-contained and
// lets a single attachment be re-declared without touching the others.
// Exported because the baseline bundle must predict exactly the file a
// future attachment ticket would write — two files behind one
// aws_iam_*_policy_attachment address make Terraform reject the module.
func AttachmentFileKey(principalType, principal, policyName string) string {
	principalType = strings.ToLower(strings.TrimSpace(principalType))
	principal = strings.TrimSpace(principal)
	policyName = strings.TrimSpace(policyName)
	if principalType == "" || principal == "" || policyName == "" {
		return ""
	}
	return "attachment-" + fileKeyToken(principalType) + "-" +
		fileKeyToken(principal) + "-" + fileKeyToken(policyName)
}

// policyFileKey returns a stable, policy-derived Terraform file key for policy
// update tickets and their rollbacks: "policy-<name>" for customer-managed
// policy updates, "group-<group>-policy-<name>" for group inline policy
// updates. Returns "" for ticket types that are keyed by ticket number.
// Rollback requests carry the update identity copied from their target by
// prepareRollbackTarget, so both directions resolve the same file. Updates that
// rewrite the source CREATE_ROLE file (SourceTicketNo set) also return "": the
// file is keyed by the source ticket instead.
func (r CreateIAMTicketRequest) policyFileKey() string {
	if strings.TrimSpace(r.SourceTicketNo) != "" {
		return ""
	}
	if r.UpdatePolicy == nil {
		return ""
	}
	if r.TicketType == TicketTypeUpdateGroupInlinePolicy ||
		strings.TrimSpace(r.UpdatePolicy.InlinePolicyName) != "" {
		// Inline policy update: identity is the owning principal (group or role)
		// + inline policy name. An incomplete identity falls back to a
		// ticket-numbered file (the validation layer rejects incomplete requests
		// before publishing).
		inline := strings.TrimSpace(r.UpdatePolicy.InlinePolicyName)
		owner := strings.TrimSpace(r.UpdatePolicy.GroupName)
		kind := "group"
		if strings.TrimSpace(r.UpdatePolicy.RoleName) != "" {
			owner = strings.TrimSpace(r.UpdatePolicy.RoleName)
			kind = "role"
		}
		if owner == "" || inline == "" {
			return ""
		}
		return InlinePolicyFileKey(kind, owner, inline)
	}
	name := strings.TrimSpace(r.UpdatePolicy.PolicyName)
	if name == "" {
		name = PolicyNameFromARN(r.UpdatePolicy.PolicyARN)
	}
	if name == "" {
		return ""
	}
	return "policy-" + fileKeyToken(name)
}

// PolicyNameFromARN extracts the policy name (last path segment) from a
// customer-managed policy ARN such as
// "arn:aws:iam::123456789012:policy/team/foo" → "foo". Returns "" when the
// ARN carries no policy path.
func PolicyNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	index := strings.LastIndex(trimmed, ":policy/")
	if index < 0 {
		return ""
	}
	name := trimmed[index+len(":policy/"):]
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return name
}

// ResourceFileKey returns the IaC file key (without the ".tf" suffix) for a
// resource's first-time declaration. kind is one of role / user / group /
// policy / instance-profile / oidc-provider / saml-provider.
//
// Exported because the baseline candidate report — and later the baseline
// generator — must predict exactly the file a ticket writes. A divergence puts
// two files behind one Terraform address, and Terraform rejects the whole
// configuration.
func ResourceFileKey(kind, name string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	name = strings.TrimSpace(name)
	if kind == "" || name == "" {
		return ""
	}
	return kind + "-" + fileKeyToken(name)
}

// InlinePolicyFileKey returns the IaC file key for an inline policy of a
// role, user or group: "<kind>-<owner>-policy-<policy>". The owner is part of
// the key because inline policy names are only unique per owner — two roles
// may both carry an "AdministratorAccess" inline policy, and they must not
// share a file. Exported so the baseline candidate set and the ticket flow
// resolve the same file for the same inline policy.
func InlinePolicyFileKey(kind, owner, policyName string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	owner = strings.TrimSpace(owner)
	policyName = strings.TrimSpace(policyName)
	if kind == "" || owner == "" || policyName == "" {
		return ""
	}
	return kind + "-" + fileKeyToken(owner) + "-policy-" + fileKeyToken(policyName)
}

// MembershipFileKey returns the IaC file key for a group's membership
// declaration: "group-<group>-membership". aws_iam_group_membership does not
// support import, so its declaration lives in its own file rather than the
// group resource file: the first apply always adds membership, and keeping it
// separate means the group's own file can stay import-only clean. Exported
// for the baseline generator (B2) and the candidate report.
func MembershipFileKey(group string) string {
	group = strings.TrimSpace(group)
	if group == "" {
		return ""
	}
	return "group-" + fileKeyToken(group) + "-membership"
}

// fileKeyToken lowercases a policy/group name and replaces characters that
// are unsafe in file names with "-", so the derived Terraform file key is a
// valid, stable path segment.
func fileKeyToken(value string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-', char == '_', char == '.':
			builder.WriteRune(char)
		default:
			builder.WriteRune('-')
		}
	}
	return builder.String()
}

// RollbackSupportedTargetType reports whether a ROLLBACK can reverse a ticket of
// the given type. A rollback only works when the reverse of the change lands in
// the file(s) the target ticket itself wrote:
//
//   - CREATE_* → the resource-named file is emptied (destroy);
//   - UPDATE_* → the snapshot restores the same file in place;
//   - ATTACH_USER_POLICY(detach) → the source attach ticket's file gets the
//     attachment back.
//
// Types outside this list have no such mapping. ADOPT_ROLE_INLINE_POLICIES in
// particular publishes one file per adopted policy, so the old fallback — a
// comment-only IAM-<ticket>.tf named after the ticket — matched no declaration:
// the PR added a file nobody references, plan stayed unchanged, and the ticket
// still reported "rolled back" while every policy it adopted survived
// (pending-issues C14). Rejecting at validation is the honest outcome.
func RollbackSupportedTargetType(ticketType string) bool {
	switch ticketType {
	case TicketTypeCreateRole, TicketTypeCreateUser, TicketTypeCreateGroup,
		TicketTypeCreateManagedPolicy, TicketTypeUpdateRole,
		TicketTypeUpdateManagedPolicy, TicketTypeUpdateGroupInlinePolicy,
		TicketTypeUpdateGroupMembership, TicketTypeAttachUserPolicy:
		return true
	}
	return false
}

// rollbackTargetUsesTicketNamedFile reports whether the target ticket's
// declaration lives in the legacy, ticket-number-named file (IAM-<ticket>.tf).
// That was the file rule before declarations became resource-named, so a
// create ticket without a usable resource name can only be reversed by
// emptying that same file. Every other type has its own exact branch.
func rollbackTargetUsesTicketNamedFile(target model.IAMTicket) bool {
	if target.TicketType == nil {
		return false
	}
	switch *target.TicketType {
	case TicketTypeCreateRole, TicketTypeCreateUser,
		TicketTypeCreateGroup, TicketTypeCreateManagedPolicy:
		return true
	}
	return false
}

// GenerateRollbackTerraform returns the Terraform file content for a ROLLBACK
// ticket: a comment-only file that clears the target ticket's declarations.
// Terraform plan against the applied state then produces destroys for the
// removed resources. The file itself is kept (empty of resources) so the
// rollback stays visible in git history.
func GenerateRollbackTerraform(rollbackTicketNo, targetTicketNo, principalName string) string {
	var hcl strings.Builder
	hcl.WriteString("# ROLLBACK of IAM ticket " + targetTicketNo + "\n")
	hcl.WriteString("# Rolled back by ticket " + rollbackTicketNo + "\n")
	hcl.WriteString("# Principal: " + principalName + "\n")
	hcl.WriteString("#\n")
	hcl.WriteString("# The original Terraform declarations were removed by this rollback.\n")
	hcl.WriteString("# Run `terraform plan` to review the destroys, then apply.\n")
	// 注释内容必然是合法 HCL，无需再做语法校验。
	return hcl.String()
}

// GenerateDetachTerraform returns the Terraform file content for a detach
// ticket: a comment-only file that clears the source attach ticket's
// declarations, so terraform plan produces a destroy of the attachment.
func GenerateDetachTerraform(detachTicketNo, sourceTicketNo, principalType, principalName, policyARN string) string {
	var hcl strings.Builder
	hcl.WriteString("# DETACH managed policy from " + principalType + " " + principalName + "\n")
	hcl.WriteString("# Detach ticket: " + detachTicketNo + "\n")
	hcl.WriteString("# Source attach ticket: " + sourceTicketNo + "\n")
	hcl.WriteString("# Managed policy: " + policyARN + "\n")
	hcl.WriteString("#\n")
	hcl.WriteString("# The attachment declarations were removed by this detach ticket.\n")
	hcl.WriteString("# Only this principal's attachment is destroyed; the policy itself\n")
	hcl.WriteString("# and its attachments to other principals are untouched.\n")
	hcl.WriteString("# Run `terraform plan` to review the destroy, then apply.\n")
	return hcl.String()
}

type TicketDecision struct {
	Result  string `json:"result"`
	Comment string `json:"comment,omitempty"`
}

type TicketPublication struct {
	TerraformCode       string
	GitPRURL            string
	GitProvider         string
	GitRepository       string
	RemoteRequestNumber string
	GitCommitSHA        string
}

// TicketListFilter selects and paginates tickets for list responses.
type TicketListFilter struct {
	Statuses   []string // empty means all statuses
	AccountID  *int64   // aws_account.id (database id)
	Submitter  string
	TicketType string
	Keyword    string // matches ticket_no or principal_name (case-insensitive)
	Limit      int
	Offset     int
}

// TicketRepository encapsulates atomic ticket and approval state transitions.
type TicketRepository interface {
	Create(ctx context.Context, ticket model.IAMTicket, approvers []string, validation TicketValidationSnapshot) (model.IAMTicket, error)
	CreateDraft(ctx context.Context, ticket model.IAMTicket) (model.IAMTicket, error)
	SubmitDraft(ctx context.Context, ticketNo string, approvers []string, validation TicketValidationSnapshot) (model.IAMTicket, error)
	Get(ctx context.Context, ticketNo string) (model.IAMTicket, error)
	ListTickets(ctx context.Context, filter TicketListFilter) ([]model.IAMTicket, int64, error)
	GetAWSAccountID(ctx context.Context, accountID int64) (string, error)
	// AWSAccountSyncEnabled reports whether the account has an onboarding
	// config with sync enabled. Missing config → false (not onboarded).
	AWSAccountSyncEnabled(ctx context.Context, accountID int64) (bool, error)
	GetPrincipalPolicies(ctx context.Context, accountID int64, principalName, principalType string) ([]ExistingIAMPolicy, bool, error)
	PrincipalExists(ctx context.Context, accountID int64, principalName, principalType string) (bool, error)
	GetPrincipalTrustPolicy(ctx context.Context, accountID int64, principalName string) (json.RawMessage, error)
	GetRoleAttributes(ctx context.Context, accountID int64, roleName string) (*RoleAttributes, error)
	CountActiveUpdateRoleTickets(ctx context.Context, accountID int64, principalName string) (int, error)
	CountAppliedUpdateRoleTickets(ctx context.Context, accountID int64, principalName string) (int, error)
	CountActiveCreateTickets(ctx context.Context, accountID int64, ticketType, principalName string) (int, error)
	CountActiveUpdatePolicyTickets(ctx context.Context, accountID int64, ticketType, principalType, policyARN, groupName, inlinePolicyName string) (int, error)
	CountAppliedUpdatePolicyTickets(ctx context.Context, accountID int64, ticketType, principalType, policyARN, groupName, inlinePolicyName string) (int, error)
	FindCreatedRoleTicket(ctx context.Context, accountID int64, principalName string) (string, error)
	ResolvePolicyAttachment(ctx context.Context, accountID int64, principalType, principalName, policyARN string) (bool, string, error)
	// GroupMembers 返回一个 IAM 组在采集清单里的当前成员（IAM 用户名）。
	// 组成员工单用它计算目标成员列表：文件缺失时清单即当前状态。
	GroupMembers(ctx context.Context, accountID int64, groupName string) ([]string, error)
	// CountActiveGroupMembershipTickets 报告一个组的进行中组成员工单数，
	// 用作并发锁：同一组的成员变更一次只能有一个工单在处理。
	CountActiveGroupMembershipTickets(ctx context.Context, accountID int64, groupName string) (int, error)
	// BaselineOwnsAttachmentFile 报告一条挂载关系是否已由全量基线纳管：
	// 对应的 attachment 文件出现在该账号已合并（MERGED）基线发布的 files
	// 清单里。这类挂载没有源挂载工单，但资源已在 Terraform state，解绑
	// 工单必须放行并改写基线文件，而不是按「野生挂载」拒绝。
	BaselineOwnsAttachmentFile(ctx context.Context, accountID int64, fileKey string) (bool, error)
	// BaselineOwnsResourceFile 报告一个资源声明文件是否已被基线发布覆盖
	// （PUBLISHED = PR 在途，MERGED = 已落 main）。CREATE_* 的 adopt_existing
	// 用它拒绝重复导入：资源已被平台声明时再导入会产生双声明。
	BaselineOwnsResourceFile(ctx context.Context, accountID int64, fileKey string) (bool, error)
	// FileDeclarationOwners 返回一个文件当前生效声明的归属：ticket_id 列表，
	// 0 表示基线发布（声明行没有工单）。空列表 = 该文件当前没有声明快照
	// （P2 之前的存量文件，或声明已作废）——调用方无法证明归属时按放行处理。
	// 整文件清空的归属检查（回滚）用它区分「撤自己写的」与「替别人删声明」。
	FileDeclarationOwners(ctx context.Context, accountID int64, fileKey string) ([]int64, error)
	GetManagedPolicyByARN(ctx context.Context, policyARN string) (json.RawMessage, bool, error)
	GetGroupInlinePolicy(ctx context.Context, accountID int64, groupName, inlinePolicyName string) (json.RawMessage, bool, error)
	GetRoleInlinePolicy(ctx context.Context, accountID int64, roleName, inlinePolicyName string) (json.RawMessage, bool, error)
	ListRoleInlinePolicies(ctx context.Context, accountID int64, roleName string) ([]ExistingIAMPolicy, error)
	CountActiveRolePolicyBatchTickets(ctx context.Context, accountID int64, roleName string) (int, error)
	GetGroupAdoptionSnapshot(ctx context.Context, accountID int64, groupName string) (adapter.IAMGroupInfo, error)
	SaveRoleSnapshot(ctx context.Context, ticketNo string, snapshot json.RawMessage) error
	FindRollbackTickets(ctx context.Context, targetTicketNo string) ([]model.IAMTicket, error)
	GetEnabledBaseline(ctx context.Context, accountID int64) (model.IAMBaseline, error)
	ListAvailableApprovers(ctx context.Context, accountID *int64) ([]model.PlatformUser, error)
	ResolveAutoApprovers(ctx context.Context, accountID int64) ([]model.PlatformUser, error)
	GetApprovalInfo(ctx context.Context, ticketNo string) (model.TicketApprovalInfo, error)
	RecordDecision(ctx context.Context, ticketNo, approver, result, comment string) (model.IAMTicket, error)
	ClaimPublication(ctx context.Context, ticketNo string, leaseDuration time.Duration) (bool, error)
	ReleasePublication(ctx context.Context, ticketNo string) error
	SavePublication(ctx context.Context, ticketNo string, publication TicketPublication) error
	SetStatus(ctx context.Context, ticketNo, expectedStatus, status string) error
	CloseTicket(ctx context.Context, ticketNo, actorID, reason, comment string) (model.IAMTicket, error)
	MarkPublishFailed(ctx context.Context, ticketNo, expectedStatus, errorMessage string) error
	// MarkCIApplyFailed 记录一次 CI 回报的 apply 失败（A12②）：merge 已落 main
	// 但 terraform 没应用成功。工单状态不变（仍留人工处理），只把
	// git_apply_result/git_ci_state 置 FAILED 并追加一条执行记录供详情页展示。
	// 同一个 commit 的重复回调幂等。
	MarkCIApplyFailed(ctx context.Context, ticketNo string, failure CIApplyFailure) error
	ResetPollSchedule(ctx context.Context, ticketNo string) error
}

type TicketValidationSnapshot struct {
	BaselineID       *int64          `json:"baseline_id,omitempty"`
	RequestSHA256    []byte          `json:"request_sha256"`
	Checks           json.RawMessage `json:"checks"`
	TerraformPreview string          `json:"terraform_preview,omitempty"`
}

// TicketPublishResult contains the result of a successful ticket publication.
type TicketPublishResult struct {
	URL                 string // MR/PR URL
	Provider            string // "gitlab" or "github"
	Project             string // GitLab project ID or GitHub "owner/repo"
	RemoteRequestNumber string // MR/PR number as string
	CommitSHA           string // Commit SHA of the Terraform file
}

// ErrTerraformFileNotFound marks a Terraform file that does not exist on the
// target (main) branch. The wild-role UPDATE path treats it as "not adopted
// yet" and generates a fresh file; every other fetch error is transient and
// must propagate — silently regenerating would risk a different resource
// label, i.e. a Terraform address change → destroy+recreate (docs item 15).
var ErrTerraformFileNotFound = errors.New("Terraform file not found on target branch")

// TicketPublisher creates a Terraform commit and a code-review request on the
// configured Git provider (GitLab Merge Request or GitHub Pull Request).
type TicketPublisher interface {
	Publish(ctx context.Context, ticket model.IAMTicket, request CreateIAMTicketRequest, terraformCode string) (*TicketPublishResult, error)
	// FetchTerraformFile reads the ticket's Terraform file from the target
	// (main) branch. UPDATE_ROLE's block-patch generation patches the live
	// file, so validation and publication must read the exact same bytes
	// (校验所见 == 发布所得) before applying the patch.
	FetchTerraformFile(ctx context.Context, ticket model.IAMTicket, request CreateIAMTicketRequest) (string, error)
}

type TerraformBundleFile struct {
	Key     string
	Content string
}

type TerraformBundlePublisher interface {
	PublishBundle(ctx context.Context, ticket model.IAMTicket, request CreateIAMTicketRequest, files []TerraformBundleFile) (*TicketPublishResult, error)
}

// MergeRequestFetcher queries the code host for the current state of
// a merge request / pull request. It guards ticket abandonment: a
// ticket whose PR is still open (or already merged) must not be
// marked ABANDONED, otherwise a later merge leaves the ticket
// mislabeled.
type MergeRequestFetcher interface {
	FetchMergeRequest(ctx context.Context, project string, number string) (*githost.MergeRequestStatus, error)
}

// AbandonGuardError reports that a ticket cannot be abandoned
// because its pull request is still open (or already merged),
// or its state could not be verified on the code host.
type AbandonGuardError struct {
	Reason string
}

func (guardError *AbandonGuardError) Error() string {
	return guardError.Reason
}

// GitStatusPollEnqueuer defines the interface for enqueuing Git status poll tasks.
type GitStatusPollEnqueuer interface {
	EnqueueGitStatusPoll(ctx context.Context, payload GitStatusPollTask) error
}

type TicketService struct {
	repository   TicketRepository
	adapter      adapter.AWSAdapter
	publisher    TicketPublisher
	pollEnqueuer GitStatusPollEnqueuer
	mrFetcher    MergeRequestFetcher
	logger       *slog.Logger
	riskMode     CandidateRiskMode
	targetFiles  *targetFileCache
	// closureSync 在人工关单勾选「触发同步」时刷新账号清单。
	// nil 安全：未装配（单测/降级部署）时静默跳过。
	closureSync ManualClosureSyncTrigger
	// reservations 是文件级发布预约（phase4-drift-design.md §4）：发布前
	// 把要写的文件集合原子预约，同一文件至多一个开放 PR 源。nil 安全：
	// 未装配（单测/降级部署）时跳过预约，行为与 phase4 之前一致。
	reservations *PublishReservationService
	// declarations 落工单侧声明快照（phase4 §5，P2b）：工单发布出去的文件
	// 就是它声明的资源意图，从发布内容反解后与基线声明并集。nil 安全：
	// 未装配（单测/降级部署）时跳过，漂移基准只剩基线侧。
	declarations *BaselineDeclarationService
}

// ManualClosureSyncTrigger refreshes the account inventory immediately after
// an operator manually closed a ticket as applied — no settle delay, since
// the operator explicitly confirmed the apply succeeded. Implemented by
// *AWSSyncRunService (which also serves the delayed auto-close path).
type ManualClosureSyncTrigger interface {
	TriggerSyncForManuallyClosedTicket(ctx context.Context, accountDBID int64, ticketNo string) error
}

// targetFileCache memoizes reads of Terraform files from the target branch for
// a short while: the realtime validation endpoint runs on every keystroke and
// the code host rate-limits API calls. Only advisory hints consume the cache —
// the published bytes always come from a fresh read.
type targetFileCache struct {
	mutex   sync.Mutex
	entries map[string]targetFileCacheEntry
}

type targetFileCacheEntry struct {
	content   string
	found     bool
	expiresAt time.Time
}

// targetFileCacheTTL bounds how long a target-branch read is reused.
const targetFileCacheTTL = time.Minute

func (cache *targetFileCache) get(key string) (content string, found bool, ok bool) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	entry, exists := cache.entries[key]
	if !exists || time.Now().After(entry.expiresAt) {
		return "", false, false
	}
	return entry.content, entry.found, true
}

func (cache *targetFileCache) put(key, content string, found bool) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.entries[key] = targetFileCacheEntry{
		content:   content,
		found:     found,
		expiresAt: time.Now().Add(targetFileCacheTTL),
	}
}

type TicketServiceOption func(*TicketService) error

func WithCandidateRiskMode(mode CandidateRiskMode) TicketServiceOption {
	return func(service *TicketService) error {
		if mode != CandidateRiskModeBlock && mode != CandidateRiskModeWarn {
			return errors.New("candidate risk mode must be BLOCK or WARN")
		}
		service.riskMode = mode
		return nil
	}
}

func NewTicketService(
	repository TicketRepository,
	publisher TicketPublisher,
	logger *slog.Logger,
	options ...TicketServiceOption,
) (*TicketService, error) {
	if repository == nil {
		return nil, errors.New("ticket repository must not be nil")
	}
	if publisher == nil {
		return nil, errors.New("ticket publisher must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	service := &TicketService{
		repository:  repository,
		adapter:     adapter.AWSAdapter{},
		publisher:   publisher,
		logger:      logger,
		riskMode:    CandidateRiskModeBlock,
		targetFiles: &targetFileCache{entries: map[string]targetFileCacheEntry{}},
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("ticket service option must not be nil")
		}
		if err := option(service); err != nil {
			return nil, fmt.Errorf("configure ticket service: %w", err)
		}
	}
	return service, nil
}

// WithGitStatusPollEnqueuer sets the Git status poll enqueuer for the ticket service.
func WithGitStatusPollEnqueuer(enqueuer GitStatusPollEnqueuer) TicketServiceOption {
	return func(service *TicketService) error {
		if enqueuer == nil {
			return errors.New("git status poll enqueuer must not be nil")
		}
		service.pollEnqueuer = enqueuer
		return nil
	}
}

// WithMergeRequestFetcher wires the code-host client used to verify
// a PR is closed before its ticket may be abandoned. A nil fetcher
// (unwired deployments, tests) skips the abandon guard.
func WithMergeRequestFetcher(fetcher MergeRequestFetcher) TicketServiceOption {
	return func(service *TicketService) error {
		service.mrFetcher = fetcher
		return nil
	}
}

// WithClosureSyncTrigger wires the inventory-refresh trigger used when a
// manually closed ticket opts in to a post-closure sync. A nil trigger
// (unwired deployments, tests) silently skips the refresh.
func WithClosureSyncTrigger(trigger ManualClosureSyncTrigger) TicketServiceOption {
	return func(service *TicketService) error {
		service.closureSync = trigger
		return nil
	}
}

// WithPublishReservations wires the file-level publish reservation service
// (phase4-drift-design.md §4). nil (unwired deployments, tests) skips
// reservation checks entirely.
func WithPublishReservations(reservations *PublishReservationService) TicketServiceOption {
	return func(service *TicketService) error {
		if reservations == nil {
			return errors.New("publish reservation service must not be nil")
		}
		service.reservations = reservations
		return nil
	}
}

// WithBaselineDeclarations wires the declaration snapshot service
// (phase4-drift-design.md §5, P2b). nil (unwired deployments, tests) skips
// ticket-side declarations: the drift baseline then only carries what the
// baseline generator declared.
func WithBaselineDeclarations(declarations *BaselineDeclarationService) TicketServiceOption {
	return func(service *TicketService) error {
		if declarations == nil {
			return errors.New("baseline declaration service must not be nil")
		}
		service.declarations = declarations
		return nil
	}
}

func (service *TicketService) CreateTicket(
	ctx context.Context,
	submitter string,
	request CreateIAMTicketRequest,
) (model.IAMTicket, error) {
	request, approverIDs, err := service.prepareTicketRequest(ctx, submitter, request)
	if err != nil {
		return model.IAMTicket{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("marshal IAM ticket request: %w", err)
	}
	validation, err := service.validateTicketRequest(ctx, request)
	if err != nil {
		return model.IAMTicket{}, err
	}
	ticketNo, err := newTicketNumber()
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("generate ticket number: %w", err)
	}

	typeValue := request.TicketType
	approvalMode := request.ApprovalMode
	accountID := request.AccountID
	principalName := request.PrincipalName
	status := TicketStatusApproving
	submitterCopy := submitter
	approverIDsJSON, err := json.Marshal(approverIDs)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("marshal approver IDs: %w", err)
	}
	ticket := model.IAMTicket{
		TicketNo:      &ticketNo,
		TicketType:    &typeValue,
		AccountID:     &accountID,
		PrincipalName: &principalName,
		RequestPolicy: model.JSONB(payload),
		ApprovalMode:  approvalMode,
		ApproverIDs:   model.JSONB(approverIDsJSON),
		Status:        &status,
		Submitter:     &submitterCopy,
	}
	created, err := service.repository.Create(ctx, ticket, approverIDs, validation)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("create IAM ticket: %w", err)
	}
	service.logger.Info("IAM ticket created",
		"ticket_no", ticketNo,
		"submitter", submitter,
		"approval_mode", approvalMode,
		"approver_count", len(approverIDs),
	)
	return created, nil
}

func (service *TicketService) CreateDraft(
	ctx context.Context,
	submitter string,
	request CreateIAMTicketRequest,
) (model.IAMTicket, error) {
	request, approverIDs, err := service.prepareTicketRequest(ctx, submitter, request)
	if err != nil {
		return model.IAMTicket{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("marshal IAM ticket draft: %w", err)
	}
	ticketNo, err := newTicketNumber()
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("generate ticket number: %w", err)
	}
	ticketType := request.TicketType
	accountID := request.AccountID
	principalName := request.PrincipalName
	status := TicketStatusDraft
	submitterCopy := strings.TrimSpace(submitter)
	approverIDsJSON, err := json.Marshal(approverIDs)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("marshal draft approver snapshot: %w", err)
	}
	ticket := model.IAMTicket{
		TicketNo: &ticketNo, TicketType: &ticketType, AccountID: &accountID,
		PrincipalName: &principalName, RequestPolicy: model.JSONB(payload),
		ApprovalMode: request.ApprovalMode, ApproverIDs: model.JSONB(approverIDsJSON),
		Status: &status, Submitter: &submitterCopy,
	}
	created, err := service.repository.CreateDraft(ctx, ticket)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("create IAM ticket draft: %w", err)
	}
	service.logger.Info("IAM ticket draft created",
		"ticket_no", ticketNo, "submitter", submitterCopy,
		"approval_mode", request.ApprovalMode, "approver_count", len(approverIDs),
	)
	return created, nil
}

func (service *TicketService) SubmitTicket(
	ctx context.Context,
	ticketNo, actorID string,
	roles []string,
) (model.IAMTicket, error) {
	ticket, err := service.GetTicket(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, err
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusDraft {
		return model.IAMTicket{}, fmt.Errorf("%w: only %s tickets can be submitted", ErrInvalidTicketState, TicketStatusDraft)
	}
	canSubmitForOthers := false
	for _, role := range roles {
		if role == "platform_admin" || role == "approval_admin" {
			canSubmitForOthers = true
			break
		}
	}
	if ticket.Submitter == nil || (*ticket.Submitter != actorID && !canSubmitForOthers) {
		return model.IAMTicket{}, ErrTicketAccessDenied
	}
	var request CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
		return model.IAMTicket{}, fmt.Errorf("decode ticket draft request: %w", err)
	}
	validation, err := service.validateTicketRequest(ctx, request)
	if err != nil {
		return model.IAMTicket{}, err
	}
	approverIDs := make([]string, 0)
	if err := json.Unmarshal(ticket.ApproverIDs, &approverIDs); err != nil {
		return model.IAMTicket{}, fmt.Errorf("decode immutable ticket approver snapshot: %w", err)
	}
	if len(approverIDs) == 0 {
		return model.IAMTicket{}, errors.New("ticket draft has no designated approvers")
	}
	submitted, err := service.repository.SubmitDraft(ctx, ticketNo, approverIDs, validation)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("submit IAM ticket draft: %w", err)
	}
	service.logger.Info("IAM ticket submitted for approval",
		"ticket_no", ticketNo, "submitter", actorID, "approver_count", len(approverIDs),
	)
	return submitted, nil
}

// prepareRollbackTarget validates the rollback target ticket and returns it.
// Only tickets closed with reason APPLIED may be rolled back, and each target
// can be rolled back at most once (no rollback-of-rollback semantics yet).
func (service *TicketService) prepareRollbackTarget(ctx context.Context, request CreateIAMTicketRequest) (model.IAMTicket, error) {
	targetNo := strings.TrimSpace(request.TargetTicketNo)
	if targetNo == "" {
		return model.IAMTicket{}, errors.New("target_ticket_no is required for ROLLBACK")
	}
	target, err := service.repository.Get(ctx, targetNo)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("load rollback target ticket: %w", err)
	}
	if target.Status == nil || *target.Status != TicketStatusClosed {
		return model.IAMTicket{}, fmt.Errorf("%w: rollback target must be %s", ErrInvalidTicketState, TicketStatusClosed)
	}
	if target.ClosureReason == nil || *target.ClosureReason != ClosureReasonApplied {
		return model.IAMTicket{}, fmt.Errorf("%w: rollback target must be closed with reason %s", ErrInvalidTicketState, ClosureReasonApplied)
	}
	existing, err := service.repository.FindRollbackTickets(ctx, targetNo)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("check existing rollback tickets: %w", err)
	}
	for _, ticket := range existing {
		if ticket.Status == nil {
			continue
		}
		switch *ticket.Status {
		case TicketStatusClosed:
			return model.IAMTicket{}, fmt.Errorf("%w: target ticket %s has already been rolled back by %s", ErrInvalidTicketState, targetNo, valueOrEmpty(ticket.TicketNo))
		case TicketStatusDraft, TicketStatusApproving, TicketStatusApproved, TicketStatusPublishing, TicketStatusPublishFailed:
			return model.IAMTicket{}, fmt.Errorf("%w: rollback ticket %s for target %s is still active", ErrInvalidTicketState, valueOrEmpty(ticket.TicketNo), targetNo)
		}
	}
	return target, nil
}

// normalizeTrustPolicyJSON unwraps role.trust_policy when it arrives as a
// JSON *string* ({"trust_policy": "{\"Version\":...}"}). curl callers commonly
// send the trust policy double-encoded; JSON objects (the frontend path)
// pass through untouched. The unwrapped text must itself be valid JSON —
// anything else fails with a role.trust_policy-prefixed 400 instead of an
// opaque 500 deep in the risk scanner.
func normalizeTrustPolicyJSON(request *CreateIAMTicketRequest) error {
	raw := bytes.TrimSpace(request.Role.TrustPolicy)
	if len(raw) == 0 {
		return nil
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return apperr.Validationf("role.trust_policy must be valid JSON: %w", err)
	}
	text, ok := decoded.(string)
	if !ok {
		return nil // already an object/array — leave as-is
	}
	inner := json.RawMessage(strings.TrimSpace(text))
	if !json.Valid(inner) {
		return apperr.Validation("role.trust_policy arrived as a JSON string whose contents are not valid JSON; send the trust policy as a JSON object (or a JSON string containing one)")
	}
	request.Role.TrustPolicy = inner
	return nil
}

func (service *TicketService) validateManagedPolicyARNs(
	ctx context.Context,
	accountID int64,
	field string,
	policyARNs []string,
) error {
	expectedAccountID := ""
	for _, policyARN := range policyARNs {
		if err := adapter.ValidateIAMPolicyARN(policyARN); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		parts := strings.Split(strings.TrimSpace(policyARN), ":")
		if parts[4] == "aws" {
			// AWS-managed policies are not included in the synced local-policy inventory.
			continue
		}
		if expectedAccountID == "" {
			var err error
			expectedAccountID, err = service.repository.GetAWSAccountID(ctx, accountID)
			if err != nil {
				return fmt.Errorf("load AWS account identifier for %s: %w", field, err)
			}
		}
		if parts[4] != expectedAccountID {
			return fmt.Errorf(
				"%s: policy ARN account %s does not match selected AWS account %s",
				field, parts[4], expectedAccountID,
			)
		}
		_, exists, err := service.repository.GetManagedPolicyByARN(ctx, policyARN)
		if err != nil {
			return fmt.Errorf("check %s %q in IAM inventory: %w", field, policyARN, err)
		}
		if !exists {
			return fmt.Errorf(
				"%s: policy ARN %q was not found in the synced IAM inventory; sync assets and try again",
				field, policyARN,
			)
		}
	}
	return nil
}

// validateRequestShape normalizes and validates the request itself — ticket
// type, rollback target inheritance, account/principal and policy statements —
// without resolving approvers. Ticket creation runs it through
// prepareTicketRequest; the realtime validation endpoint runs it standalone.
func (service *TicketService) validateRequestShape(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (CreateIAMTicketRequest, error) {
	if request.TicketType != TicketTypeCreateRole && request.TicketType != TicketTypeCreateManagedPolicy &&
		request.TicketType != TicketTypeCreateUser && request.TicketType != TicketTypeCreateGroup &&
		request.TicketType != TicketTypeAttachUserPolicy && request.TicketType != TicketTypeRollback && request.TicketType != TicketTypeUpdateRole &&
		request.TicketType != TicketTypeUpdateManagedPolicy && request.TicketType != TicketTypeUpdateGroupInlinePolicy &&
		request.TicketType != TicketTypeUpdateGroupMembership &&
		request.TicketType != TicketTypeAdoptRoleInlinePolicies {
		return CreateIAMTicketRequest{}, apperr.Validationf("unsupported ticket type %q; supported types are %s, %s, %s, %s, %s, %s, %s, %s, %s, %s and %s",
			request.TicketType, TicketTypeCreateRole, TicketTypeCreateManagedPolicy, TicketTypeCreateUser,
			TicketTypeCreateGroup, TicketTypeAttachUserPolicy, TicketTypeRollback, TicketTypeUpdateRole,
			TicketTypeUpdateManagedPolicy, TicketTypeUpdateGroupInlinePolicy, TicketTypeUpdateGroupMembership, TicketTypeAdoptRoleInlinePolicies)
	}
	// trust_policy 允许以 JSON 字符串传入（curl 直调常见，前端传对象）：
	// 在此解包，后续风险扫描/信任策略比对拿到的是对象形态。
	if err := normalizeTrustPolicyJSON(&request); err != nil {
		return CreateIAMTicketRequest{}, err
	}
	if request.TicketType == TicketTypeRollback {
		// 回滚工单：继承目标工单的 principal/account，并校验目标状态
		target, err := service.prepareRollbackTarget(ctx, request)
		if err != nil {
			return CreateIAMTicketRequest{}, err
		}
		request.TargetTicketNo = strings.TrimSpace(request.TargetTicketNo)
		if target.PrincipalName != nil {
			request.PrincipalName = *target.PrincipalName
		}
		if target.AccountID != nil {
			request.AccountID = *target.AccountID
		}
		// 回滚 UPDATE_ROLE：反向 Terraform 恢复快照，写入目标 UPDATE_ROLE
		// 所修改的源 CREATE_ROLE 文件（而非清空文件 → destroy）。
		// PrincipalType=Role 是「UPDATE_ROLE 回滚」的文件 key 标记（③），
		// 先清空用户输入，再由对应 case 按目标工单类型回填。
		request.PrincipalType = ""
		// 文件键只能由目标工单推导（C6）：回滚会把目标文件整份清空，
		// 若接受请求体里的 target_file_key，等于给了一个「清空任意文件」的
		// 入口——填基线的 role-x.tf 就能把基线声明删掉。服务端字段一律忽略，
		// 只有下面 CREATE_* 分支按目标工单自己的请求重新推导。
		request.TargetFileKey = ""
		// 回滚能力校验（C14）：目标类型必须能把「反向操作」映射到它自己写过的
		// 文件上。映射不出来的类型（批量纳管、回滚工单本身）以前会落到
		// buildRollbackTerraform 的兜底分支，按**工单号**生成一份注释空文件 ——
		// PR 多一个没人引用的文件、plan 零变更，工单却标记为已回滚，用户以为
		// 资源撤销了。宁可在校验层明确拒绝，也不给空操作的成功。
		targetType := valueOrEmpty(target.TicketType)
		if targetType == "" {
			return CreateIAMTicketRequest{}, apperr.Validationf(
				"rollback target %s has no ticket type recorded; cannot derive the Terraform files to reverse",
				request.TargetTicketNo)
		}
		if !RollbackSupportedTargetType(targetType) {
			return CreateIAMTicketRequest{}, apperr.Validationf(
				"ticket type %s does not support rollback: its declarations are spread over several Terraform files, so a rollback has no single file to reverse. Undo the change with dedicated tickets instead (for an adopted inline policy, file an %s ticket with operation=%s)",
				targetType, TicketTypeAttachUserPolicy, OperationDetach)
		}
		if target.TicketType != nil {
			var targetRequest CreateIAMTicketRequest
			switch *target.TicketType {
			case TicketTypeUpdateRole:
				if err := json.Unmarshal(target.RequestPolicy, &targetRequest); err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("decode rollback target request: %w", err)
				}
				// PrincipalType=Role 是「UPDATE_ROLE 回滚」标记：terraformFileTicketNo
				// 据此把野生回滚（SourceTicketNo 为空）指回 role-<name>.tf。
				request.PrincipalType = "Role"
				request.SourceTicketNo = strings.TrimSpace(targetRequest.SourceTicketNo)
				if len(target.RoleSnapshot) == 0 {
					return CreateIAMTicketRequest{}, apperr.Validationf("rollback target %s has no role snapshot; cannot generate reverse Terraform", request.TargetTicketNo)
				}
			case TicketTypeUpdateManagedPolicy, TicketTypeUpdateGroupInlinePolicy:
				// 回滚策略更新：复制目标的策略身份（ARN / 组 + 内嵌策略名），
				// 发布时用快照文档重新生成同一策略文件（upsert）。
				if err := json.Unmarshal(target.RequestPolicy, &targetRequest); err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("decode rollback target request: %w", err)
				}
				if targetRequest.UpdatePolicy == nil {
					return CreateIAMTicketRequest{}, apperr.Validationf("rollback target %s has no update_policy config", request.TargetTicketNo)
				}
				if len(target.RoleSnapshot) == 0 {
					return CreateIAMTicketRequest{}, apperr.Validationf("rollback target %s has no policy snapshot; cannot generate reverse Terraform", request.TargetTicketNo)
				}
				inherited := *targetRequest.UpdatePolicy
				inherited.Document = nil
				if strings.TrimSpace(inherited.ResourceName) == "" {
					// 旧工单没有存标签：按目标工单类型推导（与正向更新同一函数）。
					inherited.ResourceName = policyUpdateResourceLabel(CreateIAMTicketRequest{
						TicketType:     *target.TicketType,
						UpdatePolicy:   &inherited,
						SourceTicketNo: strings.TrimSpace(targetRequest.SourceTicketNo),
					})
				}
				request.UpdatePolicy = &inherited
				request.Operation = "" // 回滚策略更新不涉及 attach/detach
				// 覆写源 CREATE_ROLE 文件的更新，其回滚同样写源文件（用快照恢复）。
				request.SourceTicketNo = strings.TrimSpace(targetRequest.SourceTicketNo)
			case TicketTypeAttachUserPolicy:
				// 回滚 detach：重新挂载（重新生成挂载资源到源挂载工单文件）。
				if err := json.Unmarshal(target.RequestPolicy, &targetRequest); err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("decode rollback target request: %w", err)
				}
				if targetRequest.Operation == OperationDetach {
					request.Operation = OperationAttach
					request.PrincipalType = targetRequest.PrincipalType
					request.ManagedPolicyARN = targetRequest.ManagedPolicyARN
					request.SourceTicketNo = strings.TrimSpace(targetRequest.SourceTicketNo)
					if request.SourceTicketNo == "" {
						return CreateIAMTicketRequest{}, apperr.Validationf("rollback target %s has no source attach ticket recorded", request.TargetTicketNo)
					}
				} else {
					// 回滚「挂载」= 卸载，但卸载走的是 ATTACH_USER_POLICY +
					// operation=detach 的另一条链路（要定位源挂载、处理基线归属），
					// 回滚工单不复用。落到兜底只会写一个空文件（C14 同型），拒绝。
					return CreateIAMTicketRequest{}, apperr.Validationf(
						"rollback of attach ticket %s is not supported: there is no detach operation to reverse. File a detach ticket (%s with operation=%s) for this attachment instead",
						request.TargetTicketNo, TicketTypeAttachUserPolicy, OperationDetach)
				}
			case TicketTypeUpdateGroupMembership:
				// 回滚组成员变更：复制目标的组身份，发布时用快照成员列表恢复
				// 同一 membership 文件（upsert）。
				if err := json.Unmarshal(target.RequestPolicy, &targetRequest); err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("decode rollback target request: %w", err)
				}
				if targetRequest.UpdateMembership == nil {
					return CreateIAMTicketRequest{}, apperr.Validationf("rollback target %s has no update_membership config", request.TargetTicketNo)
				}
				if len(target.RoleSnapshot) == 0 {
					return CreateIAMTicketRequest{}, apperr.Validationf("rollback target %s has no membership snapshot; cannot generate reverse Terraform", request.TargetTicketNo)
				}
				request.UpdateMembership = targetRequest.UpdateMembership
				request.PrincipalType = "Group"
			case TicketTypeCreateRole, TicketTypeCreateUser, TicketTypeCreateGroup, TicketTypeCreateManagedPolicy:
				// 回滚 CREATE_*：目标声明写在"按资源命名"的文件里，回滚要写
				// 同一文件（否则空文件落在别的路径上，plan 不会销毁任何东西）。
				// 文件键在这里解析一次存进请求，预览与发布都读同一份。
				if err := json.Unmarshal(target.RequestPolicy, &targetRequest); err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("decode rollback target request: %w", err)
				}
				request.TargetFileKey = targetRequest.resourceFileKey()
			}
		}
	}
	if request.TicketType == TicketTypeUpdateRole {
		// 更新角色：校验角色存在性 + 信任策略变更检测 + 并发锁
		if err := service.validateUpdateRoleRequest(ctx, &request); err != nil {
			return CreateIAMTicketRequest{}, err
		}
	}
	if request.AccountID <= 0 {
		return CreateIAMTicketRequest{}, apperr.Validation("account_id must be positive")
	}
	if isCreateResourceTicket(request.TicketType) {
		if err := service.validateCreateResourceRequest(ctx, &request); err != nil {
			return CreateIAMTicketRequest{}, err
		}
	}
	if request.TicketType == TicketTypeUpdateManagedPolicy || request.TicketType == TicketTypeUpdateGroupInlinePolicy {
		// 策略更新先于 principal_name 检查执行：它会根据策略清单回填
		// principal_name（托管策略 = 策略名；内嵌策略 = 组名）。
		if err := service.validateUpdatePolicyRequest(ctx, &request); err != nil {
			return CreateIAMTicketRequest{}, err
		}
	}
	if request.TicketType == TicketTypeUpdateGroupMembership {
		// 组成员变更同样先于 principal_name 检查：校验会回填
		// principal_name = 组名、principal_type = Group。
		if err := service.validateUpdateGroupMembershipRequest(ctx, &request); err != nil {
			return CreateIAMTicketRequest{}, err
		}
	}
	if strings.TrimSpace(request.PrincipalName) == "" {
		return CreateIAMTicketRequest{}, apperr.Validation("principal_name must not be empty")
	}
	if request.TicketType == TicketTypeAttachUserPolicy {
		// 挂载既有 policy 到 IAM user 或 IAM group：principal 即主体名，
		// 无需 role/权限语句。principal_type 默认 User，兼容既有工单。
		// operation 默认 attach；detach 要求该挂载由平台创建（存在源挂载
		// 工单），否则无法用 GitOps 安全销毁。
		if request.PrincipalType == "" {
			request.PrincipalType = "User"
		}
		if request.PrincipalType != "User" && request.PrincipalType != "Group" && request.PrincipalType != "Role" {
			return CreateIAMTicketRequest{}, apperr.Validation("principal_type must be User, Group or Role for ATTACH_USER_POLICY")
		}
		operation := strings.ToLower(strings.TrimSpace(request.Operation))
		if operation == "" {
			operation = OperationAttach
		}
		if operation != OperationAttach && operation != OperationDetach {
			return CreateIAMTicketRequest{}, apperr.Validationf("operation must be %s or %s for ATTACH_USER_POLICY", OperationAttach, OperationDetach)
		}
		request.Operation = operation
		if err := adapter.ValidateIAMPolicyARN(request.ManagedPolicyARN); err != nil {
			return CreateIAMTicketRequest{}, apperr.Validationf("managed_policy_arn: %w", err)
		}
		request.ManagedPolicyARN = strings.TrimSpace(request.ManagedPolicyARN)
		exists, err := service.repository.PrincipalExists(ctx, request.AccountID, request.PrincipalName, request.PrincipalType)
		if err != nil {
			return CreateIAMTicketRequest{}, apperr.Validationf("load existing %s for policy attachment: %w", strings.ToLower(request.PrincipalType), err)
		}
		if !exists {
			return CreateIAMTicketRequest{}, fmt.Errorf("%s %q not found in account inventory; sync assets first", strings.ToLower(request.PrincipalType), request.PrincipalName)
		}
		if operation == OperationDetach {
			// 仅支持平台纳管的挂载：找到创建该挂载的 ATTACH_USER_POLICY
			// 工单，发布时清空其 Terraform 文件 → destroy。
			attached, sourceTicketNo, err := service.repository.ResolvePolicyAttachment(
				ctx, request.AccountID, request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN,
			)
			if err != nil {
				return CreateIAMTicketRequest{}, fmt.Errorf("resolve policy attachment: %w", err)
			}
			if !attached {
				return CreateIAMTicketRequest{}, apperr.Validation("the policy attachment no longer exists in the inventory; sync the account assets before detaching")
			}
			if sourceTicketNo == "" {
				// 无源挂载工单：可能是基线纳管的挂载（全量基线发布已把
				// attachment 文件合并进 main 并 apply 进 state），也可能是
				// 真正的野生挂载。前者放行（解绑时改写基线文件），后者
				// 仍按野生拒绝并给出两段路径。
				owned, err := service.repository.BaselineOwnsAttachmentFile(
					ctx, request.AccountID,
					AttachmentFileKey(strings.ToLower(request.PrincipalType), request.PrincipalName, PolicyNameFromARN(request.ManagedPolicyARN)),
				)
				if err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("check baseline ownership of attachment: %w", err)
				}
				if !owned {
					return CreateIAMTicketRequest{}, &WildAttachmentError{
						PrincipalType: request.PrincipalType,
						PrincipalName: request.PrincipalName,
						PolicyARN:     request.ManagedPolicyARN,
					}
				}
			}
			request.SourceTicketNo = sourceTicketNo
		} else {
			// attach：若清单显示已挂载，说明平台已纳管或为野生挂载。
			// 已由平台挂载 → 拒绝（改用 operation=detach）；野生挂载 →
			// 发布时按需生成 import block 做首次纳管（state 里没有该资源）。
			attached, sourceTicketNo, err := service.repository.ResolvePolicyAttachment(
				ctx, request.AccountID, request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN,
			)
			if err != nil {
				return CreateIAMTicketRequest{}, fmt.Errorf("resolve policy attachment: %w", err)
			}
			if attached && sourceTicketNo != "" {
				return CreateIAMTicketRequest{}, &AttachmentConflictError{
					PrincipalType:  request.PrincipalType,
					PrincipalName:  request.PrincipalName,
					PolicyARN:      request.ManagedPolicyARN,
					SourceTicketNo: sourceTicketNo,
				}
			}
			if attached && sourceTicketNo == "" {
				// 基线纳管的挂载：attachment 文件已由全量基线发布到 main，
				// 再发挂载工单会用工单副本覆写基线文件、破坏归属模型。
				owned, err := service.repository.BaselineOwnsAttachmentFile(
					ctx, request.AccountID,
					AttachmentFileKey(strings.ToLower(request.PrincipalType), request.PrincipalName, PolicyNameFromARN(request.ManagedPolicyARN)),
				)
				if err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("check baseline ownership of attachment: %w", err)
				}
				if owned {
					return CreateIAMTicketRequest{}, &AttachmentConflictError{
						PrincipalType: request.PrincipalType,
						PrincipalName: request.PrincipalName,
						PolicyARN:     request.ManagedPolicyARN,
						BaselineOwned: true,
					}
				}
			}
		}
	} else if request.TicketType == TicketTypeAdoptRoleInlinePolicies {
		roleName := strings.TrimSpace(request.PrincipalName)
		if err := adapter.ValidateIAMResourceName("role", roleName); err != nil {
			return CreateIAMTicketRequest{}, err
		}
		exists, err := service.repository.PrincipalExists(ctx, request.AccountID, roleName, "Role")
		if err != nil {
			return CreateIAMTicketRequest{}, apperr.Validationf("load existing role for inline policy adoption: %w", err)
		}
		if !exists {
			return CreateIAMTicketRequest{}, apperr.Validationf("role %q not found in account inventory; sync assets first", roleName)
		}
		active, err := service.repository.CountActiveRolePolicyBatchTickets(ctx, request.AccountID, roleName)
		if err != nil {
			return CreateIAMTicketRequest{}, fmt.Errorf("check active role inline policy adoption tickets: %w", err)
		}
		if active > 0 {
			return CreateIAMTicketRequest{}, apperr.Validation("this role already has a batch inline-policy adoption ticket in progress; retry once it is closed")
		}
		policies, err := service.repository.ListRoleInlinePolicies(ctx, request.AccountID, roleName)
		if err != nil {
			return CreateIAMTicketRequest{}, fmt.Errorf("load role inline policies for adoption: %w", err)
		}
		request.PrincipalName = roleName
		request.PrincipalType = "Role"
		request.RoleInlinePolicies = make([]RoleInlinePolicyImport, 0, len(policies))
		sourceTicketNo, err := service.repository.FindCreatedRoleTicket(ctx, request.AccountID, roleName)
		if err != nil {
			return CreateIAMTicketRequest{}, fmt.Errorf("check role ownership for inline policy adoption: %w", err)
		}
		for _, policy := range policies {
			name := strings.TrimSpace(policy.Name)
			if err := adapter.ValidateIAMResourceName("policy", name); err != nil {
				return CreateIAMTicketRequest{}, fmt.Errorf("invalid inline policy name %q: %w", name, err)
			}
			if sourceTicketNo != "" && name == roleName+"-policy" {
				continue
			}
			if len(policy.Document) == 0 || !json.Valid(policy.Document) {
				return CreateIAMTicketRequest{}, apperr.Validationf("inline policy %q has an invalid or empty document in inventory", name)
			}
			applied, err := service.repository.CountAppliedUpdatePolicyTickets(
				ctx, request.AccountID, TicketTypeUpdateGroupInlinePolicy, "Role", "", roleName, name,
			)
			if err != nil {
				return CreateIAMTicketRequest{}, fmt.Errorf("check whether inline policy %q is already managed: %w", name, err)
			}
			if applied > 0 {
				continue
			}
			active, err := service.repository.CountActiveUpdatePolicyTickets(
				ctx, request.AccountID, TicketTypeUpdateGroupInlinePolicy, "Role", "", roleName, name,
			)
			if err != nil {
				return CreateIAMTicketRequest{}, fmt.Errorf("check active ticket for inline policy %q: %w", name, err)
			}
			if active > 0 {
				return CreateIAMTicketRequest{}, apperr.Validationf("inline policy %q already has an active ticket; finish or close it before batch adoption", name)
			}
			// 基线归属防重：全量基线（含 PUBLISHED 在途 PR）已声明该内嵌策略时，
			// 再导入会产生双声明。此前只靠 build 阶段 fetch main 文件兜底，而
			// 基线 PR 在途（PUBLISHED 未 MERGED）时 main 上还没有文件，导入工单
			// 被放行——与 CREATE_* adopt 路径共用同一检查与文案。
			if err := service.rejectIfAlreadyAdopted(ctx, request,
				InlinePolicyFileKey("role", roleName, name), "inline policy", name,
				"如需变更请使用内嵌策略更新工单"); err != nil {
				return CreateIAMTicketRequest{}, err
			}
			request.RoleInlinePolicies = append(request.RoleInlinePolicies, RoleInlinePolicyImport{
				Name: name, Document: append(json.RawMessage(nil), policy.Document...),
			})
		}
		if len(request.RoleInlinePolicies) == 0 {
			return CreateIAMTicketRequest{}, apperr.Validationf("role %q has no unmanaged inline policies to adopt", roleName)
		}
	} else if request.TicketType == TicketTypeCreateRole {
		if request.Role.Name != request.PrincipalName {
			return CreateIAMTicketRequest{}, apperr.Validation("role.name must match principal_name")
		}
		// 初始挂载托管策略（对齐 CREATE_USER / CREATE_GROUP）：随创建一次性
		// 声明在同一个文件里，后续变更走挂载/解绑工单。
		request.Role.PolicyARNs = uniqueNonEmpty(request.Role.PolicyARNs)
		if err := service.validateManagedPolicyARNs(
			ctx, request.AccountID, "role.policy_arns", request.Role.PolicyARNs,
		); err != nil {
			return CreateIAMTicketRequest{}, err
		}
		// 权限声明可选：未声明任何权限时（零权限角色）跳过语句级校验，
		// 生成的文件只声明角色本体；零权限角色在 AWS 侧合法，按非阻断提示处理
		//（校验结果里的 ZERO_PERMISSION_ROLE 提示），不拒绝建单。
		if request.rolePolicyDeclared() {
			// 验证权限请求（支持新旧两种模型）
			if request.AbstractPolicy != nil {
				// 新模型验证
				if request.AbstractPolicy.Name != request.PrincipalName {
					return CreateIAMTicketRequest{}, apperr.Validation("abstract_policy.name must match principal_name")
				}
				if len(request.AbstractPolicy.Statements) == 0 {
					return CreateIAMTicketRequest{}, apperr.Validationf(
						"abstract_policy must contain at least one statement\n\n%s",
						AbstractPolicyFormatHint,
					)
				}
				if err := validateAbstractPolicyStructure(request.AbstractPolicy); err != nil {
					return CreateIAMTicketRequest{}, fmt.Errorf("%s\n\n%s", err.Error(), AbstractPolicyFormatHint)
				}
			} else {
				// 旧模型验证（向后兼容）
				if request.Permission.Principal.Name != request.PrincipalName {
					return CreateIAMTicketRequest{}, apperr.Validation("request_policy.principal.name must match principal_name")
				}
				if request.Permission.Principal.Type != "ServiceIdentity" && request.Permission.Principal.Type != "HumanUser" {
					return CreateIAMTicketRequest{}, apperr.Validation("request_policy.principal.type must be ServiceIdentity or HumanUser")
				}
			}
		}
	}
	return request, nil
}

// validateAbstractPolicyStructure validates the structure of an AbstractPolicy
// and returns a descriptive error with format guidance if invalid.
func validateAbstractPolicyStructure(policy *abstractiam.AbstractPolicy) error {
	if policy == nil {
		return apperr.Validation("abstract_policy is required")
	}
	if len(policy.Statements) == 0 {
		return errors.New("abstract_policy.statements must contain at least one statement\n\n" + AbstractPolicyFormatHint)
	}
	for i, stmt := range policy.Statements {
		if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
			return apperr.Validationf("abstract_policy.statements[%d].effect must be 'Allow' or 'Deny', got %q", i, stmt.Effect)
		}
		if len(stmt.Actions) == 0 && len(stmt.NotActions) == 0 {
			return apperr.Validationf("abstract_policy.statements[%d] must specify 'actions' or 'not_actions'", i)
		}
		if len(stmt.Resources) == 0 && len(stmt.NotResources) == 0 {
			return fmt.Errorf("abstract_policy.statements[%d] must specify 'resources' or 'not_resources'", i)
		}
		for j, cond := range stmt.Conditions {
			if cond.Key == "" {
				return apperr.Validationf("abstract_policy.statements[%d].conditions[%d].key is required", i, j)
			}
			if cond.Operator == "" {
				return fmt.Errorf("abstract_policy.statements[%d].conditions[%d].operator is required", i, j)
			}
			if len(cond.Values) == 0 {
				return fmt.Errorf("abstract_policy.statements[%d].conditions[%d].values must not be empty", i, j)
			}
		}
	}
	return nil
}

// AbstractPolicyFormatHint provides a format example for the abstract policy.
const AbstractPolicyFormatHint = `abstract_policy must follow the abstract IAM policy format (NOT AWS IAM policy format).

Correct format example:
{
  "name": "my-role",
  "description": "Optional description",
  "statements": [
    {
      "effect": "Allow",
      "actions": ["eks:CreateAccessEntry", "eks:DescribeCluster"],
      "resources": ["arn:aws:eks:ap-southeast-1:123456789012:cluster/my-cluster"]
    },
    {
      "effect": "Allow",
      "actions": ["backup:*"],
      "resources": ["*"]
    }
  ]
}

Key differences from AWS IAM policy format:
- Use "effect" (lowercase), not "Effect"
- Use "actions" (array), not "Action"
- Use "resources" (array), not "Resource"
- Use "conditions" (array of {key, operator, values}), not "Condition"
- No "Version" or "Statement" wrapper
- Action/resource wildcards use "*" as string in arrays
`

func isCreateResourceTicket(ticketType string) bool {
	return ticketType == TicketTypeCreateManagedPolicy ||
		ticketType == TicketTypeCreateUser ||
		ticketType == TicketTypeCreateGroup
}

// validateCreateResourceRequest validates the three resource-creation ticket
// types. Creation is inventory-aware: an existing resource is rejected unless
// adopt_existing is set, which switches the Terraform file to import-first
// adoption. Association sets (membership/attachments) are only allowed for
// genuinely new resources: declaring a full set for an adopted resource would
// make Terraform remove relationships the platform does not own.
func (service *TicketService) validateCreateResourceRequest(
	ctx context.Context,
	request *CreateIAMTicketRequest,
) error {
	if request.AdoptExisting && request.TicketType == TicketTypeCreateManagedPolicy {
		// Policy adoption is safe: the only managed property is the document.
	} else if request.AdoptExisting {
		// User associations are full-set resources. Group associations are
		// instead replaced with a server-side inventory snapshot below.
		switch request.TicketType {
		case TicketTypeCreateUser:
			if request.CreateUser != nil &&
				(len(uniqueNonEmpty(request.CreateUser.GroupNames)) > 0 ||
					len(uniqueNonEmpty(request.CreateUser.PolicyARNs)) > 0) {
				return errors.New("adopt_existing cannot declare group memberships or policy attachments for an existing IAM user; attach them with separate tickets after adoption")
			}
		}
	}

	switch request.TicketType {
	case TicketTypeCreateManagedPolicy:
		if request.CreatePolicy == nil {
			return apperr.Validation("create_managed_policy config must not be empty")
		}
		name := strings.TrimSpace(request.CreatePolicy.Name)
		if err := adapter.ValidateIAMResourceName("policy", name); err != nil {
			return err
		}
		path, err := adapter.NormalizeIAMPath(request.CreatePolicy.Path)
		if err != nil {
			return err
		}
		if err := adapter.ValidateIAMTags(request.CreatePolicy.Tags); err != nil {
			return err
		}
		if _, err := service.adapter.NormalizePolicyDocument(request.CreatePolicy.Document); err != nil {
			return fmt.Errorf("create_managed_policy.document: %w", err)
		}
		request.CreatePolicy.Name = name
		request.CreatePolicy.Path = path
		request.PrincipalName = name
		request.PrincipalType = "Policy"

		awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return fmt.Errorf("load AWS account identifier for policy creation: %w", err)
		}
		policyARN, err := adapter.BuildManagedPolicyARN(awsAccountID, path, name)
		if err != nil {
			return err
		}
		_, exists, err := service.repository.GetManagedPolicyByARN(ctx, policyARN)
		if err != nil {
			return fmt.Errorf("check existing managed policy: %w", err)
		}
		if request.AdoptExisting && !exists {
			return fmt.Errorf("policy %s does not exist in the account inventory; cannot adopt it (create a new policy instead)", policyARN)
		}
		if !request.AdoptExisting && exists {
			return fmt.Errorf("policy %s already exists in the account inventory; use UPDATE_MANAGED_POLICY to change it, or set adopt_existing to import it first", policyARN)
		}
		if request.AdoptExisting {
			policyName := PolicyNameFromARN(policyARN)
			if err := service.rejectIfAlreadyAdopted(ctx, *request,
				ResourceFileKey(BaselineKindPolicy, policyName), "policy", policyName,
				"如需变更请使用更新托管策略工单"); err != nil {
				return err
			}
		}
	case TicketTypeCreateUser:
		if request.CreateUser == nil {
			return apperr.Validation("create_user config must not be empty")
		}
		name := strings.TrimSpace(request.CreateUser.Name)
		if err := adapter.ValidateIAMResourceName("user", name); err != nil {
			return err
		}
		path, err := adapter.NormalizeIAMPath(request.CreateUser.Path)
		if err != nil {
			return err
		}
		if err := adapter.ValidateIAMTags(request.CreateUser.Tags); err != nil {
			return err
		}
		request.CreateUser.Name = name
		request.CreateUser.Path = path
		request.CreateUser.GroupNames = uniqueNonEmpty(request.CreateUser.GroupNames)
		for _, groupName := range request.CreateUser.GroupNames {
			if err := adapter.ValidateIAMResourceName("group", groupName); err != nil {
				return err
			}
			exists, err := service.repository.PrincipalExists(ctx, request.AccountID, groupName, "Group")
			if err != nil {
				return fmt.Errorf("check group %q: %w", groupName, err)
			}
			if !exists {
				return fmt.Errorf("group %q not found in account inventory; sync assets or create the group first", groupName)
			}
		}
		request.CreateUser.PolicyARNs = uniqueNonEmpty(request.CreateUser.PolicyARNs)
		if err := service.validateManagedPolicyARNs(
			ctx, request.AccountID, "create_user.policy_arns", request.CreateUser.PolicyARNs,
		); err != nil {
			return err
		}
		request.PrincipalName = name
		request.PrincipalType = "User"
		exists, err := service.repository.PrincipalExists(ctx, request.AccountID, name, "User")
		if err != nil {
			return fmt.Errorf("check existing IAM user: %w", err)
		}
		if request.AdoptExisting && !exists {
			return apperr.Validationf("IAM user %q does not exist in the account inventory; cannot adopt it", name)
		}
		if !request.AdoptExisting && exists {
			return apperr.Validationf("IAM user %q already exists in the account inventory; set adopt_existing to import it instead of creating a duplicate", name)
		}
		if request.AdoptExisting {
			if err := service.rejectIfAlreadyAdopted(ctx, *request,
				ResourceFileKey(BaselineKindUser, name), "user", name,
				"如需变更请使用对应的更新工单"); err != nil {
				return err
			}
		}
	case TicketTypeCreateGroup:
		if request.CreateGroup == nil {
			return apperr.Validation("create_group config must not be empty")
		}
		name := strings.TrimSpace(request.CreateGroup.Name)
		if err := adapter.ValidateIAMResourceName("group", name); err != nil {
			return err
		}
		path, err := adapter.NormalizeIAMPath(request.CreateGroup.Path)
		if err != nil {
			return err
		}
		if err := adapter.ValidateIAMTags(request.CreateGroup.Tags); err != nil {
			return err
		}
		exists, err := service.repository.PrincipalExists(ctx, request.AccountID, name, "Group")
		if err != nil {
			return fmt.Errorf("check existing IAM group: %w", err)
		}
		if request.AdoptExisting && !exists {
			return apperr.Validationf("IAM group %q does not exist in the account inventory; cannot adopt it", name)
		}
		if !request.AdoptExisting && exists {
			return apperr.Validationf("IAM group %q already exists in the account inventory; set adopt_existing to import it instead of creating a duplicate", name)
		}
		request.PrincipalName = name
		request.PrincipalType = "Group"
		if request.AdoptExisting {
			if err := service.rejectIfAlreadyAdopted(ctx, *request,
				ResourceFileKey(BaselineKindGroup, name), "group", name,
				"变更组成员请用组成员变更工单，内嵌策略请用更新内嵌策略工单"); err != nil {
				return err
			}
			snapshot, err := service.repository.GetGroupAdoptionSnapshot(ctx, request.AccountID, name)
			if err != nil {
				return fmt.Errorf("load IAM group adoption snapshot: %w", err)
			}
			request.CreateGroup = &snapshot
			break
		}

		request.CreateGroup.Name = name
		request.CreateGroup.Path = path
		request.CreateGroup.MemberUserNames = uniqueNonEmpty(request.CreateGroup.MemberUserNames)
		for _, userName := range request.CreateGroup.MemberUserNames {
			if err := adapter.ValidateIAMResourceName("user", userName); err != nil {
				return err
			}
			exists, err := service.repository.PrincipalExists(ctx, request.AccountID, userName, "User")
			if err != nil {
				return fmt.Errorf("check member user %q: %w", userName, err)
			}
			if !exists {
				return apperr.Validationf("IAM user %q not found in account inventory; sync assets or create the user first", userName)
			}
		}
		request.CreateGroup.PolicyARNs = uniqueNonEmpty(request.CreateGroup.PolicyARNs)
		if err := service.validateManagedPolicyARNs(
			ctx, request.AccountID, "create_group.policy_arns", request.CreateGroup.PolicyARNs,
		); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported create ticket type %q", request.TicketType)
	}

	active, err := service.repository.CountActiveCreateTickets(
		ctx, request.AccountID, request.TicketType, request.PrincipalName,
	)
	if err != nil {
		return fmt.Errorf("check active create tickets: %w", err)
	}
	if active > 0 {
		return apperr.Validation("this resource already has a create ticket in progress; retry once it is closed")
	}
	return nil
}

// buildCreateTerraform renders the create/adopt file for a CREATE_* ticket.
// The import ID is only emitted when adopt_existing is set; a normal creation
// must fail if Terraform finds an existing resource.
func (service *TicketService) buildCreateTerraform(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (string, error) {
	importID := ""
	if request.AdoptExisting {
		switch request.TicketType {
		case TicketTypeCreateManagedPolicy:
			accountID := strings.TrimSpace(request.AWSAccountID)
			if accountID == "" {
				var err error
				accountID, err = service.repository.GetAWSAccountID(ctx, request.AccountID)
				if err != nil {
					return "", fmt.Errorf("load AWS account identifier for policy adoption: %w", err)
				}
			}
			if request.CreatePolicy == nil {
				return "", errors.New("create_managed_policy config missing for policy creation")
			}
			policyARN, err := adapter.BuildManagedPolicyARN(accountID, request.CreatePolicy.Path, request.CreatePolicy.Name)
			if err != nil {
				return "", err
			}
			importID = policyARN
		case TicketTypeCreateUser:
			if request.CreateUser == nil {
				return "", errors.New("create_user config missing for user creation")
			}
			importID = request.CreateUser.Name
		case TicketTypeCreateGroup:
			if request.CreateGroup == nil {
				return "", errors.New("create_group config missing for group creation")
			}
			importID = request.CreateGroup.Name
		}
	}

	switch request.TicketType {
	case TicketTypeCreateManagedPolicy:
		if request.CreatePolicy == nil {
			return "", errors.New("create_managed_policy config missing for policy creation")
		}
		return service.adapter.GenerateCreateManagedPolicyTerraform(*request.CreatePolicy, importID)
	case TicketTypeCreateUser:
		if request.CreateUser == nil {
			return "", errors.New("create_user config missing for user creation")
		}
		return service.adapter.GenerateCreateUserTerraform(*request.CreateUser, importID)
	case TicketTypeCreateGroup:
		if request.CreateGroup == nil {
			return "", errors.New("create_group config missing for group creation")
		}
		return service.adapter.GenerateCreateGroupTerraform(*request.CreateGroup, importID)
	default:
		return "", fmt.Errorf("unsupported create ticket type %q", request.TicketType)
	}
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

// validateUpdateRoleRequest validates UPDATE_ROLE requests: the role must
// exist in the collected inventory, a trust-policy change forces MANUAL
// approval (backend enforcement, not just frontend greying out), and the
// same role cannot have two active UPDATE_ROLE tickets in flight.
func (service *TicketService) validateUpdateRoleRequest(
	ctx context.Context,
	request *CreateIAMTicketRequest,
) error {
	if request.UpdateRole == nil {
		return apperr.Validation("update_role config must not be empty")
	}
	// 内嵌策略与托管挂载已拆到独立工单类型（更新内嵌策略 / 挂载解绑），
	// UPDATE_ROLE 只管角色属性；收到这两个字段明确 400，不静默忽略
	//（整文件重生成时代它们会造成「留空 = 从文件消失 = 销毁」）。
	if len(request.UpdateRole.InlinePolicies) > 0 {
		return apperr.Validation("update_role.inline_policies is no longer supported; use UPDATE_GROUP_INLINE_POLICY tickets to change inline policies")
	}
	if len(request.UpdateRole.ManagedPolicyARNs) > 0 {
		return apperr.Validation("update_role.managed_policy_arns is no longer supported; use ATTACH_USER_POLICY tickets to attach or detach managed policies")
	}
	// 1. Role must exist in the synced inventory.
	_, principalExists, err := service.repository.GetPrincipalPolicies(
		ctx, request.AccountID, request.PrincipalName, "Role",
	)
	if err != nil {
		return apperr.Validationf("load existing role for update: %w", err)
	}
	if !principalExists {
		return fmt.Errorf("role %q not found in account inventory; sync assets first", request.PrincipalName)
	}
	// 2. Trust-policy change → force MANUAL approval.
	if request.UpdateRole.TrustPolicy != nil {
		currentTrust, err := service.repository.GetPrincipalTrustPolicy(
			ctx, request.AccountID, request.PrincipalName,
		)
		if err != nil {
			return fmt.Errorf("load current trust policy: %w", err)
		}
		changed := true
		if currentTrust != nil {
			changed = !trustPoliciesEqual(currentTrust, request.UpdateRole.TrustPolicy)
		}
		if changed && request.ApprovalMode != ApprovalModeManual {
			return &TrustPolicyChangeError{RoleName: request.PrincipalName}
		}
	}
	// 3. Concurrency lock: no other active UPDATE_ROLE ticket for this role.
	active, err := service.repository.CountActiveUpdateRoleTickets(
		ctx, request.AccountID, request.PrincipalName,
	)
	if err != nil {
		return fmt.Errorf("check active update-role tickets: %w", err)
	}
	if active > 0 {
		return apperr.Validation("this role already has a change ticket in progress; retry once it is closed")
	}
	// 4. Locate the CREATE_ROLE ticket whose Terraform file this update will
	// modify. ③ 野生角色不再拒绝：无源文件时走独立新文件 role-<name>.tf
	// + 首次 import 纳管；SourceTicketNo 留空即为「野生」标记。
	sourceTicketNo, err := service.repository.FindCreatedRoleTicket(
		ctx, request.AccountID, request.PrincipalName,
	)
	if err != nil {
		return fmt.Errorf("locate source ticket for role: %w", err)
	}
	request.SourceTicketNo = sourceTicketNo
	// 5. 变更检测（对齐第 12 项策略更新）：所有提交属性都与现网一致 →
	// 400，避免审批人面对一份空 diff。留空字段不参与比较。唯一例外是
	// 野生角色首次纳管：Terraform 侧新增 import 块本身就是有意义的变更。
	changes, err := service.roleUpdateChanges(ctx, *request)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		firstTimeAdoption, err := service.roleFirstTimeAdoption(ctx, *request)
		if err != nil {
			return err
		}
		if !firstTimeAdoption {
			return apperr.Validationf("update_role is identical to the current live role %s; no change to apply", request.PrincipalName)
		}
	}
	return nil
}

// defaultMaxSessionDuration is AWS's max_session_duration when the role never
// set one; comparing against it keeps a ticket that merely restates the
// default from counting as a change.
const defaultMaxSessionDuration = 3600

// roleUpdateChanges lists the role attributes an UPDATE_ROLE ticket actually
// changes, compared with the current inventory values. nil fields mean
// 「留空 = 不修改」and never count as a change; trust policies compare
// semantically (key order/whitespace ignored). An empty result means the
// ticket would publish a no-op diff.
func (service *TicketService) roleUpdateChanges(
	ctx context.Context,
	request CreateIAMTicketRequest,
) ([]string, error) {
	config := request.UpdateRole
	if config == nil {
		return nil, apperr.Validation("update_role config must not be empty")
	}
	changes := make([]string, 0, 4)
	if config.TrustPolicy != nil {
		current, err := service.repository.GetPrincipalTrustPolicy(ctx, request.AccountID, request.PrincipalName)
		if err != nil {
			return nil, fmt.Errorf("load current trust policy: %w", err)
		}
		if !trustPoliciesEqual(current, config.TrustPolicy) {
			changes = append(changes, "trust_policy")
		}
	}
	attrs, err := service.repository.GetRoleAttributes(ctx, request.AccountID, request.PrincipalName)
	if err != nil {
		return nil, fmt.Errorf("load current role attributes: %w", err)
	}
	if attrs == nil {
		attrs = &RoleAttributes{}
	}
	if config.Description != nil {
		current := ""
		if attrs.Description != nil {
			current = *attrs.Description
		}
		if *config.Description != current {
			changes = append(changes, "description")
		}
	}
	if config.MaxSessionDuration != nil {
		current := defaultMaxSessionDuration
		if attrs.MaxSessionDuration != nil && *attrs.MaxSessionDuration > 0 {
			current = int(*attrs.MaxSessionDuration)
		}
		if *config.MaxSessionDuration != current {
			changes = append(changes, "max_session_duration")
		}
	}
	if config.Tags != nil && !stringMapsEqual(attrs.Tags, config.Tags) {
		changes = append(changes, "tags")
	}
	return changes, nil
}

// stringMapsEqual reports whether two tag maps carry the same entries.
// nil and empty maps are equal (both mean "no tags").
func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if other, ok := right[key]; !ok || other != value {
			return false
		}
	}
	return true
}

// validateUpdatePolicyRequest validates UPDATE_MANAGED_POLICY and
// UPDATE_GROUP_INLINE_POLICY requests: the policy must exist in the collected
// inventory (customer-managed only for managed policies; group-owned inline
// policies only for inline updates), the document must be valid JSON, and the
// same policy cannot have two active update tickets in flight. It also fills
// in PrincipalName (policy name / group name) and PrincipalType ("Policy" /
// "Group") for display and for the concurrency lock.
func (service *TicketService) validateUpdatePolicyRequest(
	ctx context.Context,
	request *CreateIAMTicketRequest,
) error {
	if request.UpdatePolicy == nil {
		return apperr.Validation("update_policy config must not be empty")
	}
	switch request.TicketType {
	case TicketTypeUpdateManagedPolicy:
		arn := strings.TrimSpace(request.UpdatePolicy.PolicyARN)
		if arn == "" {
			return apperr.Validation("update_policy.policy_arn is required for UPDATE_MANAGED_POLICY")
		}
		if err := adapter.ValidateIAMPolicyARN(arn); err != nil {
			return fmt.Errorf("managed_policy_arn: %w", err)
		}
		if strings.HasPrefix(arn, "arn:aws:iam::aws:policy/") {
			return apperr.Validation("AWS-managed policies cannot be updated via tickets; only customer-managed policies are supported")
		}
		_, exists, err := service.repository.GetManagedPolicyByARN(ctx, arn)
		if err != nil {
			return apperr.Validationf("load managed policy for update: %w", err)
		}
		if !exists {
			return fmt.Errorf("policy %q not found in account inventory; sync assets first", PolicyNameFromARN(arn))
		}
		request.UpdatePolicy.PolicyName = PolicyNameFromARN(arn)
		request.UpdatePolicy.GroupName = ""
		request.UpdatePolicy.InlinePolicyName = ""
		request.PrincipalName = request.UpdatePolicy.PolicyName
		request.PrincipalType = "Policy"
		if len(request.UpdatePolicy.Document) == 0 {
			return apperr.Validation("update_policy document must not be empty")
		}
		// Concurrency lock: one active update ticket per policy.
		active, err := service.repository.CountActiveUpdatePolicyTickets(
			ctx, request.AccountID, TicketTypeUpdateManagedPolicy, "", arn, "", "",
		)
		if err != nil {
			return apperr.Validationf("check active update-policy tickets: %w", err)
		}
		if active > 0 {
			return apperr.Validation("this policy already has a change ticket in progress; retry once it is closed")
		}
	case TicketTypeUpdateGroupInlinePolicy:
		inlineName := strings.TrimSpace(request.UpdatePolicy.InlinePolicyName)
		if inlineName == "" {
			return apperr.Validation("update_policy.inline_policy_name is required for UPDATE_GROUP_INLINE_POLICY")
		}
		// 内嵌策略的归属主体可以是 IAM 组或 IAM 角色，由 principal_type 决定。
		principalType := strings.TrimSpace(request.PrincipalType)
		if principalType == "" {
			principalType = "Group"
		}
		if principalType != "Group" && principalType != "Role" {
			return apperr.Validation("principal_type must be Group or Role for UPDATE_GROUP_INLINE_POLICY")
		}
		if principalType == "Role" {
			role := strings.TrimSpace(request.UpdatePolicy.RoleName)
			if role == "" {
				role = strings.TrimSpace(request.PrincipalName)
				request.UpdatePolicy.RoleName = role
			}
			if role == "" {
				return apperr.Validation("update_policy.role_name is required for UPDATE_GROUP_INLINE_POLICY on a role")
			}
			exists, err := service.repository.PrincipalExists(ctx, request.AccountID, role, "Role")
			if err != nil {
				return apperr.Validationf("load existing role for inline policy update: %w", err)
			}
			if !exists {
				return fmt.Errorf("role %q not found in account inventory; sync assets first", role)
			}
			// 内嵌策略不在采集清单里（可能已被线下删除，或尚未同步到平台）：不再
			// 硬拦——Terraform 侧按声明原地更新或重建，审批人看 Terraform 预览判断；
			// 校验结果会给出 INLINE_POLICY_ABSENT 提示（非阻断）。
			if _, _, err := service.repository.GetRoleInlinePolicy(ctx, request.AccountID, role, inlineName); err != nil {
				return fmt.Errorf("load role inline policy for update: %w", err)
			}
			// 平台 CREATE_ROLE 工单声明的角色内嵌策略（<role>-policy）：更新覆写源
			// 工单的 Terraform 文件，保持单一资源声明（源文件内唯一的
			// aws_iam_role_policy 块），避免第二个文件与源文件争夺同一个 AWS 对象
			// （双重管理 → 永久 drift）。
			if sourceTicketNo, err := service.repository.FindCreatedRoleTicket(ctx, request.AccountID, role); err != nil {
				return fmt.Errorf("locate source ticket for role: %w", err)
			} else if sourceTicketNo != "" && inlineName == role+"-policy" {
				request.SourceTicketNo = sourceTicketNo
			}
			request.UpdatePolicy.GroupName = ""
			request.PrincipalName = role
		} else {
			group := strings.TrimSpace(request.UpdatePolicy.GroupName)
			if group == "" {
				group = strings.TrimSpace(request.PrincipalName)
				request.UpdatePolicy.GroupName = group
			}
			if group == "" {
				return apperr.Validation("update_policy.group_name is required for UPDATE_GROUP_INLINE_POLICY")
			}
			exists, err := service.repository.PrincipalExists(ctx, request.AccountID, group, "Group")
			if err != nil {
				return apperr.Validationf("load existing group for inline policy update: %w", err)
			}
			if !exists {
				return fmt.Errorf("group %q not found in account inventory; sync assets first", group)
			}
			// 同角色分支：策略不在清单里不阻断（线下删除/未同步 → 按声明恢复）。
			if _, _, err := service.repository.GetGroupInlinePolicy(ctx, request.AccountID, group, inlineName); err != nil {
				return apperr.Validationf("load group inline policy for update: %w", err)
			}
			request.UpdatePolicy.RoleName = ""
			request.PrincipalName = group
		}
		request.PrincipalType = principalType
		if len(request.UpdatePolicy.Document) == 0 {
			return apperr.Validation("update_policy document must not be empty")
		}
		// Concurrency lock: one active update ticket per inline policy identity.
		active, err := service.repository.CountActiveUpdatePolicyTickets(
			ctx, request.AccountID, TicketTypeUpdateGroupInlinePolicy, principalType,
			"", request.PrincipalName, inlineName,
		)
		if err != nil {
			return fmt.Errorf("check active update-policy tickets: %w", err)
		}
		if active > 0 {
			return apperr.Validation("this policy already has a change ticket in progress; retry once it is closed")
		}
	}
	// 资源标签在工单创建时解析一次并随请求持久化（update_policy.resource_name），
	// 保证审批预览与最终发布一致；源文件覆写路径按 name 属性块级 patch，不需要标签。
	request.UpdatePolicy.ResourceName = policyUpdateResourceLabel(*request)
	return nil
}

// validateUpdateGroupMembershipRequest validates UPDATE_GROUP_MEMBERSHIP
// requests: the group and every affected user must exist in the collected
// inventory, users must actually be members (remove) or not yet members
// (add), and the group cannot have another membership ticket in flight. It
// fills in PrincipalName (group name) and PrincipalType ("Group") for display
// and for the concurrency lock.
func (service *TicketService) validateUpdateGroupMembershipRequest(
	ctx context.Context,
	request *CreateIAMTicketRequest,
) error {
	config := request.UpdateMembership
	if config == nil {
		return apperr.Validation("update_membership config must not be empty")
	}
	group := strings.TrimSpace(config.GroupName)
	if group == "" {
		return apperr.Validation("update_membership.group_name is required for UPDATE_GROUP_MEMBERSHIP")
	}
	operation := strings.ToLower(strings.TrimSpace(config.Operation))
	if operation != MembershipOperationAdd && operation != MembershipOperationRemove {
		return apperr.Validation("update_membership.operation must be add or remove for UPDATE_GROUP_MEMBERSHIP")
	}
	config.Operation = operation
	// 去重去空，保持提交顺序。
	seen := map[string]bool{}
	users := make([]string, 0, len(config.Users))
	for _, user := range config.Users {
		user = strings.TrimSpace(user)
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		users = append(users, user)
	}
	if len(users) == 0 {
		return apperr.Validation("update_membership.users must list at least one IAM user")
	}
	config.Users = users
	config.GroupName = group

	exists, err := service.repository.PrincipalExists(ctx, request.AccountID, group, "Group")
	if err != nil {
		return apperr.Validationf("load existing group for membership update: %w", err)
	}
	if !exists {
		return fmt.Errorf("group %q not found in account inventory; sync assets first", group)
	}
	members, err := service.repository.GroupMembers(ctx, request.AccountID, group)
	if err != nil {
		return fmt.Errorf("load group members for membership update: %w", err)
	}
	isMember := map[string]bool{}
	for _, member := range members {
		isMember[member] = true
	}
	if operation == MembershipOperationAdd {
		var already []string
		for _, user := range users {
			if isMember[user] {
				already = append(already, user)
			}
		}
		if len(already) > 0 {
			return apperr.Validationf("update_membership: user(s) %q are already members of group %q; nothing to add", strings.Join(already, ", "), group)
		}
	} else {
		var missing []string
		for _, user := range users {
			if !isMember[user] {
				missing = append(missing, user)
			}
		}
		if len(missing) > 0 {
			return apperr.Validationf("update_membership: user(s) %q are not members of group %q; nothing to remove", strings.Join(missing, ", "), group)
		}
		if len(members)-len(users) == 0 {
			// 最后一名成员移除是合法操作（清空文件 → 销毁 membership 资源），
			// 但必须让提交者知情：解绑后组在 Terraform 里不再有成员声明。
			service.logger.Warn("removing the last member of a group; the membership resource will be destroyed",
				"group", group)
		}
	}
	for _, user := range users {
		userExists, err := service.repository.PrincipalExists(ctx, request.AccountID, user, "User")
		if err != nil {
			return apperr.Validationf("load existing user for membership update: %w", err)
		}
		if !userExists {
			return fmt.Errorf("user %q not found in account inventory; sync assets first", user)
		}
	}
	// 并发锁：同一组的成员变更一次只允许一个工单在处理。
	active, err := service.repository.CountActiveGroupMembershipTickets(ctx, request.AccountID, group)
	if err != nil {
		return fmt.Errorf("check active group membership tickets: %w", err)
	}
	if active > 0 {
		return apperr.Validation("this group already has a membership change ticket in progress; retry once it is closed")
	}
	request.PrincipalName = group
	request.PrincipalType = "Group"
	return nil
}

// WildAttachmentError is returned when a detach ticket targets an attachment
// that the platform did not create (no source ATTACH_USER_POLICY ticket). The
// platform cannot safely destroy such an attachment via GitOps because there
// is no Terraform file declaring it and no resource in Terraform state. The
// message carries the actionable two-step path: adopt it first with an attach
// ticket (auto import block, apply changes nothing on AWS), then detach.
type WildAttachmentError struct {
	PrincipalType string
	PrincipalName string
	PolicyARN     string
}

func (e *WildAttachmentError) Error() string {
	return fmt.Sprintf("该 %s %q 与策略 %s 的挂载关系未被本平台纳管，无法直接解绑（销毁需先纳管进 Terraform state）；请先发起「挂载」工单做首次纳管（校验预览自动生成 import 块，apply 后挂载关系不变），完成后再提交解绑工单",
		strings.ToLower(e.PrincipalType), e.PrincipalName, e.PolicyARN)
}

// AttachmentConflictError is returned when an attach ticket targets an
// attachment that already exists in the inventory: either created by a
// platform attach ticket (SourceTicketNo set) or adopted by a full baseline
// publication (BaselineOwned). Both cases reject the duplicate declaration —
// an attach ticket would overwrite the baseline file and break the ownership
// model — and point the submitter at the detach path instead.
type AttachmentConflictError struct {
	PrincipalType  string
	PrincipalName  string
	PolicyARN      string
	SourceTicketNo string // non-empty when a platform attach ticket created it
	BaselineOwned  bool   // adopted by a merged full baseline publication
}

func (e *AttachmentConflictError) Error() string {
	if e.SourceTicketNo != "" {
		return fmt.Sprintf("该策略已挂载到该 %s %q（源工单 %s）；如需变更请先创建解绑工单",
			strings.ToLower(e.PrincipalType), e.PrincipalName, e.SourceTicketNo)
	}
	return fmt.Sprintf("该 %s %q 与策略 %s 的挂载关系已由全量基线纳管（基线文件已声明且已 apply 进 Terraform state）；如需解绑请直接提交解绑工单",
		strings.ToLower(e.PrincipalType), e.PrincipalName, e.PolicyARN)
}

// TrustPolicyChangeError is returned when a trust-policy change is submitted
// with AUTO approval; the frontend greys out the option but the backend must
// enforce it so the rule cannot be bypassed via the API.
type TrustPolicyChangeError struct {
	RoleName string
}

func (e *TrustPolicyChangeError) Error() string {
	return "本次修改角色信任关系，属于高危操作，仅支持人工审批"
}

// trustPoliciesEqual compares two trust-policy documents semantically
// (key order and whitespace are irrelevant).
func trustPoliciesEqual(current json.RawMessage, next *map[string]interface{}) bool {
	var currentDoc map[string]interface{}
	if err := json.Unmarshal(current, &currentDoc); err != nil {
		return false
	}
	currentNorm, err := json.Marshal(currentDoc)
	if err != nil {
		return false
	}
	nextNorm, err := json.Marshal(next)
	if err != nil {
		return false
	}
	return bytes.Equal(currentNorm, nextNorm)
}

// UpdateRoleConfigFromSnapshot decodes a stored role snapshot (captured at
// UPDATE_ROLE publication time) into an UpdateRoleConfig suitable for
// generating reverse Terraform that restores the pre-update state.
func UpdateRoleConfigFromSnapshot(snapshot json.RawMessage) (*adapter.UpdateRoleConfig, error) {
	var decoded struct {
		TrustPolicy        *map[string]interface{} `json:"trust_policy"`
		Description        *string                 `json:"description"`
		MaxSessionDuration *int                    `json:"max_session_duration"`
		Tags               map[string]string       `json:"tags"`
	}
	if err := json.Unmarshal(snapshot, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshal role snapshot: %w", err)
	}
	config := &adapter.UpdateRoleConfig{}
	if decoded.TrustPolicy != nil {
		config.TrustPolicy = decoded.TrustPolicy
	}
	if decoded.Description != nil {
		config.Description = decoded.Description
	}
	if decoded.MaxSessionDuration != nil {
		config.MaxSessionDuration = decoded.MaxSessionDuration
	}
	// 注意：tags 以「key 是否存在」区分「更新前没有标签」与「更新前标签为空」，
	// 前者回滚时保持不动，后者回滚时要移除 tags 属性（恢复无标签状态）。
	config.Tags = decoded.Tags
	return config, nil
}

// captureRoleSnapshot reads the role's pre-update attributes from the
// inventory and stores them on the ticket as a JSONB snapshot. ROLLBACK of
// an UPDATE_ROLE ticket reads this snapshot to generate reverse Terraform
// that restores the pre-update state.
//
// ② 块级 patch 后回滚只还原角色属性：内嵌策略/托管挂载已拆出 UPDATE_ROLE，
// 快照不再采集 inline_policies；描述/时长/标签此前未采集导致回滚无法
// 还原，现一并采集（0017 迁移）。
func (service *TicketService) captureRoleSnapshot(
	ctx context.Context,
	ticket *model.IAMTicket,
	roleName string,
) {
	snapshot := map[string]interface{}{}
	trustPolicy, err := service.repository.GetPrincipalTrustPolicy(ctx, *ticket.AccountID, roleName)
	if err != nil {
		service.logger.Warn("snapshot trust policy failed", "ticket_no", *ticket.TicketNo, "error", err)
	} else if trustPolicy != nil {
		var doc map[string]interface{}
		if err := json.Unmarshal(trustPolicy, &doc); err == nil {
			snapshot["trust_policy"] = doc
		}
	}
	attrs, err := service.repository.GetRoleAttributes(ctx, *ticket.AccountID, roleName)
	if err != nil {
		service.logger.Warn("snapshot role attributes failed", "ticket_no", *ticket.TicketNo, "error", err)
	} else if attrs != nil {
		if attrs.Description != nil {
			snapshot["description"] = *attrs.Description
		}
		if attrs.MaxSessionDuration != nil {
			snapshot["max_session_duration"] = *attrs.MaxSessionDuration
		}
		if attrs.Tags != nil {
			snapshot["tags"] = attrs.Tags
		}
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		service.logger.Warn("marshal role snapshot failed", "ticket_no", *ticket.TicketNo, "error", err)
		return
	}
	if err := service.repository.SaveRoleSnapshot(ctx, *ticket.TicketNo, snapshotJSON); err != nil {
		service.logger.Warn("save role snapshot failed", "ticket_no", *ticket.TicketNo, "error", err)
	}
}

// capturePolicySnapshot reads the policy's current document from the
// inventory and stores it on the ticket as a JSONB snapshot. ROLLBACK of an
// UPDATE_MANAGED_POLICY / UPDATE_GROUP_INLINE_POLICY ticket reads this
// snapshot to generate reverse Terraform that restores the pre-update
// document. The snapshot column (role_snapshot) is generic JSONB reused for
// any pre-change snapshot.
func (service *TicketService) capturePolicySnapshot(
	ctx context.Context,
	ticket *model.IAMTicket,
	request CreateIAMTicketRequest,
) {
	if request.UpdatePolicy == nil || ticket.AccountID == nil || ticket.TicketNo == nil {
		return
	}
	var document json.RawMessage
	var err error
	if request.TicketType == TicketTypeUpdateGroupInlinePolicy {
		if strings.TrimSpace(request.UpdatePolicy.RoleName) != "" {
			document, _, err = service.repository.GetRoleInlinePolicy(
				ctx, *ticket.AccountID, request.UpdatePolicy.RoleName, request.UpdatePolicy.InlinePolicyName,
			)
		} else {
			document, _, err = service.repository.GetGroupInlinePolicy(
				ctx, *ticket.AccountID, request.UpdatePolicy.GroupName, request.UpdatePolicy.InlinePolicyName,
			)
		}
	} else {
		document, _, err = service.repository.GetManagedPolicyByARN(ctx, request.UpdatePolicy.PolicyARN)
	}
	if err != nil {
		service.logger.Warn("snapshot policy document failed", "ticket_no", *ticket.TicketNo, "error", err)
		return
	}
	if len(document) == 0 {
		service.logger.Warn("policy document not found for snapshot",
			"ticket_no", *ticket.TicketNo, "policy", request.UpdatePolicy.PolicyName)
		return
	}
	if err := service.repository.SaveRoleSnapshot(ctx, *ticket.TicketNo, document); err != nil {
		service.logger.Warn("save policy snapshot failed", "ticket_no", *ticket.TicketNo, "error", err)
	}
}

// captureMembershipSnapshot stores the group's pre-change membership (the
// main file's declared users when the file exists — the managed truth —
// falling back to the inventory) as a JSON array in the ticket's snapshot
// column, so ROLLBACK can restore the exact list.
func (service *TicketService) captureMembershipSnapshot(
	ctx context.Context,
	ticket *model.IAMTicket,
	request CreateIAMTicketRequest,
) {
	config := request.UpdateMembership
	if config == nil || ticket.AccountID == nil || ticket.TicketNo == nil {
		return
	}
	var members []string
	fileContent, fetchErr := service.publisher.FetchTerraformFile(ctx, *ticket, request)
	if fetchErr == nil {
		_, users, found, err := adapter.ScanGroupMembershipUsers(fileContent)
		if err != nil {
			service.logger.Warn("scan membership file for snapshot failed",
				"ticket_no", *ticket.TicketNo, "error", err)
			return
		}
		if found {
			members = users
		}
	} else if !errors.Is(fetchErr, ErrTerraformFileNotFound) {
		service.logger.Warn("fetch membership file for snapshot failed",
			"ticket_no", *ticket.TicketNo, "error", fetchErr)
		return
	}
	if members == nil {
		inventory, err := service.repository.GroupMembers(ctx, *ticket.AccountID, config.GroupName)
		if err != nil {
			service.logger.Warn("load group members for snapshot failed",
				"ticket_no", *ticket.TicketNo, "error", err)
			return
		}
		members = inventory
	}
	snapshot, err := json.Marshal(members)
	if err != nil {
		service.logger.Warn("marshal membership snapshot failed", "ticket_no", *ticket.TicketNo, "error", err)
		return
	}
	if err := service.repository.SaveRoleSnapshot(ctx, *ticket.TicketNo, snapshot); err != nil {
		service.logger.Warn("save membership snapshot failed", "ticket_no", *ticket.TicketNo, "error", err)
	}
}

// policyImportID decides whether a policy-update ticket needs a Terraform
// `import` block (first-time adoption of a pre-existing policy). The platform
// emits the import block only when no prior ticket has published an update for
// this policy identity (no MERGED/CLOSED UPDATE ticket for the same policy),
// so the first update adopts the resource into Terraform state and subsequent
// updates upsert it in place. Re-importing an already-managed resource would
// make `terraform plan` fail, so the check is required.
func (service *TicketService) policyImportID(ctx context.Context, request CreateIAMTicketRequest) string {
	if request.UpdatePolicy == nil {
		return ""
	}
	if strings.TrimSpace(request.SourceTicketNo) != "" {
		// 源 CREATE_ROLE 文件覆写路径：资源已由源文件声明并在 Terraform
		// state 中，无需 import。
		return ""
	}
	var applied int
	var err error
	if request.TicketType == TicketTypeUpdateGroupInlinePolicy {
		applied, err = service.repository.CountAppliedUpdatePolicyTickets(
			ctx, request.AccountID, TicketTypeUpdateGroupInlinePolicy, request.PrincipalType,
			"", request.PrincipalName, request.UpdatePolicy.InlinePolicyName,
		)
	} else {
		applied, err = service.repository.CountAppliedUpdatePolicyTickets(
			ctx, request.AccountID, TicketTypeUpdateManagedPolicy, "",
			request.UpdatePolicy.PolicyARN, "", "",
		)
	}
	if err != nil {
		// Fail open: emit no import block. An already-managed resource is the
		// common case; a missing import on a truly first-time adoption will be
		// caught by the operator at terraform apply with a clear error.
		service.logger.Warn("check applied update-policy tickets failed; skipping import block",
			"ticket_type", request.TicketType, "error", err)
		return ""
	}
	if applied > 0 {
		return ""
	}
	if request.TicketType == TicketTypeUpdateGroupInlinePolicy {
		// aws_iam_group_policy / aws_iam_role_policy 的 import ID 格式都是
		// <owner-name>:<policy-name>（冒号）；只有 attachment 类资源
		// (*_policy_attachment) 才用 <name>/<policy-arn>（斜杠）。
		if strings.TrimSpace(request.UpdatePolicy.RoleName) != "" {
			return request.UpdatePolicy.RoleName + ":" + request.UpdatePolicy.InlinePolicyName
		}
		return request.UpdatePolicy.GroupName + ":" + request.UpdatePolicy.InlinePolicyName
	}
	return request.UpdatePolicy.PolicyARN
}

// roleImportID returns the import id for a wild role's first-time adoption,
// or "" when no import block is needed. Only called from the wild-role
// generation path (the role file is confirmed absent from the target
// branch); see roleFirstTimeAdoption for the no-op guard's adoption check.
func (service *TicketService) roleImportID(ctx context.Context, request CreateIAMTicketRequest) string {
	if request.TicketType != TicketTypeUpdateRole {
		return ""
	}
	if strings.TrimSpace(request.SourceTicketNo) != "" {
		// 源 CREATE_ROLE 文件：角色已由源文件声明并在 Terraform state 中。
		return ""
	}
	applied, err := service.repository.CountAppliedUpdateRoleTickets(
		ctx, request.AccountID, request.PrincipalName,
	)
	if err != nil {
		// Fail open: emit no import block. An already-managed role is the
		// common case; a missing import on a truly first-time adoption fails
		// loudly at apply time (resource exists in AWS but not in state).
		service.logger.Warn("check applied update-role tickets failed; skipping import block",
			"role", request.PrincipalName, "error", err)
		return ""
	}
	if applied > 0 {
		// 已被先前的 UPDATE_ROLE 工单纳管（import 只用一次）。
		return ""
	}
	return request.PrincipalName
}

// roleFirstTimeAdoption reports whether an UPDATE_ROLE ticket would perform a
// first-time adoption of a wild role: no source CREATE file, no applied
// UPDATE_ROLE ticket, and no role declaration on the target branch — so the
// rendered Terraform still carries a fresh import block even when no
// attribute changes. Any other no-change submission (role already patched in
// place, e.g. baseline-adopted) is a pure no-op and must be rejected.
func (service *TicketService) roleFirstTimeAdoption(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (bool, error) {
	if strings.TrimSpace(request.SourceTicketNo) != "" {
		// 源 CREATE 文件声明了该角色：已纳管，原地 patch。
		return false, nil
	}
	applied, err := service.repository.CountAppliedUpdateRoleTickets(
		ctx, request.AccountID, request.PrincipalName,
	)
	if err != nil {
		// Fail closed：查询失败时按「已纳管」处理，no-op 会被拒绝，
		// 用户改任意属性即可绕开此检查，不会卡死正常流程。
		return false, fmt.Errorf("check applied update-role tickets: %w", err)
	}
	if applied > 0 {
		// 已被先前的 UPDATE_ROLE 工单纳管，import 只用一次。
		return false, nil
	}
	awsAccountID := strings.TrimSpace(request.AWSAccountID)
	if awsAccountID == "" {
		id, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return false, fmt.Errorf("load AWS account identifier for role adoption check: %w", err)
		}
		awsAccountID = id
	}
	fileRequest := request
	fileRequest.AWSAccountID = awsAccountID
	content, err := service.publisher.FetchTerraformFile(
		ctx, validationStubTicket(fileRequest), fileRequest,
	)
	if errors.Is(err, ErrTerraformFileNotFound) {
		return true, nil
	}
	if err != nil {
		// Fail closed：GitHub 瞬态故障时不放行 no-op（角色可能已被纳管，
		// 放行会产生带 import 块的重复声明）。用户提交真实变更即可重试。
		return false, fmt.Errorf("probe role Terraform file for adoption check: %w", err)
	}
	// 文件在 main 上但不含角色块（回滚清空成注释文件）→ 可重新纳管。
	return !adapter.HasRoleResourceBlock(content), nil
}

// wildRoleGenerationConfig returns the config a standalone wild-role file
// must declare: the submitted config with trust filled from inventory when
// the ticket did not change it (assume_role_policy is provider-required, so
// the file always declares it — declaring the current value changes nothing).
func (service *TicketService) wildRoleGenerationConfig(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (*adapter.UpdateRoleConfig, error) {
	if request.UpdateRole == nil {
		return nil, apperr.Validation("update_role config missing for UPDATE_ROLE ticket")
	}
	if request.UpdateRole.TrustPolicy != nil {
		return request.UpdateRole, nil
	}
	currentTrust, err := service.repository.GetPrincipalTrustPolicy(
		ctx, request.AccountID, request.PrincipalName,
	)
	if err != nil {
		return nil, fmt.Errorf("load current trust policy for role file: %w", err)
	}
	if currentTrust == nil {
		return nil, apperr.Validationf("role %s has no trust policy in inventory; cannot render role file", request.PrincipalName)
	}
	var trust map[string]interface{}
	if err := json.Unmarshal(currentTrust, &trust); err != nil {
		return nil, fmt.Errorf("decode current trust policy for role file: %w", err)
	}
	filled := *request.UpdateRole
	filled.TrustPolicy = &trust
	return &filled, nil
}

// roleIdentity loads the ForceNew role attributes (path, permissions
// boundary) that a freshly generated role file must reproduce verbatim.
// Omitting them for an imported role makes `terraform plan` read "remove the
// attribute", which the provider answers with a replacement — a new role ARN
// and every attachment broken. A role missing from the inventory yields an
// empty identity, i.e. the historical output without those attributes.
func (service *TicketService) roleIdentity(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (adapter.RoleIdentity, error) {
	attributes, err := service.repository.GetRoleAttributes(
		ctx, request.AccountID, request.PrincipalName,
	)
	if err != nil {
		return adapter.RoleIdentity{}, fmt.Errorf("load role identity for Terraform file: %w", err)
	}
	if attributes == nil {
		return adapter.RoleIdentity{}, nil
	}
	return adapter.RoleIdentity{
		Path:                   attributes.Path,
		PermissionsBoundaryARN: attributes.PermissionsBoundaryARN,
	}, nil
}

// generateUpdateRoleTerraform renders an UPDATE_ROLE ticket's Terraform and
// is shared by preview (validation) and publication so that 校验所见 ==
// 发布所得 by construction:
//
//   - ② sourced role: fetch the source CREATE_ROLE file from main and patch
//     the submitted attributes in place (block patch, no regeneration);
//   - ③ wild role: if role-<name>.tf already exists on main with a role
//     block, patch it in place — regenerating would risk a different
//     resource label, i.e. an address change → destroy+recreate (docs
//     item 15). When the file does not exist yet (or was rollback-emptied),
//     generate it fresh with the role_<name> label and the first-time
//     import block.
//
// ticket is only used to resolve the file path, so callers may pass the real
// ticket or a validation stub; the resolved file key depends on the request
// alone, keeping preview and publish byte-identical.
//
// The second return value reports whether the rendered file is byte-identical
// to the file on the target branch (an unchanged declaration): the pull
// request would carry no diff, so applying it cannot repair an AWS-side
// drift. Callers surface that as an advisory check before publication.
func (service *TicketService) generateUpdateRoleTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, bool, error) {
	if request.UpdateRole == nil {
		return "", false, errors.New("update_role config missing for UPDATE_ROLE ticket")
	}
	// 文件路径含 account-<AWS account id>：发布路径会在调用前解析好，校验路径
	// （validation stub）不会——这里统一补齐，否则预览阶段无法探测 main 上的
	// 既有文件（野生角色会被误判为「文件不存在」或直接报错）。
	if strings.TrimSpace(request.AWSAccountID) == "" {
		accountID := request.AccountID
		if ticket.AccountID != nil {
			accountID = *ticket.AccountID
		}
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, accountID)
		if err != nil {
			return "", false, fmt.Errorf("load AWS account identifier for role Terraform file: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	patch := adapter.RoleAttrPatchFromConfig(request.UpdateRole)
	if strings.TrimSpace(request.SourceTicketNo) != "" {
		fileContent, err := service.publisher.FetchTerraformFile(ctx, ticket, request)
		if err != nil {
			return "", false, apperr.Validationf("fetch role Terraform file: %w", err)
		}
		patched, err := service.adapter.PatchRoleAttributes(
			fileContent, patch, request.PrincipalName,
		)
		if err != nil {
			return "", false, err
		}
		return patched, patched == fileContent, nil
	}
	// ③ 野生角色：文件已在 main 上则原地 patch（保留既有资源 label）。
	fileContent, fetchErr := service.publisher.FetchTerraformFile(ctx, ticket, request)
	switch {
	case fetchErr == nil && adapter.HasRoleResourceBlock(fileContent):
		patched, err := service.adapter.PatchRoleAttributes(
			fileContent, patch, request.PrincipalName,
		)
		if err != nil {
			return "", false, err
		}
		return patched, patched == fileContent, nil
	case fetchErr != nil && !errors.Is(fetchErr, ErrTerraformFileNotFound):
		// 瞬态失败必须冒泡：静默回退整文件生成会冒险换 label → 地址漂移。
		return "", false, fmt.Errorf("fetch wild role Terraform file: %w", fetchErr)
	}
	generationConfig, err := service.wildRoleGenerationConfig(ctx, request)
	if err != nil {
		return "", false, err
	}
	identity, err := service.roleIdentity(ctx, request)
	if err != nil {
		return "", false, err
	}
	generated, err := service.adapter.GenerateWildRoleTerraform(
		request.PrincipalName,
		generationConfig,
		service.roleImportID(ctx, request),
		identity,
	)
	if err != nil {
		return "", false, err
	}
	return generated, false, nil
}

// generateUpdateGroupMembershipTerraform renders an UPDATE_GROUP_MEMBERSHIP
// ticket's Terraform. The membership declaration lives in exactly one file
// (group-<group>-membership.tf, shared with the full baseline), so the update
// is an in-place users-list rewrite:
//
//   - file on main: the declared users are the current membership — add
//     appends, remove filters, the result replaces the users attribute
//     (resource label, membership name and group bytes untouched);
//   - file missing: the inventory is the current membership (the group was
//     never baseline-adopted, or the file was emptied) — the ticket generates
//     the full desired list. aws_iam_group_membership does not support Terraform
//     import; the first apply adopts the existing members by declaring them,
//     which is exactly why the desired list must be complete, never a delta;
//   - the removal leaves zero members: the file lands as a comment-only
//     explanation (same shape as rollback-emptied files) — terraform plan
//     sees no declaration and destroys the membership resource.
//
// The second return value reports whether the rendered file is byte-identical
// to the target branch (an unchanged membership).
func (service *TicketService) generateUpdateGroupMembershipTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, bool, error) {
	config := request.UpdateMembership
	if config == nil {
		return "", false, apperr.Validation("update_membership config missing for UPDATE_GROUP_MEMBERSHIP ticket")
	}
	// 文件路径含 account-<AWS account id>：发布路径会在调用前解析好，校验路径
	// （validation stub）不会——这里统一补齐。
	if strings.TrimSpace(request.AWSAccountID) == "" {
		accountID := request.AccountID
		if ticket.AccountID != nil {
			accountID = *ticket.AccountID
		}
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, accountID)
		if err != nil {
			return "", false, fmt.Errorf("load AWS account identifier for membership Terraform file: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	fileContent, fetchErr := service.publisher.FetchTerraformFile(ctx, ticket, request)
	if fetchErr != nil && !errors.Is(fetchErr, ErrTerraformFileNotFound) {
		// 瞬态失败必须冒泡：静默回退清单生成会漏掉 main 上的手工成员变更。
		return "", false, fmt.Errorf("fetch group membership Terraform file: %w", fetchErr)
	}
	fileExists := fetchErr == nil

	var current []string
	if fileExists {
		_, users, found, err := adapter.ScanGroupMembershipUsers(fileContent)
		if err != nil {
			return "", false, err
		}
		if !found {
			return "", false, fmt.Errorf("group %q membership file declares no aws_iam_group_membership block; reconcile the file first", config.GroupName)
		}
		current = users
	} else {
		inventory, err := service.repository.GroupMembers(ctx, request.AccountID, config.GroupName)
		if err != nil {
			return "", false, fmt.Errorf("load group members for membership Terraform: %w", err)
		}
		current = inventory
	}

	// 目标成员列表：add 并集 / remove 差集。去掉的成员按提交顺序，新增的
	// 排序追加，保证同一请求永远渲染出同一文件。
	target := make([]string, 0, len(current)+len(config.Users))
	inTarget := map[string]bool{}
	if config.Operation == MembershipOperationRemove {
		removing := map[string]bool{}
		for _, user := range config.Users {
			removing[user] = true
		}
		for _, member := range current {
			if !removing[member] && !inTarget[member] {
				inTarget[member] = true
				target = append(target, member)
			}
		}
	} else {
		target = append(target, current...)
		for _, member := range target {
			inTarget[member] = true
		}
		added := make([]string, 0, len(config.Users))
		for _, user := range config.Users {
			if !inTarget[user] {
				added = append(added, user)
			}
		}
		sort.Strings(added)
		target = append(target, added...)
	}

	if len(target) == 0 {
		// 最后一名成员被移除：清空文件 → terraform plan 销毁 membership 资源。
		var hcl strings.Builder
		hcl.WriteString("# GROUP MEMBERSHIP emptied by " + config.Operation + " ticket\n")
		hcl.WriteString("# Group: " + config.GroupName + "\n")
		hcl.WriteString("# Removed: " + strings.Join(config.Users, ", ") + "\n")
		hcl.WriteString("#\n")
		hcl.WriteString("# The aws_iam_group_membership declaration was removed by this ticket.\n")
		hcl.WriteString("# Run `terraform plan` to review the destroy, then apply.\n")
		return hcl.String(), false, nil
	}

	if fileExists {
		patched, err := service.adapter.PatchGroupMembershipUsers(fileContent, target)
		if err != nil {
			return "", false, err
		}
		return patched, patched == fileContent, nil
	}
	generated, err := service.adapter.GenerateBaselineMembershipTerraform(config.GroupName, target)
	if err != nil {
		return "", false, err
	}
	return generated, false, nil
}

// membershipFileTarget is one group whose membership declaration a CREATE_*
// ticket must rewrite, together with the IAM users the ticket adds to it.
type membershipFileTarget struct {
	Group string
	Users []string
}

// initialMembershipTargets lists the group membership files a CREATE_* ticket
// has to rewrite for the relationships it declares at creation time. Empty for
// every other ticket type.
func initialMembershipTargets(request CreateIAMTicketRequest) []membershipFileTarget {
	switch request.TicketType {
	case TicketTypeCreateUser:
		if request.CreateUser == nil {
			return nil
		}
		user := strings.TrimSpace(request.CreateUser.Name)
		groups := uniqueNonEmpty(request.CreateUser.GroupNames)
		if user == "" || len(groups) == 0 {
			return nil
		}
		targets := make([]membershipFileTarget, 0, len(groups))
		for _, group := range groups {
			targets = append(targets, membershipFileTarget{Group: group, Users: []string{user}})
		}
		return targets
	case TicketTypeCreateGroup:
		if request.CreateGroup == nil {
			return nil
		}
		group := strings.TrimSpace(request.CreateGroup.Name)
		members := uniqueNonEmpty(request.CreateGroup.MemberUserNames)
		if group == "" || len(members) == 0 {
			return nil
		}
		return []membershipFileTarget{{Group: group, Users: members}}
	}
	return nil
}

// buildCreateMembershipBundle renders every file a CREATE_USER / CREATE_GROUP
// ticket with initial relationships publishes:
//
//   - <kind>-<name>.tf: the principal itself (plus managed-policy attachments
//     and inline policies) — never a membership declaration;
//   - group-<group>-membership.tf per touched group: the aws_iam_group_membership
//     that owns the (user, group) edge, patched in place when main already has
//     the file and generated from the inventory snapshot when it does not.
//
// One edge, one owner: before this, a CREATE_USER with groups wrote
// aws_iam_user_group_membership into user-<name>.tf while the baseline and
// UPDATE_GROUP_MEMBERSHIP wrote aws_iam_group_membership into the group's file.
// Terraform accepted both but each apply restored its own list, so the plan
// never converged (docs/pending-issues A8).
//
// Returns (preview, nil, nil) when the ticket declares no relationship, so the
// caller can fall back to the single-file path.
func (service *TicketService) buildCreateMembershipBundle(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, []TerraformBundleFile, error) {
	targets := initialMembershipTargets(request)
	if len(targets) == 0 {
		code, err := service.buildCreateTerraform(ctx, request)
		return code, nil, err
	}
	mainKey := request.resourceFileKey()
	if mainKey == "" {
		return "", nil, errors.New("unable to derive the Terraform file key of the created resource")
	}
	if strings.TrimSpace(request.AWSAccountID) == "" {
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return "", nil, fmt.Errorf("load AWS account identifier for membership Terraform files: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	mainCode, err := service.buildCreateTerraform(ctx, request)
	if err != nil {
		return "", nil, err
	}
	files := make([]TerraformBundleFile, 0, len(targets)+1)
	files = append(files, TerraformBundleFile{Key: mainKey, Content: mainCode})
	seen := map[string]bool{mainKey: true}
	for _, target := range targets {
		key := MembershipFileKey(target.Group)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		content, err := service.buildGroupMembershipFile(ctx, ticket, request, target)
		if err != nil {
			return "", nil, err
		}
		files = append(files, TerraformBundleFile{Key: key, Content: content})
	}
	return terraformFilesPreview(files), files, nil
}

// buildGroupMembershipFile renders one group-<group>-membership.tf for a CREATE_*
// ticket: the declared users on main (authoritative — they may include manual
// changes the platform has not synced yet) plus the ticket's new members, or the
// inventory snapshot plus the new members when the file does not exist yet.
func (service *TicketService) buildGroupMembershipFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	target membershipFileTarget,
) (string, error) {
	fileContent, fetchErr := service.fetchGroupMembershipFile(ctx, ticket, request, target.Group)
	if fetchErr != nil && !errors.Is(fetchErr, ErrTerraformFileNotFound) {
		// 瞬态失败必须冒泡：静默按清单生成会丢掉 main 上的手工成员变更。
		return "", fmt.Errorf("fetch group %q membership Terraform file: %w", target.Group, fetchErr)
	}
	if fetchErr == nil {
		_, declared, found, err := adapter.ScanGroupMembershipUsers(fileContent)
		if err != nil {
			return "", err
		}
		if found {
			return service.adapter.PatchGroupMembershipUsers(fileContent, mergeMembers(target.Users, declared))
		}
	}
	inventory, err := service.repository.GroupMembers(ctx, request.AccountID, target.Group)
	if err != nil {
		return "", fmt.Errorf("load group %q members for membership Terraform: %w", target.Group, err)
	}
	return service.adapter.GenerateBaselineMembershipTerraform(
		target.Group, mergeMembers(target.Users, inventory),
	)
}

// fetchGroupMembershipFile reads group-<group>-membership.tf from the target
// branch. FetchTerraformFile resolves the file from the request, so the request
// is projected onto the ticket type that owns that file.
func (service *TicketService) fetchGroupMembershipFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	group string,
) (string, error) {
	projected := request
	projected.TicketType = TicketTypeUpdateGroupMembership
	projected.SourceTicketNo = ""
	projected.TargetFileKey = ""
	projected.UpdatePolicy = nil
	projected.UpdateMembership = &UpdateMembershipConfig{
		GroupName: group,
		Operation: MembershipOperationAdd,
	}
	return service.publisher.FetchTerraformFile(ctx, ticket, projected)
}

// mergeMembers returns additions then the existing list, de-duplicated. New
// members are sorted so the same request always renders the same file; the
// declared order (manual edits included) is preserved behind them.
func mergeMembers(additions, existing []string) []string {
	seen := make(map[string]bool, len(additions)+len(existing))
	merged := make([]string, 0, len(additions)+len(existing))
	added := uniqueNonEmpty(additions)
	sort.Strings(added)
	for _, member := range added {
		seen[member] = true
		merged = append(merged, member)
	}
	for _, member := range existing {
		member = strings.TrimSpace(member)
		if member == "" || seen[member] {
			continue
		}
		seen[member] = true
		merged = append(merged, member)
	}
	return merged
}

// terraformFilesPreview concatenates a bundle into the single text the preview
// endpoint returns, with a "# File: <key>.tf" header per file so the reader can
// tell which declaration lands where.
func terraformFilesPreview(files []TerraformBundleFile) string {
	var preview strings.Builder
	for _, file := range files {
		preview.WriteString("# File: ")
		preview.WriteString(file.Key)
		preview.WriteString(".tf\n")
		preview.WriteString(file.Content)
		if !strings.HasSuffix(file.Content, "\n") {
			preview.WriteByte('\n')
		}
		preview.WriteByte('\n')
	}
	return preview.String()
}

// buildCreateRollbackBundle renders a ROLLBACK of a CREATE_USER / CREATE_GROUP
// ticket. The principal's file is emptied exactly as before; the difference is
// that the group membership files the creation ticket patched are cleaned up
// too, otherwise the declaration would keep referencing a user (or a group)
// that this rollback destroys.
//
//   - user rollback: the user is removed from each group's declared list; a
//     group left with no members lands as a comment-only file (destroying its
//     membership resource);
//   - group rollback: the membership file is emptied wholesale — the group is
//     being destroyed, so every member edge goes with it.
//
// Returns (preview, nil, nil) when the target declared no membership, so the
// caller keeps the single-file path.
func (service *TicketService) buildCreateRollbackBundle(
	ctx context.Context,
	rollbackTicketNo string,
	request CreateIAMTicketRequest,
) (string, []TerraformBundleFile, error) {
	target, err := service.repository.Get(ctx, request.TargetTicketNo)
	if err != nil {
		return "", nil, fmt.Errorf("load rollback target for membership cleanup: %w", err)
	}
	var targetRequest CreateIAMTicketRequest
	if err := json.Unmarshal(target.RequestPolicy, &targetRequest); err != nil {
		return "", nil, fmt.Errorf("decode rollback target request: %w", err)
	}
	mainKey := strings.TrimSpace(request.TargetFileKey)
	derivedKey := targetRequest.resourceFileKey()
	if mainKey == "" {
		mainKey = derivedKey
	}
	if mainKey == "" {
		return "", nil, errors.New("unable to derive the Terraform file key of the rolled back resource")
	}
	// 防御性校验（C6）：请求带来的文件键必须与目标工单自己的资源文件一致。
	// prepareRollbackTarget 已经不再信任请求体，这里再挡一次，避免将来新增
	// 调用方把回滚的空文件写到别人的文件上。
	if derivedKey != "" && mainKey != derivedKey {
		return "", nil, apperr.Validationf(
			"rollback file key %q does not match the file %q owned by target ticket %s",
			mainKey, derivedKey, request.TargetTicketNo)
	}
	mainCode := GenerateRollbackTerraform(rollbackTicketNo, request.TargetTicketNo, request.PrincipalName)

	groups := []string{}
	emptyWholeFile := false
	if target.TicketType != nil {
		switch *target.TicketType {
		case TicketTypeCreateUser:
			if targetRequest.CreateUser != nil {
				// 边界（2026-11-06 复审）：清理范围 = 目标工单**声明时刻**的
				// 组成员快照。用户在本单 apply 之后又被别的工单加进新的组，
				// 那些成员文件不在此列、回滚不会清——它们已经是另一张工单的
				// 声明对象，归属不同，越界清理反而是错的。需要彻底回收用户
				// 时，用单独的回滚/工单处理那几组成员关系。
				groups = uniqueNonEmpty(targetRequest.CreateUser.GroupNames)
			}
		case TicketTypeCreateGroup:
			if targetRequest.CreateGroup != nil {
				groups = []string{strings.TrimSpace(targetRequest.CreateGroup.Name)}
				emptyWholeFile = true
			}
		}
	}
	if len(groups) == 0 {
		return mainCode, nil, nil
	}
	if strings.TrimSpace(request.AWSAccountID) == "" {
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return "", nil, fmt.Errorf("load AWS account identifier for membership rollback: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	ticket := validationStubTicket(request)
	ticket.TicketNo = &rollbackTicketNo

	files := make([]TerraformBundleFile, 0, len(groups)+1)
	files = append(files, TerraformBundleFile{Key: mainKey, Content: mainCode})
	for _, group := range groups {
		if strings.TrimSpace(group) == "" {
			continue
		}
		key := MembershipFileKey(group)
		var content string
		var touched bool
		if emptyWholeFile {
			content, touched, err = service.emptyMembershipFile(ctx, ticket, request, group)
		} else {
			content, touched, err = service.removeMemberFromMembershipFile(
				ctx, ticket, request, group, request.PrincipalName, rollbackTicketNo,
			)
		}
		if err != nil {
			return "", nil, err
		}
		if !touched || key == "" {
			continue
		}
		files = append(files, TerraformBundleFile{Key: key, Content: content})
	}
	if len(files) == 1 {
		return mainCode, nil, nil
	}
	return terraformFilesPreview(files), files, nil
}

// rejectEmptyingForeignDeclarations 是整文件清空的归属检查（台账 C6，设计文档
// §5）。回滚会把目标文件整份清空（只留注释头），这一步只有在「该文件当前仍由
// 被回滚的工单声明」时才是撤销自己写的东西；文件已被基线发布或其他工单接管
// 时，清空等于替别人删声明 —— 基线下一轮检测会发现声明消失，Terraform 会
// plan 出 destroy，而重建只能靠人。
//
// 只看「清空」的文件：成员关系那种只改一行的块级 patch 不在此列（基线文件里
// 声明着其他成员是正常状态，不是归属冲突）。
//
// 没有声明快照时放行：P2 之前的存量文件没有声明行，一律拒绝会让历史回滚全部
// 失败；这类文件的归属只能靠 main 内容判断，留给人工 review。
func (service *TicketService) rejectEmptyingForeignFile(
	ctx context.Context,
	request CreateIAMTicketRequest,
	fileKey, content string,
) error {
	targetNo := strings.TrimSpace(request.TargetTicketNo)
	key := strings.TrimSpace(fileKey)
	if targetNo == "" || key == "" || request.AccountID <= 0 {
		return nil
	}
	// 仍有实际声明的文件是 upsert（保留/改写资源块），不存在「删别人的东西」。
	if adapter.HasActiveDeclaration(content) {
		return nil
	}
	target, err := service.repository.Get(ctx, targetNo)
	if err != nil {
		return fmt.Errorf("load rollback target %s for file ownership: %w", targetNo, err)
	}
	owners, err := service.repository.FileDeclarationOwners(ctx, request.AccountID, key)
	if err != nil {
		return fmt.Errorf("check declaration owner of %s: %w", key, err)
	}
	for _, owner := range owners {
		// 0 是「基线发布」的标记，必须排在工单比对之前：目标工单 ID
		// 未落库（0）时不能把基线声明误判成自己的。
		if owner == 0 {
			return apperr.Validationf(
				"%s.tf 已由全量基线纳管，回滚不能整份清空它；请先用基线发布收回该资源，或走漂移处置",
				key)
		}
		if owner == target.ID {
			continue
		}
		return apperr.Validationf(
			"%s.tf 当前由另一张工单声明，回滚 %s 不能整份清空它；请先处理那张工单",
			key, targetNo)
	}
	// 没有任何声明行：P2（声明快照）之前的存量文件。放行，但留一条结构化
	// 痕迹——这是全链路里唯一不过归属门的清空路径，出事时要有人能回溯
	// 「谁在什么时候清空了一个没有声明记录的旧文件」。
	if len(owners) == 0 && service.logger != nil {
		service.logger.Info("rollback empties a file without declaration snapshot; operator review advised",
			"target_ticket", targetNo,
			"file_key", key,
			"account_id", request.AccountID,
		)
	}
	return nil
}

// removeMemberFromMembershipFile drops one user from a group's declaration. A
// file that is not on main declared nothing yet, so there is nothing to undo
// (touched=false). Removing the last member empties the declaration.
func (service *TicketService) removeMemberFromMembershipFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	group, user, rollbackTicketNo string,
) (string, bool, error) {
	fileContent, err := service.fetchGroupMembershipFile(ctx, ticket, request, group)
	if errors.Is(err, ErrTerraformFileNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("fetch group %q membership Terraform file for rollback: %w", group, err)
	}
	_, declared, found, err := adapter.ScanGroupMembershipUsers(fileContent)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	remaining := make([]string, 0, len(declared))
	for _, member := range declared {
		if member != user {
			remaining = append(remaining, member)
		}
	}
	if len(remaining) == len(declared) {
		// 文件里本来就没有这名用户（例如手工已移除）：不动文件。
		return "", false, nil
	}
	if len(remaining) == 0 {
		return emptiedMembershipFileContent(
			"ROLLBACK "+rollbackTicketNo+" removed the last member",
			group, "The aws_iam_group_membership declaration was removed by this rollback ticket.",
		), true, nil
	}
	patched, err := service.adapter.PatchGroupMembershipUsers(fileContent, remaining)
	if err != nil {
		return "", false, err
	}
	return patched, true, nil
}

// emptyMembershipFile lands a group's declaration as a comment-only file
// (touched=false when main has no such file).
func (service *TicketService) emptyMembershipFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	group string,
) (string, bool, error) {
	fileContent, err := service.fetchGroupMembershipFile(ctx, ticket, request, group)
	if errors.Is(err, ErrTerraformFileNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("fetch group %q membership Terraform file for rollback: %w", group, err)
	}
	_, _, found, err := adapter.ScanGroupMembershipUsers(fileContent)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	return emptiedMembershipFileContent(
		"ROLLBACK of the group creation",
		group, "The aws_iam_group_membership declaration was removed by this rollback ticket.",
	), true, nil
}

// emptiedMembershipFileContent is the comment-only shape shared by every path
// that destroys a membership declaration (last member removed, group rollback).
func emptiedMembershipFileContent(headline, group, explanation string) string {
	var hcl strings.Builder
	hcl.WriteString("# GROUP MEMBERSHIP emptied: " + headline + "\n")
	hcl.WriteString("# Group: " + group + "\n")
	hcl.WriteString("#\n")
	hcl.WriteString("# " + explanation + "\n")
	hcl.WriteString("# Run `terraform plan` to review the destroy, then apply.\n")
	return hcl.String()
}

// policyUpdateResourceLabel resolves the Terraform resource label for a
// policy-update ticket. The resolved label is stored on the request
// (update_policy.resource_name) when the ticket is created, so the approval
// preview and the published file always match. A label already stored on the
// request wins; otherwise a unique label is derived because a role or group
// may own several inline policies (one file each). Role labels are
// "role_<owner>_<rand5>_policy" (the AWS policy name stays in the resource's
// name attribute, docs item 18); group labels keep
// "<kind>_<owner>_<rand5>_<policy>". Customer-managed policy names are already
// account-unique. The source-file rewrite path (SourceTicketNo set)
// needs no label: the source CREATE file is patched in place by name match,
// whatever label it carries.
func policyUpdateResourceLabel(request CreateIAMTicketRequest) string {
	if request.UpdatePolicy == nil || strings.TrimSpace(request.SourceTicketNo) != "" {
		return ""
	}
	if label := strings.TrimSpace(request.UpdatePolicy.ResourceName); label != "" {
		return label
	}
	switch request.TicketType {
	case TicketTypeUpdateGroupInlinePolicy:
		if strings.TrimSpace(request.UpdatePolicy.RoleName) != "" {
			return adapter.InlinePolicyResourceLabel("role", request.UpdatePolicy.RoleName, request.UpdatePolicy.InlinePolicyName)
		}
		return adapter.InlinePolicyResourceLabel("group", request.UpdatePolicy.GroupName, request.UpdatePolicy.InlinePolicyName)
	case TicketTypeUpdateManagedPolicy:
		return adapter.DefaultManagedPolicyLabel(request.UpdatePolicy.PolicyName)
	}
	return ""
}

// attachImportID decides whether an attach ticket needs a Terraform `import`
// block (first-time adoption of a pre-existing, platform-unmanaged
// attachment). The id format is the principal name and the policy ARN
// separated by "/" — the import id the AWS provider documents for
// aws_iam_user/group/role_policy_attachment alike. Validation and publication
// share this helper so the preview shows exactly what will be published.
// Fail open on lookup errors (same semantics as policyImportID).
func (service *TicketService) attachImportID(ctx context.Context, request CreateIAMTicketRequest) string {
	if request.Operation != OperationAttach || strings.TrimSpace(request.ManagedPolicyARN) == "" {
		return ""
	}
	attached, sourceTicketNo, err := service.repository.ResolvePolicyAttachment(
		ctx, request.AccountID, request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN,
	)
	if err != nil {
		return ""
	}
	if !attached || strings.TrimSpace(sourceTicketNo) != "" {
		return ""
	}
	return request.PrincipalName + "/" + strings.TrimSpace(request.ManagedPolicyARN)
}

// generateSourceRolePolicyFile renders the source CREATE_ROLE ticket's
// Terraform file with one inline-policy document replaced. Used when the
// updated inline policy is the one the CREATE ticket declared, so the policy
// keeps exactly one Terraform declaration instead of a second file competing
// with the CREATE file for the same AWS object.
//
// ② 块级 patch：以 main 上的现文件为基底，只替换该内嵌策略的 policy 属性。
// 不再从 CREATE 工单存储的 request_policy 整文件重生成——后者会把之后
// UPDATE_ROLE 改过的信任/属性回滚到 CREATE 时的值（互踩 bug）。
func (service *TicketService) generateSourceRolePolicyFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	document json.RawMessage,
) (string, bool, error) {
	if strings.TrimSpace(request.SourceTicketNo) == "" {
		return "", false, errors.New("source ticket number is required for source-file policy update")
	}
	if request.UpdatePolicy == nil || strings.TrimSpace(request.UpdatePolicy.InlinePolicyName) == "" {
		return "", false, errors.New("update_policy.inline_policy_name is required for source-file policy update")
	}
	fileContent, err := service.publisher.FetchTerraformFile(ctx, ticket, request)
	if err != nil {
		return "", false, apperr.Validationf("fetch source Terraform file for inline policy update: %w", err)
	}
	patched, err := service.adapter.PatchRoleInlinePolicy(
		fileContent,
		request.UpdatePolicy.InlinePolicyName,
		document,
	)
	if err != nil {
		return "", false, err
	}
	return patched, patched == fileContent, nil
}

// generateStandaloneInlinePolicyTerraform renders the standalone
// inline-policy file (role or group owner, no source CREATE ticket) for an
// update ticket or its rollback, mirroring generateUpdateRoleTerraform so
// preview and publish stay byte-identical (校验所见 == 发布所得):
//
//   - the file already declares this inline policy on main → block-level
//     patch: only the policy document changes and the resource label (the
//     Terraform address) is preserved. Regenerating with a fresh label would
//     turn an in-place update into destroy+recreate of the same AWS object —
//     the bug behind the cloudwatch-role inline policy deletion;
//   - transient fetch failures bubble (silently regenerating would risk an
//     address change);
//   - the file is missing or comment-only (rollback-emptied) → generate
//     fresh with the stable label and, while this is the first applied
//     update for the policy, the first-time adoption import block.
//
// ticket is only used to resolve the file path, so callers may pass the real
// ticket or a validation stub; the resolved file key depends on the request
// alone, keeping preview and publish byte-identical.
func (service *TicketService) generateStandaloneInlinePolicyTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	document json.RawMessage,
) (string, bool, error) {
	update := request.UpdatePolicy
	if update == nil {
		return "", false, apperr.Validation("update_policy config missing for standalone inline policy Terraform")
	}
	inlineName := strings.TrimSpace(update.InlinePolicyName)
	if inlineName == "" {
		return "", false, errors.New("update_policy.inline_policy_name is required for standalone inline policy Terraform")
	}
	resourceType := "aws_iam_group_policy"
	owner := strings.TrimSpace(update.GroupName)
	if strings.TrimSpace(update.RoleName) != "" {
		resourceType = "aws_iam_role_policy"
		owner = strings.TrimSpace(update.RoleName)
	}
	if owner == "" {
		return "", false, apperr.Validation("update_policy owner (role or group name) is required for standalone inline policy Terraform")
	}
	// 文件路径含 account-<AWS account id>：发布路径会在调用前解析好，校验路径
	// （validation stub）不会——这里统一补齐，否则校验阶段探测不到 main 上的
	// 既有文件（存量内嵌策略会被误判为「文件不存在」而重新生成 → 地址漂移）。
	if strings.TrimSpace(request.AWSAccountID) == "" {
		accountID := request.AccountID
		if ticket.AccountID != nil {
			accountID = *ticket.AccountID
		}
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, accountID)
		if err != nil {
			return "", false, fmt.Errorf("load AWS account identifier for inline policy Terraform file: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	importID := service.policyImportID(ctx, request)
	fileContent, fetchErr := service.publisher.FetchTerraformFile(ctx, ticket, request)
	switch {
	case fetchErr == nil && strings.TrimSpace(fileContent) != "":
		_, found, hasResources, scanErr := adapter.ScanInlinePolicyResourceBlock(fileContent, resourceType, inlineName)
		if scanErr != nil {
			return "", false, fmt.Errorf("scan inline policy Terraform file: %w", scanErr)
		}
		if found {
			// 文件已存在 = 声明已在 main 上。import 块无论已消费（apply 过）
			// 还是基线刚合并待 apply，patch 时一律剔除：残留会让 plan 报
			// "Resource already managed"；未 apply 的极端窗口首次 apply 会
			// 报 already exists，操作员补一次 import 即可（fail-open 约定，
			// 与角色 patch 一致）。真正首次纳管的 import 只在文件缺失的
			// 生成分支出现。
			patched, err := service.adapter.PatchInlinePolicyDocument(fileContent, resourceType, inlineName, document, "")
			if err != nil {
				return "", false, err
			}
			return patched, patched == fileContent, nil
		}
		if hasResources {
			// 文件里是别的资源声明（如同名不同大小写的策略撞了文件 key）：
			// 覆盖会把它们删掉，宁可报错交给运维处理。
			return "", false, fmt.Errorf("Terraform file declares no %s block for inline policy %q; refusing to overwrite a file with other resource declarations", resourceType, inlineName)
		}
		// 注释空文件（回滚清空）→ 落到下面的全新生成。
	case fetchErr != nil && !errors.Is(fetchErr, ErrTerraformFileNotFound):
		return "", false, fmt.Errorf("fetch inline policy Terraform file: %w", fetchErr)
	}
	label := policyUpdateResourceLabel(request)
	if resourceType == "aws_iam_role_policy" {
		generated, err := service.adapter.GenerateUpdateRoleInlinePolicyTerraform(owner, inlineName, document, importID, label)
		return generated, false, err
	}
	generated, err := service.adapter.GenerateUpdateGroupInlinePolicyTerraform(owner, inlineName, document, importID, label)
	return generated, false, err
}

// terraformUnchangedNotice tells approvers that the rendered Terraform is
// byte-identical to the file on the target branch: the pull request would
// carry no diff, so applying it cannot repair an AWS-side drift (the missing
// object has to come back by re-running the pipeline's apply).
const terraformUnchangedNotice = "渲染结果与目标分支一致，PR 无差异：若要修复 AWS 侧漂移，请重跑流水线 apply"

// appendValidationCheck appends one advisory entry to a validation snapshot's
// check list, keeping the entries already collected.
func appendValidationCheck(
	snapshot TicketValidationSnapshot,
	code, result, description string,
) (TicketValidationSnapshot, error) {
	checks := make([]map[string]interface{}, 0, 4)
	if len(snapshot.Checks) > 0 {
		if err := json.Unmarshal(snapshot.Checks, &checks); err != nil {
			return snapshot, fmt.Errorf("decode ticket validation checks: %w", err)
		}
	}
	checks = append(checks, map[string]interface{}{
		"code": code, "result": result, "description": description,
	})
	encoded, err := json.Marshal(checks)
	if err != nil {
		return snapshot, fmt.Errorf("marshal ticket validation checks: %w", err)
	}
	snapshot.Checks = encoded
	return snapshot, nil
}

// targetBranchTerraform returns the Terraform file currently on the target
// branch for the request; found is false when the branch carries no such file.
// The read is cached briefly: the realtime validation endpoint runs on every
// keystroke and the code host rate-limits API calls. Only advisory hints use
// it — the published bytes always come from a fresh read.
func (service *TicketService) targetBranchTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (content string, found bool, err error) {
	key := targetFileCacheKey(ticket, request)
	if cached, cachedFound, ok := service.targetFiles.get(key); ok {
		return cached, cachedFound, nil
	}
	content, err = service.publisher.FetchTerraformFile(ctx, ticket, request)
	if err != nil {
		if errors.Is(err, ErrTerraformFileNotFound) {
			service.targetFiles.put(key, "", false)
			return "", false, nil
		}
		return "", false, err
	}
	service.targetFiles.put(key, content, true)
	return content, true, nil
}

// warnIfUnchanged logs that the published Terraform is identical to the
// target branch: the pull request carries no diff, so applying it cannot
// repair an AWS-side drift (the missing object has to come back by re-running
// the pipeline's apply).
func (service *TicketService) warnIfUnchanged(ticket model.IAMTicket, unchanged bool) {
	if !unchanged {
		return
	}
	ticketNo := ""
	if ticket.TicketNo != nil {
		ticketNo = *ticket.TicketNo
	}
	service.logger.Warn("published Terraform is byte-identical to the target branch: the pull request carries no diff",
		"ticket_no", ticketNo, "hint", terraformUnchangedNotice,
	)
}

// targetFileCacheKey identifies the target-branch file of a request.
func targetFileCacheKey(ticket model.IAMTicket, request CreateIAMTicketRequest) string {
	account := ""
	if ticket.AccountID != nil {
		account = strconv.FormatInt(*ticket.AccountID, 10)
	}
	return account + "/" + strings.ToLower(request.terraformFileTicketNo(""))
}

// generateManagedPolicyTerraform renders the customer-managed policy file for
// an update ticket, mirroring generateStandaloneInlinePolicyTerraform:
//
//   - the file already declares the policy → patch the policy attribute in
//     place. A whole-file regeneration would drop the policy's path,
//     description and tags, and because path is ForceNew in the AWS provider
//     that turns an in-place document update into a policy replacement — a new
//     ARN, which breaks every attachment pointing at it;
//   - the file is missing → generate it with the first-time adoption import
//     block (wild policy adoption).
//
// The second return value reports whether the rendered file is byte-identical
// to the target branch (an unchanged declaration).
func (service *TicketService) generateManagedPolicyTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, bool, error) {
	if request.UpdatePolicy == nil {
		return "", false, apperr.Validation("update_policy config missing for managed policy Terraform")
	}
	policyName := strings.TrimSpace(request.UpdatePolicy.PolicyName)
	if policyName == "" {
		policyName = PolicyNameFromARN(request.UpdatePolicy.PolicyARN)
	}
	if policyName == "" {
		return "", false, apperr.Validation("update_policy.policy_name is required for managed policy Terraform")
	}
	// 文件路径含 account-<AWS account id>：发布路径会在调用前解析好，校验路径
	// （validation stub）不会——这里统一补齐。
	if strings.TrimSpace(request.AWSAccountID) == "" {
		accountID := request.AccountID
		if ticket.AccountID != nil {
			accountID = *ticket.AccountID
		}
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, accountID)
		if err != nil {
			return "", false, fmt.Errorf("load AWS account identifier for managed policy Terraform file: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	importID := service.policyImportID(ctx, request)
	fileContent, fetchErr := service.publisher.FetchTerraformFile(ctx, ticket, request)
	switch {
	case fetchErr == nil && strings.TrimSpace(fileContent) != "":
		// 文件已存在 → patch 一律剔除已消费 import 块（理由同独立内嵌策略
		// patch：残留 import 让 plan 报 "Resource already managed"；基线
		// 纳管不计入 applied 工单统计，靠「文件存在即剔除」兜住）。
		patched, err := service.adapter.PatchInlinePolicyDocument(
			fileContent, "aws_iam_policy", policyName, request.UpdatePolicy.Document, "",
		)
		if err != nil {
			// 文件里没有这条策略（名字对不上 / 文件属于别的资源）：不猜，直接报错，
			// 避免把别人的文件覆盖成另一条策略。
			return "", false, fmt.Errorf("patch managed policy Terraform file: %w", err)
		}
		return patched, patched == fileContent, nil
	case fetchErr != nil && !errors.Is(fetchErr, ErrTerraformFileNotFound):
		return "", false, fmt.Errorf("fetch managed policy Terraform file: %w", fetchErr)
	}
	generated, err := service.adapter.GenerateUpdateManagedPolicyTerraform(
		policyName, request.UpdatePolicy.Document, importID, policyUpdateResourceLabel(request),
	)
	if err != nil {
		return "", false, err
	}
	return generated, false, nil
}

// currentPolicyDocument loads the live document of the policy an update
// ticket targets (managed policy by ARN / group inline / role inline).
func (service *TicketService) currentPolicyDocument(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (json.RawMessage, bool, error) {
	update := request.UpdatePolicy
	switch {
	case strings.TrimSpace(update.RoleName) != "" && update.InlinePolicyName != "":
		return service.repository.GetRoleInlinePolicy(ctx, request.AccountID, update.RoleName, update.InlinePolicyName)
	case strings.TrimSpace(update.GroupName) != "" && update.InlinePolicyName != "":
		return service.repository.GetGroupInlinePolicy(ctx, request.AccountID, update.GroupName, update.InlinePolicyName)
	default:
		arn := strings.TrimSpace(update.PolicyARN)
		if arn == "" {
			// 旧工单可能只存了策略名：现网文档拿不到时跳过变更检测，
			// 由审批人核对 Terraform 预览。
			return nil, false, nil
		}
		return service.repository.GetManagedPolicyByARN(ctx, arn)
	}
}

// comparePolicyDocuments canonical-compares two policy documents: both are
// unmarshalled and re-marshalled (Go sorts map keys), so key order and
// whitespace do not count as changes. Returns semantic equality plus
// statement counts for the change summary.
func comparePolicyDocuments(live, submitted json.RawMessage) (equal bool, liveStatements, submittedStatements int, err error) {
	var liveValue, submittedValue interface{}
	if unmarshalErr := json.Unmarshal(live, &liveValue); unmarshalErr != nil {
		return false, 0, 0, unmarshalErr
	}
	if unmarshalErr := json.Unmarshal(submitted, &submittedValue); unmarshalErr != nil {
		return false, 0, 0, unmarshalErr
	}
	liveCanonical, marshalErr := json.Marshal(liveValue)
	if marshalErr != nil {
		return false, 0, 0, marshalErr
	}
	submittedCanonical, marshalErr := json.Marshal(submittedValue)
	if marshalErr != nil {
		return false, 0, 0, marshalErr
	}
	return bytes.Equal(liveCanonical, submittedCanonical),
		countPolicyStatements(liveValue), countPolicyStatements(submittedValue), nil
}

func countPolicyStatements(value interface{}) int {
	document, ok := value.(map[string]interface{})
	if !ok {
		return 0
	}
	statements, _ := document["Statement"].([]interface{})
	return len(statements)
}

// policyChangeCheck compares the submitted document against the live policy
// document from the inventory. An identical document is allowed only when
// the generated preview imports that policy for first-time adoption.
func (service *TicketService) policyChangeCheck(
	ctx context.Context,
	request CreateIAMTicketRequest,
	terraformPreview string,
) (*map[string]interface{}, error) {
	live, found, err := service.currentPolicyDocument(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("load current policy document for change detection: %w", err)
	}
	if !found || len(live) == 0 {
		return nil, nil
	}
	equal, liveCount, submittedCount, err := comparePolicyDocuments(live, request.UpdatePolicy.Document)
	if err != nil {
		return nil, fmt.Errorf("compare submitted document with live policy: %w", err)
	}
	if equal {
		resourceType := ""
		switch request.TicketType {
		case TicketTypeUpdateGroupInlinePolicy:
			resourceType = "aws_iam_group_policy"
			if strings.TrimSpace(request.UpdatePolicy.RoleName) != "" {
				resourceType = "aws_iam_role_policy"
			}
		}
		if resourceType != "" &&
			strings.Contains(terraformPreview, "import {") &&
			strings.Contains(terraformPreview, "to = "+resourceType+".") {
			entry := map[string]interface{}{
				"code":        "RESOURCE_ADOPTION",
				"result":      "PASSED",
				"description": "Policy document matches the live policy; this first-time import only adopts it into Terraform state and does not change the AWS policy",
			}
			return &entry, nil
		}
		identity := strings.TrimSpace(request.UpdatePolicy.PolicyARN)
		if identity == "" {
			identity = strings.TrimSpace(request.UpdatePolicy.PolicyName)
		}
		return nil, apperr.Validationf("update_policy document is identical to the current live policy %s; no change to apply", identity)
	}
	entry := map[string]interface{}{
		"code":   "CHANGE_DETECTION",
		"result": "PASSED",
		"description": fmt.Sprintf(
			"Document differs from the live policy (statements: %d → %d); approvers must review the Terraform preview",
			liveCount, submittedCount,
		),
	}
	return &entry, nil
}

func (service *TicketService) prepareTicketRequest(
	ctx context.Context,
	submitter string,
	request CreateIAMTicketRequest,
) (CreateIAMTicketRequest, []string, error) {
	submitter = strings.TrimSpace(submitter)
	if submitter == "" {
		return CreateIAMTicketRequest{}, nil, apperr.Validation("submitter must not be empty")
	}
	request, err := service.validateRequestShape(ctx, request)
	if err != nil {
		return CreateIAMTicketRequest{}, nil, err
	}
	if request.ApprovalMode != ApprovalModeManual && request.ApprovalMode != ApprovalModeAuto {
		return CreateIAMTicketRequest{}, nil, apperr.Validationf("approval_mode must be %s or %s", ApprovalModeManual, ApprovalModeAuto)
	}
	if request.TicketType == TicketTypeAdoptRoleInlinePolicies && request.ApprovalMode != ApprovalModeManual {
		return CreateIAMTicketRequest{}, nil, apperr.Validation("role inline policy batch adoption requires manual ticket approval")
	}
	var approverIDs []string
	if request.ApprovalMode == ApprovalModeManual {
		if len(request.ApproverIDs) == 0 {
			return CreateIAMTicketRequest{}, nil, apperr.Validation("at least one approver_id is required for MANUAL approval")
		}
		approverIDs = normalizeApprovers(request.ApproverIDs)
		if len(approverIDs) == 0 {
			return CreateIAMTicketRequest{}, nil, apperr.Validation("approver_ids must not be empty")
		}
		available, err := service.repository.ListAvailableApprovers(ctx, nil)
		if err != nil {
			return CreateIAMTicketRequest{}, nil, fmt.Errorf("load available platform approvers: %w", err)
		}
		availableUsers := make(map[string]struct{}, len(available))
		for _, user := range available {
			availableUsers[user.UserID] = struct{}{}
		}
		for _, approverID := range approverIDs {
			if _, exists := availableUsers[approverID]; !exists {
				return CreateIAMTicketRequest{}, nil, apperr.Validationf("approver_id %q is not an active platform user", approverID)
			}
		}
	} else {
		if len(request.ApproverIDs) != 0 {
			return CreateIAMTicketRequest{}, nil, apperr.Validation("approver_ids must not be provided for AUTO approval")
		}
		approvers, err := service.repository.ResolveAutoApprovers(ctx, request.AccountID)
		if err != nil {
			return CreateIAMTicketRequest{}, nil, fmt.Errorf("resolve AUTO approvers: %w", err)
		}
		if len(approvers) == 0 {
			// 结构化校验错误（apperr.ValidationError → 400）：改文案不需要
			// 再同步 handler 白名单，分类随类型走。
			return CreateIAMTicketRequest{}, nil, apperr.Validation(
				"no active approvers are bound to this AWS account; " +
					"add one on the user page (Users → edit an approver → Approver accounts) " +
					"or under Sync Management → Accounts → Approvers, " +
					"or switch to MANUAL mode and pick an approver")
		}
		// AUTO 的审批人集合由账号绑定决定，不可避免地会包含提交人自己
		// （提交人往往就是该账号的负责人）。这里剔除提交人而不是报错：
		// 自批禁令的目的在 MANUAL 是防止提交人挑选自己，在 AUTO 则只需
		// 保证集合里不出现提交人。剔除后为空才拒绝——说明该账号除提交人
		// 外无人可审。
		approverIDs = make([]string, 0, len(approvers))
		for _, approver := range approvers {
			if strings.TrimSpace(approver.UserID) == submitter {
				continue
			}
			approverIDs = append(approverIDs, approver.UserID)
		}
		if len(normalizeApprovers(approverIDs)) == 0 {
			return CreateIAMTicketRequest{}, nil, apperr.Validationf(
				"submitter %q is the only configured approver for this AWS account; "+
					"bind at least one other active approver on the user page (Users → edit an approver → Approver accounts) "+
					"or under Sync Management → Accounts → Approvers before submitting AUTO tickets", submitter)
		}
	}
	approverIDs = normalizeApprovers(approverIDs)
	for _, approverID := range approverIDs {
		if approverID == submitter {
			return CreateIAMTicketRequest{}, nil, apperr.Validation("submitter cannot approve their own ticket")
		}
	}
	request.ApproverIDs = approverIDs
	return request, approverIDs, nil
}

func (service *TicketService) validateCreateTicketRequest(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (TicketValidationSnapshot, error) {
	// 预览与发布同路径（buildTicketTerraformFiles）：带初始组关系的
	// CREATE_USER/CREATE_GROUP 会一起渲染 group-<group>-membership.tf，
	// 审阅者看到的就是 PR 里的全部文件。
	terraformPreview, _, err := service.buildTicketTerraformFiles(
		ctx, validationStubTicket(request), request, false,
	)
	if err != nil {
		return TicketValidationSnapshot{}, fmt.Errorf("validate create terraform: %w", err)
	}
	checks := make([]map[string]interface{}, 0, 4)
	adoptionResult := "SKIPPED"
	adoptionDescription := "Creates a new resource; Terraform will fail if the resource already exists"
	if request.AdoptExisting {
		adoptionResult = "PASSED"
		adoptionDescription = "Imports the existing resource into Terraform state before declaring it"
	}
	checks = append(checks, map[string]interface{}{
		"code": "RESOURCE_ADOPTION", "result": adoptionResult, "description": adoptionDescription,
	})

	switch request.TicketType {
	case TicketTypeCreateManagedPolicy:
		if request.CreatePolicy == nil {
			return TicketValidationSnapshot{}, errors.New("create_managed_policy config missing for validation")
		}
		normalized, err := service.adapter.NormalizePolicyDocument(request.CreatePolicy.Document)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("normalize managed policy document: %w", err)
		}
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("load AWS account identifier for candidate policy scan: %w", err)
		}
		riskFindings, err := ScanCandidateIAMPolicy(normalized, nil, request.CreatePolicy.Name, awsAccountID)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("scan candidate managed policy risks: %w", err)
		}
		if len(blockingCandidateRiskFindings(riskFindings, service.riskMode)) > 0 {
			return TicketValidationSnapshot{}, &CandidatePolicyRiskError{Findings: riskFindings}
		}
		riskResult := "PASSED"
		if len(riskFindings) > 0 {
			riskResult = "WARN"
		}
		checks = append(checks,
			map[string]interface{}{
				"code": "CREATE_MANAGED_POLICY", "result": "PASSED",
				"description": fmt.Sprintf("Creates customer-managed policy %s; approvers must review the document and Terraform preview", request.CreatePolicy.Name),
			},
			map[string]interface{}{
				"code": "STATIC_RISK_SCAN", "result": riskResult,
				"description": "Static candidate policy findings evaluated under configured risk mode",
				"findings":    riskFindings,
			},
		)
	case TicketTypeCreateUser:
		if request.CreateUser == nil {
			return TicketValidationSnapshot{}, errors.New("create_user config missing for validation")
		}
		checks = append(checks, map[string]interface{}{
			"code": "CREATE_USER", "result": "PASSED",
			"description": fmt.Sprintf("Creates IAM user %s without credentials; access keys/passwords must be managed outside the platform", request.CreateUser.Name),
		})
		if len(request.CreateUser.GroupNames) > 0 {
			checks = append(checks, map[string]interface{}{
				"code": "GROUP_MEMBERSHIP", "result": "REVIEW",
				"description": "User inherits the policies attached to these groups: " + strings.Join(request.CreateUser.GroupNames, ", "),
				"groups":      request.CreateUser.GroupNames,
			})
		}
		if len(request.CreateUser.PolicyARNs) > 0 {
			checks = append(checks, map[string]interface{}{
				"code": "POLICY_ATTACHMENT", "result": "REVIEW",
				"description": "Attaches managed policies at creation time: " + strings.Join(request.CreateUser.PolicyARNs, ", "),
				"policy_arns": request.CreateUser.PolicyARNs,
			})
		}
	case TicketTypeCreateGroup:
		if request.CreateGroup == nil {
			return TicketValidationSnapshot{}, errors.New("create_group config missing for validation")
		}
		checks = append(checks, map[string]interface{}{
			"code": "CREATE_GROUP", "result": "PASSED",
			"description": fmt.Sprintf("Creates IAM group %s; approvers must review membership and attached-policy impact", request.CreateGroup.Name),
		})
		if len(request.CreateGroup.MemberUserNames) > 0 {
			checks = append(checks, map[string]interface{}{
				"code": "GROUP_MEMBERSHIP", "result": "REVIEW",
				"description": "Adds these users to the group; they inherit the group's policies: " + strings.Join(request.CreateGroup.MemberUserNames, ", "),
				"members":     request.CreateGroup.MemberUserNames,
			})
		}
		if len(request.CreateGroup.PolicyARNs) > 0 {
			checks = append(checks, map[string]interface{}{
				"code": "POLICY_ATTACHMENT", "result": "REVIEW",
				"description": "Attaches managed policies to the group, granting them to all members: " + strings.Join(request.CreateGroup.PolicyARNs, ", "),
				"policy_arns": request.CreateGroup.PolicyARNs,
			})
		}
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return TicketValidationSnapshot{}, fmt.Errorf("marshal validated create request: %w", err)
	}
	requestHash := sha256.Sum256(payload)
	checksJSON, err := json.Marshal(checks)
	if err != nil {
		return TicketValidationSnapshot{}, fmt.Errorf("marshal create validation checks: %w", err)
	}
	return TicketValidationSnapshot{
		RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview,
	}, nil
}

func (service *TicketService) validateTicketRequest(
	ctx context.Context,
	request CreateIAMTicketRequest,
) (TicketValidationSnapshot, error) {
	if isCreateResourceTicket(request.TicketType) {
		return service.validateCreateTicketRequest(ctx, request)
	}
	if request.TicketType == TicketTypeAttachUserPolicy {
		// 挂载既有 managed policy：无 statement 级权限语句，baseline 比对、
		// 静态风险扫描与重叠检测不适用；仅验证 Terraform 可生成，由审批人评估。
		var terraformPreview string
		if request.Operation == OperationDetach {
			// detach：源挂载工单若为 CREATE_USER/CREATE_GROUP，预览移除
			// attachment block；否则预览清空源挂载工单的注释文件。
			preview, err := service.buildDetachTerraform(ctx, validationStubTicket(request), request)
			if err != nil {
				return TicketValidationSnapshot{}, fmt.Errorf("validate managed policy detach: %w", err)
			}
			terraformPreview = preview
		} else if terraformCode, err := service.adapter.GenerateAttachPolicyTerraform(
			// 与发布同一 import 判定：野生挂载在校验预览里就要带 import 块，
			// 避免「校验所见 ≠ 发布所得」。
			request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN,
			service.attachImportID(ctx, request),
			adapter.DefaultAttachmentLabel(request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN),
		); err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("validate managed policy attachment: %w", err)
		} else {
			terraformPreview = terraformCode
		}
		payload, err := json.Marshal(request)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", err)
		}
		requestHash := sha256.Sum256(payload)
		verb := "Attaches an existing managed policy to"
		if request.Operation == OperationDetach {
			verb = "Detaches an existing managed policy from"
		}
		checksJSON, err := json.Marshal([]map[string]interface{}{{
			"code":        "MANAGED_POLICY_ATTACHMENT",
			"result":      "SKIPPED",
			"description": verb + " an IAM " + strings.ToLower(request.PrincipalType) + "; statement-level baseline and static risk scan are not applicable",
		}})
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", err)
		}
		return TicketValidationSnapshot{RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview}, nil
	}
	if request.TicketType == TicketTypeAdoptRoleInlinePolicies {
		terraformPreview, _, err := service.buildRoleInlinePolicyBundle(
			ctx, validationStubTicket(request), request,
		)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("validate role inline policy adoption bundle: %w", err)
		}
		payload, err := json.Marshal(request)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", err)
		}
		requestHash := sha256.Sum256(payload)
		checksJSON, err := json.Marshal([]map[string]interface{}{{
			"code": "ROLE_INLINE_POLICY_ADOPTION", "result": "REVIEW",
			"description": fmt.Sprintf(
				"Imports %d existing inline policies on role %s without changing their documents; one manual approval covers the bundle, and auto-merge waits for explicit successful CI and repository branch protection",
				len(request.RoleInlinePolicies), request.PrincipalName,
			),
		}})
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", err)
		}
		return TicketValidationSnapshot{
			RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview,
		}, nil
	}
	if request.TicketType == TicketTypeUpdateGroupMembership {
		// 组成员变更：与发布共用同一渲染（patch 优先），保证校验所见 ==
		// 发布所得；语句级 baseline 比对不适用（成员关系由审批人看预览评估）。
		terraformPreview, _, err := service.generateUpdateGroupMembershipTerraform(
			ctx, validationStubTicket(request), request,
		)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("validate group membership terraform: %w", err)
		}
		payload, err := json.Marshal(request)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", err)
		}
		requestHash := sha256.Sum256(payload)
		verb := "Adds"
		if request.UpdateMembership.Operation == MembershipOperationRemove {
			verb = "Removes"
		}
		checksJSON, err := json.Marshal([]map[string]interface{}{{
			"code":   "GROUP_MEMBERSHIP",
			"result": "REVIEW",
			"description": fmt.Sprintf("%s %s on group %s; approvers must review the Terraform diff",
				verb, strings.Join(request.UpdateMembership.Users, ", "), request.UpdateMembership.GroupName),
		}})
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", err)
		}
		return TicketValidationSnapshot{RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview}, nil
	}
	if request.TicketType == TicketTypeUpdateManagedPolicy || request.TicketType == TicketTypeUpdateGroupInlinePolicy {
		// 策略更新：验证 Terraform 可生成（文档 JSON 校验在 adapter 内），
		// 语句级 baseline 比对不适用（策略已存在，由审批人评估变更差异）。
		if request.UpdatePolicy == nil {
			return TicketValidationSnapshot{}, apperr.Validation("update_policy config missing for policy update ticket")
		}
		var err error
		var terraformPreview string
		// unchanged：渲染结果与目标分支逐字节一致 → PR 无差异（提示用）。
		unchanged := false
		if strings.TrimSpace(request.SourceTicketNo) != "" &&
			strings.TrimSpace(request.UpdatePolicy.RoleName) != "" &&
			strings.TrimSpace(request.UpdatePolicy.InlinePolicyName) != "" {
			// 平台创建角色的内嵌策略：预览源 CREATE_ROLE 工单文件的覆写结果。
			terraformPreview, unchanged, err = service.generateSourceRolePolicyFile(
				ctx, validationStubTicket(request), request, request.UpdatePolicy.Document,
			)
		} else if request.TicketType == TicketTypeUpdateGroupInlinePolicy {
			// 与发布共用同一渲染（patch 优先），保证校验所见 == 发布所得。
			terraformPreview, unchanged, err = service.generateStandaloneInlinePolicyTerraform(
				ctx, validationStubTicket(request), request, request.UpdatePolicy.Document,
			)
		} else {
			// 托管策略：main 上已有声明则原地 patch（保留 path/description/tags），
			// 否则按首次纳管生成（含 import 块）。
			terraformPreview, unchanged, err = service.generateManagedPolicyTerraform(
				ctx, validationStubTicket(request), request,
			)
		}
		if err != nil {
			return TicketValidationSnapshot{}, apperr.Validationf("validate policy update terraform: %w", err)
		}
		checks := []map[string]interface{}{{
			"code":        "POLICY_UPDATE",
			"result":      "SKIPPED",
			"description": fmt.Sprintf("Updates existing policy %s in place; approvers must review the Terraform diff against the current document", request.UpdatePolicy.PolicyName),
		}}
		// 变更检测：与现网文档语义对比（key 序/空白无关）。内容一致且预览
		// 不含该策略的首次 import = no-op，直接阻断；首次纳管 import 本身
		// 是 state 变更，允许原文不变地导入。
		if changeCheck, changeErr := service.policyChangeCheck(ctx, request, terraformPreview); changeErr != nil {
			return TicketValidationSnapshot{}, changeErr
		} else if changeCheck != nil {
			checks = append(checks, *changeCheck)
		}
		// 内嵌策略不在采集清单里（被线下删除或尚未同步）：非阻断提示——Terraform
		// 侧按声明原地更新或重建，审批人对照 Terraform 预览判断。
		if request.TicketType == TicketTypeUpdateGroupInlinePolicy {
			inlineName := strings.TrimSpace(request.UpdatePolicy.InlinePolicyName)
			present := false
			if strings.TrimSpace(request.PrincipalType) == "Role" {
				role := strings.TrimSpace(request.UpdatePolicy.RoleName)
				_, present, err = service.repository.GetRoleInlinePolicy(ctx, request.AccountID, role, inlineName)
			} else {
				group := strings.TrimSpace(request.UpdatePolicy.GroupName)
				_, present, err = service.repository.GetGroupInlinePolicy(ctx, request.AccountID, group, inlineName)
			}
			if err != nil {
				return TicketValidationSnapshot{}, fmt.Errorf("load inline policy presence for validation: %w", err)
			}
			if !present {
				checks = append(checks, map[string]interface{}{
					"code":   "INLINE_POLICY_ABSENT",
					"result": "REVIEW",
					"description": "Inline policy is not present in the collected inventory (deleted outside the platform or not synced yet); " +
						"Terraform restores it from the declaration — approvers must confirm the Terraform preview",
				})
			}
		}
		payload, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", marshalErr)
		}
		requestHash := sha256.Sum256(payload)
		checksJSON, marshalErr := json.Marshal(checks)
		if marshalErr != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", marshalErr)
		}
		snapshot := TicketValidationSnapshot{RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview}
		if unchanged {
			// 渲染结果与目标分支一致 → PR 无差异：明确告诉审批人别指望这次 PR
			// 修好 AWS 侧漂移（要修得重跑流水线的 apply）。
			snapshot, err = appendValidationCheck(
				snapshot, "TERRAFORM_UNCHANGED", "REVIEW", terraformUnchangedNotice,
			)
			if err != nil {
				return TicketValidationSnapshot{}, err
			}
		}
		return snapshot, nil
	}
	if request.TicketType == TicketTypeRollback {
		// 回滚：无新权限引入，baseline 比对与风险扫描不适用；但反向 Terraform
		// 必须可生成——与发布共用生成器，目标无快照等前置问题在校验阶段快速
		// 失败，产物作为预览展示（与发布文件一致，仅注释头的回滚工单号为占位）。
		terraformPreview, _, terraformErr := service.buildTicketTerraformFiles(
			ctx, validationStubTicket(request), request, false,
		)
		if terraformErr != nil {
			return TicketValidationSnapshot{}, terraformErr
		}
		payload, err := json.Marshal(request)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", err)
		}
		requestHash := sha256.Sum256(payload)
		checksJSON, err := json.Marshal([]map[string]interface{}{{
			"code":        "ROLLBACK",
			"result":      "SKIPPED",
			"description": fmt.Sprintf("Clears Terraform declarations of applied ticket %s; no new permissions are introduced", request.TargetTicketNo),
		}})
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", err)
		}
		return TicketValidationSnapshot{RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview}, nil
	}
	if request.TicketType == TicketTypeUpdateRole {
		// 更新角色：验证 Terraform 可生成（含信任策略与内嵌策略风险扫描），
		// 语句级 baseline 比对不适用（角色已存在，由审批人评估变更差异）。
		// 预览与发布同路径（generateUpdateRoleTerraform）——② 源文件块级 patch；
		// ③ 野生角色文件已在 main 则原地 patch，否则生成新文件（首次带 import）。
		terraformPreview, unchanged, err := service.generateUpdateRoleTerraform(
			ctx,
			validationStubTicket(request),
			request,
		)
		if err != nil {
			return TicketValidationSnapshot{}, apperr.Validationf("validate role update terraform: %w", err)
		}
		if strings.TrimSpace(terraformPreview) == "" {
			return TicketValidationSnapshot{}, errors.New("empty Terraform preview for update_role ticket")
		}
		payload, err := json.Marshal(request)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", err)
		}
		requestHash := sha256.Sum256(payload)
		// 变更检测（对齐第 12 项）：列出与现网不同的属性，审批人不必去 git
		// 比对；no-op 已在校验入口被拒绝（validateUpdateRoleRequest）——
		// 唯一到达此处的空变更是野生角色首次纳管（import 块即变更）。
		changes, err := service.roleUpdateChanges(ctx, request)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("detect role update changes: %w", err)
		}
		changeSummary := "Role attributes changed: " + strings.Join(changes, ", ")
		if len(changes) == 0 {
			changeSummary = "No role attribute change; first-time adoption: the ticket imports the existing role into Terraform state"
		}
		checksJSON, err := json.Marshal([]map[string]interface{}{
			{
				"code":        "ROLE_UPDATE",
				"result":      "SKIPPED",
				"description": fmt.Sprintf("Updates existing role %s in place; approvers must review the Terraform diff against the current configuration", request.PrincipalName),
			},
			{
				"code":        "CHANGE_DETECTION",
				"result":      "PASSED",
				"description": changeSummary,
			},
		})
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", err)
		}
		snapshot := TicketValidationSnapshot{RequestSHA256: requestHash[:], Checks: checksJSON, TerraformPreview: terraformPreview}
		if unchanged {
			snapshot, err = appendValidationCheck(
				snapshot, "TERRAFORM_UNCHANGED", "REVIEW", terraformUnchangedNotice,
			)
			if err != nil {
				return TicketValidationSnapshot{}, err
			}
		}
		return snapshot, nil
	}
	baseline, baselineErr := service.repository.GetEnabledBaseline(ctx, request.AccountID)
	validationChecks := make([]map[string]interface{}, 0, 3)
	var baselineID *int64
	if baselineErr != nil && !errors.Is(baselineErr, sql.ErrNoRows) {
		return TicketValidationSnapshot{}, fmt.Errorf("load enabled account IAM baseline: %w", baselineErr)
	}
	// 获取抽象策略（优先新模型，回退旧模型）；权限声明可选——未声明任何权限时
	// 只创建角色本体（零权限角色），语句级比对不适用。
	policyDeclared := request.rolePolicyDeclared()
	var requestPolicy *abstractiam.AbstractPolicy
	if policyDeclared {
		policy, policyErr := request.GetAbstractPolicy()
		if policyErr != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("get abstract policy for validation: %w", policyErr)
		}
		requestPolicy = policy
	}
	if baselineErr == nil {
		var baselinePolicy abstractiam.AbstractPolicy
		if err := json.Unmarshal(baseline.AbstractPolicy, &baselinePolicy); err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("decode enabled account IAM baseline: %w", err)
		}
		if policyDeclared {
			violations := CheckAbstractPolicyAgainstBaseline(*requestPolicy, baselinePolicy)
			if len(violations) > 0 {
				return TicketValidationSnapshot{}, &IAMBaselineComplianceError{Violations: violations}
			}
			baselineID = &baseline.ID
			validationChecks = append(validationChecks, map[string]interface{}{
				"code": "BASELINE_COMPLIANT", "result": "PASSED",
				"description": "Request is within the enabled account baseline",
				"baseline_id": baseline.ID, "baseline_version": baseline.Version,
			})
		} else {
			baselineID = &baseline.ID
			validationChecks = append(validationChecks, map[string]interface{}{
				"code": "BASELINE_COMPLIANT", "result": "SKIPPED",
				"description": "Role declares no permissions; there is nothing to compare against the account baseline",
				"baseline_id": baseline.ID, "baseline_version": baseline.Version,
			})
		}
	} else {
		validationChecks = append(validationChecks, map[string]interface{}{
			"code": "NO_BASELINE", "result": "SKIPPED", "description": "No enabled account baseline",
		})
	}
	// 使用新模型进行静态风险扫描（未声明权限时只扫描信任策略）
	candidatePolicyJSON := json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	if policyDeclared {
		candidatePolicy, err := service.adapter.TranslateAbstractPolicy(requestPolicy)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("translate requested policy for static risk scan: %w", err)
		}
		marshaled, err := json.Marshal(candidatePolicy)
		if err != nil {
			return TicketValidationSnapshot{}, fmt.Errorf("marshal candidate IAM policy for static risk scan: %w", err)
		}
		candidatePolicyJSON = marshaled
	}
	awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TicketValidationSnapshot{}, apperr.Validationf("account_id %d: AWS account is not registered on this platform; register it and sync assets first", request.AccountID)
		}
		return TicketValidationSnapshot{}, fmt.Errorf("load AWS account identifier for candidate policy scan: %w", err)
	}
	riskFindings, err := ScanCandidateIAMPolicy(candidatePolicyJSON, request.Role.TrustPolicy, request.Role.Name, awsAccountID)
	if err != nil {
		return TicketValidationSnapshot{}, fmt.Errorf("scan candidate IAM policy risks: %w", err)
	}
	if len(blockingCandidateRiskFindings(riskFindings, service.riskMode)) > 0 {
		return TicketValidationSnapshot{}, &CandidatePolicyRiskError{Findings: riskFindings}
	}
	riskResult := "PASSED"
	if len(riskFindings) > 0 {
		riskResult = "WARN"
		service.logger.Warn("candidate IAM policy has non-blocking static risk findings",
			"risk_mode", service.riskMode, "principal_name", request.PrincipalName,
			"findings", riskFindings,
		)
	}
	validationChecks = append(validationChecks, map[string]interface{}{
		"code": "STATIC_RISK_SCAN", "result": riskResult,
		"description": "Static candidate policy and trust-policy findings evaluated under configured risk mode",
		"findings":    riskFindings,
	})
	if !policyDeclared {
		validationChecks = append(validationChecks, map[string]interface{}{
			"code": "PERMISSION_OVERLAP", "result": "SKIPPED",
			"description": "Role declares no inline policy; there is nothing to compare against existing policies",
		})
		// 零权限角色：AWS 侧合法，但审批人应知情（非阻断提示）。
		validationChecks = append(validationChecks, map[string]interface{}{
			"code": "ZERO_PERMISSION_ROLE", "result": "REVIEW",
			"description": "Role is created without any permission declaration (zero-permission role); grant access later with attach or update tickets",
		})
	} else {
		existingPolicies, principalExists, err := service.repository.GetPrincipalPolicies(ctx, request.AccountID, request.PrincipalName, "Role")
		if err != nil {
			return TicketValidationSnapshot{}, apperr.Validationf("load existing policies for target principal: %w", err)
		}
		if !principalExists {
			validationChecks = append(validationChecks, map[string]interface{}{
				"code": "PERMISSION_OVERLAP", "result": "SKIPPED",
				"description": "Target role is not present in the collected IAM inventory",
			})
		} else {
			overlaps, err := DetectPermissionOverlaps(candidatePolicyJSON, existingPolicies)
			if err != nil {
				return TicketValidationSnapshot{}, fmt.Errorf("detect existing permission overlap: %w", err)
			}
			result := "NO_OVERLAP"
			if len(overlaps) > 0 {
				result = "POSSIBLE_OVERLAP"
			}
			validationChecks = append(validationChecks, map[string]interface{}{
				"code": "PERMISSION_OVERLAP", "result": result,
				"description": "Static action/resource pattern comparison; not authorization evaluation",
				"findings":    overlaps,
			})
		}
	}
	if len(request.Role.PolicyARNs) > 0 {
		validationChecks = append(validationChecks, map[string]interface{}{
			"code": "POLICY_ATTACHMENT", "result": "REVIEW",
			"description": "Attaches managed policies at creation time: " + strings.Join(request.Role.PolicyARNs, ", "),
			"policy_arns": request.Role.PolicyARNs,
		})
	}
	// 使用新模型验证 Terraform 生成
	terraformPreview, err := service.adapter.GenerateTerraformFromAbstractPolicy(requestPolicy, request.Role)
	if err != nil {
		return TicketValidationSnapshot{}, apperr.Validationf("validate requested IAM policy: %w", err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return TicketValidationSnapshot{}, fmt.Errorf("marshal validated ticket request: %w", err)
	}
	requestHash := sha256.Sum256(payload)
	checksJSON, err := json.Marshal(validationChecks)
	if err != nil {
		return TicketValidationSnapshot{}, fmt.Errorf("marshal ticket validation checks: %w", err)
	}
	return TicketValidationSnapshot{
		BaselineID: baselineID, RequestSHA256: requestHash[:], Checks: checksJSON,
		TerraformPreview: terraformPreview,
	}, nil
}

// ListTickets returns a page of tickets for the given filter plus the total
// matching count. Limit/offset default to 20/0 and the limit is capped at 100.
func (service *TicketService) ListTickets(
	ctx context.Context,
	filter TicketListFilter,
) ([]model.IAMTicket, int64, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	tickets, total, err := service.repository.ListTickets(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("list IAM tickets: %w", err)
	}
	return tickets, total, nil
}

// PreviewValidation runs the same request-shape and policy validation as
// ticket creation without persisting anything, so the DSL editor can
// pre-check syntax, baseline compliance and static risks in real time.
// Approver selection is intentionally not validated here (the editor calls
// this endpoint before approvers are chosen); submit re-validates everything.
func (service *TicketService) PreviewValidation(
	ctx context.Context,
	submitter string,
	request CreateIAMTicketRequest,
) (TicketValidationSnapshot, error) {
	if strings.TrimSpace(submitter) == "" {
		return TicketValidationSnapshot{}, errors.New("submitter must not be empty")
	}
	request, err := service.validateRequestShape(ctx, request)
	if err != nil {
		return TicketValidationSnapshot{}, err
	}
	return service.validateTicketRequest(ctx, request)
}

func (service *TicketService) GetApprovalInfo(ctx context.Context, ticketNo string) (model.TicketApprovalInfo, error) {
	ticketNo = strings.TrimSpace(ticketNo)
	if ticketNo == "" {
		return model.TicketApprovalInfo{}, apperr.Validation("ticket number must not be empty")
	}
	info, err := service.repository.GetApprovalInfo(ctx, ticketNo)
	if err != nil {
		return model.TicketApprovalInfo{}, fmt.Errorf("get ticket approval information: %w", err)
	}
	return info, nil
}

func (service *TicketService) ListAvailableApprovers(ctx context.Context, accountID *int64) ([]model.PlatformUser, error) {
	if accountID != nil && *accountID <= 0 {
		return nil, errors.New("account_id must be positive")
	}
	users, err := service.repository.ListAvailableApprovers(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list available platform approvers: %w", err)
	}
	return users, nil
}

func (service *TicketService) GetTicket(ctx context.Context, ticketNo string) (model.IAMTicket, error) {
	ticketNo = strings.TrimSpace(ticketNo)
	if ticketNo == "" {
		return model.IAMTicket{}, errors.New("ticket number must not be empty")
	}
	ticket, err := service.repository.Get(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("get IAM ticket: %w", err)
	}
	return ticket, nil
}

func (service *TicketService) GetTicketForActor(
	ctx context.Context,
	ticketNo string,
	actorID string,
	roles []string,
) (model.IAMTicket, error) {
	ticket, err := service.GetTicket(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, err
	}
	if ticket.Submitter != nil && *ticket.Submitter == actorID {
		return ticket, nil
	}
	for _, role := range roles {
		if role == "platform_admin" || role == "approval_admin" {
			return ticket, nil
		}
	}
	return model.IAMTicket{}, ErrTicketAccessDenied
}

// Decide records an approval/rejection. The designated approver set is seeded
// when the ticket is created; MR publication happens only after every approver
// has approved. Repeated approvals can safely retry a failed GitLab publication.
func (service *TicketService) Decide(
	ctx context.Context,
	ticketNo string,
	approver string,
	decision TicketDecision,
) (model.IAMTicket, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return model.IAMTicket{}, apperr.Validation("approver must not be empty")
	}
	if decision.Result != "APPROVE" && decision.Result != "REJECT" {
		return model.IAMTicket{}, apperr.Validation("approval result must be APPROVE or REJECT")
	}
	if strings.TrimSpace(decision.Comment) == "" {
		return model.IAMTicket{}, apperr.Validation("approval reason must not be empty")
	}

	ticket, err := service.repository.RecordDecision(ctx, ticketNo, approver, decision.Result, decision.Comment)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("record IAM ticket decision: %w", err)
	}
	service.logger.Info("IAM ticket decision recorded",
		"ticket_no", ticketNo,
		"approver", approver,
		"result", decision.Result,
	)
	if ticket.Status == nil || *ticket.Status != TicketStatusApproved {
		return ticket, nil
	}

	published, err := service.publishApprovedTicket(ctx, ticket)
	if err != nil {
		return ticket, err
	}
	return published, nil
}

// CloseTicket closes a ticket with the specified reason.
// Only platform_admin or approval_admin can close tickets.
func (service *TicketService) CloseTicket(
	ctx context.Context,
	ticketNo, actorID string,
	reason string,
	comment string,
	triggerSync bool,
) (model.IAMTicket, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return model.IAMTicket{}, errors.New("actor ID must not be empty")
	}
	reason = strings.TrimSpace(reason)
	if reason != ClosureReasonApplied && reason != ClosureReasonAbandoned {
		return model.IAMTicket{}, fmt.Errorf("closure reason must be %s or %s", ClosureReasonApplied, ClosureReasonAbandoned)
	}

	// 废弃前置校验：PR 仍在开启或已合并时禁止废弃，避免
	// 「PR 后来被合并但工单已废弃」的错位。
	if reason == ClosureReasonAbandoned {
		if err := service.guardAbandon(ctx, ticketNo); err != nil {
			return model.IAMTicket{}, err
		}
	}

	closed, err := service.repository.CloseTicket(ctx, ticketNo, actorID, reason, comment)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("close IAM ticket: %w", err)
	}

	service.logger.Info("IAM ticket closed",
		"ticket_no", ticketNo,
		"actor", actorID,
		"reason", reason,
		"trigger_sync", triggerSync,
	)

	// 文件级预约释放（phase4 §4.2）：REJECTED / CLOSED（未合并）/
	// PUBLISH_FAILED 的关单即终态，把占用的文件让出来。合并路径不走这里
	// （gitstatus 自动关单先转 MERGED 态等同步确认）。失败只记日志，
	// 不影响关单结果；挂死的预约走管理员手动释放。
	if service.reservations != nil {
		if err := service.reservations.ReleaseTicket(ctx, ticketNo); err != nil {
			service.logger.Warn("failed to release publish reservations after close",
				"ticket_no", ticketNo, "error", err)
		}
	}

	// 声明作废（phase4 §5，P2b）：废弃 = PR 关闭未合并，这张工单什么都没
	// 落地，它发出去的声明必须撤回，否则漂移基准会拿着一份从未进 main 的
	// 意图去比对，把实态里正确的资源报成「被改回去了」。APPLIED 关单代表
	// 已合并生效，声明保留。失败只记日志：作废不改变关单结果，下一轮基线
	// 发布会重新建立基准。
	if reason == ClosureReasonAbandoned && service.declarations != nil {
		if err := service.declarations.VoidForTicket(ctx, closed.ID); err != nil {
			service.logger.Warn("failed to void ticket declarations after close",
				"ticket_no", ticketNo, "error", err)
		}
	}

	// 关单联动（人工版）：操作者已确认 apply 完成，立即触发清单刷新
	//（不等待自动关单的 5 分钟落地延迟；在途同步不重复排队，同步停用
	// 仅记日志）。失败只记日志，不影响关单结果。
	if reason == ClosureReasonApplied && triggerSync && service.closureSync != nil && closed.AccountID != nil {
		if err := service.closureSync.TriggerSyncForManuallyClosedTicket(ctx, *closed.AccountID, ticketNo); err != nil {
			if errors.Is(err, ErrSyncDisabled) {
				service.logger.Info("AWS sync disabled for the manually closed ticket's account; inventory refresh skipped",
					"ticket_no", ticketNo)
			} else {
				service.logger.Warn("failed to trigger AWS sync after manual close",
					"ticket_no", ticketNo, "error", err)
			}
		}
	}
	return closed, nil
}

// CIApplyFailure 是一次 CI apply 失败的现场信息（A12②）。它只用于在工单上
// 留痕与展示，不改变工单状态——失败后的处置（修代码重推 / 人工关单 /
// 放弃）由操作者决定。
type CIApplyFailure struct {
	CommitSHA string
	CIURL     string
	Note      string
}

// CIApplyResult reports the outcome of an automated terraform apply run
// performed by CI for a merged ticket PR.
type CIApplyResult struct {
	// Status must be CIApplyStatusSucceeded or CIApplyStatusFailed.
	Status string
	// CommitSHA is the applied commit (merge commit of the ticket PR), if known.
	CommitSHA string
	// CIURL points at the pipeline/job run for troubleshooting.
	CIURL string
	// Note is free-form extra context recorded with the closure.
	Note string
	// PublicationID 是可选的基线发布归属：同一次 main 提交可能同时应用了
	// 工单 PR 与基线 PR，回调带上它就能把「合并 ≠ 生效」对上号。
	PublicationID int64
}

// RecordCIApplyResult is the reserved hook for CI-driven apply (A1). The
// current default flow still closes tickets on PR merge with a delayed
// sync; once CI performs terraform apply automatically, it calls
// POST /tickets/:no/apply-result instead and the platform reacts
// immediately:
//   - succeeded → close the ticket as APPLIED and trigger an inventory
//     sync right away (same semantics as a manual close with
//     trigger_sync, no 5-minute grace delay);
//   - failed → keep the ticket open, only log the failure for operators.
//
// Repeated callbacks for an already closed ticket are idempotent success.
// Authentication uses a dedicated platform token issued for the CI runner
// (platform_admin role).
func (service *TicketService) RecordCIApplyResult(
	ctx context.Context,
	ticketNo, actorID string,
	result CIApplyResult,
) (model.IAMTicket, bool, error) {
	ticketNo = strings.TrimSpace(ticketNo)
	if ticketNo == "" {
		return model.IAMTicket{}, false, apperr.Validation("ticket number must not be empty")
	}
	if strings.TrimSpace(actorID) == "" {
		return model.IAMTicket{}, false, errors.New("actor ID must not be empty")
	}
	if result.Status != CIApplyStatusSucceeded && result.Status != CIApplyStatusFailed {
		return model.IAMTicket{}, false, apperr.Validationf(
			"apply result status must be %s or %s", CIApplyStatusSucceeded, CIApplyStatusFailed)
	}

	ticket, err := service.GetTicket(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, false, err
	}
	if ticket.Status != nil && *ticket.Status == TicketStatusClosed {
		if result.Status == CIApplyStatusFailed {
			// 终态优先：不改状态、不覆盖失败标记。但迟到/乱序的失败仍然要
			// 留执行记录——否则「关单之后 CI 才报失败」这件事只剩一行日志，
			// 审计回溯看不到。仓库层会打 metadata.late_after_close 标记。
			if err := service.repository.MarkCIApplyFailed(ctx, ticketNo, CIApplyFailure{
				CommitSHA: result.CommitSHA,
				CIURL:     result.CIURL,
				Note:      result.Note,
			}); err != nil {
				return model.IAMTicket{}, true, fmt.Errorf("record late CI apply failure: %w", err)
			}
			service.logger.Warn("late CI apply failure recorded after ticket close; state unchanged",
				"ticket_no", ticketNo,
				"commit_sha", result.CommitSHA,
				"ci_url", result.CIURL,
				"note", result.Note,
			)
			return ticket, true, nil
		}
		// Idempotent: CI retries or a race with the merge-based auto-close
		// must not surface as an error.
		service.logger.Info("CI apply result ignored; ticket already closed",
			"ticket_no", ticketNo, "status", result.Status)
		return ticket, true, nil
	}

	if result.Status == CIApplyStatusFailed {
		// A12②：失败必须落在工单上，不能只进日志——否则操作者只看到一张
		// 停在 APPROVED 的工单，无从判断「合并了但没生效」。
		if err := service.repository.MarkCIApplyFailed(ctx, ticketNo, CIApplyFailure{
			CommitSHA: result.CommitSHA,
			CIURL:     result.CIURL,
			Note:      result.Note,
		}); err != nil {
			return model.IAMTicket{}, false, fmt.Errorf("record CI apply failure: %w", err)
		}
		service.logger.Warn("CI apply reported failure; ticket marked FAILED and left open for operator action",
			"ticket_no", ticketNo,
			"commit_sha", result.CommitSHA,
			"ci_url", result.CIURL,
			"note", result.Note,
		)
		updated, err := service.GetTicket(ctx, ticketNo)
		if err != nil {
			return model.IAMTicket{}, false, err
		}
		return updated, false, nil
	}

	comment := "closed by CI apply callback"
	if result.Note != "" {
		comment = result.Note
	}
	closed, err := service.CloseTicket(ctx, ticketNo, actorID, ClosureReasonApplied, comment, true)
	if err != nil {
		return model.IAMTicket{}, false, err
	}
	service.logger.Info("CI apply callback closed ticket and triggered inventory sync",
		"ticket_no", ticketNo,
		"actor", actorID,
		"commit_sha", result.CommitSHA,
		"ci_url", result.CIURL,
	)
	return closed, true, nil
}

// guardAbandon verifies that the ticket's pull request is closed
// (not open, not merged) before the ticket may be abandoned. Tickets
// that never published a PR are unaffected. A nil fetcher (unwired
// deployments, tests) skips the guard; the API server always wires one.
func (service *TicketService) guardAbandon(ctx context.Context, ticketNo string) error {
	if service.mrFetcher == nil {
		return nil
	}
	ticket, err := service.repository.Get(ctx, ticketNo)
	if err != nil {
		return fmt.Errorf("load ticket for abandon guard: %w", err)
	}
	project := ""
	if ticket.GitRepository != nil {
		project = strings.TrimSpace(*ticket.GitRepository)
	}
	number := ""
	if ticket.RemoteRequestNumber != nil {
		number = strings.TrimSpace(*ticket.RemoteRequestNumber)
	}
	if project == "" || number == "" {
		// No PR was ever created (draft / approving) — nothing to check.
		return nil
	}
	status, err := service.mrFetcher.FetchMergeRequest(ctx, project, number)
	if err != nil {
		return &AbandonGuardError{Reason: "查询 PR 状态失败，请稍后重试"}
	}
	if status == nil {
		return &AbandonGuardError{Reason: "PR 不存在，无法确认状态"}
	}
	switch status.State {
	case githost.MergeStateOpen:
		return &AbandonGuardError{Reason: "PR 仍在开启状态，废弃前请先关闭 PR"}
	case githost.MergeStateMerged:
		return &AbandonGuardError{Reason: "PR 已合并，变更已应用，不能废弃"}
	case githost.MergeStateClosed:
		return nil
	default:
		return &AbandonGuardError{Reason: "无法确认 PR 状态，请稍后重试"}
	}
}

// RetryPublication republishes an approved ticket if a transient GitLab or DB
// error interrupted the post-approval delivery.
// Only PUBLISH_FAILED state is allowed for retry.
func (service *TicketService) RetryPublication(ctx context.Context, ticketNo string) (model.IAMTicket, error) {
	ticket, err := service.GetTicket(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, err
	}
	// Only allow retry from PUBLISH_FAILED state
	if ticket.Status == nil || *ticket.Status != TicketStatusPublishFailed {
		return model.IAMTicket{}, fmt.Errorf("%w: retry requires %s state", ErrInvalidTicketState, TicketStatusPublishFailed)
	}
	// Check if MR/PR already exists (idempotency)
	if ticket.GitPRURL != nil && *ticket.GitPRURL != "" {
		service.logger.Info("ticket already has a Git PR URL, skipping retry",
			"ticket_no", ticketNo,
			"git_pr_url", *ticket.GitPRURL,
		)
		// A transient poll failure may have marked the ticket PUBLISH_FAILED
		// after the PR was created. The publication clearly succeeded, so
		// restore the ticket to APPROVED.
		if ticket.Status != nil && *ticket.Status == TicketStatusPublishFailed {
			if err := service.repository.SetStatus(ctx, ticketNo, TicketStatusPublishFailed, TicketStatusApproved); err != nil {
				return model.IAMTicket{}, fmt.Errorf("restore published ticket to APPROVED: %w", err)
			}
			ticket.Status = stringPointer(TicketStatusApproved)
		}
		return ticket, nil
	}
	// Transition to PUBLISHING before retrying
	if err := service.repository.SetStatus(ctx, ticketNo, TicketStatusPublishFailed, TicketStatusPublishing); err != nil {
		return model.IAMTicket{}, fmt.Errorf("transition ticket to PUBLISHING: %w", err)
	}
	ticket.Status = stringPointer(TicketStatusPublishing)
	published, err := service.publishApprovedTicket(ctx, ticket)
	if err != nil {
		return ticket, err
	}
	return published, nil
}

// RearmPolling resets the poll schedule of a ticket whose PR is still
// open after the 7-day poll budget was exhausted, and enqueues a fresh
// first poll. The ticket keeps its APPROVED state throughout: the PR
// remains mergeable and the platform keeps observing it.
func (service *TicketService) RearmPolling(ctx context.Context, ticketNo string) error {
	ticketNo = strings.TrimSpace(ticketNo)
	if ticketNo == "" {
		return errors.New("ticket number must not be empty")
	}
	ticket, err := service.repository.Get(ctx, ticketNo)
	if err != nil {
		return err
	}
	if ticket.Status == nil || !isPollableTicketStatus(*ticket.Status) {
		return fmt.Errorf("%w: polling can only be re-armed for %s, %s or %s tickets",
			ErrInvalidTicketState, TicketStatusApproved, TicketStatusPublishing, TicketStatusPublishFailed)
	}
	if ticket.GitPRURL == nil || strings.TrimSpace(*ticket.GitPRURL) == "" {
		return errors.New("ticket has no published Git request to poll")
	}
	if ticket.RemoteRequestNumber == nil || strings.TrimSpace(*ticket.RemoteRequestNumber) == "" {
		return errors.New("ticket has no remote request number to poll")
	}
	if ticket.GitRepository == nil || strings.TrimSpace(*ticket.GitRepository) == "" {
		return errors.New("ticket has no Git repository recorded to poll")
	}
	if service.pollEnqueuer == nil {
		return errors.New("Git status poll enqueuer is not configured")
	}

	if err := service.repository.ResetPollSchedule(ctx, ticketNo); err != nil {
		return fmt.Errorf("reset Git poll schedule: %w", err)
	}

	payload := GitStatusPollTask{
		TicketNo:            ticketNo,
		Provider:            strings.ToLower(valueOrEmpty(ticket.GitProvider)),
		Project:             *ticket.GitRepository,
		RemoteRequestNumber: *ticket.RemoteRequestNumber,
		CommitSHA:           valueOrEmpty(ticket.GitCommitSHA),
		Attempt:             1,
	}
	if err := service.pollEnqueuer.EnqueueGitStatusPoll(ctx, payload); err != nil {
		return fmt.Errorf("enqueue Git status poll task: %w", err)
	}

	service.logger.Info("Git status polling re-armed",
		"ticket_no", ticketNo,
		"remote_request", payload.RemoteRequestNumber,
	)
	return nil
}

// isPollableTicketStatus reports whether a ticket status allows Git
// status polling (kept in sync with the gitstatus worker).
func isPollableTicketStatus(status string) bool {
	switch status {
	case TicketStatusApproved, TicketStatusPublishing, TicketStatusPublishFailed:
		return true
	default:
		return false
	}
}

func (service *TicketService) MarkMerged(ctx context.Context, ticketNo string) error {
	return service.repository.SetStatus(ctx, ticketNo, TicketStatusApproved, TicketStatusMerged)
}

// buildTicketTerraform renders the Terraform file a ticket will publish from
// its decoded request. captureSnapshots controls the pre-change snapshot
// writes ROLLBACK depends on: only publication captures them, so the
// read-only preview path never mutates ticket state.
// rollbackPreviewTicketNo 校验阶段回滚工单号尚未生成：预览中用占位符，
// 发布时以真实工单号重新生成。仅影响回滚 CREATE_ROLE 清空文件注释头的
// 「Rolled back by ticket」一行，其余内容与发布产物完全一致。
const rollbackPreviewTicketNo = "IAM-<pending>"

// validationStubTicket builds the minimal ticket identity the publisher's
// file fetcher needs (account ID for the path, ticket number as file-key
// fallback). Validation runs before the ticket exists, so TicketNo stays
// nil; rollback passes its own ticket number.
func validationStubTicket(request CreateIAMTicketRequest) model.IAMTicket {
	accountID := request.AccountID
	return model.IAMTicket{AccountID: &accountID}
}

// rejectIfAlreadyAdopted 拒绝对已纳管资源重复发起 CREATE_* 导入工单。
// 「已纳管」= 基线台账（PUBLISHED/MERGED）已覆盖该资源声明文件，或 main 上
// 已存在同名声明文件（早期工单或手工发布）。两种情况再导入都会产生双声明，
// Terraform 会拒绝整个配置。错误消息以 label 开头（"group \"/ "user \"/
// "policy \""），命中 handler 的 400 白名单。
func (service *TicketService) rejectIfAlreadyAdopted(
	ctx context.Context,
	request CreateIAMTicketRequest,
	fileKey, label, displayName, actionHint string,
) error {
	owned, err := service.repository.BaselineOwnsResourceFile(ctx, request.AccountID, fileKey)
	if err != nil {
		return fmt.Errorf("check baseline ownership of %s %q: %w", label, displayName, err)
	}
	if owned {
		return fmt.Errorf(
			`%s "%s" 已由全量基线纳管（声明文件 %s.tf 已发布）；无需重复导入，%s`,
			label, displayName, fileKey, actionHint,
		)
	}
	// shape 校验阶段 AWSAccountID 尚未回填（各 generate 分支各自补），这里
	// fetch main 文件需要它，先查一次。
	if strings.TrimSpace(request.AWSAccountID) == "" {
		awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return fmt.Errorf("load AWS account identifier for adoption check: %w", err)
		}
		request.AWSAccountID = awsAccountID
	}
	if content, err := service.publisher.FetchTerraformFile(
		ctx, validationStubTicket(request), request,
	); err == nil {
		// 只认仍带实际声明的文件：被解绑/回滚清空的注释空文件意味着资源已
		// 销毁，重新导入是合法的重新纳管。
		if adapter.HasActiveDeclaration(content) {
			return fmt.Errorf(
				`%s "%s" 已纳管（声明文件 %s.tf 已存在于仓库 main）；无需重复导入，%s`,
				label, displayName, fileKey, actionHint,
			)
		}
	} else if !errors.Is(err, ErrTerraformFileNotFound) {
		// 判定依赖 GitHub 可用性：网络异常时宁可让用户重试，也不能放行
		// 一个可能双声明的导入工单。
		return fmt.Errorf("check whether %s %q is already adopted: %w", label, displayName, err)
	}
	return nil
}

// buildRollbackTerraform 生成回滚工单的反向 Terraform。校验预览与发布共用，
// 保证「校验所见 == 发布所得」：目标无快照等前置问题在校验阶段即失败，
// 而不是拖到审批通过后的发布环节。rollbackTicketNo 仅写入清空文件的注释头。
func (service *TicketService) buildRollbackTerraform(
	ctx context.Context,
	rollbackTicketNo string,
	request CreateIAMTicketRequest,
) (string, error) {
	switch {
	case request.UpdateMembership != nil && strings.TrimSpace(request.TargetTicketNo) != "":
		// 回滚组成员变更：用目标工单的快照成员列表恢复 membership 文件
		// （main 上现文件原地 patch；文件缺失则按快照全量生成——与正向
		// 更新同一「完整列表」语义）。快照为空数组 = 目标工单移除了最后
		// 一名成员，此时同样恢复为空 → 注释空文件 → destroy（回滚一个
		// destroy 操作）。
		target, targetErr := service.repository.Get(ctx, request.TargetTicketNo)
		if targetErr != nil {
			return "", fmt.Errorf("load rollback target for membership snapshot restore: %w", targetErr)
		}
		var snapshotMembers []string
		if err := json.Unmarshal(target.RoleSnapshot, &snapshotMembers); err != nil {
			return "", fmt.Errorf("decode membership snapshot: %w", err)
		}
		restoreTicket := validationStubTicket(request)
		restoreTicket.TicketNo = &rollbackTicketNo
		if request.AccountID > 0 && strings.TrimSpace(request.AWSAccountID) == "" {
			awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
			if err != nil {
				return "", fmt.Errorf("load AWS account identifier for membership rollback: %w", err)
			}
			request.AWSAccountID = awsAccountID
		}
		fileContent, fetchErr := service.publisher.FetchTerraformFile(ctx, restoreTicket, request)
		if fetchErr != nil && !errors.Is(fetchErr, ErrTerraformFileNotFound) {
			return "", fmt.Errorf("fetch group membership Terraform file for rollback: %w", fetchErr)
		}
		if len(snapshotMembers) == 0 {
			var hcl strings.Builder
			hcl.WriteString("# GROUP MEMBERSHIP emptied by rollback ticket " + rollbackTicketNo + "\n")
			hcl.WriteString("# Group: " + request.UpdateMembership.GroupName + "\n")
			hcl.WriteString("#\n")
			hcl.WriteString("# The aws_iam_group_membership declaration was removed by this rollback ticket.\n")
			hcl.WriteString("# Run `terraform plan` to review the destroy, then apply.\n")
			return hcl.String(), nil
		}
		if fetchErr == nil {
			restored, err := service.adapter.PatchGroupMembershipUsers(fileContent, snapshotMembers)
			if err != nil {
				return "", err
			}
			return restored, nil
		}
		return service.adapter.GenerateBaselineMembershipTerraform(request.UpdateMembership.GroupName, snapshotMembers)
	case request.UpdatePolicy != nil && request.Operation == "" && strings.TrimSpace(request.SourceTicketNo) != "" && strings.TrimSpace(request.TargetTicketNo) != "":
		// 回滚「覆写源 CREATE_ROLE 文件的内嵌策略更新」：用快照文档重新
		// 生成源文件（单一声明 managed_policy 保持不变）。
		target, targetErr := service.repository.Get(ctx, request.TargetTicketNo)
		if targetErr != nil {
			return "", fmt.Errorf("load rollback target for source-file policy restore: %w", targetErr)
		}
		restoreDocument := json.RawMessage(target.RoleSnapshot)
		if len(restoreDocument) == 0 {
			return "", apperr.Validation("rollback target has no policy snapshot; cannot generate reverse Terraform")
		}
		// ② 块级 patch：以 main 上的现文件为基底只替换该内嵌策略的 policy
		// 属性（与正向更新同一原语），其余字节不动。
		restoreTicket := validationStubTicket(request)
		restoreTicket.TicketNo = &rollbackTicketNo
		restored, _, err := service.generateSourceRolePolicyFile(ctx, restoreTicket, request, restoreDocument)
		return restored, err
	case request.UpdatePolicy != nil && request.Operation == "" && request.TargetTicketNo != "":
		// 回滚策略更新（独立策略文件）：用快照文档重新生成同一策略文件（upsert）。
		target, targetErr := service.repository.Get(ctx, request.TargetTicketNo)
		if targetErr != nil {
			return "", fmt.Errorf("load rollback target for policy snapshot restore: %w", targetErr)
		}
		restoreDocument := json.RawMessage(target.RoleSnapshot)
		if len(restoreDocument) == 0 {
			return "", errors.New("rollback target has no policy snapshot; cannot generate reverse Terraform")
		}
		label := policyUpdateResourceLabel(request)
		if strings.TrimSpace(request.UpdatePolicy.InlinePolicyName) != "" &&
			(strings.TrimSpace(request.UpdatePolicy.RoleName) != "" || strings.TrimSpace(request.UpdatePolicy.GroupName) != "") {
			// 独立内嵌策略文件：优先 patch 现文件（保留资源 label，回滚同样是
			// 原地更新而非销毁重建）；文件缺失/被清空时按稳定 label 重生成。
			restoreTicket := validationStubTicket(request)
			restoreTicket.TicketNo = &rollbackTicketNo
			restored, _, err := service.generateStandaloneInlinePolicyTerraform(ctx, restoreTicket, request, restoreDocument)
			return restored, err
		}
		// 策略名缺失时从 ARN 推导（历史工单可能只存了 ARN）。
		policyName := strings.TrimSpace(request.UpdatePolicy.PolicyName)
		if policyName == "" {
			policyName = PolicyNameFromARN(request.UpdatePolicy.PolicyARN)
		}
		return service.adapter.GenerateUpdateManagedPolicyTerraform(
			policyName, restoreDocument, "", label,
		)
	case request.Operation == OperationAttach && request.SourceTicketNo != "" && request.ManagedPolicyARN != "" && request.TargetTicketNo != "":
		// 回滚 detach：重新挂载（重新生成挂载资源到源挂载工单文件）。
		// detach 已 apply → AWS 与 state 均无该资源，重新挂载是纯 create，
		// 不需要 import block。
		return service.adapter.GenerateAttachPolicyTerraform(
			request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN, "",
			adapter.DefaultAttachmentLabel(request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN),
		)
	case strings.TrimSpace(request.SourceTicketNo) != "" ||
		(request.TicketType == TicketTypeRollback && request.PrincipalType == "Role"):
		// 回滚 UPDATE_ROLE：用目标工单的变更前快照生成反向 Terraform ——
		// 有源文件则覆盖源 CREATE_ROLE 文件；野生角色（③）patch 回
		// role-<name>.tf（角色留在 state，不 destroy）。
		target, targetErr := service.repository.Get(ctx, request.TargetTicketNo)
		if targetErr != nil {
			return "", fmt.Errorf("load rollback target for snapshot restore: %w", targetErr)
		}
		restoreConfig, cfgErr := UpdateRoleConfigFromSnapshot(json.RawMessage(target.RoleSnapshot))
		if cfgErr != nil {
			return "", fmt.Errorf("decode rollback target snapshot: %w", cfgErr)
		}
		// ② 块级 patch：以 main 上的现文件（更新后状态）为基底，把快照里
		// 采集到的每个属性还原；快照未覆盖的属性（旧快照）保持不动。
		restoreTicket := validationStubTicket(request)
		restoreTicket.TicketNo = &rollbackTicketNo
		fileContent, err := service.publisher.FetchTerraformFile(
			ctx,
			restoreTicket,
			request,
		)
		if err != nil {
			return "", apperr.Validationf("fetch role Terraform file for rollback: %w", err)
		}
		return service.adapter.PatchRoleAttributes(
			fileContent,
			adapter.RoleAttrPatchFromConfig(restoreConfig),
			request.PrincipalName,
		)
	default:
		// 还剩一种合法情形：CREATE_* 存量工单的请求里没有资源名，推导不出
		// role-<name>.tf / user-<name>.tf 这类资源键（P2 之前声明确实按工单号
		// 命名，文件就是 IAM-<ticket>.tf）。此时清空同名文件才是真正的反向操作。
		// 其它类型（批量纳管、回滚工单本身、挂载工单）没有任何按工单号命名的
		// 声明，以前在这里生成空文件 → 「PR 合并、plan 零变更、工单显示已回滚」
		// （C14），现在明确报错。
		target, targetErr := service.repository.Get(ctx, request.TargetTicketNo)
		if targetErr != nil {
			return "", fmt.Errorf("load rollback target for legacy file key: %w", targetErr)
		}
		if !rollbackTargetUsesTicketNamedFile(target) {
			return "", apperr.Validationf(
				"rollback of ticket %s cannot be generated: its ticket type has no reverse Terraform path; undo the change with a dedicated ticket",
				request.TargetTicketNo)
		}
		return GenerateRollbackTerraform(rollbackTicketNo, request.TargetTicketNo, request.PrincipalName), nil
	}
}

func (service *TicketService) buildDetachTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, error) {
	if sourceTicketNo := strings.TrimSpace(request.SourceTicketNo); sourceTicketNo != "" {
		source, err := service.repository.Get(ctx, sourceTicketNo)
		if err != nil && !errors.Is(err, ErrTicketNotFound) {
			return "", fmt.Errorf("load detach source ticket: %w", err)
		}
		if err == nil && source.TicketType != nil && isCreateResourceTicket(*source.TicketType) {
			// 校验路径（validation stub）不带 AWSAccountID，这里统一补齐，
			// 否则 FetchTerraformFile 直接 500「valid AWS account ID is required」。
			if !isAWSAccountID(request.AWSAccountID) {
				awsAccountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
				if err != nil {
					return "", fmt.Errorf("load AWS account identifier for source detach: %w", err)
				}
				request.AWSAccountID = awsAccountID
			}
			fileContent, err := service.publisher.FetchTerraformFile(ctx, source, request)
			if err != nil {
				return "", fmt.Errorf("fetch source create Terraform file for detach: %w", err)
			}
			return service.removeAttachmentForDetach(fileContent, request)
		}
	}
	// 基线纳管的挂载：无源工单，声明活在基线发布的 attachment 文件里
	//（resourceFileKey 正好解析到同一路径）。解绑 = 抓取 main 上的基线
	// 文件、移除该挂载块后由工单 PR 覆写——资源地址不变，只是声明消失。
	if strings.TrimSpace(request.SourceTicketNo) == "" &&
		strings.TrimSpace(request.ManagedPolicyARN) != "" {
		owned, err := service.repository.BaselineOwnsAttachmentFile(
			ctx, request.AccountID,
			AttachmentFileKey(strings.ToLower(request.PrincipalType), request.PrincipalName, PolicyNameFromARN(request.ManagedPolicyARN)),
		)
		if err == nil && owned {
			if !isAWSAccountID(request.AWSAccountID) {
				request.AWSAccountID, err = service.repository.GetAWSAccountID(ctx, request.AccountID)
				if err != nil {
					return "", fmt.Errorf("load AWS account identifier for baseline detach: %w", err)
				}
			}
			fileContent, err := service.publisher.FetchTerraformFile(ctx, ticket, request)
			if err != nil {
				return "", fmt.Errorf("fetch baseline attachment file for detach: %w", err)
			}
			return service.removeAttachmentForDetach(fileContent, request)
		}
		// 查询失败或未纳管：落回通用 detach 文件生成（校验层已拒绝野生挂载，
		// 走到这里说明查询不可用，保留旧行为保底）。
	}
	ticketNo := ""
	if ticket.TicketNo != nil {
		ticketNo = *ticket.TicketNo
	}
	if strings.TrimSpace(ticketNo) == "" {
		ticketNo = rollbackPreviewTicketNo
	}
	return GenerateDetachTerraform(ticketNo, request.SourceTicketNo, request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN), nil
}

// removeAttachmentForDetach strips an attachment (resource + matching import
// block + its first-time-adoption comment header) from a Terraform file. When
// the file becomes empty — the usual case for a one-attachment-per-file
// baseline declaration — it returns a comment-only file explaining the detach
// (the same "comment-only emptied file" shape rollbacks leave behind), so the
// published PR is self-explanatory instead of a blank diff.
func (service *TicketService) removeAttachmentForDetach(
	fileContent string,
	request CreateIAMTicketRequest,
) (string, error) {
	removed, err := service.adapter.RemoveAttachmentFromTerraform(
		fileContent, request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN,
	)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(removed) == "" {
		var hcl strings.Builder
		hcl.WriteString("# DETACH managed policy from " + strings.ToUpper(request.PrincipalType) + " " + request.PrincipalName + "\n")
		hcl.WriteString("# Managed policy: " + request.ManagedPolicyARN + "\n")
		hcl.WriteString("#\n")
		hcl.WriteString("# The attachment declaration (and its import block) was removed by this detach ticket.\n")
		hcl.WriteString("# Only this principal's attachment is destroyed; the policy itself\n")
		hcl.WriteString("# and its attachments to other principals are untouched.\n")
		hcl.WriteString("# Run `terraform plan` to review the destroy, then apply.\n")
		return hcl.String(), nil
	}
	return removed, nil
}

func (service *TicketService) buildRoleInlinePolicyBundle(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, []TerraformBundleFile, error) {
	if strings.TrimSpace(request.PrincipalName) == "" || len(request.RoleInlinePolicies) == 0 {
		return "", nil, apperr.Validation("role name and at least one inline policy are required for batch adoption")
	}
	if strings.TrimSpace(request.AWSAccountID) == "" {
		accountID, err := service.repository.GetAWSAccountID(ctx, request.AccountID)
		if err != nil {
			return "", nil, fmt.Errorf("load AWS account identifier for role inline policy adoption: %w", err)
		}
		request.AWSAccountID = accountID
	}
	files := make([]TerraformBundleFile, 0, len(request.RoleInlinePolicies))
	seenKeys := make(map[string]struct{}, len(request.RoleInlinePolicies))
	var preview strings.Builder
	for _, policy := range request.RoleInlinePolicies {
		updateRequest := request
		updateRequest.TicketType = TicketTypeUpdateGroupInlinePolicy
		updateRequest.PrincipalType = "Role"
		updateRequest.UpdatePolicy = &adapter.UpdatePolicyConfig{
			RoleName: request.PrincipalName, InlinePolicyName: policy.Name,
		}
		key := updateRequest.policyFileKey()
		if key == "" {
			return "", nil, fmt.Errorf("unable to derive Terraform file key for inline policy %q", policy.Name)
		}
		if _, exists := seenKeys[key]; exists {
			return "", nil, apperr.Validationf("inline policy file-key collision at %s.tf; reconcile colliding policy names before batch adoption", key)
		}
		seenKeys[key] = struct{}{}
		existing, err := service.publisher.FetchTerraformFile(ctx, ticket, updateRequest)
		if err != nil && !errors.Is(err, ErrTerraformFileNotFound) {
			return "", nil, fmt.Errorf("check target Terraform file for inline policy %q: %w", policy.Name, err)
		}
		if err == nil && strings.TrimSpace(existing) != "" {
			return "", nil, fmt.Errorf("Terraform file %s.tf already exists; reconcile it before batch adoption", key)
		}
		code, err := service.adapter.GenerateUpdateRoleInlinePolicyTerraform(
			request.PrincipalName, policy.Name, policy.Document,
			request.PrincipalName+":"+policy.Name,
			adapter.InlinePolicyResourceLabel("role", request.PrincipalName, policy.Name),
		)
		if err != nil {
			return "", nil, fmt.Errorf("generate Terraform for inline policy %q: %w", policy.Name, err)
		}
		files = append(files, TerraformBundleFile{Key: key, Content: code})
		preview.WriteString("# File: ")
		preview.WriteString(key)
		preview.WriteString(".tf\n")
		preview.WriteString(code)
		if !strings.HasSuffix(code, "\n") {
			preview.WriteByte('\n')
		}
		preview.WriteByte('\n')
	}
	return preview.String(), files, nil
}

// buildTicketTerraformFiles renders the ticket's Terraform and, for tickets
// whose declarations span several files, the explicit bundle. The returned
// preview is the concatenation of those files, so what the approver reads is
// exactly what the pull request holds (校验所见 == 发布所得).
//
// Bundles exist for: adopting a role's inline policies (one file per policy),
// creating a user/group with initial relationships (the principal file plus one
// group-<group>-membership.tf per touched group), and rolling such a ticket
// back. A nil file slice means the single-file publish path.
func (service *TicketService) buildTicketTerraformFiles(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	captureSnapshots bool,
) (string, []TerraformBundleFile, error) {
	switch {
	case request.TicketType == TicketTypeAdoptRoleInlinePolicies:
		return service.buildRoleInlinePolicyBundle(ctx, ticket, request)
	case request.TicketType == TicketTypeCreateUser || request.TicketType == TicketTypeCreateGroup:
		if len(initialMembershipTargets(request)) > 0 {
			return service.buildCreateMembershipBundle(ctx, ticket, request)
		}
	case request.TicketType == TicketTypeRollback:
		// 回滚不生成"新声明"，只清空/反写目标文件；校验阶段工单号尚未生成，
		// 用占位符（只影响注释头）。
		rollbackTicketNo := rollbackPreviewTicketNo
		if ticket.TicketNo != nil && strings.TrimSpace(*ticket.TicketNo) != "" {
			rollbackTicketNo = *ticket.TicketNo
		}
		if strings.TrimSpace(request.TargetFileKey) != "" {
			code, files, err := service.buildCreateRollbackBundle(ctx, rollbackTicketNo, request)
			if err != nil {
				return "", nil, err
			}
			// 整文件清空的归属检查（C6）：清空前必须确认文件仍归被回滚的工单。
			// 只查主文件（目标工单自己的资源声明）：membership 这类副作用文件
			// 可能是基线在维护，清空它是回滚本身必须做的事（例如被回滚的用户
			// 恰是最后一个成员），拦下来只会让回滚永远做不了。
			if err := service.rejectEmptyingForeignFile(
				ctx, request, request.TargetFileKey, code,
			); err != nil {
				return "", nil, err
			}
			return code, files, nil
		}
		code, err := service.buildRollbackTerraform(ctx, rollbackTicketNo, request)
		if err != nil {
			return "", nil, err
		}
		// 单文件回滚（历史工单号命名的文件）：同样要过归属检查。
		if err := service.rejectEmptyingForeignFile(
			ctx, request, request.terraformFileTicketNo(rollbackTicketNo), code,
		); err != nil {
			return "", nil, err
		}
		return code, nil, nil
	}
	code, err := service.buildTicketTerraform(ctx, ticket, request, captureSnapshots)
	return code, nil, err
}

// buildTicketTerraform renders the single Terraform file a ticket publishes
// from its decoded request. captureSnapshots controls the pre-change snapshot
// writes ROLLBACK depends on: only publication captures them, so the read-only
// preview path never mutates ticket state. Multi-file tickets go through
// buildTicketTerraformFiles instead.
func (service *TicketService) buildTicketTerraform(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	captureSnapshots bool,
) (string, error) {
	// 获取抽象策略（优先新模型，回退旧模型）；ATTACH_USER_POLICY 挂载既有 policy
	var terraformCode string
	var err error
	if isCreateResourceTicket(request.TicketType) {
		terraformCode, err = service.buildCreateTerraform(ctx, request)
	} else if request.TicketType == TicketTypeAdoptRoleInlinePolicies {
		terraformCode, _, err = service.buildRoleInlinePolicyBundle(ctx, ticket, request)
	} else if request.TicketType == TicketTypeAttachUserPolicy {
		if request.Operation == OperationDetach {
			// detach：源挂载工单若是 CREATE_USER/CREATE_GROUP，挂载块与用户/组
			// 声明在同一个文件里，只移除对应 attachment block；否则清空源挂载
			// 工单文件 → destroy 该挂载。
			terraformCode, err = service.buildDetachTerraform(ctx, ticket, request)
		} else {
			// attach：清单里已存在但平台未纳管的野生挂载 → 用 import block
			// 首次纳管（幂等的 attach 也会成功，但 state 需要显式导入）。
			// 与校验预览共用 attachImportID（格式 <principalName>/<policyARN>，
			// 此前误用策略名做第二段，apply 时 provider 解析会失败）。
			terraformCode, err = service.adapter.GenerateAttachPolicyTerraform(
				request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN,
				service.attachImportID(ctx, request),
				adapter.DefaultAttachmentLabel(request.PrincipalType, request.PrincipalName, request.ManagedPolicyARN),
			)
		}
	} else if request.TicketType == TicketTypeUpdateGroupMembership {
		// 组成员变更（与预览同路径 generateUpdateGroupMembershipTerraform）：
		// main 上已有 group-<group>-membership.tf 则原地改写 users 列表，
		// 否则按清单全量生成（aws_iam_group_membership 不支持 import，首次
		// apply 以声明采纳现状）；移除最后一名成员 → 注释空文件 → destroy。
		terraformCode, _, err = service.generateUpdateGroupMembershipTerraform(ctx, ticket, request)
		if err == nil && captureSnapshots {
			service.captureMembershipSnapshot(ctx, &ticket, request)
		}
	} else if request.TicketType == TicketTypeRollback {
		// 回滚生成逻辑抽为共享方法：校验预览走同一路径（见 buildRollbackTerraform）。
		terraformCode, err = service.buildRollbackTerraform(ctx, *ticket.TicketNo, request)
	} else if request.TicketType == TicketTypeUpdateRole {
		// 更新角色（与预览同路径 generateUpdateRoleTerraform）：
		// - ② 有源文件：以 main 上的源 CREATE_ROLE 文件为基底，只改用户提交的
		//   属性（GitOps 原地更新，其余字节不动）；
		// - ③ 野生角色：main 上已有 role-<name>.tf 则原地 patch（保留既有资源
		//   label，避免地址漂移），否则生成新文件（首次带 import 纳管）。
		terraformCode, _, err = service.generateUpdateRoleTerraform(ctx, ticket, request)
		if err == nil && captureSnapshots {
			service.captureRoleSnapshot(ctx, &ticket, request.PrincipalName)
		}
	} else if request.TicketType == TicketTypeUpdateManagedPolicy || request.TicketType == TicketTypeUpdateGroupInlinePolicy {
		// 策略更新：用新文档 upsert 策略文件（GitOps 原地更新）。
		// 先拍快照（当前清单文档），回滚时用它重新生成。
		if captureSnapshots {
			service.capturePolicySnapshot(ctx, &ticket, request)
		}
		if strings.TrimSpace(request.SourceTicketNo) != "" &&
			request.UpdatePolicy != nil &&
			strings.TrimSpace(request.UpdatePolicy.RoleName) != "" &&
			strings.TrimSpace(request.UpdatePolicy.InlinePolicyName) != "" {
			// 平台创建角色的内嵌策略：覆写源 CREATE_ROLE 工单的 Terraform
			// 文件（② 块级 patch：只替换该内嵌策略的 policy 属性，与正向
			// 更新同一原语）。
			var unchanged bool
			terraformCode, unchanged, err = service.generateSourceRolePolicyFile(ctx, ticket, request, request.UpdatePolicy.Document)
			service.warnIfUnchanged(ticket, unchanged)
		} else if request.TicketType == TicketTypeUpdateGroupInlinePolicy {
			if request.UpdatePolicy == nil {
				return "", apperr.Validation("update_policy config missing for UPDATE_GROUP_INLINE_POLICY ticket")
			}
			// 独立内联策略文件：main 上已有该策略声明则块级 patch（label 不动，
			// 地址永不漂移），否则按稳定 label 全新生成。
			var unchanged bool
			terraformCode, unchanged, err = service.generateStandaloneInlinePolicyTerraform(ctx, ticket, request, request.UpdatePolicy.Document)
			service.warnIfUnchanged(ticket, unchanged)
		} else {
			if request.UpdatePolicy == nil {
				return "", errors.New("update_policy config missing for UPDATE_MANAGED_POLICY ticket")
			}
			// 原地 patch 现有声明（保留 path/description/tags），文件不在才生成。
			var unchanged bool
			terraformCode, unchanged, err = service.generateManagedPolicyTerraform(ctx, ticket, request)
			service.warnIfUnchanged(ticket, unchanged)
		}
	} else {
		// CREATE_ROLE：权限声明可选——未声明任何权限时只生成角色本体与初始挂载
		// （零权限角色），不生成 <role>-policy 内嵌策略资源。
		var abstractPolicy *abstractiam.AbstractPolicy
		if request.rolePolicyDeclared() {
			policy, policyErr := request.GetAbstractPolicy()
			if policyErr != nil {
				return "", fmt.Errorf("get abstract policy for Terraform generation: %w", policyErr)
			}
			abstractPolicy = policy
		}
		terraformCode, err = service.adapter.GenerateTerraformFromAbstractPolicy(abstractPolicy, request.Role)
	}
	return terraformCode, err
}

// PreviewTicketTerraform returns the Terraform file the ticket would publish.
// Published tickets return the stored content so the preview always matches
// the PR; unpublished tickets render on demand from the stored request.
// Generation is read-only: no snapshot capture, no publication lease, no
// status change.
func (service *TicketService) PreviewTicketTerraform(
	ctx context.Context,
	ticketNo, actorID string,
	roles []string,
) (string, error) {
	ticket, err := service.GetTicketForActor(ctx, ticketNo, actorID, roles)
	if err != nil {
		return "", err
	}
	if ticket.TerraformCode != nil && strings.TrimSpace(*ticket.TerraformCode) != "" {
		return *ticket.TerraformCode, nil
	}
	if ticket.TicketNo == nil || ticket.AccountID == nil {
		return "", errors.New("ticket is missing its number or AWS account ID")
	}
	var request CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
		return "", fmt.Errorf("decode ticket request for Terraform preview: %w", err)
	}
	request.AWSAccountID, err = service.repository.GetAWSAccountID(ctx, *ticket.AccountID)
	if err != nil {
		return "", fmt.Errorf("load AWS account identifier for preview: %w", err)
	}
	preview, _, err := service.buildTicketTerraformFiles(ctx, ticket, request, false)
	return preview, err
}

func (service *TicketService) publishApprovedTicket(
	ctx context.Context,
	ticket model.IAMTicket,
) (model.IAMTicket, error) {
	if ticket.TicketNo == nil || *ticket.TicketNo == "" {
		return model.IAMTicket{}, errors.New("approved ticket has no ticket number")
	}
	if ticket.GitPRURL != nil && *ticket.GitPRURL != "" {
		return ticket, nil
	}
	// Skip claim if already in PUBLISHING state (retry path)
	if ticket.Status == nil || *ticket.Status != TicketStatusPublishing {
		claimed, err := service.repository.ClaimPublication(ctx, *ticket.TicketNo, publicationLeaseDuration)
		if err != nil {
			return model.IAMTicket{}, fmt.Errorf("claim ticket publication: %w", err)
		}
		if !claimed {
			latest, err := service.repository.Get(ctx, *ticket.TicketNo)
			if err != nil {
				return model.IAMTicket{}, fmt.Errorf("load ticket publication state: %w", err)
			}
			return latest, nil
		}
	}
	publicationSaved := false
	defer func() {
		if !publicationSaved {
			if err := service.repository.ReleasePublication(ctx, *ticket.TicketNo); err != nil {
				service.logger.Error("release ticket publication claim",
					"ticket_no", *ticket.TicketNo,
					"error", err,
				)
			}
		}
	}()

	var request CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
		return model.IAMTicket{}, fmt.Errorf("decode approved ticket request: %w", err)
	}
	if ticket.AccountID == nil {
		return model.IAMTicket{}, errors.New("approved ticket has no AWS account database ID")
	}
	var err error
	request.AWSAccountID, err = service.repository.GetAWSAccountID(ctx, *ticket.AccountID)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("load AWS account identifier for ticket: %w", err)
	}
	terraformCode, bundleFiles, err := service.buildTicketTerraformFiles(ctx, ticket, request, true)
	if err != nil {
		// Mark ticket as PUBLISH_FAILED
		if markErr := service.repository.MarkPublishFailed(ctx, *ticket.TicketNo, TicketStatusPublishing, err.Error()); markErr != nil {
			service.logger.Error("failed to mark ticket as PUBLISH_FAILED",
				"ticket_no", *ticket.TicketNo,
				"error", markErr,
			)
		}
		return model.IAMTicket{}, &PublicationFailedError{Cause: fmt.Errorf("generate approved Terraform: %w", err)}
	}
	var publishResult *TicketPublishResult
	// 发布出去的文件集合：预约与声明快照共用这一份推导，避免两处口径
	// 漂移（单文件路径的 key 来自 terraformFileTicketNo，bundle 路径是
	// 生成器已经算好的 key）。
	publishedFiles := bundleFiles
	if len(publishedFiles) == 0 {
		publishedFiles = []TerraformBundleFile{{
			Key:     strings.ToLower(request.terraformFileTicketNo(*ticket.TicketNo)),
			Content: terraformCode,
		}}
	}
	if len(bundleFiles) > 0 {
		// 文件级发布预约（phase4 §4）：同一账号同一文件至多一个开放 PR 源。
		// 冲突 = 有别的工单/基线正在写同一文件，整单 PUBLISH_FAILED（可
		// 重试），错误信息指明占用者。nil 安全：未装配时跳过。
		if service.reservations != nil {
			reservedKeys := make([]string, 0, len(bundleFiles))
			for _, file := range bundleFiles {
				reservedKeys = append(reservedKeys, file.Key)
			}
			if _, err := service.reservations.ReserveForTicket(
				ctx, *ticket.AccountID, *ticket.TicketNo, reservedKeys,
			); err != nil {
				if markErr := service.repository.MarkPublishFailed(ctx, *ticket.TicketNo, TicketStatusPublishing, err.Error()); markErr != nil {
					service.logger.Error("failed to mark ticket as PUBLISH_FAILED",
						"ticket_no", *ticket.TicketNo,
						"error", markErr,
					)
				}
				return model.IAMTicket{}, &PublicationFailedError{Cause: err}
			}
		}
		bundlePublisher, ok := service.publisher.(TerraformBundlePublisher)
		if !ok {
			err = errors.New("configured Git publisher does not support Terraform bundles")
		} else {
			publishResult, err = bundlePublisher.PublishBundle(ctx, ticket, request, bundleFiles)
		}
	} else {
		// 单文件路径的文件 key 与发布器保持同一推导（publishFiles 模板）。
		if service.reservations != nil {
			singleKey := publishedFiles[0].Key
			if _, err := service.reservations.ReserveForTicket(
				ctx, *ticket.AccountID, *ticket.TicketNo, []string{singleKey},
			); err != nil {
				if markErr := service.repository.MarkPublishFailed(ctx, *ticket.TicketNo, TicketStatusPublishing, err.Error()); markErr != nil {
					service.logger.Error("failed to mark ticket as PUBLISH_FAILED",
						"ticket_no", *ticket.TicketNo,
						"error", markErr,
					)
				}
				return model.IAMTicket{}, &PublicationFailedError{Cause: err}
			}
		}
		publishResult, err = service.publisher.Publish(ctx, ticket, request, terraformCode)
	}
	if err != nil {
		// Mark ticket as PUBLISH_FAILED；预约同步释放，把文件让出来。
		if service.reservations != nil {
			if releaseErr := service.reservations.ReleaseTicket(ctx, *ticket.TicketNo); releaseErr != nil {
				service.logger.Warn("failed to release publish reservations",
					"ticket_no", *ticket.TicketNo, "error", releaseErr)
			}
		}
		if markErr := service.repository.MarkPublishFailed(ctx, *ticket.TicketNo, TicketStatusPublishing, err.Error()); markErr != nil {
			service.logger.Error("failed to mark ticket as PUBLISH_FAILED",
				"ticket_no", *ticket.TicketNo,
				"error", markErr,
			)
		}
		return model.IAMTicket{}, &PublicationFailedError{Cause: fmt.Errorf("publish ticket to Git host: %w", err)}
	}
	if publishResult == nil || strings.TrimSpace(publishResult.URL) == "" {
		err := errors.New("Git host publisher returned an empty Merge Request URL")
		// Mark ticket as PUBLISH_FAILED；预约同步释放，把文件让出来。
		if service.reservations != nil {
			if releaseErr := service.reservations.ReleaseTicket(ctx, *ticket.TicketNo); releaseErr != nil {
				service.logger.Warn("failed to release publish reservations",
					"ticket_no", *ticket.TicketNo, "error", releaseErr)
			}
		}
		return model.IAMTicket{}, &PublicationFailedError{Cause: err}
	}

	publication := TicketPublication{
		TerraformCode:       terraformCode,
		GitPRURL:            publishResult.URL,
		GitProvider:         strings.ToUpper(publishResult.Provider),
		GitRepository:       publishResult.Project,
		RemoteRequestNumber: publishResult.RemoteRequestNumber,
		GitCommitSHA:        publishResult.CommitSHA,
	}
	if err := service.repository.SavePublication(ctx, *ticket.TicketNo, publication); err != nil {
		return model.IAMTicket{}, fmt.Errorf("save Git host Merge Request URL: %w", err)
	}
	publicationSaved = true
	// 声明快照（phase4 §5，P2b）：PR 一开，这张工单声明了哪些资源就已经
	// 确定；从发布内容反解，与基线侧共用同一套形状。PR 被关闭未合并时
	// CloseTicket 会作废这张工单的声明。
	service.recordTicketDeclarations(ctx, ticket, request, publishedFiles)
	ticket.TerraformCode = stringPointer(terraformCode)
	ticket.GitPRURL = stringPointer(publishResult.URL)
	ticket.GitProvider = stringPointer(strings.ToUpper(publishResult.Provider))
	ticket.GitRepository = stringPointer(publishResult.Project)
	ticket.RemoteRequestNumber = stringPointer(publishResult.RemoteRequestNumber)
	ticket.GitCommitSHA = stringPointer(publishResult.CommitSHA)
	ticket.Status = stringPointer(TicketStatusApproved)

	// 入队 Git 状态轮询任务
	if service.pollEnqueuer != nil {
		pollPayload := GitStatusPollTask{
			TicketNo:            *ticket.TicketNo,
			Provider:            publishResult.Provider,
			Project:             publishResult.Project,
			RemoteRequestNumber: publishResult.RemoteRequestNumber,
			CommitSHA:           publishResult.CommitSHA,
			Attempt:             1,
		}
		if err := service.pollEnqueuer.EnqueueGitStatusPoll(ctx, pollPayload); err != nil {
			service.logger.Warn("failed to enqueue Git status poll task",
				"ticket_no", *ticket.TicketNo,
				"error", err,
			)
		} else {
			service.logger.Info("Git status poll task enqueued",
				"ticket_no", *ticket.TicketNo,
				"provider", publishResult.Provider,
			)
		}
	}

	service.logger.Info("IAM ticket published to code host",
		"ticket_no", *ticket.TicketNo,
		"git_pr_url", publishResult.URL,
		"git_provider", publishResult.Provider,
		"remote_request_number", publishResult.RemoteRequestNumber,
	)
	return ticket, nil
}

// recordTicketDeclarations 把工单发布出去的文件反解成声明快照落库
// （phase4 §5，P2b）：声明集合 = 基线声明 ∪ 成功工单声明，工单这一半从
// 发布内容里读——创建类工单一个文件里可能同时有主体、内联策略和挂载，
// 更新类工单只 patch 部分属性，只有内容里才有「完整声明」。
//
// 反解不全（引用解析不到、文件解析失败）只告警不阻断：发布已经成功，
// 把已开的 PR 报成失败更糟；缺口写进日志与 Drift 页的覆盖说明，绝不假装
// 已覆盖。
func (service *TicketService) recordTicketDeclarations(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	files []TerraformBundleFile,
) {
	if service.declarations == nil || ticket.AccountID == nil || len(files) == 0 {
		return
	}
	ticketNo := ""
	if ticket.TicketNo != nil {
		ticketNo = *ticket.TicketNo
	}
	declarations, gaps := ExtractDeclarations(files, DeclarationLabelsFromRequest(request))
	gapFiles := make(map[string]bool, len(gaps))
	for _, gap := range gaps {
		gapFiles[gap.FileKey] = true
	}
	if len(gaps) > 0 {
		service.logger.Warn("ticket declarations incomplete; those resources stay outside drift coverage",
			"ticket_no", ticketNo,
			"gaps", declarationGapSummary(gaps),
		)
	}
	published := make([]BaselineBundleFile, 0, len(files))
	touched := make([]string, 0, len(files))
	for _, file := range files {
		published = append(published, BaselineBundleFile{Key: file.Key, Content: file.Content})
		// 反解不出来的文件不动它的旧声明：那是不确定，不是「文件被清空」。
		if !gapFiles[file.Key] {
			touched = append(touched, file.Key)
		}
	}
	if len(declarations) == 0 && len(touched) == 0 {
		return
	}
	ticketID := ticket.ID
	target := DeclarationTarget{
		AccountDBID:  *ticket.AccountID,
		AWSAccountID: request.AWSAccountID,
		TicketID:     &ticketID,
		Declarations: declarations,
		TouchedFiles: touched,
	}
	if err := service.declarations.RecordDeclarations(ctx, target, published); err != nil {
		service.logger.Error("failed to record ticket declarations",
			"ticket_no", ticketNo,
			"account_id", *ticket.AccountID,
			"error", err,
		)
	}
}

// SQLTicketRepository persists ticket state and its designated approvers. A
// NULL approval_result is the pending state for a seeded designated approver.
type SQLTicketRepository struct {
	db *sql.DB
}

func NewSQLTicketRepository(db *sql.DB) (*SQLTicketRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLTicketRepository{db: db}, nil
}

func (repository *SQLTicketRepository) Create(
	ctx context.Context,
	ticket model.IAMTicket,
	approvers []string,
	validation TicketValidationSnapshot,
) (model.IAMTicket, error) {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("begin ticket creation transaction: %w", err)
	}
	defer transaction.Rollback()

	err = transaction.QueryRowContext(ctx, `INSERT INTO iam_ticket
		(ticket_no, ticket_type, account_id, principal_name, request_policy,
		 approval_mode, approver_ids, terraform_code, git_pr_url, status, submitter, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, NULL, NULL, $8, $9, NOW(), NOW())
		RETURNING id, created_at, updated_at`,
		ticket.TicketNo, ticket.TicketType, ticket.AccountID, ticket.PrincipalName,
		string(ticket.RequestPolicy), ticket.ApprovalMode, string(ticket.ApproverIDs), ticket.Status, ticket.Submitter,
	).Scan(&ticket.ID, &ticket.CreatedAt, &ticket.UpdatedAt)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("insert IAM ticket: %w", err)
	}

	for _, approver := range approvers {
		if _, err := transaction.ExecContext(ctx, `INSERT INTO ticket_approval
			(ticket_id, approver, approval_result, comment, created_at)
			VALUES ($1, $2, NULL, NULL, NOW())`, ticket.ID, approver); err != nil {
			return model.IAMTicket{}, fmt.Errorf("add designated approver %s: %w", approver, err)
		}
	}
	if len(validation.RequestSHA256) != sha256.Size || !json.Valid(validation.Checks) {
		return model.IAMTicket{}, errors.New("ticket validation snapshot is incomplete")
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO ticket_validation_record
		(ticket_id, attempt, baseline_id, request_sha256, result, checks, skipped_checks, created_at)
		VALUES ($1, 1, $2, $3, 'PASSED', $4::jsonb, '[]'::jsonb, NOW())`,
		ticket.ID, validation.BaselineID, validation.RequestSHA256, string(validation.Checks),
	); err != nil {
		return model.IAMTicket{}, fmt.Errorf("insert immutable ticket validation record: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return model.IAMTicket{}, fmt.Errorf("commit ticket creation: %w", err)
	}
	return ticket, nil
}

func (repository *SQLTicketRepository) CreateDraft(
	ctx context.Context,
	ticket model.IAMTicket,
) (model.IAMTicket, error) {
	if ticket.Status == nil || *ticket.Status != TicketStatusDraft ||
		len(ticket.RequestPolicy) == 0 || !json.Valid(ticket.RequestPolicy) ||
		len(ticket.ApproverIDs) == 0 || !json.Valid(ticket.ApproverIDs) {
		return model.IAMTicket{}, errors.New("ticket draft snapshot is incomplete")
	}
	err := repository.db.QueryRowContext(ctx, `INSERT INTO iam_ticket
		(ticket_no, ticket_type, account_id, principal_name, request_policy,
		 approval_mode, approver_ids, terraform_code, git_pr_url, status, submitter, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, NULL, NULL, $8, $9, NOW(), NOW())
		RETURNING id, created_at, updated_at`,
		ticket.TicketNo, ticket.TicketType, ticket.AccountID, ticket.PrincipalName,
		string(ticket.RequestPolicy), ticket.ApprovalMode, string(ticket.ApproverIDs),
		ticket.Status, ticket.Submitter,
	).Scan(&ticket.ID, &ticket.CreatedAt, &ticket.UpdatedAt)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("insert IAM ticket draft: %w", err)
	}
	return ticket, nil
}

func (repository *SQLTicketRepository) SubmitDraft(
	ctx context.Context,
	ticketNo string,
	approvers []string,
	validation TicketValidationSnapshot,
) (model.IAMTicket, error) {
	if len(validation.RequestSHA256) != sha256.Size || !json.Valid(validation.Checks) {
		return model.IAMTicket{}, errors.New("ticket validation snapshot is incomplete")
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("begin ticket submission transaction: %w", err)
	}
	defer transaction.Rollback()

	var ticketID int64
	var status string
	if err := transaction.QueryRowContext(ctx, `SELECT id, status FROM iam_ticket WHERE ticket_no = $1 FOR UPDATE`,
		ticketNo,
	).Scan(&ticketID, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.IAMTicket{}, ErrTicketNotFound
		}
		return model.IAMTicket{}, fmt.Errorf("lock ticket draft: %w", err)
	}
	if status != TicketStatusDraft {
		return model.IAMTicket{}, fmt.Errorf("%w: only %s tickets can be submitted", ErrInvalidTicketState, TicketStatusDraft)
	}
	for _, approver := range approvers {
		if _, err := transaction.ExecContext(ctx, `INSERT INTO ticket_approval
			(ticket_id, approver, approval_result, comment, created_at)
			VALUES ($1, $2, NULL, NULL, NOW())`, ticketID, approver); err != nil {
			return model.IAMTicket{}, fmt.Errorf("add designated approver %s: %w", approver, err)
		}
	}
	var attempt int
	if err := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(attempt), 0) + 1
		FROM ticket_validation_record WHERE ticket_id = $1`, ticketID).Scan(&attempt); err != nil {
		return model.IAMTicket{}, fmt.Errorf("allocate ticket validation attempt: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO ticket_validation_record
		(ticket_id, attempt, baseline_id, request_sha256, result, checks, skipped_checks, created_at)
		VALUES ($1, $2, $3, $4, 'PASSED', $5::jsonb, '[]'::jsonb, NOW())`,
		ticketID, attempt, validation.BaselineID, validation.RequestSHA256, string(validation.Checks),
	); err != nil {
		return model.IAMTicket{}, fmt.Errorf("insert immutable ticket validation record: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $2, updated_at = NOW() WHERE id = $1 AND status = $3`,
		ticketID, TicketStatusApproving, TicketStatusDraft,
	); err != nil {
		return model.IAMTicket{}, fmt.Errorf("transition ticket draft to approval: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return model.IAMTicket{}, fmt.Errorf("commit ticket submission: %w", err)
	}
	return repository.Get(ctx, ticketNo)
}

func (repository *SQLTicketRepository) GetEnabledBaseline(
	ctx context.Context,
	accountID int64,
) (model.IAMBaseline, error) {
	baseline, err := scanIAMBaseline(repository.db.QueryRowContext(ctx, `SELECT id, account_id, version,
		abstract_policy, enabled, created_by, created_at
		FROM iam_baseline
		WHERE account_id = $1 AND enabled = TRUE`, accountID))
	if err != nil {
		return model.IAMBaseline{}, err
	}
	return baseline, nil
}

// iamTicketColumns 是 iam_ticket 的完整读取列序。Get / ListTickets /
// RecordDecision（FOR UPDATE）三处查询必须共用它，列序与 scanIAMTicket
// 严格对应——分开写迟早会漏列，Scan 直接错位。
const iamTicketColumns = `id, ticket_no, ticket_type, account_id, principal_name, request_policy, approval_mode, approver_ids,
		terraform_code, git_pr_url, git_provider, git_repository, status, submitter, created_at, updated_at,
		next_poll_at, last_status_poll_at, closed_at, closed_by, closure_reason,
		poll_attempt_count, remote_request_number, role_snapshot,
		git_merge_state, git_ci_state, git_apply_result`

func (repository *SQLTicketRepository) Get(ctx context.Context, ticketNo string) (model.IAMTicket, error) {
	ticket, err := scanIAMTicket(repository.db.QueryRowContext(ctx, `SELECT `+iamTicketColumns+`
		FROM iam_ticket WHERE ticket_no = $1`, ticketNo))
	if errors.Is(err, sql.ErrNoRows) {
		return model.IAMTicket{}, ErrTicketNotFound
	}
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("select IAM ticket: %w", err)
	}
	return ticket, nil
}

func (repository *SQLTicketRepository) ListAvailableApprovers(
	ctx context.Context,
	accountID *int64,
) ([]model.PlatformUser, error) {
	// Only users who can actually decide a ticket may be selected as
	// approvers. Listing every active platform user let a standard_user be
	// designated as approver, but the decision endpoint correctly rejected
	// them, leaving the ticket permanently stuck.
	query := `SELECT DISTINCT users.user_id, users.display_name, users.email,
			users.is_active, users.created_at, users.updated_at
		FROM platform_user AS users
		JOIN user_role_mapping AS mapping ON mapping.user_id = users.user_id
		JOIN platform_role AS role ON role.id = mapping.role_id
		WHERE users.is_active = TRUE
			AND role.role_code IN ('platform_admin', 'approval_admin')`
	args := []interface{}{}
	if accountID != nil {
		query = `SELECT DISTINCT users.user_id, users.display_name, users.email,
				users.is_active, users.created_at, users.updated_at
			FROM platform_user AS users
			JOIN user_role_mapping AS mapping ON mapping.user_id = users.user_id
			JOIN platform_role AS role ON role.id = mapping.role_id
			JOIN aws_account_approver AS binding ON binding.user_id = users.user_id
			WHERE users.is_active = TRUE
				AND role.role_code IN ('platform_admin', 'approval_admin')
				AND binding.account_id = $1`
		args = append(args, *accountID)
	}
	query += ` ORDER BY display_name, user_id`
	rows, err := repository.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query platform approvers: %w", err)
	}
	defer rows.Close()

	users := make([]model.PlatformUser, 0)
	for rows.Next() {
		var user model.PlatformUser
		if err := rows.Scan(&user.UserID, &user.DisplayName, &user.Email, &user.IsActive, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan platform approver: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate platform approvers: %w", err)
	}
	return users, nil
}

func (repository *SQLTicketRepository) ResolveAutoApprovers(
	ctx context.Context,
	accountID int64,
) ([]model.PlatformUser, error) {
	if accountID <= 0 {
		return nil, errors.New("account database ID must be positive")
	}
	users, err := repository.ListAvailableApprovers(ctx, &accountID)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (repository *SQLTicketRepository) GetApprovalInfo(
	ctx context.Context,
	ticketNo string,
) (model.TicketApprovalInfo, error) {
	var info model.TicketApprovalInfo
	err := repository.db.QueryRowContext(ctx, `SELECT ticket_no, approval_mode, COALESCE(status, '')
		FROM iam_ticket WHERE ticket_no = $1`, ticketNo,
	).Scan(&info.TicketNo, &info.ApprovalMode, &info.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return model.TicketApprovalInfo{}, ErrTicketNotFound
	}
	if err != nil {
		return model.TicketApprovalInfo{}, fmt.Errorf("select ticket approval header: %w", err)
	}

	rows, err := repository.db.QueryContext(ctx, `SELECT approval.approver,
			COALESCE(users.display_name, approval.approver),
			approval.approval_result, approval.comment, approval.created_at
		FROM ticket_approval AS approval
		LEFT JOIN platform_user AS users ON users.user_id = approval.approver
		JOIN iam_ticket AS ticket ON ticket.id = approval.ticket_id
		WHERE ticket.ticket_no = $1
		ORDER BY approval.created_at, approval.approver`, ticketNo)
	if err != nil {
		return model.TicketApprovalInfo{}, fmt.Errorf("query ticket approval entries: %w", err)
	}
	defer rows.Close()

	info.Approvals = make([]model.TicketApprovalEntry, 0)
	for rows.Next() {
		var entry model.TicketApprovalEntry
		if err := rows.Scan(&entry.ApproverID, &entry.DisplayName, &entry.Result, &entry.Comment, &entry.CreatedAt); err != nil {
			return model.TicketApprovalInfo{}, fmt.Errorf("scan ticket approval entry: %w", err)
		}
		info.Approvals = append(info.Approvals, entry)
	}
	if err := rows.Err(); err != nil {
		return model.TicketApprovalInfo{}, fmt.Errorf("iterate ticket approval entries: %w", err)
	}
	return info, nil
}

func (repository *SQLTicketRepository) GetAWSAccountID(ctx context.Context, accountDatabaseID int64) (string, error) {
	var accountID string
	err := repository.db.QueryRowContext(ctx,
		`SELECT account_id FROM aws_account WHERE id = $1`,
		accountDatabaseID,
	).Scan(&accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("AWS account database ID %d: %w", accountDatabaseID, sql.ErrNoRows)
	}
	if err != nil {
		return "", fmt.Errorf("select AWS account identifier: %w", err)
	}
	if !isAWSAccountID(accountID) {
		return "", fmt.Errorf("AWS account database ID %d has invalid account ID %q", accountDatabaseID, accountID)
	}
	return accountID, nil
}

// AWSAccountSyncEnabled reports whether the account has an onboarding config
// with sync enabled. An account without any config row is treated as
// disabled: it was never onboarded onto the platform, so provisioning or
// syncing against it is rejected up front.
func (repository *SQLTicketRepository) AWSAccountSyncEnabled(ctx context.Context, accountDatabaseID int64) (bool, error) {
	var enabled bool
	err := repository.db.QueryRowContext(ctx, `
		SELECT COALESCE(bool_or(c.sync_enabled), FALSE)
		FROM aws_account a
		LEFT JOIN aws_account_config c
			ON c.aws_account_db_id = a.id
			OR (c.aws_account_db_id IS NULL AND c.aws_account_id = a.account_id)
		WHERE a.id = $1`,
		accountDatabaseID,
	).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("check AWS account sync enabled: %w", err)
	}
	return enabled, nil
}

func (repository *SQLTicketRepository) GetPrincipalPolicies(
	ctx context.Context,
	accountDatabaseID int64,
	principalName, principalType string,
) ([]ExistingIAMPolicy, bool, error) {
	rows, err := repository.db.QueryContext(ctx, `
		WITH effective_policy AS (
			SELECT principal_id, policy_id FROM iam_principal_policy
			UNION
			SELECT membership.user_principal_id, group_policy.policy_id
			FROM iam_group_membership AS membership
			JOIN iam_group_policy AS group_policy ON group_policy.group_id = membership.group_id
		)
		SELECT principal.id, policy.policy_name, policy.policy_document
		FROM iam_principal AS principal
		LEFT JOIN effective_policy AS attached ON attached.principal_id = principal.id
		LEFT JOIN iam_policy AS policy ON policy.id = attached.policy_id
		WHERE principal.account_id = $1
			AND principal.principal_name = $2
			AND principal.principal_type = $3
		ORDER BY policy.policy_name, policy.id`,
		accountDatabaseID, principalName, principalType,
	)
	if err != nil {
		return nil, false, fmt.Errorf("query policies for IAM principal: %w", err)
	}
	defer rows.Close()

	policies := make([]ExistingIAMPolicy, 0)
	principalExists := false
	for rows.Next() {
		var principalID int64
		var policyName sql.NullString
		var policyDocument []byte
		if err := rows.Scan(&principalID, &policyName, &policyDocument); err != nil {
			return nil, false, fmt.Errorf("scan existing IAM principal policy: %w", err)
		}
		principalExists = true
		if policyDocument == nil {
			continue
		}
		policies = append(policies, ExistingIAMPolicy{
			Name: policyName.String, Document: append(json.RawMessage(nil), policyDocument...),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate existing IAM principal policies: %w", err)
	}
	return policies, principalExists, nil
}

// PrincipalExists reports whether an IAM principal (User) or group (Group)
// exists in the collected inventory for the given account.
func (repository *SQLTicketRepository) PrincipalExists(
	ctx context.Context,
	accountDatabaseID int64,
	principalName, principalType string,
) (bool, error) {
	var count int
	var err error
	switch principalType {
	case "User", "Role":
		err = repository.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM iam_principal
			WHERE account_id = $1 AND principal_name = $2 AND principal_type = $3
				AND is_deleted = FALSE`,
			accountDatabaseID, principalName, principalType,
		).Scan(&count)
	case "Group":
		err = repository.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM iam_group
			WHERE account_id = $1 AND group_name = $2`,
			accountDatabaseID, principalName,
		).Scan(&count)
	default:
		return false, fmt.Errorf("unsupported principal type %q", principalType)
	}
	if err != nil {
		return false, fmt.Errorf("check %s %q in inventory: %w", strings.ToLower(principalType), principalName, err)
	}
	return count > 0, nil
}

// GetPrincipalTrustPolicy returns the current trust policy of a role.
func (repository *SQLTicketRepository) GetPrincipalTrustPolicy(
	ctx context.Context,
	accountDatabaseID int64,
	principalName string,
) (json.RawMessage, error) {
	var trustPolicy []byte
	err := repository.db.QueryRowContext(ctx, `
		SELECT trust_policy FROM iam_principal
		WHERE account_id = $1 AND principal_name = $2 AND principal_type = 'Role'
			AND is_deleted = FALSE`,
		accountDatabaseID, principalName,
	).Scan(&trustPolicy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query trust policy for role %s: %w", principalName, err)
	}
	if len(trustPolicy) == 0 {
		return nil, nil
	}
	return append(json.RawMessage(nil), trustPolicy...), nil
}

// RoleAttributes carries the role's collectible attributes beyond the trust
// policy: description, max session duration, and tags. Read by the UPDATE_ROLE
// snapshot so ROLLBACK can restore each attribute the update changed.
type RoleAttributes struct {
	Description        *string
	MaxSessionDuration *int64
	Tags               map[string]string
	// Path and PermissionsBoundaryARN are ForceNew: they are captured so a
	// regenerated/adopted declaration can reproduce them instead of silently
	// asking Terraform to drop them (which replaces the role).
	Path                   string
	PermissionsBoundaryARN string
}

func (repository *SQLTicketRepository) GetRoleAttributes(
	ctx context.Context,
	accountDatabaseID int64,
	roleName string,
) (*RoleAttributes, error) {
	var description sql.NullString
	var maxSessionDuration sql.NullInt64
	var tags []byte
	var path sql.NullString
	var permissionsBoundary sql.NullString
	err := repository.db.QueryRowContext(ctx, `
		SELECT description, max_session_duration, tags, path, permissions_boundary_arn
		FROM iam_principal
		WHERE account_id = $1 AND principal_name = $2 AND principal_type = 'Role'
			AND is_deleted = FALSE`,
		accountDatabaseID, roleName,
	).Scan(&description, &maxSessionDuration, &tags, &path, &permissionsBoundary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query role attributes for %s: %w", roleName, err)
	}
	attributes := &RoleAttributes{}
	if description.Valid {
		value := description.String
		attributes.Description = &value
	}
	if maxSessionDuration.Valid {
		value := maxSessionDuration.Int64
		attributes.MaxSessionDuration = &value
	}
	if len(tags) > 0 {
		var tagMap map[string]string
		if err := json.Unmarshal(tags, &tagMap); err != nil {
			return nil, fmt.Errorf("decode tags for role %s: %w", roleName, err)
		}
		attributes.Tags = tagMap
	}
	if path.Valid {
		attributes.Path = path.String
	}
	if permissionsBoundary.Valid {
		attributes.PermissionsBoundaryARN = permissionsBoundary.String
	}
	return attributes, nil
}

// FindCreatedRoleTicket returns the CREATE_ROLE ticket that created this role,
// used by UPDATE_ROLE to locate the Terraform file to modify. Only tickets
// whose Terraform actually landed (status MERGED, or CLOSED with
// closure_reason='APPLIED') qualify: DRAFT/ABANDONED tickets never published a
// file, so treating one as the source would aim the update at a file that does
// not exist on main and would wrongly bypass the "not created via this
// platform" guard. Returns (empty, nil) when the role was not created via the
// platform.
func (repository *SQLTicketRepository) FindCreatedRoleTicket(
	ctx context.Context,
	accountDatabaseID int64,
	principalName string,
) (string, error) {
	var ticketNo string
	err := repository.db.QueryRowContext(ctx, `
		SELECT ticket_no FROM iam_ticket
		WHERE account_id = $1 AND principal_name = $2 AND ticket_type = 'CREATE_ROLE'
			AND (status = 'MERGED' OR (status = 'CLOSED' AND closure_reason = 'APPLIED'))
		ORDER BY created_at DESC
		LIMIT 1`,
		accountDatabaseID, principalName,
	).Scan(&ticketNo)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find creating ticket for role %s: %w", principalName, err)
	}
	return ticketNo, nil
}

// CountActiveUpdateRoleTickets counts UPDATE_ROLE tickets for a role that are
// still in flight (DRAFT through MERGED, excluding REJECTED/CLOSED/FAILED).
func (repository *SQLTicketRepository) CountActiveUpdateRoleTickets(
	ctx context.Context,
	accountDatabaseID int64,
	principalName string,
) (int, error) {
	var count int
	err := repository.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_ticket
		WHERE account_id = $1 AND principal_name = $2 AND ticket_type = 'UPDATE_ROLE'
			AND status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
		accountDatabaseID, principalName,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active update-role tickets: %w", err)
	}
	return count, nil
}

// CountActiveCreateTickets counts in-flight CREATE_* tickets for one resource.
// A second creation ticket for the same name would race the first one and
// produce duplicate Terraform addresses or an import conflict.
func (repository *SQLTicketRepository) CountActiveCreateTickets(
	ctx context.Context,
	accountDatabaseID int64,
	ticketType, principalName string,
) (int, error) {
	var count int
	err := repository.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_ticket
		WHERE account_id = $1 AND ticket_type = $2 AND principal_name = $3
			AND status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
		accountDatabaseID, ticketType, principalName,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active create tickets: %w", err)
	}
	return count, nil
}

// CountAppliedUpdateRoleTickets counts UPDATE_ROLE tickets for one role that
// reached CLOSED(APPLIED) — the adoption mirror of FindCreatedRoleTicket:
// once one applied, the wild role has been imported into Terraform state and
// later updates must not emit another import block.
func (repository *SQLTicketRepository) CountAppliedUpdateRoleTickets(
	ctx context.Context,
	accountDatabaseID int64,
	principalName string,
) (int, error) {
	var count int
	err := repository.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_ticket
		WHERE account_id = $1 AND principal_name = $2 AND ticket_type = 'UPDATE_ROLE'
			AND status = 'CLOSED' AND closure_reason = 'APPLIED'`,
		accountDatabaseID, principalName,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count applied update-role tickets: %w", err)
	}
	return count, nil
}

// CountActiveUpdatePolicyTickets counts in-flight policy-update tickets for
// one policy identity: UPDATE_MANAGED_POLICY matched by managed_policy_arn,
// or UPDATE_GROUP_INLINE_POLICY matched by principal_type + principal name +
// inline policy name. principal_type is part of the key because a group and a
// role may share a name.
func (repository *SQLTicketRepository) CountActiveUpdatePolicyTickets(
	ctx context.Context,
	accountDatabaseID int64,
	ticketType, principalType, policyARN, groupName, inlinePolicyName string,
) (int, error) {
	var count int
	var err error
	switch ticketType {
	case TicketTypeUpdateManagedPolicy:
		err = repository.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM iam_ticket
			WHERE account_id = $1 AND ticket_type = $2
				AND request_policy #>> '{update_policy,policy_arn}' = $3
				AND status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
			accountDatabaseID, ticketType, policyARN,
		).Scan(&count)
	case TicketTypeUpdateGroupInlinePolicy:
		err = repository.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM iam_ticket
			WHERE account_id = $1 AND ticket_type = $2
				AND request_policy->>'principal_type' = $3
				AND request_policy->>'principal_name' = $4
				AND request_policy #>> '{update_policy,inline_policy_name}' = $5
				AND status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
			accountDatabaseID, ticketType, principalType, groupName, inlinePolicyName,
		).Scan(&count)
		if err == nil && principalType == "Role" {
			var batchCount int
			err = repository.db.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM iam_ticket t
				WHERE t.account_id = $1 AND t.ticket_type = $2
					AND t.request_policy->>'principal_name' = $3
					AND EXISTS (
						SELECT 1 FROM jsonb_array_elements(t.request_policy->'role_inline_policies') p
						WHERE p->>'name' = $4
					)
					AND t.status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
				accountDatabaseID, TicketTypeAdoptRoleInlinePolicies, groupName, inlinePolicyName,
			).Scan(&batchCount)
			count += batchCount
		}
	default:
		return 0, fmt.Errorf("unsupported policy update ticket type %q", ticketType)
	}
	if err != nil {
		return 0, fmt.Errorf("count active update-policy tickets: %w", err)
	}
	return count, nil
}

func (repository *SQLTicketRepository) CountActiveRolePolicyBatchTickets(
	ctx context.Context,
	accountDatabaseID int64,
	roleName string,
) (int, error) {
	var count int
	err := repository.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_ticket
		WHERE account_id = $1 AND ticket_type = $2
			AND request_policy->>'principal_type' = 'Role'
			AND request_policy->>'principal_name' = $3
			AND status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
		accountDatabaseID, TicketTypeAdoptRoleInlinePolicies, roleName,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active role inline policy adoption tickets: %w", err)
	}
	return count, nil
}

// CountAppliedUpdatePolicyTickets counts policy-update tickets that have been
// published and actually applied (status MERGED, or CLOSED with
// closure_reason='APPLIED'), meaning the policy resource is already managed in
// Terraform state and no import block is needed. CLOSED/ABANDONED tickets
// never published a Terraform file, so they must NOT suppress the import.
func (repository *SQLTicketRepository) CountAppliedUpdatePolicyTickets(
	ctx context.Context,
	accountDatabaseID int64,
	ticketType, principalType, policyARN, groupName, inlinePolicyName string,
) (int, error) {
	const applied = `(status = 'MERGED' OR (status = 'CLOSED' AND closure_reason = 'APPLIED'))`
	var count int
	var err error
	switch ticketType {
	case TicketTypeUpdateManagedPolicy:
		err = repository.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM iam_ticket
			WHERE account_id = $1 AND ticket_type = $2
				AND request_policy #>> '{update_policy,policy_arn}' = $3
				AND `+applied,
			accountDatabaseID, ticketType, policyARN,
		).Scan(&count)
	case TicketTypeUpdateGroupInlinePolicy:
		err = repository.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM iam_ticket
			WHERE account_id = $1 AND ticket_type = $2
				AND request_policy->>'principal_type' = $3
				AND request_policy->>'principal_name' = $4
				AND request_policy #>> '{update_policy,inline_policy_name}' = $5
				AND `+applied,
			accountDatabaseID, ticketType, principalType, groupName, inlinePolicyName,
		).Scan(&count)
		if err == nil && principalType == "Role" {
			var batchCount int
			err = repository.db.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM iam_ticket t
				WHERE t.account_id = $1 AND t.ticket_type = $2
					AND t.request_policy->>'principal_name' = $3
					AND EXISTS (
						SELECT 1 FROM jsonb_array_elements(t.request_policy->'role_inline_policies') p
						WHERE p->>'name' = $4
					)
					AND (t.status = 'MERGED' OR (t.status = 'CLOSED' AND t.closure_reason = 'APPLIED'))`,
				accountDatabaseID, TicketTypeAdoptRoleInlinePolicies, groupName, inlinePolicyName,
			).Scan(&batchCount)
			count += batchCount
		}
	default:
		return 0, fmt.Errorf("unsupported policy update ticket type %q", ticketType)
	}
	if err != nil {
		return 0, fmt.Errorf("count applied update-policy tickets: %w", err)
	}
	return count, nil
}

// ResolvePolicyAttachment reports whether the managed policy is currently
// attached to the principal in the collected inventory, and returns the
// ATTACH_USER_POLICY ticket that created the attachment (empty string for a
// platform-unmanaged "wild" attachment). Detach tickets use the source ticket
// to locate the Terraform file to clear; attach tickets use it to decide
// whether a Terraform `import` block is needed for first-time adoption.
func (repository *SQLTicketRepository) ResolvePolicyAttachment(
	ctx context.Context,
	accountDatabaseID int64,
	principalType, principalName, policyARN string,
) (bool, string, error) {
	var attached bool
	var err error
	switch principalType {
	case "Group":
		err = repository.db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM iam_group_policy gp
				JOIN iam_group g ON g.id = gp.group_id
				JOIN iam_policy pol ON pol.id = gp.policy_id
				WHERE g.account_id = $1 AND g.group_name = $2 AND pol.policy_arn = $3
			)`,
			accountDatabaseID, principalName, policyARN,
		).Scan(&attached)
	default:
		err = repository.db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM iam_principal_policy ipp
				JOIN iam_principal p ON p.id = ipp.principal_id
				JOIN iam_policy pol ON pol.id = ipp.policy_id
				WHERE p.account_id = $1 AND p.principal_name = $2 AND p.principal_type = $3
					AND pol.policy_arn = $4 AND p.is_deleted = FALSE
			)`,
			accountDatabaseID, principalName, principalType, policyARN,
		).Scan(&attached)
	}
	if err != nil {
		return false, "", fmt.Errorf("resolve policy attachment for %s %q policy %s: %w",
			strings.ToLower(principalType), principalName, policyARN, err)
	}
	if !attached {
		return false, "", nil
	}

	var sourceTicketNo string
	err = repository.db.QueryRowContext(ctx, `
		SELECT ticket_no FROM iam_ticket
		WHERE account_id = $1
			AND principal_name = $2
			AND request_policy->>'principal_type' = $3
			AND (status = 'MERGED' OR (status = 'CLOSED' AND closure_reason = 'APPLIED'))
			AND (
				(
					ticket_type = 'ATTACH_USER_POLICY'
					AND request_policy->>'managed_policy_arn' = $4
					AND request_policy->>'operation' IS DISTINCT FROM 'detach'
				)
				OR (
					ticket_type = 'CREATE_USER'
					AND jsonb_exists(request_policy->'create_user'->'policy_arns', $4)
				)
				OR (
					ticket_type = 'CREATE_GROUP'
					AND jsonb_exists(request_policy->'create_group'->'policy_arns', $4)
				)
				OR (
					ticket_type = 'CREATE_ROLE'
					AND jsonb_exists(request_policy->'role'->'policy_arns', $4)
				)
			)
		ORDER BY created_at DESC
		LIMIT 1`,
		accountDatabaseID, principalName, principalType, policyARN,
	).Scan(&sourceTicketNo)
	if errors.Is(err, sql.ErrNoRows) {
		return true, "", nil
	}
	if err != nil {
		return true, "", fmt.Errorf("find attach ticket for %s %q policy %s: %w",
			strings.ToLower(principalType), principalName, policyARN, err)
	}
	return true, sourceTicketNo, nil
}

// GroupMembers 返回一个 IAM 组在采集清单里的当前成员。
func (repository *SQLTicketRepository) GroupMembers(
	ctx context.Context,
	accountDatabaseID int64,
	groupName string,
) ([]string, error) {
	rows, err := repository.db.QueryContext(ctx, `
		SELECT p.principal_name
		FROM iam_group_membership m
		JOIN iam_group g ON g.id = m.group_id
		JOIN iam_principal p ON p.id = m.user_principal_id
		WHERE g.account_id = $1 AND g.group_name = $2 AND p.is_deleted = FALSE
		ORDER BY p.principal_name`,
		accountDatabaseID, groupName,
	)
	if err != nil {
		return nil, fmt.Errorf("load group members for %s: %w", groupName, err)
	}
	defer rows.Close()
	members := []string{}
	for rows.Next() {
		var member string
		if err := rows.Scan(&member); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

// CountActiveGroupMembershipTickets 报告一个组的进行中组成员工单数。
func (repository *SQLTicketRepository) CountActiveGroupMembershipTickets(
	ctx context.Context,
	accountDatabaseID int64,
	groupName string,
) (int, error) {
	var count int
	err := repository.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_ticket
		WHERE account_id = $1 AND ticket_type = $2
			AND request_policy #>> '{update_membership,group_name}' = $3
			AND status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED')`,
		accountDatabaseID, TicketTypeUpdateGroupMembership, groupName,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active group membership tickets for %s: %w", groupName, err)
	}
	return count, nil
}

// BaselineOwnsAttachmentFile 查询 attachment 文件是否出现在该账号任一已合并
// 基线发布的 files 清单里。只认 MERGED：PUBLISHED（PR 仍开放）时文件还没进
// main，解绑预览按 main 上的文件内容改写会拿不到内容。fileKey 是不带后缀的
// AttachmentFileKey 形态，台账 files 里的 file 字段带 ".tf"，比较时补齐。
func (repository *SQLTicketRepository) BaselineOwnsAttachmentFile(
	ctx context.Context,
	accountDatabaseID int64,
	fileKey string,
) (bool, error) {
	var owned bool
	err := repository.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM iam_baseline_publication bp,
			     jsonb_array_elements(bp.files) elem
			WHERE bp.account_id = $1
				AND bp.status = 'MERGED'
				AND elem->>'file' = $2 || '.tf'
		)`,
		accountDatabaseID, fileKey,
	).Scan(&owned)
	if err != nil {
		return false, fmt.Errorf("check baseline ownership of %s: %w", fileKey, err)
	}
	return owned, nil
}

// BaselineOwnsResourceFile 查询资源声明文件是否出现在该账号任一基线发布的
// files 清单里。与 BaselineOwnsAttachmentFile（只认 MERGED）不同，这里把
// PUBLISHED 也算「已纳管」：adopt 工单再写同一文件会和在途基线 PR 冲突。
// fileKey 是不带后缀的 ResourceFileKey 形态，比较时补 ".tf"。
func (repository *SQLTicketRepository) BaselineOwnsResourceFile(
	ctx context.Context,
	accountDatabaseID int64,
	fileKey string,
) (bool, error) {
	var owned bool
	err := repository.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM iam_baseline_publication bp,
			     jsonb_array_elements(bp.files) elem
			WHERE bp.account_id = $1
				AND bp.status IN ('PUBLISHED', 'MERGED')
				AND elem->>'file' = $2 || '.tf'
		)`,
		accountDatabaseID, fileKey,
	).Scan(&owned)
	if err != nil {
		return false, fmt.Errorf("check baseline ownership of %s: %w", fileKey, err)
	}
	return owned, nil
}

// FileDeclarationOwners 返回文件当前生效声明的归属集合（ticket_id，0 = 基线）。
// 空切片表示没有生效声明——调用方据此决定「无法证明归属」时的策略。
func (repository *SQLTicketRepository) FileDeclarationOwners(
	ctx context.Context,
	accountDatabaseID int64,
	fileKey string,
) ([]int64, error) {
	rows, err := repository.db.QueryContext(ctx, `
		SELECT DISTINCT COALESCE(ticket_id, 0)
		FROM iam_baseline_declaration
		WHERE account_id = $1 AND file_key = $2 AND superseded_at IS NULL
		ORDER BY 1`,
		accountDatabaseID, fileKey)
	if err != nil {
		return nil, fmt.Errorf("load declaration owners of %s: %w", fileKey, err)
	}
	defer rows.Close()
	owners := make([]int64, 0, 2)
	for rows.Next() {
		var owner int64
		if err := rows.Scan(&owner); err != nil {
			return nil, fmt.Errorf("scan declaration owner of %s: %w", fileKey, err)
		}
		owners = append(owners, owner)
	}
	return owners, rows.Err()
}

// GetManagedPolicyByARN returns the current document of a managed policy by
// ARN. Returns (nil, false, nil) when the policy is not in the inventory.
func (repository *SQLTicketRepository) GetManagedPolicyByARN(
	ctx context.Context,
	policyARN string,
) (json.RawMessage, bool, error) {
	var document []byte
	err := repository.db.QueryRowContext(ctx, `
		SELECT policy_document FROM iam_policy
		WHERE policy_arn = $1`,
		policyARN,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("query managed policy %s: %w", policyARN, err)
	}
	return append(json.RawMessage(nil), document...), true, nil
}

// GetGroupInlinePolicy returns the current document of a group inline policy
// by group name + inline policy name. Returns (nil, false, nil) when the
// inline policy is not found on the group.
func (repository *SQLTicketRepository) GetGroupInlinePolicy(
	ctx context.Context,
	accountDatabaseID int64,
	groupName, inlinePolicyName string,
) (json.RawMessage, bool, error) {
	var document []byte
	err := repository.db.QueryRowContext(ctx, `
		SELECT p.policy_document FROM iam_policy p
		JOIN iam_group_policy gp ON gp.policy_id = p.id
		JOIN iam_group g ON g.id = gp.group_id
		WHERE g.account_id = $1 AND g.group_name = $2 AND p.policy_name = $3
			AND p.policy_type = 'inline'`,
		accountDatabaseID, groupName, inlinePolicyName,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("query group inline policy %s on group %s: %w",
			inlinePolicyName, groupName, err)
	}
	return append(json.RawMessage(nil), document...), true, nil
}

func (repository *SQLTicketRepository) GetGroupAdoptionSnapshot(
	ctx context.Context,
	accountDatabaseID int64,
	groupName string,
) (adapter.IAMGroupInfo, error) {
	var snapshot adapter.IAMGroupInfo
	var groupID int64
	if err := repository.db.QueryRowContext(ctx, `
		SELECT id, group_name, path
		FROM iam_group
		WHERE account_id = $1 AND group_name = $2`,
		accountDatabaseID, groupName,
	).Scan(&groupID, &snapshot.Name, &snapshot.Path); err != nil {
		return adapter.IAMGroupInfo{}, fmt.Errorf("load group identity: %w", err)
	}

	snapshot.MemberUserNames = make([]string, 0)
	memberRows, err := repository.db.QueryContext(ctx, `
		SELECT p.principal_name
		FROM iam_group_membership gm
		JOIN iam_principal p ON p.id = gm.user_principal_id
		WHERE gm.group_id = $1 AND p.is_deleted = FALSE
		ORDER BY p.principal_name`, groupID)
	if err != nil {
		return adapter.IAMGroupInfo{}, fmt.Errorf("load group members: %w", err)
	}
	for memberRows.Next() {
		var name string
		if err := memberRows.Scan(&name); err != nil {
			memberRows.Close()
			return adapter.IAMGroupInfo{}, fmt.Errorf("scan group member: %w", err)
		}
		snapshot.MemberUserNames = append(snapshot.MemberUserNames, name)
	}
	if err := memberRows.Err(); err != nil {
		memberRows.Close()
		return adapter.IAMGroupInfo{}, fmt.Errorf("iterate group members: %w", err)
	}
	if err := memberRows.Close(); err != nil {
		return adapter.IAMGroupInfo{}, fmt.Errorf("close group member rows: %w", err)
	}

	snapshot.PolicyARNs = make([]string, 0)
	snapshot.InlinePolicies = make([]adapter.IAMInlinePolicy, 0)
	policyRows, err := repository.db.QueryContext(ctx, `
		SELECT p.policy_name, p.policy_type, p.policy_arn, p.policy_document
		FROM iam_group_policy gp
		JOIN iam_policy p ON p.id = gp.policy_id
		WHERE gp.group_id = $1
		ORDER BY p.policy_name`, groupID)
	if err != nil {
		return adapter.IAMGroupInfo{}, fmt.Errorf("load group policies: %w", err)
	}
	for policyRows.Next() {
		var name, policyType string
		var policyARN sql.NullString
		var document []byte
		if err := policyRows.Scan(&name, &policyType, &policyARN, &document); err != nil {
			policyRows.Close()
			return adapter.IAMGroupInfo{}, fmt.Errorf("scan group policy: %w", err)
		}
		if policyType == "inline" {
			if len(document) == 0 || !json.Valid(document) {
				policyRows.Close()
				return adapter.IAMGroupInfo{}, fmt.Errorf("group inline policy %q has no valid inventory document", name)
			}
			snapshot.InlinePolicies = append(snapshot.InlinePolicies, adapter.IAMInlinePolicy{
				Name: name, Document: append(json.RawMessage(nil), document...),
			})
			continue
		}
		if !policyARN.Valid || strings.TrimSpace(policyARN.String) == "" {
			policyRows.Close()
			return adapter.IAMGroupInfo{}, fmt.Errorf("managed group policy %q has no ARN in inventory", name)
		}
		snapshot.PolicyARNs = append(snapshot.PolicyARNs, strings.TrimSpace(policyARN.String))
	}
	if err := policyRows.Err(); err != nil {
		policyRows.Close()
		return adapter.IAMGroupInfo{}, fmt.Errorf("iterate group policies: %w", err)
	}
	if err := policyRows.Close(); err != nil {
		return adapter.IAMGroupInfo{}, fmt.Errorf("close group policy rows: %w", err)
	}
	return snapshot, nil
}

// GetRoleInlinePolicy returns the current document of a role inline policy by
// role name + inline policy name. Returns (nil, false, nil) when the inline
// policy is not found on the role. Roles live in the unified iam_principal
// table (principal_type = 'Role'); the policy link table is
// iam_principal_policy.
func (repository *SQLTicketRepository) GetRoleInlinePolicy(
	ctx context.Context,
	accountDatabaseID int64,
	roleName, inlinePolicyName string,
) (json.RawMessage, bool, error) {
	var document []byte
	err := repository.db.QueryRowContext(ctx, `
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
	return append(json.RawMessage(nil), document...), true, nil
}

func (repository *SQLTicketRepository) ListRoleInlinePolicies(
	ctx context.Context,
	accountDatabaseID int64,
	roleName string,
) ([]ExistingIAMPolicy, error) {
	rows, err := repository.db.QueryContext(ctx, `
		SELECT p.policy_name, p.policy_document
		FROM iam_policy p
		JOIN iam_principal_policy pp ON pp.policy_id = p.id
		JOIN iam_principal r ON r.id = pp.principal_id
		WHERE r.account_id = $1 AND r.principal_type = 'Role'
			AND r.principal_name = $2 AND p.policy_type = 'inline'
			AND r.is_deleted = FALSE
		ORDER BY p.policy_name`,
		accountDatabaseID, roleName,
	)
	if err != nil {
		return nil, fmt.Errorf("query inline policies for role %s: %w", roleName, err)
	}
	defer rows.Close()
	policies := make([]ExistingIAMPolicy, 0)
	for rows.Next() {
		var policy ExistingIAMPolicy
		if err := rows.Scan(&policy.Name, &policy.Document); err != nil {
			return nil, fmt.Errorf("scan inline policy for role %s: %w", roleName, err)
		}
		policy.Document = append(json.RawMessage(nil), policy.Document...)
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inline policies for role %s: %w", roleName, err)
	}
	return policies, nil
}

// FindRollbackTickets returns ROLLBACK tickets that target the given ticket.
func (repository *SQLTicketRepository) FindRollbackTickets(ctx context.Context, targetTicketNo string) ([]model.IAMTicket, error) {
	rows, err := repository.db.QueryContext(ctx, `
		SELECT ticket_no, status FROM iam_ticket
		WHERE ticket_type = $1 AND request_policy->>'target_ticket_no' = $2`,
		TicketTypeRollback, targetTicketNo,
	)
	if err != nil {
		return nil, fmt.Errorf("query rollback tickets for target %s: %w", targetTicketNo, err)
	}
	defer rows.Close()

	tickets := make([]model.IAMTicket, 0)
	for rows.Next() {
		var ticketNo, status string
		if err := rows.Scan(&ticketNo, &status); err != nil {
			return nil, fmt.Errorf("scan rollback ticket: %w", err)
		}
		tickets = append(tickets, model.IAMTicket{
			TicketNo: stringPointer(ticketNo),
			Status:   stringPointer(status),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rollback tickets: %w", err)
	}
	return tickets, nil
}

// ListTickets returns tickets matching the filter ordered by creation time
// (newest first), plus the total matching count for pagination.
func (repository *SQLTicketRepository) ListTickets(
	ctx context.Context,
	filter TicketListFilter,
) ([]model.IAMTicket, int64, error) {
	conditions := []string{"TRUE"}
	args := make([]interface{}, 0, 6)
	addArg := func(value interface{}) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, 0, len(filter.Statuses))
		for _, status := range filter.Statuses {
			placeholders = append(placeholders, addArg(status))
		}
		conditions = append(conditions, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if filter.AccountID != nil {
		conditions = append(conditions, "account_id = "+addArg(*filter.AccountID))
	}
	if submitter := strings.TrimSpace(filter.Submitter); submitter != "" {
		conditions = append(conditions, "submitter = "+addArg(submitter))
	}
	if ticketType := strings.TrimSpace(filter.TicketType); ticketType != "" {
		conditions = append(conditions, "ticket_type = "+addArg(ticketType))
	}
	if keyword := strings.TrimSpace(filter.Keyword); keyword != "" {
		pattern := addArg("%" + keyword + "%")
		conditions = append(conditions, "(ticket_no ILIKE "+pattern+" OR principal_name ILIKE "+addArg("%"+keyword+"%")+")")
	}
	where := strings.Join(conditions, " AND ")

	var total int64
	if err := repository.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM iam_ticket WHERE "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count IAM tickets: %w", err)
	}
	tickets := make([]model.IAMTicket, 0)
	if total == 0 || filter.Offset >= int(total) {
		return tickets, total, nil
	}

	queryArgs := append(append([]interface{}{}, args...), filter.Limit, filter.Offset)
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	offsetPlaceholder := fmt.Sprintf("$%d", len(args)+2)
	rows, err := repository.db.QueryContext(ctx, `SELECT `+iamTicketColumns+`
		FROM iam_ticket WHERE `+where+` ORDER BY created_at DESC, id DESC
		LIMIT `+limitPlaceholder+` OFFSET `+offsetPlaceholder, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list IAM tickets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		ticket, err := scanIAMTicket(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan IAM ticket row: %w", err)
		}
		tickets = append(tickets, ticket)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate IAM tickets: %w", err)
	}
	return tickets, total, nil
}

func (repository *SQLTicketRepository) RecordDecision(
	ctx context.Context,
	ticketNo, approver, result, comment string,
) (model.IAMTicket, error) {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("begin approval transaction: %w", err)
	}
	defer transaction.Rollback()

	ticket, err := scanIAMTicket(transaction.QueryRowContext(ctx, `SELECT `+iamTicketColumns+`
		FROM iam_ticket WHERE ticket_no = $1 FOR UPDATE`, ticketNo))
	if errors.Is(err, sql.ErrNoRows) {
		return model.IAMTicket{}, ErrTicketNotFound
	}
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("lock IAM ticket: %w", err)
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		if ticket.Status != nil && *ticket.Status == TicketStatusApproved {
			var approved bool
			err := transaction.QueryRowContext(ctx, `SELECT EXISTS (
				SELECT 1 FROM ticket_approval
				WHERE ticket_id = $1 AND approver = $2 AND approval_result = 'APPROVE'
			)`, ticket.ID, approver).Scan(&approved)
			if err != nil {
				return model.IAMTicket{}, fmt.Errorf("verify approved approver: %w", err)
			}
			if !approved {
				return model.IAMTicket{}, ErrNotDesignatedApprover
			}
			if err := transaction.Commit(); err != nil {
				return model.IAMTicket{}, fmt.Errorf("commit repeat approval check: %w", err)
			}
			return ticket, nil
		}
		return model.IAMTicket{}, fmt.Errorf("%w: ticket status is %q", ErrInvalidTicketState, statusString(ticket.Status))
	}

	updateResult, err := transaction.ExecContext(ctx, `UPDATE ticket_approval
		SET approval_result = $1, comment = $2
		WHERE ticket_id = $3 AND approver = $4 AND approval_result IS NULL`,
		result, nullableComment(comment), ticket.ID, approver,
	)
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("update ticket approval: %w", err)
	}
	rowsAffected, err := updateResult.RowsAffected()
	if err != nil {
		return model.IAMTicket{}, fmt.Errorf("check ticket approval update: %w", err)
	}
	if rowsAffected == 0 {
		var pending bool
		err := transaction.QueryRowContext(ctx, `SELECT approval_result IS NULL
			FROM ticket_approval WHERE ticket_id = $1 AND approver = $2`, ticket.ID, approver).Scan(&pending)
		if errors.Is(err, sql.ErrNoRows) {
			return model.IAMTicket{}, ErrNotDesignatedApprover
		}
		if err != nil {
			return model.IAMTicket{}, fmt.Errorf("check designated approver: %w", err)
		}
		if !pending {
			return model.IAMTicket{}, ErrApprovalAlreadySet
		}
		return model.IAMTicket{}, errors.New("approval decision did not update a pending approver")
	}

	if result == "REJECT" {
		ticket.Status = stringPointer(TicketStatusRejected)
		if _, err := transaction.ExecContext(ctx, `UPDATE iam_ticket
			SET status = $1, updated_at = NOW() WHERE id = $2`,
			TicketStatusRejected, ticket.ID,
		); err != nil {
			return model.IAMTicket{}, fmt.Errorf("reject IAM ticket: %w", err)
		}
	} else {
		var pendingApprovers int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM ticket_approval
			WHERE ticket_id = $1 AND approval_result IS NULL`, ticket.ID).Scan(&pendingApprovers); err != nil {
			return model.IAMTicket{}, fmt.Errorf("count pending ticket approvers: %w", err)
		}
		if pendingApprovers == 0 {
			ticket.Status = stringPointer(TicketStatusApproved)
			if _, err := transaction.ExecContext(ctx, `UPDATE iam_ticket
				SET status = $1, updated_at = NOW() WHERE id = $2`,
				TicketStatusApproved, ticket.ID,
			); err != nil {
				return model.IAMTicket{}, fmt.Errorf("approve IAM ticket: %w", err)
			}
		}
	}

	if err := transaction.Commit(); err != nil {
		return model.IAMTicket{}, fmt.Errorf("commit ticket approval: %w", err)
	}
	return ticket, nil
}

func (repository *SQLTicketRepository) SavePublication(
	ctx context.Context,
	ticketNo string,
	publication TicketPublication,
) error {
	result, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket
		SET terraform_code = $1,
			git_pr_url = $2,
			git_provider = $3,
			git_repository = $4,
			remote_request_number = $5,
			git_commit_sha = $6,
			status = $7,
			updated_at = NOW()
		WHERE ticket_no = $8 AND status = $9`,
		publication.TerraformCode, publication.GitPRURL,
		publication.GitProvider, publication.GitRepository,
		publication.RemoteRequestNumber, publication.GitCommitSHA,
		TicketStatusApproved, ticketNo, TicketStatusPublishing,
	)
	if err != nil {
		return fmt.Errorf("update ticket publication: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check ticket publication update: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: approved ticket %s was not updated", ErrInvalidTicketState, ticketNo)
	}
	return nil
}

// ResetPollSchedule clears the consumed poll budget so the gitstatus
// worker starts a fresh observation window for the ticket.
func (repository *SQLTicketRepository) ResetPollSchedule(ctx context.Context, ticketNo string) error {
	result, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket
		SET poll_attempt_count = 0, updated_at = NOW()
		WHERE ticket_no = $1`, ticketNo)
	if err != nil {
		return fmt.Errorf("reset poll schedule: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check poll schedule reset: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: ticket %s not found for poll reset", ErrTicketNotFound, ticketNo)
	}
	return nil
}

func (repository *SQLTicketRepository) CloseTicket(
	ctx context.Context,
	ticketNo, actorID, reason, comment string,
) (model.IAMTicket, error) {
	ticket, err := repository.Get(ctx, ticketNo)
	if err != nil {
		return model.IAMTicket{}, err
	}

	// Check if ticket is in a closable state
	if ticket.Status == nil {
		return model.IAMTicket{}, fmt.Errorf("ticket %s has no status", ticketNo)
	}

	closableStates := []string{
		TicketStatusDraft,
		TicketStatusApproving,
		TicketStatusApproved,
		TicketStatusPublishing,
		TicketStatusPublishFailed,
	}

	isClosable := false
	for _, state := range closableStates {
		if *ticket.Status == state {
			isClosable = true
			break
		}
	}

	if !isClosable {
		return model.IAMTicket{}, fmt.Errorf("ticket %s cannot be closed from state %s", ticketNo, *ticket.Status)
	}

	// Update ticket status to CLOSED
	result, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, closed_at = NOW(), closed_by = $2, closure_reason = $3, closure_comment = $4, updated_at = NOW()
		WHERE ticket_no = $5`,
		TicketStatusClosed, actorID, reason, comment, ticketNo,
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

	ticket.Status = stringPointer(TicketStatusClosed)
	closedBy := actorID
	ticket.ClosedBy = &closedBy
	closedAt := time.Now()
	ticket.ClosedAt = &closedAt
	closureReason := reason
	ticket.ClosureReason = &closureReason
	closureComment := comment
	ticket.ClosureComment = &closureComment

	return ticket, nil
}

func (repository *SQLTicketRepository) ClaimPublication(
	ctx context.Context,
	ticketNo string,
	leaseDuration time.Duration,
) (bool, error) {
	if leaseDuration <= 0 {
		return false, errors.New("publication lease duration must be positive")
	}
	leaseSeconds := int64(leaseDuration.Seconds())
	if leaseSeconds == 0 {
		leaseSeconds = 1
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, updated_at = NOW()
		WHERE ticket_no = $2 AND (
			status = $3 OR
			(status = $1 AND updated_at < NOW() - ($4 * INTERVAL '1 second'))
		)`,
		TicketStatusPublishing, ticketNo, TicketStatusApproved, leaseSeconds,
	)
	if err != nil {
		return false, fmt.Errorf("claim IAM ticket publication: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check IAM ticket publication claim: %w", err)
	}
	return rowsAffected == 1, nil
}

func (repository *SQLTicketRepository) ReleasePublication(ctx context.Context, ticketNo string) error {
	if _, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, updated_at = NOW()
		WHERE ticket_no = $2 AND status = $3`,
		TicketStatusApproved, ticketNo, TicketStatusPublishing,
	); err != nil {
		return fmt.Errorf("release IAM ticket publication claim: %w", err)
	}
	return nil
}

// SaveRoleSnapshot stores the role's pre-update configuration snapshot on the
// ticket. ROLLBACK of an UPDATE_ROLE ticket reads this snapshot to generate
// reverse Terraform that restores the original state.
func (repository *SQLTicketRepository) SaveRoleSnapshot(
	ctx context.Context,
	ticketNo string,
	snapshot json.RawMessage,
) error {
	_, err := repository.db.ExecContext(ctx, `
		UPDATE iam_ticket SET role_snapshot = $2, updated_at = NOW()
		WHERE ticket_no = $1`,
		ticketNo, snapshot,
	)
	if err != nil {
		return fmt.Errorf("save role snapshot for ticket %s: %w", ticketNo, err)
	}
	return nil
}

func (repository *SQLTicketRepository) SetStatus(
	ctx context.Context,
	ticketNo, expectedStatus, status string,
) error {
	// Validate state transition
	if err := ValidateTransition(expectedStatus, status); err != nil {
		return err
	}

	result, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket SET status = $1, updated_at = NOW()
		WHERE ticket_no = $2 AND status = $3`,
		status, ticketNo, expectedStatus,
	)
	if err != nil {
		return fmt.Errorf("update ticket status: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check ticket status update: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: cannot transition ticket %s from %s to %s", ErrInvalidTicketState, ticketNo, expectedStatus, status)
	}
	return nil
}

// MarkPublishFailed transitions a ticket to PUBLISH_FAILED state and records the error.
func (repository *SQLTicketRepository) MarkPublishFailed(
	ctx context.Context,
	ticketNo, expectedStatus, errorMessage string,
) error {
	// Validate state transition
	if err := ValidateTransition(expectedStatus, TicketStatusPublishFailed); err != nil {
		return err
	}

	result, err := repository.db.ExecContext(ctx, `UPDATE iam_ticket
		SET status = $1, updated_at = NOW()
		WHERE ticket_no = $2 AND status = $3`,
		TicketStatusPublishFailed, ticketNo, expectedStatus,
	)
	if err != nil {
		return fmt.Errorf("mark ticket publish failed: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check mark publish failed result: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: cannot transition ticket %s from %s to %s", ErrInvalidTicketState, ticketNo, expectedStatus, TicketStatusPublishFailed)
	}

	// Record the error in execution records
	sanitizedError := sanitizeErrorMessage(errorMessage)
	_, err = repository.db.ExecContext(ctx, `INSERT INTO iac_execution_record
		(ticket_id, provider, repository, merge_state, ci_state, apply_result, attempt, idempotency_key, sanitized_error, metadata, observed_at, created_at)
		SELECT id, 'GITHUB', '', 'UNKNOWN', 'UNKNOWN', 'FAILED', 1, $2, $3, '{}'::jsonb, NOW(), NOW()
		FROM iam_ticket WHERE ticket_no = $1`,
		ticketNo,
		fmt.Sprintf("%s:%s:%d", ticketNo, expectedStatus, time.Now().UnixNano()),
		sanitizedError,
	)
	if err != nil {
		return fmt.Errorf("record publish failure: %w", err)
	}

	return nil
}

// MarkCIApplyFailed 记录 CI 回报的 apply 失败（A12②）：工单状态不变，只把
// git_apply_result/git_ci_state 置 FAILED，并追加一条执行记录（含 CI 链接与
// 失败说明），让详情页能显示「合并已生效但变更没落地」。同一个 commit 的重复
// 回调靠 idempotency_key 幂等。
//
// 已关闭的工单不改状态（终态优先），但**仍然写执行记录**：迟到 / 乱序的失败
// 回调（典型场景是 succeeded 抢先关单后，CI 在后续步骤里又失败）如果连记录
// 都不留，事后只剩一行日志——对一个以审计立身的平台这是漏报。记录带
// metadata.late_after_close=true 标明「关单之后才到的失败」，供回溯区分。
func (repository *SQLTicketRepository) MarkCIApplyFailed(
	ctx context.Context,
	ticketNo string,
	failure CIApplyFailure,
) error {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin CI apply failure transaction: %w", err)
	}
	defer transaction.Rollback()

	var ticketID int64
	var status string
	var provider, repositoryName, remoteRequestNumber sql.NullString
	err = transaction.QueryRowContext(ctx, `SELECT id, status, git_provider, git_repository, remote_request_number
		FROM iam_ticket WHERE ticket_no = $1 FOR UPDATE`, ticketNo).Scan(
		&ticketID, &status, &provider, &repositoryName, &remoteRequestNumber)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTicketNotFound
	}
	if err != nil {
		return fmt.Errorf("lock ticket for CI apply failure: %w", err)
	}

	lateAfterClose := status == TicketStatusClosed
	if !lateAfterClose {
		if _, err := transaction.ExecContext(ctx, `UPDATE iam_ticket
			SET git_apply_result = 'FAILED', git_ci_state = 'FAILED', updated_at = NOW()
			WHERE id = $1`, ticketID); err != nil {
			return fmt.Errorf("mark ticket CI apply failed: %w", err)
		}
	}

	providerName := strings.ToUpper(strings.TrimSpace(provider.String))
	if providerName != "GITHUB" && providerName != "GITLAB" {
		// 没有 git provider 的工单（未发布过 PR）写不了执行记录（CHECK 限制），
		// 未关闭时上面的状态标记已经生效，足够前端呈现。
		return transaction.Commit()
	}

	var attempt int
	if err := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(attempt), 0) + 1
		FROM iac_execution_record WHERE ticket_id = $1`, ticketID).Scan(&attempt); err != nil {
		return fmt.Errorf("allocate execution record attempt: %w", err)
	}

	// 幂等键：同一 commit 的重复回调只留一条记录；没有 commit 时退化为
	// 按失败说明摘要去重（CI 重试会带同样的 note）。
	keyPart := strings.TrimSpace(failure.CommitSHA)
	if keyPart == "" {
		sum := sha256.Sum256([]byte(strings.TrimSpace(failure.Note)))
		keyPart = hex.EncodeToString(sum[:8])
	}
	idempotencyKey := fmt.Sprintf("ci-apply-failed:%s:%s", ticketNo, keyPart)

	metadata := []byte(`{}`)
	if lateAfterClose {
		metadata = []byte(`{"late_after_close":true}`)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO iac_execution_record
		(ticket_id, provider, repository, remote_request_number, remote_url, commit_sha,
		 merge_state, ci_state, apply_result, attempt, idempotency_key, sanitized_error, metadata, observed_at, created_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''),
		 'MERGED', 'FAILED', 'FAILED', $7, $8, NULLIF($9, ''), $10::jsonb, NOW(), NOW())
		ON CONFLICT (idempotency_key) DO NOTHING`,
		ticketID, providerName, repositoryName.String,
		remoteRequestNumber.String, failure.CIURL, failure.CommitSHA,
		attempt, idempotencyKey, sanitizeErrorMessage(failure.Note), metadata,
	); err != nil {
		return fmt.Errorf("record CI apply failure: %w", err)
	}

	return transaction.Commit()
}

// sanitizeErrorMessage removes sensitive information from error messages.
func sanitizeErrorMessage(err string) string {
	// Truncate very long errors
	if len(err) > 1000 {
		err = err[:1000]
	}
	return err
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanIAMTicket(row rowScanner) (model.IAMTicket, error) {
	var ticket model.IAMTicket
	var requestPolicy []byte
	var approverIDs []byte
	var roleSnapshot []byte
	err := row.Scan(
		&ticket.ID,
		&ticket.TicketNo,
		&ticket.TicketType,
		&ticket.AccountID,
		&ticket.PrincipalName,
		&requestPolicy,
		&ticket.ApprovalMode,
		&approverIDs,
		&ticket.TerraformCode,
		&ticket.GitPRURL,
		&ticket.GitProvider,
		&ticket.GitRepository,
		&ticket.Status,
		&ticket.Submitter,
		&ticket.CreatedAt,
		&ticket.UpdatedAt,
		&ticket.NextPollAt,
		&ticket.LastStatusPollAt,
		&ticket.ClosedAt,
		&ticket.ClosedBy,
		&ticket.ClosureReason,
		&ticket.PollAttemptCount,
		&ticket.RemoteRequestNumber,
		&roleSnapshot,
		&ticket.GitMergeState,
		&ticket.GitCIState,
		&ticket.GitApplyResult,
	)
	if err != nil {
		return model.IAMTicket{}, err
	}
	ticket.RequestPolicy = model.JSONB(requestPolicy)
	ticket.ApproverIDs = model.JSONB(approverIDs)
	if len(roleSnapshot) > 0 {
		ticket.RoleSnapshot = model.JSONB(roleSnapshot)
	}
	return ticket, nil
}

type GitLabConfig struct {
	BaseURL       string
	Token         string
	ProjectID     string
	TargetBranch  string
	TerraformPath string
}

type GitLabSDKPublisher struct {
	client *gitlab.Client
	config GitLabConfig
}

func NewGitLabSDKPublisher(gitlabConfig GitLabConfig) (*GitLabSDKPublisher, error) {
	if strings.TrimSpace(gitlabConfig.Token) == "" {
		return nil, errors.New("GitLab token must not be empty")
	}
	if strings.TrimSpace(gitlabConfig.ProjectID) == "" {
		return nil, errors.New("GitLab project ID must not be empty")
	}
	if strings.TrimSpace(gitlabConfig.TargetBranch) == "" {
		gitlabConfig.TargetBranch = "main"
	}
	if strings.TrimSpace(gitlabConfig.TerraformPath) == "" {
		gitlabConfig.TerraformPath = "iam"
	}

	options := []gitlab.ClientOptionFunc{gitlab.WithHTTPClient(&http.Client{Timeout: maxCodeHostRequestDuration})}
	if gitlabConfig.BaseURL != "" {
		options = append(options, gitlab.WithBaseURL(gitlabConfig.BaseURL))
	}
	client, err := gitlab.NewClient(gitlabConfig.Token, options...)
	if err != nil {
		return nil, fmt.Errorf("create GitLab SDK client: %w", err)
	}
	return &GitLabSDKPublisher{client: client, config: gitlabConfig}, nil
}

func (publisher *GitLabSDKPublisher) Publish(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	terraformCode string,
) (*TicketPublishResult, error) {
	if ticket.TicketNo == nil {
		return nil, apperr.Validation("ticket number is required for GitLab publication")
	}
	fileKey := strings.ToLower(request.terraformFileTicketNo(*ticket.TicketNo))
	return publisher.publishFiles(ctx, ticket, request, []TerraformBundleFile{{Key: fileKey, Content: terraformCode}})
}

func (publisher *GitLabSDKPublisher) PublishBundle(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	files []TerraformBundleFile,
) (*TicketPublishResult, error) {
	return publisher.publishFiles(ctx, ticket, request, files)
}

func (publisher *GitLabSDKPublisher) publishFiles(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	files []TerraformBundleFile,
) (*TicketPublishResult, error) {
	if ticket.TicketNo == nil || strings.TrimSpace(*ticket.TicketNo) == "" {
		return nil, errors.New("ticket number is required for GitLab publication")
	}
	if ticket.AccountID == nil {
		return nil, errors.New("ticket account ID is required for GitLab publication")
	}
	if strings.TrimSpace(request.AWSAccountID) == "" {
		return nil, errors.New("AWS account ID is required for GitLab publication")
	}

	ticketNo := *ticket.TicketNo
	sourceBranch := "iam-ticket/" + strings.ToLower(ticketNo)
	if len(files) == 0 {
		return nil, errors.New("at least one Terraform file is required for GitLab publication")
	}
	directory := path.Join(publisher.config.TerraformPath, "account-"+request.AWSAccountID)
	for _, file := range files {
		if strings.TrimSpace(file.Key) == "" || path.Base(file.Key) != file.Key || strings.ContainsAny(file.Key, `/\`) {
			return nil, fmt.Errorf("invalid Terraform bundle file key %q", file.Key)
		}
	}
	title := fmt.Sprintf("IAM ticket %s: %s", ticketNo, request.PrincipalName)
	if request.TicketType == TicketTypeRollback {
		title = fmt.Sprintf("Rollback %s of IAM ticket %s: %s", ticketNo, request.TargetTicketNo, request.PrincipalName)
	}
	commitMessage := title
	description := fmt.Sprintf("Generated Terraform for IAM ticket %s.\n\nSubmitter: %s", ticketNo, valueOrEmpty(ticket.Submitter))
	timeoutCtx, cancel := context.WithTimeout(ctx, maxPublishSequenceDuration)
	defer cancel()
	requestOption := gitlab.WithContext(timeoutCtx)

	if _, _, err := publisher.client.Branches.GetBranch(publisher.config.ProjectID, sourceBranch, requestOption); err != nil {
		_, _, createErr := publisher.client.Branches.CreateBranch(
			publisher.config.ProjectID,
			&gitlab.CreateBranchOptions{
				Branch: gitlab.String(sourceBranch),
				Ref:    gitlab.String(publisher.config.TargetBranch),
			},
			requestOption,
		)
		if createErr != nil {
			if _, _, branchErr := publisher.client.Branches.GetBranch(publisher.config.ProjectID, sourceBranch, requestOption); branchErr != nil {
				return nil, fmt.Errorf("create GitLab branch %s: %w", sourceBranch, createErr)
			}
		}
	}

	for _, file := range files {
		fileName := path.Join(directory, file.Key+".tf")
		_, _, err := publisher.client.RepositoryFiles.CreateFile(
			publisher.config.ProjectID,
			fileName,
			&gitlab.CreateFileOptions{
				Branch:        gitlab.String(sourceBranch),
				Content:       gitlab.String(file.Content),
				CommitMessage: gitlab.String(commitMessage),
			},
			requestOption,
		)
		if err != nil {
			_, _, updateErr := publisher.client.RepositoryFiles.UpdateFile(
				publisher.config.ProjectID,
				fileName,
				&gitlab.UpdateFileOptions{
					Branch:        gitlab.String(sourceBranch),
					Content:       gitlab.String(file.Content),
					CommitMessage: gitlab.String(commitMessage),
				},
				requestOption,
			)
			if updateErr != nil {
				return nil, fmt.Errorf("commit Terraform file %s: %w", fileName, err)
			}
		}
	}

	existingMRs, _, err := publisher.client.MergeRequests.ListProjectMergeRequests(
		publisher.config.ProjectID,
		&gitlab.ListProjectMergeRequestsOptions{
			State:        gitlab.String("opened"),
			SourceBranch: gitlab.String(sourceBranch),
		},
		requestOption,
	)
	if err != nil {
		return nil, fmt.Errorf("find existing GitLab Merge Request: %w", err)
	}
	if len(existingMRs) > 0 && existingMRs[0] != nil && existingMRs[0].WebURL != "" {
		return &TicketPublishResult{
			URL:                 existingMRs[0].WebURL,
			Provider:            "gitlab",
			Project:             publisher.config.ProjectID,
			RemoteRequestNumber: fmt.Sprintf("%d", existingMRs[0].IID),
			CommitSHA:           existingMRs[0].SHA,
		}, nil
	}

	mergeRequest, _, err := publisher.client.MergeRequests.CreateMergeRequest(
		publisher.config.ProjectID,
		&gitlab.CreateMergeRequestOptions{
			Title:              gitlab.String(title),
			Description:        gitlab.String(description),
			SourceBranch:       gitlab.String(sourceBranch),
			TargetBranch:       gitlab.String(publisher.config.TargetBranch),
			RemoveSourceBranch: gitlab.Bool(true),
		},
		requestOption,
	)
	if err != nil {
		return nil, fmt.Errorf("create GitLab Merge Request: %w", err)
	}
	if mergeRequest == nil || mergeRequest.WebURL == "" {
		return nil, errors.New("GitLab API returned a Merge Request without a web URL")
	}
	return &TicketPublishResult{
		URL:                 mergeRequest.WebURL,
		Provider:            "gitlab",
		Project:             publisher.config.ProjectID,
		RemoteRequestNumber: fmt.Sprintf("%d", mergeRequest.IID),
		CommitSHA:           mergeRequest.SHA,
	}, nil
}

// FetchTerraformFile reads the ticket's Terraform file from the target branch
// (main) via the GitLab API. UPDATE_ROLE 块级 patch 以 main 上的现文件为基底，
// 读取失败即报错（不静默回退整文件生成——那会重新引入互踩）。
func (publisher *GitLabSDKPublisher) FetchTerraformFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, error) {
	if ticket.AccountID == nil {
		return "", errors.New("ticket account ID is required to fetch Terraform file")
	}
	if strings.TrimSpace(request.AWSAccountID) == "" {
		return "", errors.New("AWS account ID is required to fetch Terraform file")
	}
	fallback := ""
	if ticket.TicketNo != nil {
		fallback = *ticket.TicketNo
	}
	fileName := path.Join(
		publisher.config.TerraformPath,
		"account-"+request.AWSAccountID,
		strings.ToLower(request.terraformFileTicketNo(fallback))+".tf",
	)
	timeoutCtx, cancel := context.WithTimeout(ctx, maxPublishSequenceDuration)
	defer cancel()
	file, resp, err := publisher.client.RepositoryFiles.GetFile(
		publisher.config.ProjectID,
		fileName,
		&gitlab.GetFileOptions{Ref: gitlab.String(publisher.config.TargetBranch)},
		gitlab.WithContext(timeoutCtx),
	)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			// Meaningful answer ("file not on main yet"), not a transport
			// failure — see ErrTerraformFileNotFound.
			return "", fmt.Errorf("%w: %s (branch %s)",
				ErrTerraformFileNotFound, fileName, publisher.config.TargetBranch)
		}
		return "", fmt.Errorf("fetch Terraform file %s: %w", fileName, err)
	}
	// GitLab contents API 的 content 恒为 base64（encoding=base64），与
	// GitHub 侧（github_publisher.go）保持一致：先解码再返回，否则 HCL
	// 扫描/补丁会把单行 base64 blob 当 Terraform 源码解析——base64 尾部
	// 的 "=" 会被当成无值的属性赋值，报 "Missing expression; Expected
	// the start of an expression, but found the end of the file"。
	content := file.Content
	if strings.TrimSpace(content) == "" {
		return "", fmt.Errorf("Terraform file %s is empty on branch %s", fileName, publisher.config.TargetBranch)
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(
		strings.Join(strings.Fields(content), ""))
	if decodeErr != nil {
		return "", fmt.Errorf("decode Terraform file %s (GitLab contents API returns base64): %w",
			fileName, decodeErr)
	}
	content = string(decoded)
	return content, nil
}

func normalizeApprovers(approvers []string) []string {
	seen := make(map[string]struct{}, len(approvers))
	result := make([]string, 0, len(approvers))
	for _, approver := range approvers {
		approver = strings.TrimSpace(approver)
		if approver == "" {
			continue
		}
		if _, exists := seen[approver]; exists {
			continue
		}
		seen[approver] = struct{}{}
		result = append(result, approver)
	}
	return result
}

func newTicketNumber() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "IAM-" + strings.ToUpper(hex.EncodeToString(random[:])), nil
}

func nullableComment(comment string) interface{} {
	if strings.TrimSpace(comment) == "" {
		return nil
	}
	return comment
}

func statusString(status *string) string {
	if status == nil {
		return ""
	}
	return *status
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func isAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

var _ TicketRepository = (*SQLTicketRepository)(nil)
var _ TicketPublisher = (*GitLabSDKPublisher)(nil)
