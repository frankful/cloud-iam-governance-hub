package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// ProvisionUserMaxAccounts caps one provisioning batch: each account becomes
// a separate CREATE_USER ticket with its own approval flow.
const ProvisionUserMaxAccounts = 20

// ProvisionUserRequest is the payload of the platform-user cloud onboarding:
// one batch, one IAM user (named after the platform user ID), N target AWS
// accounts. Each account gets its own CREATE_USER ticket so approvers review
// per-account scope.
type ProvisionUserRequest struct {
	Accounts     []int64           `json:"accounts"`
	Groups       []string          `json:"groups,omitempty"`
	PolicyARNs   []string          `json:"policy_arns,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	ApprovalMode string            `json:"approval_mode"`
	ApproverIDs  []string          `json:"approver_ids,omitempty"`
}

// ProvisionConflictUserExists flags a per-account result where the IAM user
// name is already taken in the target account. Provisioning never falls back
// to an implicit import: adopting an existing identity changes who owns it, so
// it stays an explicit decision made through an adopt_existing ticket.
const ProvisionConflictUserExists = "user_exists"

// ProvisionConflictAccountDisabled flags a per-account result where the
// target account is not available for provisioning: it has no onboarding
// config (never onboarded) or its sync was disabled by an administrator
// under Sync Management → Accounts.
const ProvisionConflictAccountDisabled = "account_disabled"

// ProvisionUserAccountResult is the per-account outcome of one batch.
type ProvisionUserAccountResult struct {
	AccountID int64  `json:"account_id"`
	TicketNo  string `json:"ticket_no,omitempty"`
	Conflict  string `json:"conflict,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ProvisionUser turns a platform user into IAM users on the requested AWS
// accounts by creating one CREATE_USER ticket per account. It deliberately
// reuses the ticket pipeline (validation, already-adopted detection,
// approver resolution, GitOps publication) instead of mutating AWS directly:
// "one click" only fills the forms, approval still gates the change.
//
// The IAM user name equals the platform user ID. Credentials (access keys,
// console passwords) are intentionally out of scope, matching the existing
// CREATE_USER semantics.
func (service *TicketService) ProvisionUser(
	ctx context.Context,
	actorID string,
	userID string,
	request ProvisionUserRequest,
) ([]ProvisionUserAccountResult, error) {
	if service == nil {
		return nil, errors.New("ticket service is not configured")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("platform user id is required")
	}
	if err := adapter.ValidateIAMResourceName("user", userID); err != nil {
		return nil, err
	}
	// 同一账号只建一张工单：去重保序。
	seen := make(map[int64]bool, len(request.Accounts))
	accountIDs := make([]int64, 0, len(request.Accounts))
	for _, accountID := range request.Accounts {
		if accountID <= 0 {
			return nil, errors.New("accounts must contain positive aws account ids")
		}
		if seen[accountID] {
			continue
		}
		seen[accountID] = true
		accountIDs = append(accountIDs, accountID)
	}
	if len(accountIDs) == 0 {
		return nil, errors.New("at least one target aws account is required")
	}
	if len(accountIDs) > ProvisionUserMaxAccounts {
		return nil, fmt.Errorf("at most %d accounts per batch (got %d)", ProvisionUserMaxAccounts, len(accountIDs))
	}
	approvalMode := strings.ToUpper(strings.TrimSpace(request.ApprovalMode))
	if approvalMode == "" {
		approvalMode = ApprovalModeAuto
	}
	if approvalMode != ApprovalModeManual && approvalMode != ApprovalModeAuto {
		return nil, fmt.Errorf("approval_mode must be %s or %s", ApprovalModeManual, ApprovalModeAuto)
	}
	if approvalMode == ApprovalModeManual && len(request.ApproverIDs) == 0 {
		return nil, errors.New("approver_ids is required for MANUAL approval")
	}

	results := make([]ProvisionUserAccountResult, 0, len(accountIDs))
	for _, accountID := range accountIDs {
		result := ProvisionUserAccountResult{AccountID: accountID}
		// 可用性预检：账号必须有接入配置且同步处于启用状态。停用/未接入的
		// 账号不生成工单（前端下拉同样过滤，这里是权威兜底）。
		enabled, syncErr := service.repository.AWSAccountSyncEnabled(ctx, accountID)
		if syncErr != nil {
			result.Error = fmt.Sprintf("check account availability: %v", syncErr)
			results = append(results, result)
			continue
		}
		if !enabled {
			result.Conflict = ProvisionConflictAccountDisabled
			result.Error = service.describeAccountDisabled(ctx, accountID)
			results = append(results, result)
			continue
		}
		// 预检同名 IAM user：命中时 CreateDraft 只会返回一句英文校验错误，
		// 用户看不出下一步该做什么。这里提前拦下并给出可执行提示。
		exists, checkErr := service.repository.PrincipalExists(ctx, accountID, userID, "User")
		if checkErr != nil {
			result.Error = fmt.Sprintf("check existing IAM user: %v", checkErr)
			results = append(results, result)
			continue
		}
		if exists {
			result.Conflict = ProvisionConflictUserExists
			result.Error = service.describeUserConflict(ctx, accountID, userID)
			results = append(results, result)
			continue
		}
		ticket, err := service.CreateDraft(ctx, actorID, CreateIAMTicketRequest{
			TicketType:    TicketTypeCreateUser,
			AccountID:     accountID,
			PrincipalName: userID,
			CreateUser: &adapter.IAMUserInfo{
				Name:       userID,
				Tags:       request.Tags,
				GroupNames: request.Groups,
				PolicyARNs: request.PolicyARNs,
			},
			ApprovalMode: approvalMode,
			ApproverIDs:  request.ApproverIDs,
		})
		switch {
		case err != nil && strings.Contains(err.Error(), "already exists in the account inventory"):
			// 预检与建单之间被并发占用：同样换成可执行提示。
			result.Conflict = ProvisionConflictUserExists
			result.Error = service.describeUserConflict(ctx, accountID, userID)
		case err != nil:
			result.Error = err.Error()
		case ticket.TicketNo != nil:
			result.TicketNo = *ticket.TicketNo
		}
		results = append(results, result)
	}
	return results, nil
}

// describeAccountDisabled explains why provisioning stopped for an
// unavailable account and where to re-enable it.
func (service *TicketService) describeAccountDisabled(
	ctx context.Context,
	accountID int64,
) string {
	account := fmt.Sprintf("账号 #%d", accountID)
	if number, err := service.repository.GetAWSAccountID(ctx, accountID); err == nil && number != "" {
		account = "账号 " + number
	}
	return fmt.Sprintf(
		"%s 当前不可用（未接入平台配置，或已停用同步）；"+
			"请在「同步管理 → 账号」中启用该账号后再开通到云。",
		account,
	)
}

// describeUserConflict explains why provisioning stopped and what to do next:
// the name is already taken in the target account, so the only safe paths are
// importing the existing identity (adopt_existing) or an update ticket.
func (service *TicketService) describeUserConflict(
	ctx context.Context,
	accountID int64,
	userID string,
) string {
	account := fmt.Sprintf("账号 #%d", accountID)
	if number, err := service.repository.GetAWSAccountID(ctx, accountID); err == nil && number != "" {
		account = "账号 " + number
	}
	return fmt.Sprintf(
		"IAM 用户 %q 在%s 中已存在（平台同步台账已收录），不能再创建同名用户；"+
			"若该身份尚未纳管，请改走「新建工单 → 创建 IAM 用户」并勾选「导入已存在资源（adopt_existing）」完成纳管；"+
			"若已纳管，请使用对应的更新工单。",
		userID, account,
	)
}
