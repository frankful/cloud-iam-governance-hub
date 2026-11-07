package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

type memoryTicketRepository struct {
	tickets          map[string]model.IAMTicket
	approvers        map[string]map[string]*string
	enabledBaseline  *model.IAMBaseline
	validationChecks map[string]TicketValidationSnapshot
	existingPolicies []ExistingIAMPolicy
	principalExists  bool
	// existingPrincipals overrides principalExists for specific
	// "<type>/<name>" keys (used by CREATE_USER/CREATE_GROUP tests).
	existingPrincipals map[string]bool
	trustPolicy        json.RawMessage
	// policyRecords seeds managed policies (key: ARN) and group inline
	// policies (key: "group/<group>/<name>") for policy-update tests.
	policyRecords map[string]json.RawMessage
	// roleAttributes seeds the role's description / max session duration /
	// tags for UPDATE_ROLE snapshot and rollback tests.
	roleDescription        *string
	roleMaxSessionDuration *int64
	roleTags               map[string]string
	// rolePath / roleBoundary are the ForceNew attributes the inventory
	// carries; a regenerated role file must reproduce them.
	rolePath     string
	roleBoundary string
	// attachments seeds collected policy attachments
	// (key: "<principalType>/<principalName>/<policyARN>" → source attach
	// ticket no, "" for a platform-unmanaged wild attachment).
	attachments map[string]string
	// baselineOwnedFiles seeds attachment files adopted via a merged full
	// baseline (key: attachment file key) — such attachments have no source
	// attach ticket but are already in Terraform state.
	baselineOwnedFiles map[string]bool
	// baselineOwnedResourceFiles seeds resource declaration files (role-,
	// user-, group-, policy-<name>) covered by a baseline publication —
	// adopt_existing must reject re-adopting such resources.
	baselineOwnedResourceFiles map[string]bool
	// fileDeclarationOwners seeds the current declaration owner of a file
	// (key: file key → ticket ids, 0 = baseline). Absent means "no declaration
	// snapshot", which the rollback ownership check lets through.
	fileDeclarationOwners map[string][]int64
	// autoApprovers overrides the account-bound approver list resolved for
	// AUTO tickets (nil → the default alice/bob pair).
	autoApprovers []model.PlatformUser
	// groupMembers seeds collected group memberships (key: group name).
	// nil map means the group has no membership recorded.
	groupMembers map[string][]string
	// activeMembershipTickets seeds the in-flight membership ticket count
	// used by the concurrency lock (key: group name).
	activeMembershipTickets map[string]int
	groupAdoptionSnapshot   adapter.IAMGroupInfo
	logger                  *slog.Logger
	// accountSyncEnabled stubs AWSAccountSyncEnabled for provision tests
	// (nil → all accounts available).
	accountSyncEnabled *bool
	// ciApplyFailures 记录 MarkCIApplyFailed 的失败现场，供 A12② 单测断言。
	ciApplyFailures []CIApplyFailure
}

func newMemoryTicketRepository() *memoryTicketRepository {
	return &memoryTicketRepository{
		tickets:                    make(map[string]model.IAMTicket),
		approvers:                  make(map[string]map[string]*string),
		validationChecks:           make(map[string]TicketValidationSnapshot),
		policyRecords:              make(map[string]json.RawMessage),
		attachments:                make(map[string]string),
		baselineOwnedFiles:         make(map[string]bool),
		baselineOwnedResourceFiles: make(map[string]bool),
		fileDeclarationOwners:      make(map[string][]int64),
		logger:                     slog.Default(),
	}
}

func (repository *memoryTicketRepository) Create(
	_ context.Context,
	ticket model.IAMTicket,
	approvers []string,
	validation TicketValidationSnapshot,
) (model.IAMTicket, error) {
	ticket.ID = int64(len(repository.tickets) + 1)
	ticket.CreatedAt = time.Now()
	ticket.UpdatedAt = ticket.CreatedAt
	repository.tickets[*ticket.TicketNo] = ticket
	repository.validationChecks[*ticket.TicketNo] = validation
	repository.approvers[*ticket.TicketNo] = make(map[string]*string, len(approvers))
	for _, approver := range approvers {
		repository.approvers[*ticket.TicketNo][approver] = nil
	}
	return ticket, nil
}

func (repository *memoryTicketRepository) CreateDraft(
	_ context.Context,
	ticket model.IAMTicket,
) (model.IAMTicket, error) {
	ticket.ID = int64(len(repository.tickets) + 1)
	ticket.CreatedAt = time.Now()
	ticket.UpdatedAt = ticket.CreatedAt
	repository.tickets[*ticket.TicketNo] = ticket
	return ticket, nil
}

func (repository *memoryTicketRepository) SubmitDraft(
	_ context.Context,
	ticketNo string,
	approvers []string,
	validation TicketValidationSnapshot,
) (model.IAMTicket, error) {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return model.IAMTicket{}, ErrTicketNotFound
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusDraft {
		return model.IAMTicket{}, ErrInvalidTicketState
	}
	ticket.Status = stringPointer(TicketStatusApproving)
	ticket.UpdatedAt = time.Now()
	repository.tickets[ticketNo] = ticket
	repository.validationChecks[ticketNo] = validation
	repository.approvers[ticketNo] = make(map[string]*string, len(approvers))
	for _, approver := range approvers {
		repository.approvers[ticketNo][approver] = nil
	}
	return ticket, nil
}

func (repository *memoryTicketRepository) GetEnabledBaseline(
	context.Context,
	int64,
) (model.IAMBaseline, error) {
	if repository.enabledBaseline == nil {
		return model.IAMBaseline{}, sql.ErrNoRows
	}
	return *repository.enabledBaseline, nil
}

func (repository *memoryTicketRepository) Get(_ context.Context, ticketNo string) (model.IAMTicket, error) {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return model.IAMTicket{}, ErrTicketNotFound
	}
	return ticket, nil
}

func (repository *memoryTicketRepository) GetAWSAccountID(_ context.Context, accountID int64) (string, error) {
	if accountID <= 0 {
		return "", errors.New("invalid account database ID")
	}
	if accountID == 999 {
		// 模拟 aws_account 表查无此账号（SQL 实现返回 sql.ErrNoRows）。
		return "", fmt.Errorf("AWS account database ID %d: %w", accountID, sql.ErrNoRows)
	}
	return "123456789012", nil
}

// accountSyncEnabled 覆盖默认值（nil → 全部可用）。
func (repository *memoryTicketRepository) AWSAccountSyncEnabled(_ context.Context, accountID int64) (bool, error) {
	if repository.accountSyncEnabled != nil {
		return *repository.accountSyncEnabled, nil
	}
	return true, nil
}

func (repository *memoryTicketRepository) ListTickets(
	_ context.Context,
	filter TicketListFilter,
) ([]model.IAMTicket, int64, error) {
	matched := make([]model.IAMTicket, 0, len(repository.tickets))
	for _, ticket := range repository.tickets {
		if len(filter.Statuses) > 0 && (ticket.Status == nil || !containsString(filter.Statuses, *ticket.Status)) {
			continue
		}
		if filter.AccountID != nil && (ticket.AccountID == nil || *ticket.AccountID != *filter.AccountID) {
			continue
		}
		if filter.Submitter != "" && (ticket.Submitter == nil || *ticket.Submitter != filter.Submitter) {
			continue
		}
		if filter.TicketType != "" && (ticket.TicketType == nil || *ticket.TicketType != filter.TicketType) {
			continue
		}
		if keyword := strings.ToLower(strings.TrimSpace(filter.Keyword)); keyword != "" {
			ticketNo := strings.ToLower(valueOrEmpty(ticket.TicketNo))
			principal := strings.ToLower(valueOrEmpty(ticket.PrincipalName))
			if !strings.Contains(ticketNo, keyword) && !strings.Contains(principal, keyword) {
				continue
			}
		}
		matched = append(matched, ticket)
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		}
		return matched[i].ID > matched[j].ID
	})
	total := int64(len(matched))
	if filter.Offset >= len(matched) {
		return []model.IAMTicket{}, total, nil
	}
	end := filter.Offset + filter.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[filter.Offset:end], total, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (repository *memoryTicketRepository) FindRollbackTickets(
	_ context.Context,
	targetTicketNo string,
) ([]model.IAMTicket, error) {
	matched := make([]model.IAMTicket, 0)
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != TicketTypeRollback {
			continue
		}
		var request CreateIAMTicketRequest
		if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
			continue
		}
		if strings.TrimSpace(request.TargetTicketNo) == targetTicketNo {
			matched = append(matched, ticket)
		}
	}
	return matched, nil
}

func (repository *memoryTicketRepository) GetPrincipalPolicies(
	_ context.Context,
	accountID int64,
	principalName, principalType string,
) ([]ExistingIAMPolicy, bool, error) {
	if accountID <= 0 || principalName == "" || principalType != "Role" {
		return nil, false, errors.New("invalid target principal")
	}
	return repository.existingPolicies, repository.principalExists, nil
}

func (repository *memoryTicketRepository) PrincipalExists(
	_ context.Context,
	accountID int64,
	principalName, principalType string,
) (bool, error) {
	if accountID <= 0 || principalName == "" {
		return false, errors.New("invalid principal")
	}
	switch principalType {
	case "User", "Group", "Role":
		if repository.existingPrincipals != nil {
			if exists, ok := repository.existingPrincipals[principalType+"/"+principalName]; ok {
				return exists, nil
			}
		}
		return repository.principalExists, nil
	default:
		return false, fmt.Errorf("unsupported principal type %q", principalType)
	}
}

func (repository *memoryTicketRepository) GetGroupAdoptionSnapshot(
	_ context.Context,
	accountID int64,
	groupName string,
) (adapter.IAMGroupInfo, error) {
	if accountID <= 0 || strings.TrimSpace(groupName) == "" {
		return adapter.IAMGroupInfo{}, errors.New("invalid group adoption identity")
	}
	snapshot := repository.groupAdoptionSnapshot
	if snapshot.Name == "" {
		snapshot.Name = groupName
		snapshot.Path = "/"
	}
	return snapshot, nil
}

func (repository *memoryTicketRepository) GetPrincipalTrustPolicy(
	_ context.Context,
	accountID int64,
	principalName string,
) (json.RawMessage, error) {
	if accountID <= 0 || principalName == "" {
		return nil, errors.New("invalid principal")
	}
	return repository.trustPolicy, nil
}

func (repository *memoryTicketRepository) CountActiveUpdateRoleTickets(
	_ context.Context,
	accountID int64,
	principalName string,
) (int, error) {
	count := 0
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != TicketTypeUpdateRole {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		if ticket.PrincipalName == nil || *ticket.PrincipalName != principalName {
			continue
		}
		if ticket.Status == nil {
			continue
		}
		switch *ticket.Status {
		case TicketStatusDraft, TicketStatusApproving, TicketStatusApproved,
			TicketStatusPublishing, TicketStatusPublishFailed:
			count++
		}
	}
	return count, nil
}

func (repository *memoryTicketRepository) CountActiveCreateTickets(
	_ context.Context,
	accountID int64,
	ticketType, principalName string,
) (int, error) {
	count := 0
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != ticketType {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		if ticket.PrincipalName == nil || *ticket.PrincipalName != principalName {
			continue
		}
		if ticket.Status == nil {
			continue
		}
		switch *ticket.Status {
		case TicketStatusDraft, TicketStatusApproving, TicketStatusApproved,
			TicketStatusPublishing, TicketStatusPublishFailed:
			count++
		}
	}
	return count, nil
}

func (repository *memoryTicketRepository) CountAppliedUpdateRoleTickets(
	_ context.Context,
	accountID int64,
	principalName string,
) (int, error) {
	// Mirrors the SQL: only CLOSED+APPLIED UPDATE_ROLE tickets count — the
	// moment one applied, the wild role is in Terraform state (import used).
	count := 0
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != TicketTypeUpdateRole {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		if ticket.PrincipalName == nil || *ticket.PrincipalName != principalName {
			continue
		}
		if ticket.Status == nil || *ticket.Status != TicketStatusClosed {
			continue
		}
		if ticket.ClosureReason != nil && *ticket.ClosureReason == "APPLIED" {
			count++
		}
	}
	return count, nil
}

func (repository *memoryTicketRepository) FindCreatedRoleTicket(
	_ context.Context,
	accountID int64,
	principalName string,
) (string, error) {
	// Mirrors the SQL: only tickets whose Terraform landed (MERGED, or
	// CLOSED+APPLIED) qualify, newest created_at wins. ABANDONED/DRAFT
	// tickets must never be returned.
	var (
		found   string
		newest  time.Time
		matched bool
	)
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != TicketTypeCreateRole {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		if ticket.PrincipalName == nil || *ticket.PrincipalName != principalName {
			continue
		}
		if ticket.Status == nil {
			continue
		}
		applied := *ticket.Status == TicketStatusMerged ||
			(*ticket.Status == TicketStatusClosed &&
				ticket.ClosureReason != nil && *ticket.ClosureReason == "APPLIED")
		if !applied {
			continue
		}
		if matched && !ticket.CreatedAt.After(newest) {
			continue
		}
		found, newest, matched = *ticket.TicketNo, ticket.CreatedAt, true
	}
	if !matched {
		return "", nil
	}
	return found, nil
}

func (repository *memoryTicketRepository) SaveRoleSnapshot(
	_ context.Context,
	ticketNo string,
	snapshot json.RawMessage,
) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	ticket.RoleSnapshot = model.JSONB(snapshot)
	repository.tickets[ticketNo] = ticket
	return nil
}

func (repository *memoryTicketRepository) CountActiveUpdatePolicyTickets(
	_ context.Context,
	accountID int64,
	ticketType, principalType, policyARN, groupName, inlinePolicyName string,
) (int, error) {
	count := 0
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != ticketType {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		var request CreateIAMTicketRequest
		if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
			continue
		}
		if request.UpdatePolicy == nil {
			continue
		}
		if ticketType == TicketTypeUpdateManagedPolicy {
			if strings.TrimSpace(request.UpdatePolicy.PolicyARN) != strings.TrimSpace(policyARN) {
				continue
			}
		} else {
			owner := strings.TrimSpace(request.UpdatePolicy.GroupName)
			if strings.TrimSpace(request.UpdatePolicy.RoleName) != "" {
				owner = strings.TrimSpace(request.UpdatePolicy.RoleName)
			}
			if strings.TrimSpace(request.PrincipalType) != principalType ||
				owner != strings.TrimSpace(groupName) ||
				strings.TrimSpace(request.UpdatePolicy.InlinePolicyName) != strings.TrimSpace(inlinePolicyName) {
				continue
			}
		}
		if ticket.Status == nil {
			continue
		}
		switch *ticket.Status {
		case TicketStatusDraft, TicketStatusApproving, TicketStatusApproved,
			TicketStatusPublishing, TicketStatusPublishFailed:
			count++
		}
	}
	if ticketType == TicketTypeUpdateGroupInlinePolicy && principalType == "Role" {
		for _, ticket := range repository.tickets {
			if ticket.TicketType == nil || *ticket.TicketType != TicketTypeAdoptRoleInlinePolicies ||
				ticket.AccountID == nil || *ticket.AccountID != accountID ||
				ticket.PrincipalName == nil || *ticket.PrincipalName != groupName || ticket.Status == nil {
				continue
			}
			switch *ticket.Status {
			case TicketStatusDraft, TicketStatusApproving, TicketStatusApproved,
				TicketStatusPublishing, TicketStatusPublishFailed:
			default:
				continue
			}
			var request CreateIAMTicketRequest
			if json.Unmarshal(ticket.RequestPolicy, &request) != nil {
				continue
			}
			for _, policy := range request.RoleInlinePolicies {
				if policy.Name == inlinePolicyName {
					count++
					break
				}
			}
		}
	}
	return count, nil
}

func (repository *memoryTicketRepository) CountActiveRolePolicyBatchTickets(
	_ context.Context,
	accountID int64,
	roleName string,
) (int, error) {
	count := 0
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != TicketTypeAdoptRoleInlinePolicies ||
			ticket.AccountID == nil || *ticket.AccountID != accountID ||
			ticket.PrincipalName == nil || *ticket.PrincipalName != roleName || ticket.Status == nil {
			continue
		}
		switch *ticket.Status {
		case TicketStatusDraft, TicketStatusApproving, TicketStatusApproved,
			TicketStatusPublishing, TicketStatusPublishFailed:
			count++
		}
	}
	return count, nil
}

func (repository *memoryTicketRepository) CountAppliedUpdatePolicyTickets(
	_ context.Context,
	accountID int64,
	ticketType, principalType, policyARN, groupName, inlinePolicyName string,
) (int, error) {
	count := 0
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil || *ticket.TicketType != ticketType {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		var request CreateIAMTicketRequest
		if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
			continue
		}
		if request.UpdatePolicy == nil {
			continue
		}
		if ticketType == TicketTypeUpdateManagedPolicy {
			if strings.TrimSpace(request.UpdatePolicy.PolicyARN) != strings.TrimSpace(policyARN) {
				continue
			}
		} else {
			owner := strings.TrimSpace(request.UpdatePolicy.GroupName)
			if strings.TrimSpace(request.UpdatePolicy.RoleName) != "" {
				owner = strings.TrimSpace(request.UpdatePolicy.RoleName)
			}
			if strings.TrimSpace(request.PrincipalType) != principalType ||
				owner != strings.TrimSpace(groupName) ||
				strings.TrimSpace(request.UpdatePolicy.InlinePolicyName) != strings.TrimSpace(inlinePolicyName) {
				continue
			}
		}
		if ticket.Status == nil {
			continue
		}
		if *ticket.Status == TicketStatusMerged ||
			(*ticket.Status == TicketStatusClosed && ticket.ClosureReason != nil &&
				*ticket.ClosureReason == ClosureReasonApplied) {
			count++
		}
	}
	if ticketType == TicketTypeUpdateGroupInlinePolicy && principalType == "Role" {
		for _, ticket := range repository.tickets {
			if ticket.TicketType == nil || *ticket.TicketType != TicketTypeAdoptRoleInlinePolicies ||
				ticket.AccountID == nil || *ticket.AccountID != accountID ||
				ticket.PrincipalName == nil || *ticket.PrincipalName != groupName || ticket.Status == nil {
				continue
			}
			if *ticket.Status != TicketStatusMerged &&
				!(*ticket.Status == TicketStatusClosed && ticket.ClosureReason != nil &&
					*ticket.ClosureReason == ClosureReasonApplied) {
				continue
			}
			var request CreateIAMTicketRequest
			if json.Unmarshal(ticket.RequestPolicy, &request) != nil {
				continue
			}
			for _, policy := range request.RoleInlinePolicies {
				if policy.Name == inlinePolicyName {
					count++
					break
				}
			}
		}
	}
	return count, nil
}

func (repository *memoryTicketRepository) BaselineOwnsAttachmentFile(
	_ context.Context,
	_ int64,
	fileKey string,
) (bool, error) {
	return repository.baselineOwnedFiles[fileKey], nil
}

func (repository *memoryTicketRepository) BaselineOwnsResourceFile(
	_ context.Context,
	_ int64,
	fileKey string,
) (bool, error) {
	return repository.baselineOwnedResourceFiles[fileKey], nil
}

func (repository *memoryTicketRepository) FileDeclarationOwners(
	_ context.Context,
	_ int64,
	fileKey string,
) ([]int64, error) {
	if owners, ok := repository.fileDeclarationOwners[fileKey]; ok {
		return owners, nil
	}
	return []int64{}, nil
}

func (repository *memoryTicketRepository) GroupMembers(
	_ context.Context,
	_ int64,
	groupName string,
) ([]string, error) {
	members := repository.groupMembers[groupName]
	if members == nil {
		return []string{}, nil
	}
	return members, nil
}

func (repository *memoryTicketRepository) CountActiveGroupMembershipTickets(
	_ context.Context,
	_ int64,
	groupName string,
) (int, error) {
	return repository.activeMembershipTickets[groupName], nil
}

func (repository *memoryTicketRepository) ResolvePolicyAttachment(
	_ context.Context,
	accountID int64,
	principalType, principalName, policyARN string,
) (bool, string, error) {
	// Seeded attachments (tests may add directly): presence means the
	// attachment exists in the collected inventory.
	key := principalType + "/" + principalName + "/" + policyARN
	if source, ok := repository.attachments[key]; ok {
		return true, source, nil
	}
	for _, ticket := range repository.tickets {
		if ticket.TicketType == nil {
			continue
		}
		if *ticket.TicketType != TicketTypeAttachUserPolicy &&
			*ticket.TicketType != TicketTypeCreateUser &&
			*ticket.TicketType != TicketTypeCreateGroup {
			continue
		}
		if ticket.AccountID == nil || *ticket.AccountID != accountID {
			continue
		}
		if ticket.PrincipalName == nil || *ticket.PrincipalName != principalName {
			continue
		}
		var request CreateIAMTicketRequest
		if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
			continue
		}
		if request.PrincipalType != principalType {
			continue
		}
		matches := false
		switch *ticket.TicketType {
		case TicketTypeAttachUserPolicy:
			matches = request.Operation != OperationDetach &&
				strings.TrimSpace(request.ManagedPolicyARN) == strings.TrimSpace(policyARN)
		case TicketTypeCreateUser:
			matches = request.CreateUser != nil && containsString(request.CreateUser.PolicyARNs, policyARN)
		case TicketTypeCreateGroup:
			matches = request.CreateGroup != nil && containsString(request.CreateGroup.PolicyARNs, policyARN)
		}
		if !matches || ticket.Status == nil {
			continue
		}
		applied := *ticket.Status == TicketStatusMerged ||
			(*ticket.Status == TicketStatusClosed && ticket.ClosureReason != nil &&
				*ticket.ClosureReason == ClosureReasonApplied)
		if applied && ticket.TicketNo != nil {
			return true, *ticket.TicketNo, nil
		}
	}
	return false, "", nil
}

func (repository *memoryTicketRepository) GetManagedPolicyByARN(
	_ context.Context,
	policyARN string,
) (json.RawMessage, bool, error) {
	document, exists := repository.policyRecords[policyARN]
	if !exists {
		return nil, false, nil
	}
	return document, true, nil
}

func (repository *memoryTicketRepository) GetGroupInlinePolicy(
	_ context.Context,
	accountID int64,
	groupName, inlinePolicyName string,
) (json.RawMessage, bool, error) {
	document, exists := repository.policyRecords["group/"+groupName+"/"+inlinePolicyName]
	if !exists {
		return nil, false, nil
	}
	return document, true, nil
}

func (repository *memoryTicketRepository) GetRoleInlinePolicy(
	_ context.Context,
	accountID int64,
	roleName, inlinePolicyName string,
) (json.RawMessage, bool, error) {
	document, exists := repository.policyRecords["role/"+roleName+"/"+inlinePolicyName]
	if !exists {
		return nil, false, nil
	}
	return document, true, nil
}

func (repository *memoryTicketRepository) ListRoleInlinePolicies(
	_ context.Context,
	accountID int64,
	roleName string,
) ([]ExistingIAMPolicy, error) {
	policies := make([]ExistingIAMPolicy, 0)
	prefix := "role/" + roleName + "/"
	for key, document := range repository.policyRecords {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		policies = append(policies, ExistingIAMPolicy{
			Name: strings.TrimPrefix(key, prefix), Document: append(json.RawMessage(nil), document...),
		})
	}
	return policies, nil
}

func (repository *memoryTicketRepository) GetRoleAttributes(
	_ context.Context,
	accountID int64,
	roleName string,
) (*RoleAttributes, error) {
	return &RoleAttributes{
		Description:            repository.roleDescription,
		MaxSessionDuration:     repository.roleMaxSessionDuration,
		Tags:                   repository.roleTags,
		Path:                   repository.rolePath,
		PermissionsBoundaryARN: repository.roleBoundary,
	}, nil
}

func (repository *memoryTicketRepository) ListAvailableApprovers(
	_ context.Context,
	accountID *int64,
) ([]model.PlatformUser, error) {
	if accountID != nil {
		return []model.PlatformUser{
			{UserID: "alice", DisplayName: "Alice", IsActive: true},
			{UserID: "bob", DisplayName: "Bob", IsActive: true},
		}, nil
	}
	return []model.PlatformUser{
		{UserID: "alice", DisplayName: "Alice", IsActive: true},
		{UserID: "bob", DisplayName: "Bob", IsActive: true},
		{UserID: "charlie", DisplayName: "Charlie", IsActive: true},
	}, nil
}

func (repository *memoryTicketRepository) ResolveAutoApprovers(
	ctx context.Context,
	accountID int64,
) ([]model.PlatformUser, error) {
	if repository.autoApprovers != nil {
		return repository.autoApprovers, nil
	}
	return repository.ListAvailableApprovers(ctx, &accountID)
}

func (repository *memoryTicketRepository) GetApprovalInfo(
	_ context.Context,
	ticketNo string,
) (model.TicketApprovalInfo, error) {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return model.TicketApprovalInfo{}, ErrTicketNotFound
	}
	info := model.TicketApprovalInfo{
		TicketNo:     ticketNo,
		ApprovalMode: ticket.ApprovalMode,
		Status:       statusString(ticket.Status),
		Approvals:    make([]model.TicketApprovalEntry, 0),
	}
	for userID, result := range repository.approvers[ticketNo] {
		info.Approvals = append(info.Approvals, model.TicketApprovalEntry{
			ApproverID:  userID,
			DisplayName: userID,
			Result:      result,
		})
	}
	return info, nil
}

func (repository *memoryTicketRepository) RecordDecision(
	_ context.Context,
	ticketNo, approver, result, _ string,
) (model.IAMTicket, error) {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return model.IAMTicket{}, ErrTicketNotFound
	}
	assigned, exists := repository.approvers[ticketNo][approver]
	if !exists {
		return model.IAMTicket{}, ErrNotDesignatedApprover
	}
	if assigned != nil {
		if ticket.Status != nil && *ticket.Status == TicketStatusApproved && *assigned == "APPROVE" {
			return ticket, nil
		}
		return model.IAMTicket{}, ErrApprovalAlreadySet
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		return model.IAMTicket{}, ErrInvalidTicketState
	}
	resultCopy := result
	repository.approvers[ticketNo][approver] = &resultCopy
	if result == "REJECT" {
		ticket.Status = stringPointer(TicketStatusRejected)
	} else {
		allApproved := true
		for _, decision := range repository.approvers[ticketNo] {
			if decision == nil || *decision != "APPROVE" {
				allApproved = false
			}
		}
		if allApproved {
			ticket.Status = stringPointer(TicketStatusApproved)
		}
	}
	repository.tickets[ticketNo] = ticket
	return ticket, nil
}

func (repository *memoryTicketRepository) SavePublication(
	_ context.Context,
	ticketNo string,
	publication TicketPublication,
) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusPublishing {
		return ErrInvalidTicketState
	}
	ticket.TerraformCode = stringPointer(publication.TerraformCode)
	ticket.GitPRURL = stringPointer(publication.GitPRURL)
	ticket.Status = stringPointer(TicketStatusApproved)
	repository.tickets[ticketNo] = ticket
	return nil
}

func (repository *memoryTicketRepository) ClaimPublication(
	_ context.Context,
	ticketNo string,
	_ time.Duration,
) (bool, error) {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return false, ErrTicketNotFound
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproved {
		return false, nil
	}
	ticket.Status = stringPointer(TicketStatusPublishing)
	repository.tickets[ticketNo] = ticket
	return true, nil
}

func (repository *memoryTicketRepository) ReleasePublication(_ context.Context, ticketNo string) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	if ticket.Status != nil && *ticket.Status == TicketStatusPublishing {
		ticket.Status = stringPointer(TicketStatusApproved)
		repository.tickets[ticketNo] = ticket
	}
	return nil
}

func (repository *memoryTicketRepository) SetStatus(
	_ context.Context,
	ticketNo, expectedStatus, status string,
) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	if ticket.Status == nil || *ticket.Status != expectedStatus {
		return ErrInvalidTicketState
	}
	ticket.Status = stringPointer(status)
	repository.tickets[ticketNo] = ticket
	return nil
}

func (repository *memoryTicketRepository) ResetPollSchedule(
	_ context.Context,
	ticketNo string,
) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	ticket.PollAttemptCount = 0
	repository.tickets[ticketNo] = ticket
	return nil
}

func (repository *memoryTicketRepository) CloseTicket(
	_ context.Context,
	ticketNo, actorID, reason, comment string,
) (model.IAMTicket, error) {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return model.IAMTicket{}, ErrTicketNotFound
	}
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

	ticket.Status = stringPointer(TicketStatusClosed)
	closedBy := actorID
	ticket.ClosedBy = &closedBy
	closedAt := time.Now()
	ticket.ClosedAt = &closedAt
	closureReason := reason
	ticket.ClosureReason = &closureReason
	closureComment := comment
	ticket.ClosureComment = &closureComment
	repository.tickets[ticketNo] = ticket

	return ticket, nil
}

func (repository *memoryTicketRepository) MarkPublishFailed(
	_ context.Context,
	ticketNo, expectedStatus, errorMessage string,
) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	if ticket.Status == nil || *ticket.Status != expectedStatus {
		return ErrInvalidTicketState
	}

	// Validate state transition
	if !CanTransition(expectedStatus, TicketStatusPublishFailed) {
		return fmt.Errorf("invalid state transition: %s -> %s", expectedStatus, TicketStatusPublishFailed)
	}

	ticket.Status = stringPointer(TicketStatusPublishFailed)
	repository.tickets[ticketNo] = ticket

	// Store error message in a simple way (in real implementation, this would go to execution_records)
	repository.logger.Warn("ticket marked as PUBLISH_FAILED",
		"ticket_no", ticketNo,
		"error", errorMessage,
	)

	return nil
}

// MarkCIApplyFailed 在内存仓库里只改工单状态并留痕，语义与 SQL 实现一致：
// 工单未关闭时置 FAILED；已关闭则终态优先不覆盖状态，但失败现场仍然留痕
// （SQL 侧对应 iac_execution_record 的 late_after_close 记录）。
func (repository *memoryTicketRepository) MarkCIApplyFailed(
	_ context.Context,
	ticketNo string,
	failure CIApplyFailure,
) error {
	ticket, exists := repository.tickets[ticketNo]
	if !exists {
		return ErrTicketNotFound
	}
	repository.ciApplyFailures = append(repository.ciApplyFailures, failure)
	if ticket.Status != nil && *ticket.Status == TicketStatusClosed {
		return nil
	}
	failed := "FAILED"
	ticket.GitApplyResult = &failed
	ticket.GitCIState = &failed
	repository.tickets[ticketNo] = ticket
	return nil
}

type memoryTicketPublisher struct {
	url          string
	err          error
	calls        int
	request      CreateIAMTicketRequest
	terraform    string
	bundleFiles  []TerraformBundleFile
	fetchFile    string
	fetchErr     error
	fetchCalls   int
	fetchRequest CreateIAMTicketRequest
}

func (publisher *memoryTicketPublisher) Publish(
	_ context.Context,
	_ model.IAMTicket,
	request CreateIAMTicketRequest,
	terraformCode string,
) (*TicketPublishResult, error) {
	publisher.calls++
	publisher.request = request
	publisher.terraform = terraformCode
	if publisher.err != nil {
		return nil, publisher.err
	}
	return &TicketPublishResult{
		URL:                 publisher.url,
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		CommitSHA:           "abc123",
	}, nil
}

func (publisher *memoryTicketPublisher) PublishBundle(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	files []TerraformBundleFile,
) (*TicketPublishResult, error) {
	publisher.bundleFiles = append([]TerraformBundleFile(nil), files...)
	var terraform strings.Builder
	for _, file := range files {
		terraform.WriteString(file.Content)
	}
	return publisher.Publish(ctx, ticket, request, terraform.String())
}

func (publisher *memoryTicketPublisher) FetchTerraformFile(
	_ context.Context,
	_ model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, error) {
	publisher.fetchCalls++
	publisher.fetchRequest = request
	if publisher.fetchErr != nil {
		return "", publisher.fetchErr
	}
	return publisher.fetchFile, nil
}

func validTicketRequest() CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateRole,
		AccountID:     12,
		PrincipalName: "billing-reader",
		Permission: model.AbstractPermission{
			Principal: model.PermissionPrincipal{
				Name: "billing-reader",
				Type: "ServiceIdentity",
			},
			Permissions: []model.PermissionGrant{
				{Action: model.ActionStorageRead, Resource: "storage://billing/reports"},
			},
			Description: "Read billing reports",
		},
		Role:         adapterRole("billing-reader"),
		ApprovalMode: ApprovalModeManual,
		ApproverIDs: []string{
			"alice",
			"bob",
		},
	}
}

func adapterRole(name string) adapter.AWSRoleInfo {
	return adapter.AWSRoleInfo{
		Name:        name,
		TrustPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
		Description: "billing report reader",
	}
}

func newTestTicketService(t *testing.T, repository TicketRepository, publisher TicketPublisher) *TicketService {
	t.Helper()
	service, err := NewTicketService(repository, publisher, nil)
	if err != nil {
		t.Fatalf("NewTicketService() error = %v", err)
	}
	return service
}

func TestCreateGroupAdoptionUsesInventorySnapshotForAllRelationships(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.existingPrincipals = map[string]bool{"Group/platform-readonly": true}
	repository.groupAdoptionSnapshot = adapter.IAMGroupInfo{
		Name:            "platform-readonly",
		Path:            "/platform/",
		MemberUserNames: []string{"alice"},
		PolicyARNs:      []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		InlinePolicies: []adapter.IAMInlinePolicy{{
			Name:     "InlineReadOnly",
			Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`),
		}},
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateGroup,
		AccountID:     1,
		PrincipalName: "platform-readonly",
		AdoptExisting: true,
		CreateGroup: &adapter.IAMGroupInfo{
			Name:            "platform-readonly",
			MemberUserNames: []string{"stale-user-from-form"},
		},
	}

	if err := service.validateCreateResourceRequest(context.Background(), &request); err != nil {
		t.Fatalf("validateCreateResourceRequest() error = %v", err)
	}
	if len(request.CreateGroup.MemberUserNames) != 1 || request.CreateGroup.MemberUserNames[0] != "alice" {
		t.Fatalf("member snapshot = %v, want inventory member alice", request.CreateGroup.MemberUserNames)
	}
	if len(request.CreateGroup.PolicyARNs) != 1 ||
		request.CreateGroup.PolicyARNs[0] != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Fatalf("managed policy snapshot = %v", request.CreateGroup.PolicyARNs)
	}
	if len(request.CreateGroup.InlinePolicies) != 1 ||
		request.CreateGroup.InlinePolicies[0].Name != "InlineReadOnly" {
		t.Fatalf("inline policy snapshot = %+v", request.CreateGroup.InlinePolicies)
	}

	hcl, err := service.buildCreateTerraform(context.Background(), request)
	if err != nil {
		t.Fatalf("buildCreateTerraform() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_group" "group_platform-readonly"`,
		`to = aws_iam_group_policy_attachment.attachment_group_platform-readonly_ReadOnlyAccess`,
		`resource "aws_iam_group_policy" "group_platform-readonly_pfmot_InlineReadOnly"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("adoption Terraform missing %q:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, `to = aws_iam_group_membership.`) {
		t.Errorf("aws_iam_group_membership does not support import; no import block expected:\n%s", hcl)
	}
	// 纳管时成员快照改由组 membership 文件承载（单一 owner），组文件不声明。
	if strings.Contains(hcl, `aws_iam_group_membership`) {
		t.Errorf("adopted group file must not declare membership:\n%s", hcl)
	}
	preview, _, err := service.buildTicketTerraformFiles(
		context.Background(), validationStubTicket(request), request, false,
	)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v", err)
	}
	for _, want := range []string{
		`# File: group-platform-readonly.tf`,
		`# File: group-platform-readonly-membership.tf`,
		`resource "aws_iam_group_membership" "group_platform-readonly_membership"`,
		`"alice"`,
	} {
		if !strings.Contains(preview, want) {
			t.Errorf("adoption bundle missing %q:\n%s", want, preview)
		}
	}
}

// fakeMergeRequestFetcher stubs the code-host PR state lookup used
// by the abandon guard.
type fakeMergeRequestFetcher struct {
	status *githost.MergeRequestStatus
	err    error
	calls  int
}

func (fetcher *fakeMergeRequestFetcher) FetchMergeRequest(
	_ context.Context,
	_, _ string,
) (*githost.MergeRequestStatus, error) {
	fetcher.calls++
	return fetcher.status, fetcher.err
}

// seedApprovedTicketWithPR seeds an APPROVED ticket whose PR was
// published to the code host.
func seedApprovedTicketWithPR(
	repository *memoryTicketRepository,
	ticketNo, gitRepository, remoteNumber string,
) {
	status := TicketStatusApproved
	gitRepo := gitRepository
	remoteNo := remoteNumber
	prURL := "https://github.example/" + gitRepository + "/pull/" + remoteNumber
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:            stringPointer(ticketNo),
		Status:              &status,
		GitRepository:       &gitRepo,
		RemoteRequestNumber: &remoteNo,
		GitPRURL:            &prURL,
	}
}

// 废弃前置校验：PR 仍在开启或已合并时禁止废弃，
// 防止「PR 后来被合并但工单已废弃」的错位。
func TestCloseTicketAbandonGuard(t *testing.T) {
	t.Run("rejects abandon while PR is open", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedApprovedTicketWithPR(repository, "IAM-PR-OPEN", "team/iac", "15")
		fetcher := &fakeMergeRequestFetcher{
			status: &githost.MergeRequestStatus{State: githost.MergeStateOpen},
		}
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
			WithMergeRequestFetcher(fetcher))
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		_, err = service.CloseTicket(context.Background(), "IAM-PR-OPEN", "admin", ClosureReasonAbandoned, "", false)
		if err == nil || !strings.Contains(err.Error(), "PR 仍在开启状态") {
			t.Fatalf("expected open-PR rejection, got %v", err)
		}
		if fetcher.calls != 1 {
			t.Fatalf("fetcher calls = %d, want 1", fetcher.calls)
		}
	})

	t.Run("rejects abandon after PR merged", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedApprovedTicketWithPR(repository, "IAM-PR-MERGED", "team/iac", "16")
		fetcher := &fakeMergeRequestFetcher{
			status: &githost.MergeRequestStatus{State: githost.MergeStateMerged},
		}
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
			WithMergeRequestFetcher(fetcher))
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		_, err = service.CloseTicket(context.Background(), "IAM-PR-MERGED", "admin", ClosureReasonAbandoned, "", false)
		if err == nil || !strings.Contains(err.Error(), "PR 已合并") {
			t.Fatalf("expected merged-PR rejection, got %v", err)
		}
	})

	t.Run("allows abandon after PR closed", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedApprovedTicketWithPR(repository, "IAM-PR-CLOSED", "team/iac", "17")
		fetcher := &fakeMergeRequestFetcher{
			status: &githost.MergeRequestStatus{State: githost.MergeStateClosed},
		}
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
			WithMergeRequestFetcher(fetcher))
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		ticket, err := service.CloseTicket(context.Background(), "IAM-PR-CLOSED", "admin", ClosureReasonAbandoned, "", false)
		if err != nil {
			t.Fatalf("CloseTicket(ABANDONED) error = %v", err)
		}
		if ticket.ClosureReason == nil || *ticket.ClosureReason != ClosureReasonAbandoned {
			t.Fatalf("closure_reason = %v, want ABANDONED", ticket.ClosureReason)
		}
	})

	t.Run("fetch failure blocks abandon", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedApprovedTicketWithPR(repository, "IAM-PR-ERR", "team/iac", "18")
		fetcher := &fakeMergeRequestFetcher{err: errors.New("code host unavailable")}
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
			WithMergeRequestFetcher(fetcher))
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		_, err = service.CloseTicket(context.Background(), "IAM-PR-ERR", "admin", ClosureReasonAbandoned, "", false)
		if err == nil || !strings.Contains(err.Error(), "查询 PR 状态失败") {
			t.Fatalf("expected fetch-failure rejection, got %v", err)
		}
	})

	t.Run("allows abandon without fetcher wired", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedApprovedTicketWithPR(repository, "IAM-NO-FETCHER", "team/iac", "19")
		service := newTestTicketService(t, repository, &memoryTicketPublisher{})
		if _, err := service.CloseTicket(context.Background(), "IAM-NO-FETCHER", "admin", ClosureReasonAbandoned, "", false); err != nil {
			t.Fatalf("CloseTicket(ABANDONED) without fetcher error = %v", err)
		}
	})

	t.Run("allows abandon for ticket without PR", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		status := TicketStatusApproved
		repository.tickets["IAM-NO-PR"] = model.IAMTicket{
			TicketNo: stringPointer("IAM-NO-PR"),
			Status:   &status,
		}
		fetcher := &fakeMergeRequestFetcher{}
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
			WithMergeRequestFetcher(fetcher))
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		if _, err := service.CloseTicket(context.Background(), "IAM-NO-PR", "admin", ClosureReasonAbandoned, "", false); err != nil {
			t.Fatalf("CloseTicket(ABANDONED) for PR-less ticket error = %v", err)
		}
		if fetcher.calls != 0 {
			t.Fatalf("fetcher calls = %d, want 0 for PR-less ticket", fetcher.calls)
		}
	})

	t.Run("applied close is not blocked by open PR", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedApprovedTicketWithPR(repository, "IAM-APPLIED-GUARD", "team/iac", "20")
		fetcher := &fakeMergeRequestFetcher{
			status: &githost.MergeRequestStatus{State: githost.MergeStateOpen},
		}
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
			WithMergeRequestFetcher(fetcher))
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		ticket, err := service.CloseTicket(context.Background(), "IAM-APPLIED-GUARD", "system", ClosureReasonApplied, "", false)
		if err != nil {
			t.Fatalf("CloseTicket(APPLIED) error = %v", err)
		}
		if ticket.ClosureReason == nil || *ticket.ClosureReason != ClosureReasonApplied {
			t.Fatalf("closure_reason = %v, want APPLIED", ticket.ClosureReason)
		}
	})
}

func TestCloseTicketStoresComment(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedApprovedTicketWithPR(repository, "IAM-COMMENT-1", "team/iac", "21")
	seedApprovedTicketWithPR(repository, "IAM-COMMENT-2", "team/iac", "22")
	service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil)
	if err != nil {
		t.Fatalf("NewTicketService() error = %v", err)
	}

	ticket, err := service.CloseTicket(
		context.Background(), "IAM-COMMENT-1", "admin", ClosureReasonAbandoned, "重复工单，不再需要", false,
	)
	if err != nil {
		t.Fatalf("CloseTicket(ABANDONED) error = %v", err)
	}
	if ticket.ClosureComment == nil || *ticket.ClosureComment != "重复工单，不再需要" {
		t.Fatalf("closure_comment = %v, want '重复工单，不再需要'", ticket.ClosureComment)
	}

	// 空 comment 也应正常存储（返回空指针或空字符串均可，但不能 panic）。
	ticket2, err := service.CloseTicket(context.Background(), "IAM-COMMENT-2", "admin2", ClosureReasonApplied, "  ", false)
	if err != nil {
		t.Fatalf("CloseTicket(APPLIED) error = %v", err)
	}
	if ticket2.ClosureComment == nil {
		t.Fatal("closure_comment should not be nil")
	}
}

func updateRoleTicketRequest() CreateIAMTicketRequest {
	trust := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{
				"Effect":    "Allow",
				"Principal": map[string]interface{}{"Service": "ec2.amazonaws.com"},
				"Action":    "sts:AssumeRole",
			},
		},
	}
	return CreateIAMTicketRequest{
		TicketType:    TicketTypeUpdateRole,
		AccountID:     1,
		PrincipalName: "billing-reader",
		UpdateRole: &adapter.UpdateRoleConfig{
			TrustPolicy: &trust,
		},
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"alice", "bob"},
	}
}

// roleTerraformFile mirrors the CREATE_ROLE generator output for
// billing-reader (the role used across UPDATE_ROLE tests): a role block plus
// the role's own inline policy. UPDATE_ROLE's block-patch generation reads
// this file as the patch base.
const roleTerraformFile = `resource "aws_iam_role" "managed_role" {
	name               = "billing-reader"
	assume_role_policy = jsonencode({
		"Version" = "2012-10-17"
		"Statement" = [
			{
				"Effect" = "Allow"
				"Principal" = { "Service" = "ec2.amazonaws.com" }
				"Action" = "sts:AssumeRole"
			},
		]
	})
	description = "billing report reader"
}

resource "aws_iam_role_policy" "managed_policy" {
	name   = "billing-reader-policy"
	role   = aws_iam_role.managed_role.id
	policy = jsonencode({
		"Version" = "2012-10-17"
		"Statement" = [
			{
				"Effect" = "Allow"
				"Action" = ["iam:GetRole"]
				"Resource" = "*"
			},
		]
	})
}
`

func TestTicketLifecycleRequiresAllApproversBeforePublication(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/group/iac/-/merge_requests/34"}
	service := newTestTicketService(t, repository, publisher)

	ticket, err := service.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatalf("CreateTicket() error = %v", err)
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		t.Fatalf("created status = %v, want APPROVING", ticket.Status)
	}
	validation, exists := repository.validationChecks[*ticket.TicketNo]
	if !exists || len(validation.RequestSHA256) != 32 || validation.BaselineID != nil ||
		!strings.Contains(string(validation.Checks), "NO_BASELINE") ||
		!strings.Contains(string(validation.Checks), "STATIC_RISK_SCAN") ||
		!strings.Contains(string(validation.Checks), `"code":"PERMISSION_OVERLAP","description":"Target role is not present in the collected IAM inventory","result":"SKIPPED"`) {
		t.Fatalf("ticket validation snapshot missing or invalid: %+v", validation)
	}
	if ticket.TerraformCode != nil || ticket.GitPRURL != nil || publisher.calls != 0 {
		t.Fatal("ticket was published before all approvals")
	}
	if !json.Valid(ticket.RequestPolicy) {
		t.Fatalf("ticket request JSON is invalid: %s", ticket.RequestPolicy)
	}
	if ticket.ApprovalMode != ApprovalModeManual || string(ticket.ApproverIDs) != `["alice","bob"]` {
		t.Fatalf("stored approval config = %s/%s", ticket.ApprovalMode, ticket.ApproverIDs)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "Required scope is justified"})
	if err != nil {
		t.Fatalf("first approval error = %v", err)
	}
	if *ticket.Status != TicketStatusApproving || publisher.calls != 0 {
		t.Fatal("first approval should leave ticket pending and unpublished")
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "Reviewed and approved"})
	if err != nil {
		t.Fatalf("final approval error = %v", err)
	}
	if *ticket.Status != TicketStatusApproved || ticket.GitPRURL == nil || *ticket.GitPRURL != publisher.url {
		t.Fatalf("approved ticket publication = %#v", ticket)
	}
	if publisher.calls != 1 || !strings.Contains(publisher.terraform, `resource "aws_iam_role"`) {
		t.Fatalf("publisher calls/code = %d/%q", publisher.calls, publisher.terraform)
	}
	if publisher.request.AWSAccountID != "123456789012" {
		t.Errorf("publisher AWS account ID = %q", publisher.request.AWSAccountID)
	}
	if ticket.TerraformCode == nil || *ticket.TerraformCode != publisher.terraform {
		t.Error("Terraform code was not saved back to the ticket")
	}
}

// TestPreviewTicketTerraformRendersUnpublishedTicket proves the preview path
// renders the HCL a ticket would publish without mutating anything: no
// publication, no rollback snapshot capture, no status change.
func TestPreviewTicketTerraformRendersUnpublishedTicket(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/app-ReadOnly"
	repository.policyRecords[arn] = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/99"}
	service := newTestTicketService(t, repository, publisher)
	ctx := context.Background()

	request := updateManagedPolicyTicketRequest(
		arn,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`,
	)
	request.UpdatePolicy.PolicyName = "app-ReadOnly"
	ticket, err := service.CreateTicket(ctx, "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket() error = %v", err)
	}

	preview, err := service.PreviewTicketTerraform(ctx, *ticket.TicketNo, "requester", nil)
	if err != nil {
		t.Fatalf("PreviewTicketTerraform() error = %v", err)
	}
	if !strings.Contains(preview, `resource "aws_iam_policy"`) {
		t.Fatalf("preview = %q", preview)
	}

	stored, err := repository.Get(ctx, *ticket.TicketNo)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if stored.TerraformCode != nil {
		t.Error("preview persisted terraform code on the ticket")
	}
	if stored.Status == nil || *stored.Status != TicketStatusApproving {
		t.Errorf("status after preview = %v", stored.Status)
	}
	if len(stored.RoleSnapshot) != 0 {
		t.Errorf("preview captured a rollback snapshot: %s", stored.RoleSnapshot)
	}
	if publisher.calls != 0 {
		t.Errorf("publisher calls = %d, want 0", publisher.calls)
	}
}

// TestPreviewTicketTerraformReturnsStoredFileForPublishedTicket proves published
// tickets return the stored file verbatim: the preview must match what reached
// the Git host even when the stored request can no longer be decoded.
func TestPreviewTicketTerraformReturnsStoredFileForPublishedTicket(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/7"})
	status := TicketStatusApproved
	accountID := int64(1)
	repository.tickets["IAM-PUBLISHED1"] = model.IAMTicket{
		TicketNo:      stringPointer("IAM-PUBLISHED1"),
		AccountID:     &accountID,
		Submitter:     stringPointer("requester"),
		Status:        &status,
		TerraformCode: stringPointer("# stored file"),
		RequestPolicy: model.JSONB("{ not valid json"),
	}

	preview, err := service.PreviewTicketTerraform(context.Background(), "IAM-PUBLISHED1", "requester", nil)
	if err != nil {
		t.Fatalf("PreviewTicketTerraform() error = %v", err)
	}
	if preview != "# stored file" {
		t.Errorf("preview = %q", preview)
	}
}

func TestCreateTicketIsBlockedByEnabledAccountBaseline(t *testing.T) {
	repository := newMemoryTicketRepository()
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"},
		Resources: []string{"//storage/bucket/billing/reports"},
	}}}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	repository.enabledBaseline = &model.IAMBaseline{
		ID: 27, AccountID: 12, Version: 3, Enabled: true, AbstractPolicy: model.JSONB(baselineJSON),
	}
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := validTicketRequest()
	request.Permission.Permissions[0].Resource = "storage://engineering/private"
	_, err = ticketService.CreateTicket(context.Background(), "requester", request)
	var violations *IAMBaselineComplianceError
	if !errors.As(err, &violations) {
		t.Fatalf("expected baseline violation error, got %v", err)
	}
	if len(violations.Violations) != 1 ||
		violations.Violations[0].Code != "GRANT_OUTSIDE_BASELINE" ||
		len(repository.tickets) != 0 {
		t.Fatalf("out-of-baseline request was not blocked before ticket creation: violations=%+v tickets=%d",
			violations.Violations, len(repository.tickets))
	}
}

func TestCreateTicketStoresEnabledBaselineVersionInValidationSnapshot(t *testing.T) {
	repository := newMemoryTicketRepository()
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"},
		Resources: []string{"//storage/bucket/billing/*"},
	}}}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	repository.enabledBaseline = &model.IAMBaseline{
		ID: 28, AccountID: 12, Version: 4, Enabled: true, AbstractPolicy: model.JSONB(baselineJSON),
	}
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := validTicketRequest()
	// 使用与基线匹配的资源格式
	request.Permission.Permissions[0].Resource = "//storage/bucket/billing/reports"
	ticket, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("create compliant request: %v", err)
	}
	validation := repository.validationChecks[*ticket.TicketNo]
	if validation.BaselineID == nil || *validation.BaselineID != 28 ||
		!strings.Contains(string(validation.Checks), "BASELINE_COMPLIANT") {
		t.Fatalf("enabled baseline version was not captured: %+v", validation)
	}
}

func TestCreateTicketBlocksExternalTrustAndReturnsRiskFinding(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := validTicketRequest()
	request.Role.TrustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::210987654321:root"},"Action":"sts:AssumeRole"}]}`)
	_, err := ticketService.CreateTicket(context.Background(), "requester", request)
	var riskError *CandidatePolicyRiskError
	if !errors.As(err, &riskError) {
		t.Fatalf("expected structured static-risk error, got %v", err)
	}
	if len(riskError.Findings) != 1 || riskError.Findings[0].RiskType != iamRiskExternalTrust ||
		riskError.Findings[0].RiskLevel != "HIGH" || len(repository.tickets) != 0 {
		t.Fatalf("external trust was not blocked before ticket persistence: findings=%+v tickets=%d",
			riskError.Findings, len(repository.tickets))
	}
}

func TestCreateTicketWarnModeAllowsOnlyAdminLikePolicyNameFinding(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{}
	ticketService, err := NewTicketService(
		repository, publisher, nil,
		WithCandidateRiskMode(CandidateRiskModeWarn),
	)
	if err != nil {
		t.Fatalf("NewTicketService(WARN): %v", err)
	}
	request := validTicketRequest()
	request.PrincipalName = "admin-reader"
	request.Role.Name = request.PrincipalName
	request.Permission.Principal.Name = request.PrincipalName
	ticket, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("WARN mode blocked a name-only heuristic finding: %v", err)
	}
	validation := repository.validationChecks[*ticket.TicketNo]
	if !strings.Contains(string(validation.Checks), `"code":"STATIC_RISK_SCAN","description":"Static candidate policy and trust-policy findings evaluated under configured risk mode","findings":[{"risk_type":"phase0_iam_admin_policy"`) ||
		!strings.Contains(string(validation.Checks), `"result":"WARN"`) {
		t.Fatalf("warning finding/mode not captured in validation snapshot: %s", validation.Checks)
	}
}

func TestCreateTicketWarnModeStillBlocksHighRiskFindings(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService, err := NewTicketService(
		repository, &memoryTicketPublisher{}, nil,
		WithCandidateRiskMode(CandidateRiskModeWarn),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := validTicketRequest()
	request.Role.TrustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::210987654321:root"},"Action":"sts:AssumeRole"}]}`)
	if _, err := ticketService.CreateTicket(context.Background(), "requester", request); err == nil {
		t.Fatal("WARN mode allowed external trust finding")
	}
	if len(repository.tickets) != 0 {
		t.Fatalf("WARN mode persisted %d ticket(s) despite high-risk finding", len(repository.tickets))
	}
}

func TestCreateTicketRecordsPermissionOverlapAsAdvisory(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.existingPolicies = []ExistingIAMPolicy{{
		Name:     "existing-read-policy",
		Document: json.RawMessage(`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::billing/*"}}`),
	}}
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	ticket, err := ticketService.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatalf("possible permission overlap blocked ticket creation: %v", err)
	}
	validation := repository.validationChecks[*ticket.TicketNo]
	if !strings.Contains(string(validation.Checks), `"result":"POSSIBLE_OVERLAP"`) ||
		!strings.Contains(string(validation.Checks), "existing-read-policy") {
		t.Fatalf("possible overlap was not recorded in validation snapshot: %s", validation.Checks)
	}
}

func TestCreateDraftDefersValidationAndPersistsImmutableSnapshots(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	ticket, err := ticketService.CreateDraft(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatalf("CreateDraft() error = %v", err)
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusDraft {
		t.Fatalf("draft status = %v, want DRAFT", ticket.Status)
	}
	if len(repository.validationChecks) != 0 || len(repository.approvers[*ticket.TicketNo]) != 0 {
		t.Fatal("draft creation performed submit-time validation or created approval rows")
	}
	var savedRequest CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &savedRequest); err != nil {
		t.Fatalf("decode draft request snapshot: %v", err)
	}
	if strings.Join(savedRequest.ApproverIDs, ",") != "alice,bob" ||
		string(ticket.ApproverIDs) != `["alice","bob"]` {
		t.Fatalf("draft approver snapshot differs: request=%v column=%s", savedRequest.ApproverIDs, ticket.ApproverIDs)
	}
}

func TestSubmitDraftRunsValidationAndMovesToApproval(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	ticket, err := ticketService.CreateDraft(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}
	submitted, err := ticketService.SubmitTicket(
		context.Background(), *ticket.TicketNo, "requester", []string{"standard_user"},
	)
	if err != nil {
		t.Fatalf("SubmitTicket() error = %v", err)
	}
	if submitted.Status == nil || *submitted.Status != TicketStatusApproving {
		t.Fatalf("submitted status = %v, want APPROVING", submitted.Status)
	}
	validation, exists := repository.validationChecks[*ticket.TicketNo]
	if !exists || len(validation.RequestSHA256) != 32 ||
		!strings.Contains(string(validation.Checks), "STATIC_RISK_SCAN") ||
		len(repository.approvers[*ticket.TicketNo]) != 2 {
		t.Fatalf("submission did not persist validation/approval snapshots: validation=%+v approvals=%v",
			validation, repository.approvers[*ticket.TicketNo])
	}
	if _, err := ticketService.SubmitTicket(
		context.Background(), *ticket.TicketNo, "requester", []string{"standard_user"},
	); !errors.Is(err, ErrInvalidTicketState) {
		t.Fatalf("resubmission error = %v, want invalid state", err)
	}
}

func TestFailedDraftValidationLeavesDraftAndApproverSnapshotUntouched(t *testing.T) {
	repository := newMemoryTicketRepository()
	baseline, err := json.Marshal(abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/allowed/*"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := validTicketRequest()
	request.Permission.Permissions[0].Resource = "storage://denied/private"
	draft, err := ticketService.CreateDraft(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateDraft() should defer policy validation: %v", err)
	}
	repository.enabledBaseline = &model.IAMBaseline{ID: 29, Version: 1, Enabled: true, AbstractPolicy: model.JSONB(baseline)}
	before := append([]byte(nil), draft.ApproverIDs...)
	_, err = ticketService.SubmitTicket(
		context.Background(), *draft.TicketNo, "requester", []string{"standard_user"},
	)
	var complianceError *IAMBaselineComplianceError
	if !errors.As(err, &complianceError) {
		t.Fatalf("SubmitTicket() error = %v, want baseline failure", err)
	}
	stored, getErr := ticketService.GetTicket(context.Background(), *draft.TicketNo)
	if getErr != nil || stored.Status == nil || *stored.Status != TicketStatusDraft {
		t.Fatalf("failed submission changed ticket state: status=%v error=%v", stored.Status, getErr)
	}
	if string(stored.ApproverIDs) != string(before) ||
		len(repository.validationChecks) != 0 || len(repository.approvers[*draft.TicketNo]) != 0 {
		t.Fatalf("failed submission mutated immutable snapshots: approvers=%s validations=%v approval rows=%v",
			stored.ApproverIDs, repository.validationChecks, repository.approvers[*draft.TicketNo])
	}
}

func TestSubmitDraftEnforcesSubmitterScope(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})
	draft, err := ticketService.CreateDraft(context.Background(), "owner", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ticketService.SubmitTicket(
		context.Background(), *draft.TicketNo, "another-user", []string{"standard_user"},
	); !errors.Is(err, ErrTicketAccessDenied) {
		t.Fatalf("SubmitTicket(non-owner) error = %v, want access denied", err)
	}
	if got := *repository.tickets[*draft.TicketNo].Status; got != TicketStatusDraft {
		t.Fatalf("unauthorized submission changed state to %s", got)
	}
}

func TestGetTicketForActorEnforcesSubmitterScope(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketNo, submitter := "IAM-READ-1", "alice"
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo: &ticketNo, Submitter: &submitter,
	}
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	if _, err := ticketService.GetTicketForActor(context.Background(), ticketNo, "bob", []string{"standard_user"}); !errors.Is(err, ErrTicketAccessDenied) {
		t.Fatalf("GetTicketForActor(other user) error = %v, want access denied", err)
	}
	if _, err := ticketService.GetTicketForActor(context.Background(), ticketNo, "alice", []string{"standard_user"}); err != nil {
		t.Fatalf("GetTicketForActor(owner) error = %v", err)
	}
	if _, err := ticketService.GetTicketForActor(context.Background(), ticketNo, "bob", []string{"approval_admin"}); err != nil {
		t.Fatalf("GetTicketForActor(approval admin) error = %v", err)
	}
}

func TestTicketRejectionStopsPublication(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/mr/35"}
	service := newTestTicketService(t, repository, publisher)
	ticket, err := service.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{
		Result:  "REJECT",
		Comment: "Policy scope is not justified",
	})
	if err != nil {
		t.Fatalf("reject decision error = %v", err)
	}
	if *ticket.Status != TicketStatusRejected || publisher.calls != 0 {
		t.Fatalf("rejected ticket was incorrectly published: status=%s calls=%d", *ticket.Status, publisher.calls)
	}
}

func TestTicketValidationAndApproverAuthorization(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/mr/36"}
	service := newTestTicketService(t, repository, publisher)

	request := validTicketRequest()
	request.TicketType = "DELETE_ROLE"
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil {
		t.Fatal("CreateTicket() accepted unsupported ticket type")
	}
	request = validTicketRequest()
	// 通配动作是 HIGH 级：仍阻断（通配资源为 MEDIUM，改为告警不阻断）
	request.Permission.Permissions[0].Action = "*"
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil {
		t.Fatal("CreateTicket() accepted a high-risk wildcard policy")
	}
	request = validTicketRequest()
	if _, err := service.CreateTicket(context.Background(), "alice", request); err == nil {
		t.Fatal("CreateTicket() allowed submitter to approve own ticket")
	}
	request = validTicketRequest()
	request.ApproverIDs = []string{"unregistered-user"}
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil {
		t.Fatal("CreateTicket() allowed an unregistered platform user to approve")
	}
	request = validTicketRequest()
	request.ApprovalMode = ApprovalModeAuto
	request.ApproverIDs = []string{"client-selected-user"}
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil {
		t.Fatal("CreateTicket() accepted client-selected approvers in AUTO mode")
	}

	ticket, err := service.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "mallory", TicketDecision{Result: "APPROVE", Comment: "Approve"}); !errors.Is(err, ErrNotDesignatedApprover) {
		t.Fatalf("Decide() error = %v, want ErrNotDesignatedApprover", err)
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "MAYBE"}); err == nil {
		t.Fatal("Decide() accepted invalid decision")
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "REJECT"}); err == nil {
		t.Fatal("Decide() accepted rejection without a comment")
	}
}

func TestAutoApproversAreResolvedByAccountBinding(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/mr/40"}
	service := newTestTicketService(t, repository, publisher)
	request := validTicketRequest()
	request.ApprovalMode = ApprovalModeAuto
	request.ApproverIDs = nil

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(AUTO) error = %v", err)
	}
	if ticket.ApprovalMode != ApprovalModeAuto || string(ticket.ApproverIDs) != `["alice","bob"]` {
		t.Fatalf("AUTO approvers = %s/%s", ticket.ApprovalMode, ticket.ApproverIDs)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stored.ApproverIDs, ",") != "alice,bob" {
		t.Errorf("request snapshot approvers = %v", stored.ApproverIDs)
	}
}

// TestAutoApproversExcludeSubmitter AUTO 的审批人来自账号绑定，常包含提交人
// 自己（账号负责人）；自批禁令应通过剔除提交人实现，而不是拒绝整张工单。
func TestAutoApproversExcludeSubmitter(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/42"})
	request := validTicketRequest()
	request.ApprovalMode = ApprovalModeAuto
	request.ApproverIDs = nil

	// 提交人 alice 本身就在该账号的绑定审批人里。
	ticket, err := service.CreateTicket(context.Background(), "alice", request)
	if err != nil {
		t.Fatalf("CreateTicket(AUTO, submitter is an approver) error = %v", err)
	}
	if string(ticket.ApproverIDs) != `["bob"]` {
		t.Fatalf("AUTO approvers = %s, want [\"bob\"] (submitter removed)", ticket.ApproverIDs)
	}
}

// TestAutoApproversRejectWhenSubmitterIsOnlyApprover 账号只有提交人一个审批人时，
// AUTO 无法成立，须给出明确错误（400）而不是静默生成自批工单。
func TestAutoApproversRejectWhenSubmitterIsOnlyApprover(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.autoApprovers = []model.PlatformUser{
		{UserID: "alice", DisplayName: "Alice", IsActive: true},
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/43"})
	request := validTicketRequest()
	request.ApprovalMode = ApprovalModeAuto
	request.ApproverIDs = nil

	_, err := service.CreateTicket(context.Background(), "alice", request)
	if err == nil {
		t.Fatal("CreateTicket(AUTO) allowed the submitter to be the only approver")
	}
	if !strings.Contains(err.Error(), "only configured approver") {
		t.Fatalf("err = %v, want the only-configured-approver message", err)
	}
}

func TestTicketApprovalInfoAndAvailableApprovers(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/41"})
	ticket, err := service.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}
	info, err := service.GetApprovalInfo(context.Background(), *ticket.TicketNo)
	if err != nil {
		t.Fatalf("GetApprovalInfo() error = %v", err)
	}
	if info.ApprovalMode != ApprovalModeManual || len(info.Approvals) != 2 {
		t.Errorf("approval info = %+v", info)
	}
	users, err := service.ListAvailableApprovers(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListAvailableApprovers() error = %v", err)
	}
	if len(users) != 3 {
		t.Errorf("available platform approvers = %d, want 3", len(users))
	}
}

func TestFailedGitLabPublicationCanBeRetried(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{err: errors.New("GitLab unavailable")}
	service := newTestTicketService(t, repository, publisher)
	ticket, err := service.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "Reviewed"}); err != nil {
		t.Fatal(err)
	}

	// Final approval triggers publish which fails
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "Reviewed"}); err == nil || !strings.Contains(err.Error(), "GitLab unavailable") {
		t.Fatalf("final approval error = %v, want GitLab publication error", err)
	}

	// After publish failure, ticket should be in PUBLISH_FAILED state
	stored, err := service.GetTicket(context.Background(), *ticket.TicketNo)
	if err != nil || stored.Status == nil || *stored.Status != TicketStatusPublishFailed {
		t.Fatalf("ticket after publication error = %#v, error %v, want PUBLISH_FAILED", stored, err)
	}

	// Retry should work from PUBLISH_FAILED state
	publisher.err = nil
	publisher.url = "https://gitlab.example/mr/37"
	stored, err = service.RetryPublication(context.Background(), *ticket.TicketNo)
	if err != nil {
		t.Fatalf("RetryPublication() error = %v", err)
	}
	if stored.GitPRURL == nil || *stored.GitPRURL != publisher.url || publisher.calls != 2 {
		t.Fatalf("retry result/calls = %#v/%d", stored, publisher.calls)
	}
}

func TestGitLabPublicationURLRequiredAndMergedTransition(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{}
	service := newTestTicketService(t, repository, publisher)
	ticket, err := service.CreateTicket(context.Background(), "requester", validTicketRequest())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "Reviewed"})
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "Reviewed"}); err == nil || !strings.Contains(err.Error(), "empty Merge Request URL") {
		t.Fatalf("publication error = %v, want empty URL error", err)
	}

	repository.tickets[*ticket.TicketNo] = model.IAMTicket{
		TicketNo: stringPointer(*ticket.TicketNo),
		Status:   stringPointer(TicketStatusApproved),
	}
	if err := service.MarkMerged(context.Background(), *ticket.TicketNo); err != nil {
		t.Fatalf("MarkMerged() error = %v", err)
	}
	merged, _ := service.GetTicket(context.Background(), *ticket.TicketNo)
	if *merged.Status != TicketStatusMerged {
		t.Errorf("merged status = %s", *merged.Status)
	}
}

func TestNormalizeApproversAndTicketNumber(t *testing.T) {
	got := normalizeApprovers([]string{" alice ", "", "alice", "bob"})
	if fmt.Sprint(got) != "[alice bob]" {
		t.Fatalf("normalizeApprovers() = %v", got)
	}
	first, err := newTicketNumber()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTicketNumber()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "IAM-") || first == second {
		t.Fatalf("ticket numbers = %q and %q", first, second)
	}
}

func TestGitLabSDKPublisherCreatesBundleAndMergeRequest(t *testing.T) {
	var branchCreates, fileCreates, mergeRequestLists, mergeRequestCreates int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && strings.Contains(request.URL.EscapedPath(), "/repository/branches/"):
			http.Error(writer, `{"message":"404 Branch Not Found"}`, http.StatusNotFound)
		case request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/repository/branches"):
			branchCreates++
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"name":"iam-ticket/iam-123"}`))
		case request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/repository/files/"):
			fileCreates++
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"file_path":"iam/account-12/iam-123.tf"}`))
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/merge_requests"):
			mergeRequestLists++
			_, _ = writer.Write([]byte(`[]`))
		case request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/merge_requests"):
			mergeRequestCreates++
			_, _ = writer.Write([]byte(`{"web_url":"https://gitlab.example/group/iac/-/merge_requests/123"}`))
		default:
			t.Errorf("unexpected GitLab request: %s %s", request.Method, request.URL)
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	publisher, err := NewGitLabSDKPublisher(GitLabConfig{
		BaseURL:      server.URL + "/api/v4",
		Token:        "test-token",
		ProjectID:    "17",
		TargetBranch: "main",
	})
	if err != nil {
		t.Fatalf("NewGitLabSDKPublisher() error = %v", err)
	}
	ticketNo := "IAM-123"
	accountID := int64(12)
	ticket := model.IAMTicket{
		TicketNo:  &ticketNo,
		AccountID: &accountID,
		Submitter: stringPointer("requester"),
	}
	request := validTicketRequest()
	request.AWSAccountID = "123456789012"
	publishResult, err := publisher.PublishBundle(context.Background(), ticket, request, []TerraformBundleFile{
		{Key: "role-workspaces_defaultrole-policy-one", Content: `resource "aws_iam_role_policy" "one" {}`},
		{Key: "role-workspaces_defaultrole-policy-two", Content: `resource "aws_iam_role_policy" "two" {}`},
	})
	if err != nil {
		t.Fatalf("PublishBundle() error = %v", err)
	}
	if publishResult == nil || publishResult.URL != "https://gitlab.example/group/iac/-/merge_requests/123" {
		t.Errorf("Merge Request URL = %v", publishResult)
	}
	if branchCreates != 1 || fileCreates != 2 || mergeRequestLists != 1 || mergeRequestCreates != 1 {
		t.Errorf("GitLab operation counts branch/file/list/MR = %d/%d/%d/%d",
			branchCreates, fileCreates, mergeRequestLists, mergeRequestCreates)
	}
}

// ==================== 新模型（AbstractPolicy）测试 ====================

// validAbstractPolicyRequest 返回使用新模型 AbstractPolicy 的测试请求
func validAbstractPolicyRequest() CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateRole,
		AccountID:     12,
		PrincipalName: "billing-reader",
		AbstractPolicy: &abstractiam.AbstractPolicy{
			Name:        "billing-reader",
			Description: "Read billing reports",
			Statements: []abstractiam.AbstractStatement{
				{
					Effect:    "Allow",
					Actions:   []string{"storage:read"},
					Resources: []string{"//storage/bucket/billing/reports"},
				},
			},
		},
		Role:         adapterRole("billing-reader"),
		ApprovalMode: ApprovalModeManual,
		ApproverIDs: []string{
			"alice",
			"bob",
		},
	}
}

// TestCreateTicketWithAbstractPolicy 验证使用新模型创建工单
func TestCreateTicketWithAbstractPolicy(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/mr/50"}
	ticketService := newTestTicketService(t, repository, publisher)

	ticket, err := ticketService.CreateTicket(context.Background(), "requester", validAbstractPolicyRequest())
	if err != nil {
		t.Fatalf("CreateTicket() with abstract_policy error = %v", err)
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		t.Fatalf("ticket status = %v, want APPROVING", ticket.Status)
	}
	if len(repository.validationChecks) != 1 {
		t.Fatalf("validation checks count = %d, want 1", len(repository.validationChecks))
	}
	validation := repository.validationChecks[*ticket.TicketNo]
	if !strings.Contains(string(validation.Checks), "STATIC_RISK_SCAN") {
		t.Fatalf("validation checks missing STATIC_RISK_SCAN: %s", validation.Checks)
	}
}

// TestCreateTicketAbstractPolicyBaselineValidation 验证新模型的基线验证
func TestCreateTicketAbstractPolicyBaselineValidation(t *testing.T) {
	repository := newMemoryTicketRepository()
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"},
		Resources: []string{"//storage/bucket/billing/*"},
	}}}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	repository.enabledBaseline = &model.IAMBaseline{
		ID: 30, AccountID: 12, Version: 1, Enabled: true, AbstractPolicy: model.JSONB(baselineJSON),
	}
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	// 合规请求应该成功
	ticket, err := ticketService.CreateTicket(context.Background(), "requester", validAbstractPolicyRequest())
	if err != nil {
		t.Fatalf("compliant abstract_policy request failed: %v", err)
	}
	validation := repository.validationChecks[*ticket.TicketNo]
	if !strings.Contains(string(validation.Checks), "BASELINE_COMPLIANT") {
		t.Fatalf("baseline compliance not recorded: %s", validation.Checks)
	}

	// 不合规请求应该失败
	invalidRequest := validAbstractPolicyRequest()
	invalidRequest.AbstractPolicy.Statements[0].Resources = []string{"//storage/bucket/other/*"}
	_, err = ticketService.CreateTicket(context.Background(), "requester", invalidRequest)
	var complianceError *IAMBaselineComplianceError
	if !errors.As(err, &complianceError) {
		t.Fatalf("expected baseline violation error, got %v", err)
	}
	if len(complianceError.Violations) != 1 {
		t.Fatalf("violations count = %d, want 1", len(complianceError.Violations))
	}
}

// TestCreateTicketAbstractPolicyRiskScan 验证新模型的风险扫描
func TestCreateTicketAbstractPolicyRiskScan(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	// 通配资源是 MEDIUM 级：告警不阻断（大量 AWS 服务无资源级 ARN）
	request := validAbstractPolicyRequest()
	request.AbstractPolicy.Statements[0].Resources = []string{"*"}
	ticket, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("wildcard resource should warn instead of blocking: %v", err)
	}
	validation := repository.validationChecks[*ticket.TicketNo]
	checks := string(validation.Checks)
	if !strings.Contains(checks, `"code":"STATIC_RISK_SCAN"`) ||
		!strings.Contains(checks, `"result":"WARN"`) ||
		!strings.Contains(checks, `phase0_iam_wildcard_resource`) {
		t.Fatalf("wildcard resource warning not captured in validation snapshot: %s", checks)
	}
}

// TestCreateTicketAbstractPolicyTerraformGeneration 验证新模型生�?Terraform
func TestCreateTicketAbstractPolicyTerraformGeneration(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/mr/51"}
	ticketService := newTestTicketService(t, repository, publisher)

	ticket, err := ticketService.CreateTicket(context.Background(), "requester", validAbstractPolicyRequest())
	if err != nil {
		t.Fatalf("CreateTicket() error = %v", err)
	}

	// 审批通过触发 Terraform 生成
	ticket, err = ticketService.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{
		Result:  "APPROVE",
		Comment: "Reviewed",
	})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	ticket, err = ticketService.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{
		Result:  "APPROVE",
		Comment: "Reviewed",
	})
	if err != nil {
		t.Fatalf("final Decide() error = %v", err)
	}

	// 验证 Terraform 代码生成
	if publisher.terraform == "" {
		t.Fatal("Terraform code was not generated")
	}
	if !strings.Contains(publisher.terraform, "aws_iam_role") {
		t.Errorf("Terraform missing aws_iam_role resource: %s", publisher.terraform)
	}
	if !strings.Contains(publisher.terraform, "aws_iam_role_policy") {
		t.Errorf("Terraform missing aws_iam_role_policy resource: %s", publisher.terraform)
	}
	if !strings.Contains(publisher.terraform, "s3:GetObject") {
		t.Errorf("Terraform missing s3:GetObject action: %s", publisher.terraform)
	}
}

// TestAbstractPolicyAndLegacyOutputConsistency 验证新旧模型输出一致性
func TestAbstractPolicyAndLegacyOutputConsistency(t *testing.T) {
	// 旧模型请求
	legacyRequest := validTicketRequest()
	legacyRequest.Permission.Permissions[0].Resource = "//storage/bucket/billing/reports"

	// 新模型请求（等效）
	abstractRequest := validAbstractPolicyRequest()

	// 验证两者都能生成相同的抽象策略
	legacyPolicy, err := legacyRequest.GetAbstractPolicy()
	if err != nil {
		t.Fatalf("legacy GetAbstractPolicy() error = %v", err)
	}
	abstractPolicy, err := abstractRequest.GetAbstractPolicy()
	if err != nil {
		t.Fatalf("abstract GetAbstractPolicy() error = %v", err)
	}

	// 验证策略名称一致
	if legacyPolicy.Name != abstractPolicy.Name {
		t.Errorf("policy name mismatch: legacy=%s abstract=%s", legacyPolicy.Name, abstractPolicy.Name)
	}

	// 验证语句数量一致
	if len(legacyPolicy.Statements) != len(abstractPolicy.Statements) {
		t.Errorf("statement count mismatch: legacy=%d abstract=%d",
			len(legacyPolicy.Statements), len(abstractPolicy.Statements))
	}

	// 验证动作一致
	if len(legacyPolicy.Statements) > 0 && len(abstractPolicy.Statements) > 0 {
		if legacyPolicy.Statements[0].Actions[0] != abstractPolicy.Statements[0].Actions[0] {
			t.Errorf("action mismatch: legacy=%s abstract=%s",
				legacyPolicy.Statements[0].Actions[0], abstractPolicy.Statements[0].Actions[0])
		}
	}
}

// TestCreateTicketAbstractPolicyWithConditions 验证带条件的新模型请求
func TestCreateTicketAbstractPolicyWithConditions(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := validAbstractPolicyRequest()
	request.AbstractPolicy.Statements[0].Conditions = []abstractiam.AbstractCondition{
		{
			Key:      "aws:SourceIp",
			Operator: "IpAddress",
			Values:   []interface{}{"10.0.0.0/8"},
		},
	}

	ticket, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket() with conditions error = %v", err)
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		t.Fatalf("ticket status = %v, want APPROVING", ticket.Status)
	}
}

// TestCreateTicketAbstractPolicyMultipleStatements 验证多语句新模型请求
func TestCreateTicketAbstractPolicyMultipleStatements(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := validAbstractPolicyRequest()
	request.AbstractPolicy.Statements = []abstractiam.AbstractStatement{
		{
			Effect:    "Allow",
			Actions:   []string{"storage:read"},
			Resources: []string{"//storage/bucket/billing/reports"},
		},
		{
			Effect:    "Allow",
			Actions:   []string{"storage:list"},
			Resources: []string{"//storage/bucket/billing"},
		},
	}

	ticket, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket() with multiple statements error = %v", err)
	}
	if ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		t.Fatalf("ticket status = %v, want APPROVING", ticket.Status)
	}
}

// TestCreateTicketAbstractPolicyEmptyStatements 验证空语句新模型请求被拒绝
func TestCreateTicketAbstractPolicyEmptyStatements(t *testing.T) {
	ticketService := newTestTicketService(t, newMemoryTicketRepository(), &memoryTicketPublisher{})

	request := validAbstractPolicyRequest()
	request.AbstractPolicy.Statements = []abstractiam.AbstractStatement{}

	_, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err == nil {
		t.Fatal("CreateTicket() accepted empty statements")
	}
}

// TestCreateTicketAbstractPolicyNameMismatch 验证名称不匹配的新模型请求被拒绝
func TestCreateTicketAbstractPolicyNameMismatch(t *testing.T) {
	repository := newMemoryTicketRepository()
	ticketService := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := validAbstractPolicyRequest()
	request.AbstractPolicy.Name = "different-name"

	_, err := ticketService.CreateTicket(context.Background(), "requester", request)
	if err == nil {
		t.Fatal("CreateTicket() accepted name mismatch")
	}
}

func seedAppliedTicket(repository *memoryTicketRepository, ticketNo string) {
	status := TicketStatusClosed
	reason := ClosureReasonApplied
	principal := "e2e-role"
	accountID := int64(12)
	ticketType := TicketTypeCreateRole
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:      stringPointer(ticketNo),
		TicketType:    &ticketType,
		AccountID:     &accountID,
		PrincipalName: &principal,
		Status:        &status,
		ClosureReason: &reason,
		RequestPolicy: model.JSONB(`{}`),
	}
}

func rollbackTicketRequest(targetTicketNo string) CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: targetTicketNo,
		ApprovalMode:   ApprovalModeManual,
		ApproverIDs:    []string{"alice"},
	}
}

func TestRollbackTicket(t *testing.T) {
	t.Run("creates rollback inheriting principal and account from target", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedAppliedTicket(repository, "IAM-APPLIED-001")
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})

		ticket, err := service.CreateTicket(context.Background(), "requester", rollbackTicketRequest("IAM-APPLIED-001"))
		if err != nil {
			t.Fatalf("CreateTicket(ROLLBACK) error = %v", err)
		}
		if ticket.PrincipalName == nil || *ticket.PrincipalName != "e2e-role" {
			t.Errorf("principal_name = %v, want inherited e2e-role", ticket.PrincipalName)
		}
		if ticket.AccountID == nil || *ticket.AccountID != 12 {
			t.Errorf("account_id = %v, want inherited 12", ticket.AccountID)
		}
	})

	t.Run("rejects unknown target", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		if _, err := service.CreateTicket(context.Background(), "requester", rollbackTicketRequest("IAM-MISSING")); err == nil {
			t.Fatal("CreateTicket(ROLLBACK) should reject unknown target")
		}
	})

	t.Run("rejects target that is not CLOSED", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		status := TicketStatusApproved
		repository.tickets["IAM-OPEN-001"] = model.IAMTicket{
			TicketNo: stringPointer("IAM-OPEN-001"),
			Status:   &status,
		}
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		if _, err := service.CreateTicket(context.Background(), "requester", rollbackTicketRequest("IAM-OPEN-001")); err == nil {
			t.Fatal("CreateTicket(ROLLBACK) should reject non-CLOSED target")
		}
	})

	t.Run("rejects target closed as ABANDONED", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		status := TicketStatusClosed
		reason := ClosureReasonAbandoned
		repository.tickets["IAM-ABANDONED-001"] = model.IAMTicket{
			TicketNo:      stringPointer("IAM-ABANDONED-001"),
			Status:        &status,
			ClosureReason: &reason,
		}
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		if _, err := service.CreateTicket(context.Background(), "requester", rollbackTicketRequest("IAM-ABANDONED-001")); err == nil {
			t.Fatal("CreateTicket(ROLLBACK) should reject target closed as ABANDONED")
		}
	})

	t.Run("rejects already rolled back target", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedAppliedTicket(repository, "IAM-APPLIED-001")
		rollbackStatus := TicketStatusClosed
		rollbackType := TicketTypeRollback
		repository.tickets["IAM-ROLLBACK-OLD"] = model.IAMTicket{
			TicketNo:      stringPointer("IAM-ROLLBACK-OLD"),
			TicketType:    &rollbackType,
			Status:        &rollbackStatus,
			RequestPolicy: model.JSONB(`{"target_ticket_no":"IAM-APPLIED-001"}`),
		}
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		if _, err := service.CreateTicket(context.Background(), "requester", rollbackTicketRequest("IAM-APPLIED-001")); err == nil {
			t.Fatal("CreateTicket(ROLLBACK) should reject already rolled back target")
		}
	})

	t.Run("rejects active rollback for same target", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedAppliedTicket(repository, "IAM-APPLIED-001")
		rollbackStatus := TicketStatusApproving
		rollbackType := TicketTypeRollback
		repository.tickets["IAM-ROLLBACK-ACTIVE"] = model.IAMTicket{
			TicketNo:      stringPointer("IAM-ROLLBACK-ACTIVE"),
			TicketType:    &rollbackType,
			Status:        &rollbackStatus,
			RequestPolicy: model.JSONB(`{"target_ticket_no":"IAM-APPLIED-001"}`),
		}
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		if _, err := service.CreateTicket(context.Background(), "requester", rollbackTicketRequest("IAM-APPLIED-001")); err == nil {
			t.Fatal("CreateTicket(ROLLBACK) should reject when an active rollback exists")
		}
	})

	t.Run("requires target_ticket_no", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		request := rollbackTicketRequest("")
		if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil {
			t.Fatal("CreateTicket(ROLLBACK) should require target_ticket_no")
		}
	})
}

func TestGenerateRollbackTerraform(t *testing.T) {
	code := GenerateRollbackTerraform("IAM-ROLLBACK-001", "IAM-APPLIED-001", "e2e-role")
	if strings.Contains(code, "resource \"") {
		t.Errorf("rollback Terraform must contain no resource declarations:\n%s", code)
	}
	if !strings.Contains(code, "IAM-APPLIED-001") || !strings.Contains(code, "IAM-ROLLBACK-001") {
		t.Errorf("rollback Terraform should reference both ticket numbers:\n%s", code)
	}
	if strings.TrimSpace(code) == "" {
		t.Error("rollback Terraform must keep a non-empty comment file")
	}
}

// 回滚校验必须产出反向 Terraform 预览（与发布共用生成器），且目标无快照时
// 在校验阶段快速失败——此前回滚校验只有一条 SKIPPED 检查，既无预览，也不
// 能提前发现不可回滚的目标。
func TestRollbackValidationPreviewsReverseTerraform(t *testing.T) {
	t.Run("previews cleared file for CREATE_ROLE rollback", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		seedAppliedTicket(repository, "IAM-APPLIED-001")
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})

		snapshot, err := service.PreviewValidation(context.Background(), "requester", rollbackTicketRequest("IAM-APPLIED-001"))
		if err != nil {
			t.Fatalf("PreviewValidation(ROLLBACK) error = %v", err)
		}
		if !strings.Contains(snapshot.TerraformPreview, "# ROLLBACK of IAM ticket IAM-APPLIED-001") {
			t.Errorf("preview should clear the target file, got:\n%s", snapshot.TerraformPreview)
		}
		if !strings.Contains(snapshot.TerraformPreview, rollbackPreviewTicketNo) {
			t.Errorf("preview should use the %q placeholder ticket number, got:\n%s", rollbackPreviewTicketNo, snapshot.TerraformPreview)
		}
		if strings.Contains(snapshot.TerraformPreview, "resource \"") {
			t.Errorf("rollback preview must declare no resources:\n%s", snapshot.TerraformPreview)
		}
	})

	t.Run("fails fast when policy-update target has no snapshot", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		status := TicketStatusClosed
		reason := ClosureReasonApplied
		ticketType := TicketTypeUpdateManagedPolicy
		principal := "demo-policy"
		accountID := int64(12)
		repository.tickets["IAM-NO-SNAPSHOT"] = model.IAMTicket{
			TicketNo:      stringPointer("IAM-NO-SNAPSHOT"),
			TicketType:    &ticketType,
			AccountID:     &accountID,
			PrincipalName: &principal,
			Status:        &status,
			ClosureReason: &reason,
			RequestPolicy: model.JSONB(`{"update_policy":{"policy_arn":"arn:aws:iam::123456789012:policy/demo-policy","policy_name":"demo-policy"}}`),
			// RoleSnapshot intentionally empty：老工单未采集快照
		}
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})

		_, err := service.PreviewValidation(context.Background(), "requester", rollbackTicketRequest("IAM-NO-SNAPSHOT"))
		if err == nil {
			t.Fatal("PreviewValidation should fail when the rollback target has no policy snapshot")
		}
		if !strings.Contains(err.Error(), "no policy snapshot") {
			t.Errorf("error = %v, want mention of missing policy snapshot", err)
		}
	})
}

func seedTicketForList(
	repository *memoryTicketRepository,
	id int64,
	ticketNo, ticketType, status, submitter, principal string,
	accountID int64,
	createdAt time.Time,
) {
	repository.tickets[ticketNo] = model.IAMTicket{
		ID:            id,
		TicketNo:      stringPointer(ticketNo),
		TicketType:    stringPointer(ticketType),
		AccountID:     &accountID,
		PrincipalName: stringPointer(principal),
		Submitter:     stringPointer(submitter),
		Status:        stringPointer(status),
		CreatedAt:     createdAt,
		RequestPolicy: model.JSONB(`{}`),
	}
}

func TestListTicketsFiltersAndPaginates(t *testing.T) {
	repository := newMemoryTicketRepository()
	base := time.Now().Add(-time.Hour)
	seedTicketForList(repository, 1, "IAM-ALPHA", TicketTypeCreateRole, TicketStatusDraft, "alice", "alpha", 12, base)
	seedTicketForList(repository, 2, "IAM-BETA", TicketTypeRollback, TicketStatusClosed, "bob", "beta", 12, base.Add(time.Minute))
	seedTicketForList(repository, 3, "IAM-GAMMA", TicketTypeCreateRole, TicketStatusDraft, "alice", "gamma-reader", 13, base.Add(2*time.Minute))
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
	ctx := context.Background()

	for _, test := range []struct {
		name   string
		filter TicketListFilter
		want   int64
	}{
		{"status single", TicketListFilter{Statuses: []string{TicketStatusDraft}}, 2},
		{"status multi", TicketListFilter{Statuses: []string{TicketStatusDraft, TicketStatusClosed}}, 3},
		{"submitter", TicketListFilter{Submitter: "alice"}, 2},
		{"account", TicketListFilter{AccountID: int64Pointer(13)}, 1},
		{"ticket type", TicketListFilter{TicketType: TicketTypeRollback}, 1},
		{"keyword principal", TicketListFilter{Keyword: "gamma"}, 1},
		{"keyword ticket no", TicketListFilter{Keyword: "iam-beta"}, 1},
		{"no match", TicketListFilter{Keyword: "nothing-matches"}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			filter := test.filter
			filter.Limit = 20
			tickets, total, err := service.ListTickets(ctx, filter)
			if err != nil {
				t.Fatalf("ListTickets() error = %v", err)
			}
			if total != test.want {
				t.Errorf("total = %d, want %d", total, test.want)
			}
			if int64(len(tickets)) != test.want {
				t.Errorf("len(tickets) = %d, want %d", len(tickets), test.want)
			}
		})
	}

	t.Run("pages newest first", func(t *testing.T) {
		tickets, total, err := service.ListTickets(ctx, TicketListFilter{Limit: 1, Offset: 1})
		if err != nil {
			t.Fatalf("ListTickets() error = %v", err)
		}
		if total != 3 {
			t.Errorf("total = %d, want 3", total)
		}
		if len(tickets) != 1 || valueOrEmpty(tickets[0].TicketNo) != "IAM-BETA" {
			t.Errorf("page 1 = %v, want IAM-BETA (newest first)", tickets)
		}
	})
}

func TestListTicketsAppliesDefaultAndMaximumLimit(t *testing.T) {
	repository := newMemoryTicketRepository()
	base := time.Now().Add(-time.Hour)
	for id := int64(1); id <= 120; id++ {
		seedTicketForList(repository, id, fmt.Sprintf("IAM-%03d", id), TicketTypeCreateRole,
			TicketStatusDraft, "alice", fmt.Sprintf("principal-%03d", id), 12,
			base.Add(time.Duration(id)*time.Second))
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})

	tickets, total, err := service.ListTickets(context.Background(), TicketListFilter{})
	if err != nil {
		t.Fatalf("ListTickets() default error = %v", err)
	}
	if total != 120 || len(tickets) != 20 {
		t.Errorf("default total/len = %d/%d, want 120/20", total, len(tickets))
	}

	tickets, total, err = service.ListTickets(context.Background(), TicketListFilter{Limit: 500})
	if err != nil {
		t.Fatalf("ListTickets() capped error = %v", err)
	}
	if total != 120 || len(tickets) != 100 {
		t.Errorf("capped total/len = %d/%d, want 120/100", total, len(tickets))
	}
}

func TestRoleInlinePolicyBatchAdoptionPreviewsEveryPolicyAsImport(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.policyRecords["role/workspaces_DefaultRole/AmazonWorkSpacesServiceAccess"] =
		json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"workspaces:*","Resource":"*"}]}`)
	repository.policyRecords["role/workspaces_DefaultRole/AmazonWorkSpacesPoolServiceAccess"] =
		json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"workspaces:Describe*","Resource":"*"}]}`)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	snapshot, err := service.PreviewValidation(context.Background(), "requester", CreateIAMTicketRequest{
		TicketType:    TicketTypeAdoptRoleInlinePolicies,
		AccountID:     12,
		PrincipalName: "workspaces_DefaultRole",
		ApprovalMode:  ApprovalModeManual,
	})
	if err != nil {
		t.Fatalf("PreviewValidation(batch adoption) error = %v", err)
	}
	if strings.Count(snapshot.TerraformPreview, "import {") != 2 {
		t.Fatalf("batch preview contains %d import blocks, want 2:\n%s",
			strings.Count(snapshot.TerraformPreview, "import {"), snapshot.TerraformPreview)
	}
	for _, name := range []string{"AmazonWorkSpacesServiceAccess", "AmazonWorkSpacesPoolServiceAccess"} {
		if !strings.Contains(snapshot.TerraformPreview, "id = \"workspaces_DefaultRole:"+name+"\"") {
			t.Errorf("batch preview does not import %s:\n%s", name, snapshot.TerraformPreview)
		}
	}
}

func TestRoleInlinePolicyBatchAdoptionPublishesAfterManualApproval(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.policyRecords["role/workspaces_DefaultRole/PolicyA"] =
		json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"}]}`)
	repository.policyRecords["role/workspaces_DefaultRole/PolicyB"] =
		json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"}]}`)
	publisher := &memoryTicketPublisher{url: "https://github.example/pull/1"}
	service := newTestTicketService(t, repository, publisher)

	ticket, err := service.CreateTicket(context.Background(), "requester", CreateIAMTicketRequest{
		TicketType:    TicketTypeAdoptRoleInlinePolicies,
		AccountID:     12,
		PrincipalName: "workspaces_DefaultRole",
		ApprovalMode:  ApprovalModeManual,
		ApproverIDs:   []string{"alice"},
	})
	if err != nil {
		t.Fatalf("CreateTicket(batch adoption) error = %v", err)
	}
	if publisher.calls != 0 || ticket.Status == nil || *ticket.Status != TicketStatusApproving {
		t.Fatalf("ticket was published before manual approval: status=%v calls=%d", ticket.Status, publisher.calls)
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{
		Result: "APPROVE", Comment: "Reviewed the import-only bundle",
	}); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if publisher.calls != 1 || len(publisher.bundleFiles) != 2 {
		t.Fatalf("publisher calls/files = %d/%d, want 1/2", publisher.calls, len(publisher.bundleFiles))
	}
	if publisher.request.TicketType != TicketTypeAdoptRoleInlinePolicies {
		t.Errorf("published ticket type = %q", publisher.request.TicketType)
	}
}

func TestRoleInlinePolicyBatchAdoptionRejectsAlreadyAdoptedPolicies(t *testing.T) {
	policyDoc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"workspaces:*","Resource":"*"}]}`)

	t.Run("baseline owns the declaration file", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		repository.policyRecords["role/workspaces_DefaultRole/AmazonWorkSpacesServiceAccess"] = policyDoc
		// 全量基线（含 PUBLISHED 在途 PR）已发布 role-<role>-policy-<policy>.tf。
		repository.baselineOwnedResourceFiles[InlinePolicyFileKey("role", "workspaces_DefaultRole", "AmazonWorkSpacesServiceAccess")] = true
		service := newTestTicketService(t, repository, &memoryTicketPublisher{})

		_, err := service.CreateTicket(context.Background(), "requester", CreateIAMTicketRequest{
			TicketType:    TicketTypeAdoptRoleInlinePolicies,
			AccountID:     12,
			PrincipalName: "workspaces_DefaultRole",
			ApprovalMode:  ApprovalModeManual,
			ApproverIDs:   []string{"alice"},
		})
		if err == nil {
			t.Fatal("CreateTicket(baseline-owned inline policy) succeeded, want rejection")
		}
		if !strings.Contains(err.Error(), "已由全量基线纳管") {
			t.Fatalf("error = %v, want baseline-adopted rejection message", err)
		}
	})

	t.Run("declaration file already exists on main", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		repository.policyRecords["role/workspaces_DefaultRole/AmazonWorkSpacesServiceAccess"] = policyDoc
		publisher := &memoryTicketPublisher{
			fetchFile: "resource \"aws_iam_role_policy\" \"x\" { name = \"AmazonWorkSpacesServiceAccess\" }",
		}
		service := newTestTicketService(t, repository, publisher)

		_, err := service.CreateTicket(context.Background(), "requester", CreateIAMTicketRequest{
			TicketType:    TicketTypeAdoptRoleInlinePolicies,
			AccountID:     12,
			PrincipalName: "workspaces_DefaultRole",
			ApprovalMode:  ApprovalModeManual,
			ApproverIDs:   []string{"alice"},
		})
		if err == nil {
			t.Fatal("CreateTicket(inline policy declared on main) succeeded, want rejection")
		}
		if !strings.Contains(err.Error(), "已纳管") {
			t.Fatalf("error = %v, want adopted-on-main rejection message", err)
		}
	})
}

func TestPreviewValidation(t *testing.T) {
	t.Run("returns checks without persisting tickets", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		snapshot, err := service.PreviewValidation(context.Background(), "requester", validTicketRequest())
		if err != nil {
			t.Fatalf("PreviewValidation() error = %v", err)
		}

		if len(snapshot.RequestSHA256) != 32 {
			t.Errorf("request_sha256 length = %d, want 32", len(snapshot.RequestSHA256))
		}
		checks := string(snapshot.Checks)
		for _, code := range []string{"STATIC_RISK_SCAN", "PERMISSION_OVERLAP"} {
			if !strings.Contains(checks, code) {
				t.Errorf("checks missing %s: %s", code, checks)
			}
		}
		if len(repository.tickets) != 0 {
			t.Errorf("preview persisted %d tickets, want 0", len(repository.tickets))
		}
	})

	t.Run("matches submit-time validation hash", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		request := validTicketRequest()
		preview, err := service.PreviewValidation(context.Background(), "requester", request)
		if err != nil {
			t.Fatalf("PreviewValidation() error = %v", err)
		}
		created, err := service.CreateTicket(context.Background(), "requester", request)
		if err != nil {
			t.Fatalf("CreateTicket() error = %v", err)
		}
		stored := repository.validationChecks[valueOrEmpty(created.TicketNo)]
		if string(stored.RequestSHA256) != string(preview.RequestSHA256) {
			t.Errorf("preview hash %x != stored hash %x", preview.RequestSHA256, stored.RequestSHA256)
		}
	})

	t.Run("rejects principal mismatch", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		request := validTicketRequest()
		request.Role.Name = "someone-else"
		if _, err := service.PreviewValidation(context.Background(), "requester", request); err == nil {
			t.Fatal("PreviewValidation() should reject role.name mismatch")
		}
	})

	t.Run("requires submitter", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		if _, err := service.PreviewValidation(context.Background(), "  ", validTicketRequest()); err == nil {
			t.Fatal("PreviewValidation() should require a submitter")
		}
	})

	t.Run("unwraps string-form trust_policy to the object form", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		objectRequest := validTicketRequest()
		stringRequest := validTicketRequest()
		wrapped, err := json.Marshal(string(objectRequest.Role.TrustPolicy))
		if err != nil {
			t.Fatalf("marshal string-form trust_policy: %v", err)
		}
		stringRequest.Role.TrustPolicy = wrapped
		stringPreview, err := service.PreviewValidation(context.Background(), "requester", stringRequest)
		if err != nil {
			t.Fatalf("PreviewValidation() with string-form trust_policy error = %v", err)
		}
		objectPreview, err := service.PreviewValidation(context.Background(), "requester", objectRequest)
		if err != nil {
			t.Fatalf("PreviewValidation() with object-form trust_policy error = %v", err)
		}
		if string(stringPreview.RequestSHA256) != string(objectPreview.RequestSHA256) {
			t.Errorf("string-form hash %x != object-form hash %x; both encodings must converge to one request",
				stringPreview.RequestSHA256, objectPreview.RequestSHA256)
		}
	})

	t.Run("rejects string-form trust_policy with non-JSON contents", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		request := validTicketRequest()
		request.Role.TrustPolicy = json.RawMessage(`"not json at all"`)
		_, err := service.PreviewValidation(context.Background(), "requester", request)
		if err == nil {
			t.Fatal("PreviewValidation() should reject non-JSON trust_policy string contents")
		}
		if !strings.HasPrefix(err.Error(), "role.trust_policy") {
			t.Errorf("error %q should carry the role.trust_policy prefix for 400 mapping", err.Error())
		}
	})

	t.Run("maps unregistered account to account_id validation error", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://gitlab.example/mr/1"})
		request := validTicketRequest()
		request.AccountID = 999 // fake repo returns sql.ErrNoRows for this ID
		_, err := service.PreviewValidation(context.Background(), "requester", request)
		if err == nil {
			t.Fatal("PreviewValidation() should reject an unregistered AWS account")
		}
		if !strings.HasPrefix(err.Error(), "account_id 999") {
			t.Errorf("error %q should carry the account_id prefix for 400 mapping", err.Error())
		}
		if !strings.Contains(err.Error(), "not registered on this platform") {
			t.Errorf("error %q should explain the account is unregistered", err.Error())
		}
	})
}

func TestNormalizeTrustPolicyJSON(t *testing.T) {
	object := json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)

	t.Run("empty is a no-op", func(t *testing.T) {
		request := CreateIAMTicketRequest{}
		if err := normalizeTrustPolicyJSON(&request); err != nil {
			t.Fatalf("normalizeTrustPolicyJSON() error = %v", err)
		}
		if len(request.Role.TrustPolicy) != 0 {
			t.Errorf("TrustPolicy = %s, want empty", request.Role.TrustPolicy)
		}
	})

	t.Run("object passes through untouched", func(t *testing.T) {
		request := CreateIAMTicketRequest{Role: adapterRole("x")}
		request.Role.TrustPolicy = object
		if err := normalizeTrustPolicyJSON(&request); err != nil {
			t.Fatalf("normalizeTrustPolicyJSON() error = %v", err)
		}
		if string(request.Role.TrustPolicy) != string(object) {
			t.Errorf("TrustPolicy = %s, want unchanged object", request.Role.TrustPolicy)
		}
	})

	t.Run("string form is unwrapped", func(t *testing.T) {
		request := CreateIAMTicketRequest{Role: adapterRole("x")}
		wrapped, err := json.Marshal(string(object))
		if err != nil {
			t.Fatalf("marshal string-form trust_policy: %v", err)
		}
		request.Role.TrustPolicy = wrapped
		if err := normalizeTrustPolicyJSON(&request); err != nil {
			t.Fatalf("normalizeTrustPolicyJSON() error = %v", err)
		}
		if string(request.Role.TrustPolicy) != string(object) {
			t.Errorf("TrustPolicy = %s, want unwrapped object %s", request.Role.TrustPolicy, object)
		}
	})

	t.Run("non-JSON inner string fails with prefix", func(t *testing.T) {
		request := CreateIAMTicketRequest{Role: adapterRole("x")}
		request.Role.TrustPolicy = json.RawMessage(`"{broken"`)
		err := normalizeTrustPolicyJSON(&request)
		if err == nil {
			t.Fatal("normalizeTrustPolicyJSON() should fail for non-JSON inner contents")
		}
		if !strings.HasPrefix(err.Error(), "role.trust_policy") {
			t.Errorf("error %q should carry the role.trust_policy prefix", err.Error())
		}
	})

	t.Run("invalid outer JSON fails with prefix", func(t *testing.T) {
		request := CreateIAMTicketRequest{Role: adapterRole("x")}
		request.Role.TrustPolicy = json.RawMessage(`{broken`)
		err := normalizeTrustPolicyJSON(&request)
		if err == nil {
			t.Fatal("normalizeTrustPolicyJSON() should fail for invalid outer JSON")
		}
		if !strings.HasPrefix(err.Error(), "role.trust_policy") {
			t.Errorf("error %q should carry the role.trust_policy prefix", err.Error())
		}
	})
}

// mockPollEnqueuer records enqueued Git status poll tasks.
type mockPollEnqueuer struct {
	payloads []GitStatusPollTask
	err      error
}

func (m *mockPollEnqueuer) EnqueueGitStatusPoll(_ context.Context, payload GitStatusPollTask) error {
	m.payloads = append(m.payloads, payload)
	return m.err
}

func TestTicketServiceRearmPolling(t *testing.T) {
	prURL := "https://github.com/example-org/iam-baseline/pull/4"
	provider := "GITHUB"
	project := "example-org/iam-baseline"
	remoteNumber := "4"

	newService := func(repo *memoryTicketRepository, enqueuer GitStatusPollEnqueuer) *TicketService {
		publisher := &memoryTicketPublisher{url: "https://example.invalid/mr/1"}
		svc, err := NewTicketService(repo, publisher, slog.Default(), WithGitStatusPollEnqueuer(enqueuer))
		if err != nil {
			t.Fatalf("NewTicketService: %v", err)
		}
		return svc
	}

	t.Run("resets schedule and enqueues first poll", func(t *testing.T) {
		repo := newMemoryTicketRepository()
		repo.tickets["IAM-1"] = model.IAMTicket{
			TicketNo:            stringPointer("IAM-1"),
			Status:              stringPointer(TicketStatusApproved),
			GitPRURL:            &prURL,
			GitProvider:         &provider,
			GitRepository:       &project,
			RemoteRequestNumber: &remoteNumber,
			PollAttemptCount:    MaxPollAttempts, // budget exhausted
		}
		enqueuer := &mockPollEnqueuer{}

		if err := newService(repo, enqueuer).RearmPolling(context.Background(), "IAM-1"); err != nil {
			t.Fatalf("RearmPolling: %v", err)
		}

		if got := repo.tickets["IAM-1"].PollAttemptCount; got != 0 {
			t.Errorf("PollAttemptCount = %d, want 0", got)
		}
		if len(enqueuer.payloads) != 1 {
			t.Fatalf("enqueued %d payloads, want 1", len(enqueuer.payloads))
		}
		payload := enqueuer.payloads[0]
		if payload.TicketNo != "IAM-1" || payload.Attempt != 1 ||
			payload.RemoteRequestNumber != "4" || payload.Project != "example-org/iam-baseline" {
			t.Errorf("unexpected payload: %+v", payload)
		}
	})

	t.Run("rejects closed tickets", func(t *testing.T) {
		repo := newMemoryTicketRepository()
		repo.tickets["IAM-2"] = model.IAMTicket{
			TicketNo: stringPointer("IAM-2"),
			Status:   stringPointer(TicketStatusClosed),
		}
		enqueuer := &mockPollEnqueuer{}

		err := newService(repo, enqueuer).RearmPolling(context.Background(), "IAM-2")
		if !errors.Is(err, ErrInvalidTicketState) {
			t.Errorf("error = %v, want ErrInvalidTicketState", err)
		}
		if len(enqueuer.payloads) != 0 {
			t.Errorf("closed ticket must not enqueue polls")
		}
	})

	t.Run("rejects tickets without remote request", func(t *testing.T) {
		repo := newMemoryTicketRepository()
		repo.tickets["IAM-3"] = model.IAMTicket{
			TicketNo: stringPointer("IAM-3"),
			Status:   stringPointer(TicketStatusApproved),
			GitPRURL: &prURL,
		}
		enqueuer := &mockPollEnqueuer{}

		err := newService(repo, enqueuer).RearmPolling(context.Background(), "IAM-3")
		if err == nil {
			t.Fatal("expected error for missing remote request number")
		}
		if len(enqueuer.payloads) != 0 {
			t.Errorf("missing remote request must not enqueue polls")
		}
	})
}

// seedClosedCreateRoleTicket seeds a CREATE_ROLE ticket that really reached
// Terraform (CLOSED + APPLIED), i.e. a role UPDATE_ROLE is allowed to modify.
func seedClosedCreateRoleTicket(repository *memoryTicketRepository, accountID int64, principalName string) string {
	ticketNo := "IAM-CREATE-ROLE-0001"
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:      stringPointer(ticketNo),
		TicketType:    stringPointer(TicketTypeCreateRole),
		AccountID:     &accountID,
		PrincipalName: stringPointer(principalName),
		Status:        stringPointer(TicketStatusClosed),
		ClosureReason: stringPointer("APPLIED"),
	}
	return ticketNo
}

// seedAbandonedCreateRoleTicket seeds a CREATE_ROLE ticket that was closed
// without ever publishing Terraform (no PR, no state) — the shape left behind
// by API probes.
func seedAbandonedCreateRoleTicket(repository *memoryTicketRepository, accountID int64, principalName, ticketNo string, createdAt time.Time) string {
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:      stringPointer(ticketNo),
		TicketType:    stringPointer(TicketTypeCreateRole),
		AccountID:     &accountID,
		PrincipalName: stringPointer(principalName),
		Status:        stringPointer(TicketStatusClosed),
		ClosureReason: stringPointer("ABANDONED"),
		CreatedAt:     createdAt,
	}
	return ticketNo
}

func TestCreateUpdateRoleTicketStoresSourceAndPublishesTerraform(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	description := "billing report reader"
	repository.roleDescription = &description
	sourceNo := seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/12", fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	// 提交一项实际变更（描述）：纯 no-op 工单会被变更检测拒绝。
	newDescription := "billing report reader v2"
	request.UpdateRole.Description = &newDescription
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE) error = %v", err)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.SourceTicketNo != sourceNo {
		t.Fatalf("stored source ticket = %q, want %q", stored.SourceTicketNo, sourceNo)
	}
	if ticket.ApprovalMode != ApprovalModeManual {
		t.Fatalf("approval mode = %s, want MANUAL", ticket.ApprovalMode)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	// 信任与基底文件相同 → 不重写该属性；产物 = 基底文件（块级 patch 的
	// 最小差异语义：没提交的字段一个字节都不动）。
	if ticket.TerraformCode == nil || !strings.Contains(*ticket.TerraformCode, `resource "aws_iam_role" "managed_role"`) {
		t.Fatalf("published Terraform missing role resource: %v", ticket.TerraformCode)
	}
	if ticket.TerraformCode == nil || !strings.Contains(*ticket.TerraformCode, `resource "aws_iam_role_policy" "managed_policy"`) {
		t.Fatalf("published Terraform must keep the inline policy declaration: %s", *ticket.TerraformCode)
	}
	if ticket.GitPRURL == nil || *ticket.GitPRURL != publisher.url {
		t.Fatalf("ticket not published: %#v", ticket)
	}
	// Snapshot captured at publication: trust policy + role attributes from
	// inventory（内嵌策略不再采集——已拆出 UPDATE_ROLE）。
	published, exists := repository.tickets[*ticket.TicketNo]
	if !exists || len(published.RoleSnapshot) == 0 {
		t.Fatalf("role snapshot was not captured at publication: %+v", published.RoleSnapshot)
	}
	var snapshot struct {
		TrustPolicy map[string]interface{} `json:"trust_policy"`
		Description *string                `json:"description"`
	}
	if err := json.Unmarshal(published.RoleSnapshot, &snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snapshot.TrustPolicy == nil {
		t.Fatal("snapshot missing trust policy")
	}
	if snapshot.Description == nil || *snapshot.Description != "billing report reader" {
		t.Fatalf("snapshot missing description: %+v", snapshot.Description)
	}
}

func TestCreateUpdateRoleTrustPolicyChangeForcesManualApproval(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := updateRoleTicketRequest()
	// 与库存中的信任策略不同 → 触发强制人工审批
	request.UpdateRole.TrustPolicy = &map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{"Effect": "Allow", "Principal": map[string]interface{}{"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"},
		},
	}
	request.ApprovalMode = ApprovalModeAuto
	request.ApproverIDs = nil
	_, err := service.CreateTicket(context.Background(), "requester", request)
	var trustErr *TrustPolicyChangeError
	if !errors.As(err, &trustErr) {
		t.Fatalf("expected TrustPolicyChangeError for AUTO + changed trust policy, got %v", err)
	}
	if len(repository.tickets) != 0 {
		// seed 的 CREATE_ROLE 工单除外，不应有新工单落库
		for _, ticket := range repository.tickets {
			if ticket.TicketType != nil && *ticket.TicketType == TicketTypeUpdateRole {
				t.Fatal("ticket must not be created when trust-policy change bypasses manual approval")
			}
		}
	}
}

func TestCreateUpdateRoleTrustPolicyUnchangedAllowsAutoApproval(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	// 语义相同但键序不同的信任策略 → 不算变更
	request.UpdateRole.TrustPolicy = &map[string]interface{}{
		"Statement": []interface{}{
			map[string]interface{}{"Action": "sts:AssumeRole", "Principal": map[string]interface{}{"Service": "ec2.amazonaws.com"}, "Effect": "Allow"},
		},
		"Version": "2012-10-17",
	}
	request.ApprovalMode = ApprovalModeAuto
	request.ApproverIDs = nil
	// 只改描述：信任语义相同、键序不同 → 不强制 MANUAL，且工单仍有实际变更
	//（变更检测会拒绝纯 no-op）。
	description := "auto-approved description change"
	request.UpdateRole.Description = &description
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("unchanged trust policy must allow AUTO approval: %v", err)
	}
	if ticket.ApprovalMode != ApprovalModeAuto {
		t.Fatalf("approval mode = %s, want AUTO", ticket.ApprovalMode)
	}
}

// 变更检测（对齐第 12 项）：提交的属性与现网完全一致 → 400，不产生空 diff
// 的工单。留空字段不参与比较。
func TestCreateUpdateRoleRejectsNoOp(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	same := "unchanged description"
	repository.roleDescription = &same
	repository.roleMaxSessionDuration = func() *int64 {
		value := int64(3600)
		return &value
	}()
	repository.roleTags = map[string]string{"team": "otel"}
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	duration := 3600
	request.UpdateRole.Description = &same
	request.UpdateRole.MaxSessionDuration = &duration
	request.UpdateRole.Tags = map[string]string{"team": "otel"}
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "identical to the current live role") {
		t.Fatalf("expected no-op rejection, got %v", err)
	}

	// 空 update_role 同样是 no-op。
	request.UpdateRole = &adapter.UpdateRoleConfig{}
	if _, err := service.PreviewValidation(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "identical to the current live role") {
		t.Fatalf("expected no-op rejection for empty update_role, got %v", err)
	}
}

func TestPreviewValidationUpdateRoleAllowsNoOpForWildRoleAdoption(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	publisher := &memoryTicketPublisher{fetchErr: ErrTerraformFileNotFound}
	service := newTestTicketService(t, repository, publisher)

	snapshot, err := service.PreviewValidation(context.Background(), "requester", updateRoleTicketRequest())
	if err != nil {
		t.Fatalf("PreviewValidation(unchanged wild role adoption) error = %v", err)
	}
	if !strings.Contains(snapshot.TerraformPreview, `import {`) {
		t.Fatalf("wild role adoption preview must include an import block:\n%s", snapshot.TerraformPreview)
	}
	if !strings.Contains(snapshot.TerraformPreview, `id = "billing-reader"`) {
		t.Fatalf("wild role adoption preview must import the existing role by name:\n%s", snapshot.TerraformPreview)
	}
}

// 基线纳管角色（无 CREATE 源工单、无已应用 UPDATE_ROLE，但 main 上已有角色
// 声明文件）：无属性变更的提交是纯 no-op（原地 patch，无 import 块），
// 必须被拒绝，而不是带着空的「Role attributes changed:」提示通过校验。
func TestCreateUpdateRoleRejectsNoOpForAdoptedRoleOnMain(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest() // 只重申信任策略 → 无任何变更
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "identical to the current live role") {
		t.Fatalf("expected no-op rejection for adopted role, got %v", err)
	}
	if len(repository.tickets) != 0 {
		t.Fatal("no-op UPDATE_ROLE requests must not persist tickets")
	}
}

// 野生角色首次纳管（main 上无角色文件）时，无属性变更的工单仍然有效——
// import 块本身就是变更；校验 checks 必须明确说明「首次纳管」，不能出现
// 空的「Role attributes changed:」。
func TestPreviewValidationUpdateRoleAdoptionExplainsImportOnlyChange(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	publisher := &memoryTicketPublisher{fetchErr: ErrTerraformFileNotFound}
	service := newTestTicketService(t, repository, publisher)

	snapshot, err := service.PreviewValidation(context.Background(), "requester", updateRoleTicketRequest())
	if err != nil {
		t.Fatalf("PreviewValidation(unchanged wild role adoption) error = %v", err)
	}
	var checks []map[string]interface{}
	if err := json.Unmarshal(snapshot.Checks, &checks); err != nil {
		t.Fatalf("decode checks: %v", err)
	}
	var summary string
	for _, check := range checks {
		if check["code"] == "CHANGE_DETECTION" {
			summary, _ = check["description"].(string)
		}
	}
	if strings.Contains(summary, "Role attributes changed:") && strings.HasSuffix(strings.TrimSpace(summary), "changed:") {
		t.Fatalf("CHANGE_DETECTION must not show an empty change list: %s", summary)
	}
	if !strings.Contains(summary, "first-time adoption") {
		t.Fatalf("CHANGE_DETECTION must explain the import-only adoption, got: %s", summary)
	}
}

// 有实际差异时，校验 checks 带 CHANGE_DETECTION 摘要（审批人不必去 git 比对）。
func TestPreviewValidationUpdateRoleReportsChangeDetection(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	oldDescription := "old description"
	repository.roleDescription = &oldDescription
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	description := "new description"
	request.UpdateRole.Description = &description

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(UPDATE_ROLE) error = %v", err)
	}
	var checks []map[string]interface{}
	if err := json.Unmarshal(snapshot.Checks, &checks); err != nil {
		t.Fatalf("decode checks: %v", err)
	}
	var summary string
	for _, check := range checks {
		if check["code"] == "CHANGE_DETECTION" {
			summary, _ = check["description"].(string)
		}
	}
	if !strings.Contains(summary, "description") {
		t.Fatalf("CHANGE_DETECTION must list the changed attribute, checks = %+v", checks)
	}
	if strings.Contains(summary, "trust_policy") {
		t.Fatalf("unchanged trust policy must not be reported as changed: %s", summary)
	}
}

func TestCreateUpdateRoleRequiresExistingInventoryRole(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = false
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := updateRoleTicketRequest()
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "not found in account inventory") {
		t.Fatalf("expected inventory-missing error, got %v", err)
	}
	if len(repository.tickets) != 0 {
		t.Fatal("invalid UPDATE_ROLE requests must not persist tickets")
	}
}

// ③ 野生角色（无 CREATE 源工单）走首次 import 纳管：生成独立
// role-<name>.tf，只声明角色块（内嵌/挂载零接触），信任未提交时从清单
// 补全（只声明、不变更）。
func TestCreateUpdateRoleAdoptsWildRoleWithImport(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/42"}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	request.UpdateRole.TrustPolicy = nil // 只改描述：信任从清单补全
	description := "adopted via import"
	request.UpdateRole.Description = &description

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE on wild role) error = %v", err)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.SourceTicketNo != "" {
		t.Fatalf("wild role must have no source ticket, got %q", stored.SourceTicketNo)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	// 野生路径现在会先查 main 上是否已有 role 文件（存在 → 原地 patch 保留
	// 地址；不存在 → 新文件 + import）：预览与发布各探测一次。
	if publisher.fetchCalls != 2 {
		t.Fatalf("wild path must probe main for an existing role file (preview + publish), fetchCalls = %d", publisher.fetchCalls)
	}
	code := *ticket.TerraformCode
	for _, want := range []string{
		`import {`,
		`id = "billing-reader"`,
		`to = aws_iam_role.role_billing-reader`,
		`resource "aws_iam_role" "role_billing-reader"`,
		`name               = "billing-reader"`,
		`"Service" = "ec2.amazonaws.com"`,
		`description        = "adopted via import"`,
	} {
		if !strings.Contains(code, want) {
			t.Errorf("wild role file missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, "aws_iam_role_policy") {
		t.Errorf("wild role file must not declare inline policies:\n%s", code)
	}
}

// 野生角色纳管必须把库存里的 ForceNew 属性（path / permissions_boundary）
// 原样写进声明：漏掉它们，plan 会读成「删除属性」，AWS provider 直接重建角色
// （新 ARN -> 所有挂载、实例 profile 断裂）。这是基线生成前的最小闭环。
func TestCreateUpdateRoleAdoptionCarriesForceNewAttributesFromInventory(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	repository.rolePath = "/app/"
	repository.roleBoundary = "arn:aws:iam::123456789012:policy/app-boundary"
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/46"}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	request.UpdateRole.TrustPolicy = nil
	description := "adopted with identity"
	request.UpdateRole.Description = &description

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE on wild role) error = %v", err)
	}
	for _, approver := range []string{"alice", "bob"} {
		ticket, err = service.Decide(context.Background(), *ticket.TicketNo, approver, TicketDecision{Result: "APPROVE", Comment: "LGTM"})
		if err != nil {
			t.Fatalf("approval by %s: %v", approver, err)
		}
	}
	code := *ticket.TerraformCode
	for _, want := range []string{
		`path                 = "/app/"`,
		`permissions_boundary = "arn:aws:iam::123456789012:policy/app-boundary"`,
		`description          = "adopted with identity"`,
	} {
		if !strings.Contains(code, want) {
			t.Errorf("adopted role file missing %q:\n%s", want, code)
		}
	}
}

// GetRoleAttributes 的 SQL 投影与 Scan 目标必须一一对应：历史上漏扫一列
// （managed_by）就让详情接口 500 过一次。这里同时锁住新增的两列 ForceNew
// 属性，避免「查询里有、Scan 里没有」再次发生。
func TestSQLTicketRepositoryRoleAttributesIncludesForceNewColumns(t *testing.T) {
	state := &recordingSQLDriver{}
	db := sql.OpenDB(recordingSQLConnector{state: state})
	defer db.Close()
	db.SetMaxOpenConns(1)
	repository, err := NewSQLTicketRepository(db)
	if err != nil {
		t.Fatalf("NewSQLTicketRepository() error = %v", err)
	}

	attributes, err := repository.GetRoleAttributes(context.Background(), 7, "billing-reader")
	if err != nil {
		t.Fatalf("GetRoleAttributes() error = %v", err)
	}
	if attributes == nil {
		t.Fatal("GetRoleAttributes() returned no attributes")
	}
	if attributes.Path != "/app/" {
		t.Errorf("role path = %q, want /app/", attributes.Path)
	}
	if attributes.PermissionsBoundaryARN != "arn:aws:iam::123456789012:policy/app-boundary" {
		t.Errorf("permissions boundary = %q", attributes.PermissionsBoundaryARN)
	}
	// 既有字段不能被新列挤掉（列顺序即 Scan 顺序）。
	if attributes.Description == nil || *attributes.Description != "application role" ||
		attributes.MaxSessionDuration == nil || *attributes.MaxSessionDuration != 7200 ||
		attributes.Tags["team"] != "otel" {
		t.Errorf("existing role attributes regressed: %#v", attributes)
	}
}

// Regression: PreviewValidation builds its own stub ticket and never sets
// request.AWSAccountID (publication resolves it first). The wild-role file
// probe must resolve it too, otherwise the preview fails with "valid AWS
// account ID is required to fetch Terraform file" (live, 2026-10-20) — and a
// fallback that regenerates on fetch failure would silently change the
// resource address.
func TestPreviewValidationUpdateRoleResolvesAWSAccountIDForWildProbe(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	description := "patched in place"
	request.UpdateRole.Description = &description

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(UPDATE_ROLE wild role) error = %v", err)
	}
	if publisher.fetchCalls != 1 {
		t.Fatalf("preview must probe main once, fetchCalls = %d", publisher.fetchCalls)
	}
	if publisher.fetchRequest.AWSAccountID != "123456789012" {
		t.Errorf("probe must carry the resolved AWS account ID, got %q", publisher.fetchRequest.AWSAccountID)
	}
	// 既有文件的地址必须原样保留（不能被重新生成为 role_<name>）。
	if !strings.Contains(snapshot.TerraformPreview, `resource "aws_iam_role" "managed_role"`) {
		t.Errorf("preview must patch the existing file, got:\n%s", snapshot.TerraformPreview)
	}
	if !strings.Contains(snapshot.TerraformPreview, `"patched in place"`) {
		t.Errorf("preview must apply the description patch, got:\n%s", snapshot.TerraformPreview)
	}
}

// Regression: API probes left CREATE_ROLE tickets closed without ever
// publishing Terraform. They must not be mistaken for the role's source file
// (③：按野生角色纳管 —— 独立文件 + import，而不是指向不存在的源文件）。
func TestCreateUpdateRoleAdoptsAbandonedCreateRoleAsWild(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	seedAbandonedCreateRoleTicket(repository, 1, "billing-reader",
		"IAM-PROBEUPDATEROLE01", time.Date(2026, 10, 13, 11, 24, 58, 0, time.UTC))
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/43"}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE with abandoned CREATE only) error = %v", err)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.SourceTicketNo != "" {
		t.Fatalf("abandoned CREATE must not become the source; source = %q", stored.SourceTicketNo)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if !strings.Contains(*ticket.TerraformCode, `import {`) {
		t.Fatalf("abandoned-create role must be adopted with an import block:\n%s", *ticket.TerraformCode)
	}
}

// When an ABANDONED CREATE_ROLE ticket for a role the platform really did
// create is *newer* than the applied one (exactly the e2e-role situation),
// newest-created must not win: only tickets that reached Terraform qualify.
func TestCreateUpdateRolePrefersAppliedTicketOverNewerAbandonedOne(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	appliedNo := seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	applied := repository.tickets[appliedNo]
	applied.CreatedAt = time.Date(2026, 10, 9, 14, 32, 43, 0, time.UTC)
	repository.tickets[appliedNo] = applied
	seedAbandonedCreateRoleTicket(repository, 1, "billing-reader",
		"IAM-F6476A6ECD5BFC41", time.Date(2026, 10, 9, 16, 30, 16, 0, time.UTC))
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	ticket, err := service.CreateTicket(context.Background(), "requester", updateRoleTicketRequest())
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE) error = %v", err)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.SourceTicketNo != appliedNo {
		t.Fatalf("source ticket = %q, want applied ticket %q", stored.SourceTicketNo, appliedNo)
	}
}

func TestCreateUpdateRoleEnforcesConcurrencyLock(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	if _, err := service.CreateTicket(context.Background(), "requester", request); err != nil {
		t.Fatalf("first UPDATE_ROLE ticket: %v", err)
	}
	request = updateRoleTicketRequest()
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "change ticket in progress") {
		t.Fatalf("expected concurrency-lock error for second UPDATE_ROLE ticket, got %v", err)
	}
}

func TestUpdateRoleConfigFromSnapshotRestoresPreUpdateState(t *testing.T) {
	snapshot := json.RawMessage(`{"trust_policy":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"rds.amazonaws.com"},"Action":"sts:AssumeRole"}]},"description":"old description","max_session_duration":3600,"tags":{"team":"old"}}`)
	config, err := UpdateRoleConfigFromSnapshot(snapshot)
	if err != nil {
		t.Fatalf("UpdateRoleConfigFromSnapshot() error = %v", err)
	}
	if config.TrustPolicy == nil || (*config.TrustPolicy)["Version"] != "2012-10-17" {
		t.Fatalf("restored trust policy = %+v", config.TrustPolicy)
	}
	if config.Description == nil || *config.Description != "old description" {
		t.Fatalf("restored description = %+v", config.Description)
	}
	if config.MaxSessionDuration == nil || *config.MaxSessionDuration != 3600 {
		t.Fatalf("restored max session duration = %+v", config.MaxSessionDuration)
	}
	if config.Tags["team"] != "old" {
		t.Fatalf("restored tags = %+v", config.Tags)
	}
	// 旧快照（② 之前）只有 trust_policy：未采集的属性保持 nil，
	// 回滚时不动（留语义），不报错。
	legacy, err := UpdateRoleConfigFromSnapshot(json.RawMessage(`{"trust_policy":{"Version":"2012-10-17","Statement":[]}}`))
	if err != nil {
		t.Fatalf("legacy snapshot decode error = %v", err)
	}
	if legacy.Description != nil || legacy.MaxSessionDuration != nil || legacy.Tags != nil {
		t.Fatalf("legacy snapshot must leave attributes untouched: %+v", legacy)
	}
}

// ① UPDATE_ROLE 收窄后，内嵌策略/托管挂载字段必须明确 400（不静默忽略）。
func TestCreateUpdateRoleRejectsRemovedFields(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := updateRoleTicketRequest()
	request.UpdateRole.InlinePolicies = map[string]interface{}{"p": map[string]interface{}{}}
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "inline_policies is no longer supported") {
		t.Fatalf("expected inline_policies rejection, got %v", err)
	}
	request = updateRoleTicketRequest()
	request.UpdatePolicy = nil
	request.UpdateRole.ManagedPolicyARNs = []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"}
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "managed_policy_arns is no longer supported") {
		t.Fatalf("expected managed_policy_arns rejection, got %v", err)
	}
}

// ② 块级 patch：只改提交的属性——信任未变（键序不同）不重写，内嵌策略块
// 一个字节不动，预览即最小 diff。
func TestUpdateRolePreviewPatchesOnlySubmittedAttributes(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	publisher := &memoryTicketPublisher{fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleTicketRequest()
	// 与库存语义相同、键序不同的信任 + 只改描述
	reordered := map[string]interface{}{
		"Statement": []interface{}{
			map[string]interface{}{"Action": "sts:AssumeRole", "Principal": map[string]interface{}{"Service": "ec2.amazonaws.com"}, "Effect": "Allow"},
		},
		"Version": "2012-10-17",
	}
	request.UpdateRole.TrustPolicy = &reordered
	description := "updated description"
	request.UpdateRole.Description = &description

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(UPDATE_ROLE) error = %v", err)
	}
	preview := snapshot.TerraformPreview
	if !strings.Contains(preview, `description = "updated description"`) {
		t.Fatalf("preview missing description change:\n%s", preview)
	}
	// 信任未变 → 原格式保留（Version 在前、带引号 key）
	if !strings.Contains(preview, "\t\t\"Version\" = \"2012-10-17\"\n\t\t\"Statement\" = [") {
		t.Fatalf("unchanged trust must keep its original formatting:\n%s", preview)
	}
	// 内嵌策略块原样保留
	if !strings.Contains(preview, `resource "aws_iam_role_policy" "managed_policy"`) ||
		!strings.Contains(preview, `"Action" = ["iam:GetRole"]`) {
		t.Fatalf("inline policy block must be untouched:\n%s", preview)
	}
}

// ② 回滚 UPDATE_ROLE：快照里的属性（信任/描述）逐一还原，文件里其余部分
// （内嵌策略）不动。
func TestUpdateRoleRollbackRestoresAttributes(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	oldDescription := "old description"
	repository.roleDescription = &oldDescription
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/99", fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	// 正向更新：信任 ec2 → rds，描述 old → new
	request := updateRoleTicketRequest()
	newTrust := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{"Effect": "Allow", "Principal": map[string]interface{}{"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"},
		},
	}
	request.UpdateRole.TrustPolicy = &newTrust
	newDescription := "new description"
	request.UpdateRole.Description = &newDescription
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE) error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if !strings.Contains(*ticket.TerraformCode, `"Service" = "rds.amazonaws.com"`) ||
		!strings.Contains(*ticket.TerraformCode, `description = "new description"`) {
		t.Fatalf("published update missing new values:\n%s", *ticket.TerraformCode)
	}
	// 模拟 apply 完成：目标工单关闭（回滚前置要求 CLOSED(APPLIED)）
	if _, err := service.CloseTicket(context.Background(), *ticket.TicketNo, "system", ClosureReasonApplied, "", false); err != nil {
		t.Fatalf("close update ticket: %v", err)
	}

	// 模拟合并：main 上的文件变成更新后的产物
	publisher.fetchFile = *ticket.TerraformCode

	// 回滚：快照恢复信任 ec2 + 描述 old，内嵌策略块保留
	rollback := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		AccountID:      1,
		PrincipalName:  "billing-reader",
		TargetTicketNo: *ticket.TicketNo,
		ApprovalMode:   ApprovalModeManual,
		ApproverIDs:    []string{"alice", "bob"},
	}
	rollbackTicket, err := service.CreateTicket(context.Background(), "requester", rollback)
	if err != nil {
		t.Fatalf("CreateTicket(ROLLBACK) error = %v", err)
	}
	rollbackTicket, err = service.Decide(context.Background(), *rollbackTicket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("rollback first approval: %v", err)
	}
	rollbackTicket, err = service.Decide(context.Background(), *rollbackTicket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("rollback final approval: %v", err)
	}
	restored := *rollbackTicket.TerraformCode
	if !strings.Contains(restored, `"Service" = "ec2.amazonaws.com"`) {
		t.Fatalf("rollback must restore the trust policy:\n%s", restored)
	}
	if !strings.Contains(restored, `description = "old description"`) {
		t.Fatalf("rollback must restore the description:\n%s", restored)
	}
	if strings.Contains(restored, "rds.amazonaws.com") || strings.Contains(restored, "new description") {
		t.Fatalf("rollback must not keep updated values:\n%s", restored)
	}
	if !strings.Contains(restored, `resource "aws_iam_role_policy" "managed_policy"`) {
		t.Fatalf("rollback must keep the inline policy declaration:\n%s", restored)
	}
}

// 互踩回归（B-path）：UPDATE_ROLE 改过信任后，内嵌策略更新只 patch 自己的
// policy 属性——文件里的信任必须保持 UPDATE_ROLE 后的新值，不被 CREATE
// 快照回滚。
func TestUpdateRoleThenInlineUpdateKeepsTrust(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	seedClosedCreateRoleTicket(repository, 1, "billing-reader")
	// 内嵌策略更新校验需要库存里存在该内嵌策略
	repository.policyRecords["role/billing-reader/billing-reader-policy"] = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GetRole"],"Resource":["*"]}]}`)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/98", fetchFile: roleTerraformFile}
	service := newTestTicketService(t, repository, publisher)

	// 1. UPDATE_ROLE：信任 ec2 → rds
	update := updateRoleTicketRequest()
	newTrust := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{"Effect": "Allow", "Principal": map[string]interface{}{"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"},
		},
	}
	update.UpdateRole.TrustPolicy = &newTrust
	updateTicket, err := service.CreateTicket(context.Background(), "requester", update)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_ROLE) error = %v", err)
	}
	updateTicket, err = service.Decide(context.Background(), *updateTicket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("update first approval: %v", err)
	}
	updateTicket, err = service.Decide(context.Background(), *updateTicket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("update final approval: %v", err)
	}
	if !strings.Contains(*updateTicket.TerraformCode, `"Service" = "rds.amazonaws.com"`) {
		t.Fatalf("published update missing new trust:\n%s", *updateTicket.TerraformCode)
	}
	// 2. 模拟合并
	publisher.fetchFile = *updateTicket.TerraformCode

	// 3. 内嵌策略更新（同一角色）→ 只 patch policy 属性
	inline := CreateIAMTicketRequest{
		TicketType:    TicketTypeUpdateGroupInlinePolicy,
		AccountID:     1,
		PrincipalName: "billing-reader",
		PrincipalType: "Role",
		ApprovalMode:  ApprovalModeManual,
		ApproverIDs:   []string{"alice", "bob"},
		UpdatePolicy: &adapter.UpdatePolicyConfig{
			RoleName:         "billing-reader",
			InlinePolicyName: "billing-reader-policy",
			Document:         json.RawMessage(`{"name":"p","statements":[{"effect":"Allow","actions":["s3:ListBucket"],"resources":["*"]}]}`),
		},
	}
	inlineTicket, err := service.CreateTicket(context.Background(), "requester", inline)
	if err != nil {
		t.Fatalf("CreateTicket(inline update) error = %v", err)
	}
	inlineTicket, err = service.Decide(context.Background(), *inlineTicket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("inline first approval: %v", err)
	}
	inlineTicket, err = service.Decide(context.Background(), *inlineTicket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("inline final approval: %v", err)
	}
	published := *inlineTicket.TerraformCode
	if !strings.Contains(published, `"Service" = "rds.amazonaws.com"`) {
		t.Fatalf("inline update must not roll back the trust policy:\n%s", published)
	}
	if !strings.Contains(published, `"s3:ListBucket"`) {
		t.Fatalf("inline update missing new document:\n%s", published)
	}
	if strings.Contains(published, `"Action" = ["iam:GetRole"]`) {
		t.Fatalf("old inline document must be replaced:\n%s", published)
	}
}

// ③ 二次更新：角色已被先前 apply 的 UPDATE_ROLE 工单纳管（import 已用过），
// 新文件不得再带 import block。
func TestUpdateRoleWildSecondUpdateSkipsImport(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/44"}
	service := newTestTicketService(t, repository, publisher)

	first, err := service.CreateTicket(context.Background(), "requester", updateRoleTicketRequest())
	if err != nil {
		t.Fatalf("first wild UPDATE_ROLE error = %v", err)
	}
	first, err = service.Decide(context.Background(), *first.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	first, err = service.Decide(context.Background(), *first.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first final approval: %v", err)
	}
	if !strings.Contains(*first.TerraformCode, `import {`) {
		t.Fatalf("first wild update must carry the import block:\n%s", *first.TerraformCode)
	}
	// 模拟 apply：纳管完成（CLOSED+APPLIED → CountAppliedUpdateRoleTickets>0）。
	if _, err := service.CloseTicket(context.Background(), *first.TicketNo, "system", ClosureReasonApplied, "", false); err != nil {
		t.Fatalf("close first update: %v", err)
	}

	second, err := service.CreateTicket(context.Background(), "requester", updateRoleTicketRequest())
	if err != nil {
		t.Fatalf("second wild UPDATE_ROLE error = %v", err)
	}
	second, err = service.Decide(context.Background(), *second.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	second, err = service.Decide(context.Background(), *second.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("second final approval: %v", err)
	}
	if strings.Contains(*second.TerraformCode, `import {`) {
		t.Fatalf("second update must not re-import an already-managed role:\n%s", *second.TerraformCode)
	}
	if !strings.Contains(*second.TerraformCode, `resource "aws_iam_role" "role_billing-reader"`) {
		t.Fatalf("second update must still declare the role block:\n%s", *second.TerraformCode)
	}
}

// ③ 野生回滚：把目标工单快照里的属性 patch 回 role-<name>.tf（角色留在
// state，不 destroy），文件 key 两个方向解析到同一文件。
func TestUpdateRoleRollbackRestoresWildRoleFile(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.trustPolicy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	oldDescription := "old description"
	repository.roleDescription = &oldDescription
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/45"}
	service := newTestTicketService(t, repository, publisher)

	// 野生更新：描述 old → new（信任不变，从清单补全进新文件）
	request := updateRoleTicketRequest()
	request.UpdateRole.TrustPolicy = nil
	newDescription := "new description"
	request.UpdateRole.Description = &newDescription
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("wild UPDATE_ROLE error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if !strings.Contains(*ticket.TerraformCode, `description        = "new description"`) {
		t.Fatalf("published wild update missing new description:\n%s", *ticket.TerraformCode)
	}
	if _, err := service.CloseTicket(context.Background(), *ticket.TicketNo, "system", ClosureReasonApplied, "", false); err != nil {
		t.Fatalf("close update ticket: %v", err)
	}
	// 模拟合并：main 上的文件就是 role-<name>.tf
	publisher.fetchFile = *ticket.TerraformCode

	// 回滚：快照还原描述，其余字节（信任等）不动
	rollback := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		AccountID:      1,
		PrincipalName:  "billing-reader",
		TargetTicketNo: *ticket.TicketNo,
		ApprovalMode:   ApprovalModeManual,
		ApproverIDs:    []string{"alice", "bob"},
	}
	rollbackTicket, err := service.CreateTicket(context.Background(), "requester", rollback)
	if err != nil {
		t.Fatalf("CreateTicket(ROLLBACK) error = %v", err)
	}
	rollbackTicket, err = service.Decide(context.Background(), *rollbackTicket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("rollback first approval: %v", err)
	}
	rollbackTicket, err = service.Decide(context.Background(), *rollbackTicket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("rollback final approval: %v", err)
	}
	restored := *rollbackTicket.TerraformCode
	if !strings.Contains(restored, `description        = "old description"`) {
		t.Fatalf("rollback must restore the description:\n%s", restored)
	}
	if strings.Contains(restored, "new description") {
		t.Fatalf("rollback must not keep the updated description:\n%s", restored)
	}
	if !strings.Contains(restored, `"Service" = "ec2.amazonaws.com"`) {
		t.Fatalf("rollback must keep the (unchanged) trust:\n%s", restored)
	}
	if publisher.fetchCalls == 0 {
		t.Fatal("wild rollback must patch the role-<name>.tf file fetched from main")
	}
}

func attachPolicyTicketRequest(principalType, principalName string) CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType:       TicketTypeAttachUserPolicy,
		AccountID:        1,
		PrincipalName:    principalName,
		PrincipalType:    principalType,
		ManagedPolicyARN: "arn:aws:iam::aws:policy/IAMReadOnlyAccess",
		ApprovalMode:     ApprovalModeManual,
		ApproverIDs:      []string{"alice", "bob"},
	}
}

func TestAttachPolicyToGroupPublishesGroupAttachment(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/20"}
	service := newTestTicketService(t, repository, publisher)

	ticket, err := service.CreateTicket(context.Background(), "requester", attachPolicyTicketRequest("Group", "developers"))
	if err != nil {
		t.Fatalf("CreateTicket(ATTACH to group) error = %v", err)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.PrincipalType != "Group" {
		t.Fatalf("stored principal_type = %q, want Group", stored.PrincipalType)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil || !strings.Contains(*ticket.TerraformCode, `resource "aws_iam_group_policy_attachment"`) {
		t.Fatalf("published Terraform missing group attachment resource: %v", ticket.TerraformCode)
	}
	if ticket.GitPRURL == nil || *ticket.GitPRURL != publisher.url {
		t.Fatalf("ticket not published: %#v", ticket)
	}
}

func TestAttachPolicyDefaultsToUserAndRejectsUnknownPrincipal(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	// 省略 principal_type → 默认 User
	request := attachPolicyTicketRequest("", "app-user")
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(default user) error = %v", err)
	}
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.PrincipalType != "User" {
		t.Fatalf("default principal_type = %q, want User", stored.PrincipalType)
	}

	// Role 是合法主体（④ 角色挂载）：建单成功且类型正确落库
	request = attachPolicyTicketRequest("Role", "some-role")
	roleTicket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(role attach) error = %v", err)
	}
	var roleStored CreateIAMTicketRequest
	if err := json.Unmarshal(roleTicket.RequestPolicy, &roleStored); err != nil {
		t.Fatalf("decode stored role request: %v", err)
	}
	if roleStored.PrincipalType != "Role" {
		t.Fatalf("stored principal_type = %q, want Role", roleStored.PrincipalType)
	}

	// 非法 principal_type → 拒绝
	request = attachPolicyTicketRequest("Service", "some-service")
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "principal_type must be User, Group or Role") {
		t.Fatalf("expected principal_type validation error, got %v", err)
	}

	// 主体不在库存 → 拒绝
	repository.principalExists = false
	request = attachPolicyTicketRequest("Group", "missing-group")
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "not found in account inventory") {
		t.Fatalf("expected inventory-missing error, got %v", err)
	}
}

// ④ 角色挂载：Role 主体走 ATTACH 工单，野生挂载在校验预览与发布产物里
// 都带 import 块（<role>/<policyARN>，provider 文档格式），资源类型为
// aws_iam_role_policy_attachment —— 同时守住「校验所见 == 发布所得」。
func TestRoleAttachPolicyAdoptsWildAttachment(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/agentic-commerce-prod-AWSLoadBalancerControllerIAMPolicy"
	repository.attachments["Role/agentic-commerce-prod-kms-irsa-role/"+arn] = "" // 野生挂载
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/40"})

	request := attachPolicyTicketRequest("Role", "agentic-commerce-prod-kms-irsa-role")
	request.ManagedPolicyARN = arn
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(role attach) error = %v", err)
	}

	preview := repository.validationChecks[*ticket.TicketNo].TerraformPreview
	for _, want := range []string{
		"import {",
		`id = "agentic-commerce-prod-kms-irsa-role/` + arn + `"`,
		`resource "aws_iam_role_policy_attachment"`,
	} {
		if !strings.Contains(preview, want) {
			t.Fatalf("validation preview missing %q:\n%s", want, preview)
		}
	}

	if ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"}); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"}); err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil ||
		!strings.Contains(*ticket.TerraformCode, `resource "aws_iam_role_policy_attachment"`) ||
		!strings.Contains(*ticket.TerraformCode, `agentic-commerce-prod-kms-irsa-role/`+arn) {
		t.Fatalf("published role attach Terraform unexpected:\n%v", ticket.TerraformCode)
	}
}

func updateManagedPolicyTicketRequest(arn, document string) CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType: TicketTypeUpdateManagedPolicy,
		AccountID:  1,
		UpdatePolicy: &adapter.UpdatePolicyConfig{
			PolicyARN: arn,
			Document:  json.RawMessage(document),
		},
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"alice", "bob"},
	}
}

func updateGroupInlinePolicyTicketRequest(group, inlineName, document string) CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType: TicketTypeUpdateGroupInlinePolicy,
		AccountID:  1,
		UpdatePolicy: &adapter.UpdatePolicyConfig{
			GroupName:        group,
			InlinePolicyName: inlineName,
			Document:         json.RawMessage(document),
		},
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"alice", "bob"},
	}
}

// updateRoleInlinePolicyTicketRequest builds an inline-policy update whose owner
// is an IAM role rather than a group.
func updateRoleInlinePolicyTicketRequest(role, inlineName, document string) CreateIAMTicketRequest {
	request := updateGroupInlinePolicyTicketRequest(role, inlineName, document)
	request.UpdatePolicy.GroupName = ""
	request.UpdatePolicy.RoleName = role
	request.PrincipalType = "Role"
	return request
}

func TestUpdateRoleInlinePolicyAllowsIdenticalDocumentForFirstAdoption(t *testing.T) {
	const role = "workspaces_DefaultRole"
	const policyName = "AmazonWorkSpacesServiceAccess"
	const document = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["workspaces:DescribeWorkspaces"],"Resource":["*"]}]}`

	t.Run("first adoption imports without changing AWS policy", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		repository.policyRecords["role/"+role+"/"+policyName] = json.RawMessage(document)
		service := newTestTicketService(t, repository, &memoryTicketPublisher{})

		snapshot, err := service.PreviewValidation(context.Background(), "requester",
			updateRoleInlinePolicyTicketRequest(role, policyName, document))
		if err != nil {
			t.Fatalf("PreviewValidation(first inline-policy adoption) error = %v", err)
		}
		if !strings.Contains(snapshot.TerraformPreview, "import {") ||
			!strings.Contains(snapshot.TerraformPreview, role+":"+policyName) {
			t.Fatalf("first adoption preview must import the existing inline policy:\n%s", snapshot.TerraformPreview)
		}
		if !strings.Contains(string(snapshot.Checks), `"code":"RESOURCE_ADOPTION"`) {
			t.Fatalf("validation checks must explain state-only adoption: %s", snapshot.Checks)
		}
	})

	t.Run("already adopted policy still rejects no-op", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		repository.policyRecords["role/"+role+"/"+policyName] = json.RawMessage(document)
		seedAppliedRoleInlineUpdateTicket(repository, "IAM-PRIOR-APPLIED", role, policyName)
		service := newTestTicketService(t, repository, &memoryTicketPublisher{})

		_, err := service.PreviewValidation(context.Background(), "requester",
			updateRoleInlinePolicyTicketRequest(role, policyName, document))
		if err == nil || !strings.Contains(err.Error(), "identical to the current live policy") {
			t.Fatalf("expected no-op rejection after adoption, got %v", err)
		}
	})
}

// item 23：内嵌策略不在采集清单里（被线下删除，或平台尚未同步到）时不再硬拦
// ——Terraform 侧按声明原地更新或重建；校验结果给出 INLINE_POLICY_ABSENT 提示
// （非阻断），审批人对照 Terraform 预览判断。
func TestUpdateRoleInlinePolicyAllowsPolicyMissingFromInventory(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	// 清单里刻意不放这条内嵌策略（模拟线上已删除）
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/79"})

	request := updateRoleInlinePolicyTicketRequest(
		"otel-acm-prd-cloudwatch-role",
		"otel-acm-prd-cloudwatch-rolePolicy",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:PutLogEvents"],"Resource":["*"]}]}`,
	)
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(missing inline policy) error = %v", err)
	}
	if !strings.Contains(string(snapshot.Checks), "INLINE_POLICY_ABSENT") {
		t.Fatalf("validation checks missing INLINE_POLICY_ABSENT: %s", snapshot.Checks)
	}
	if !strings.Contains(snapshot.TerraformPreview, `aws_iam_role_policy`) {
		t.Fatalf("preview must still declare the inline policy:\n%s", snapshot.TerraformPreview)
	}

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(missing inline policy) error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	if !strings.Contains(*ticket.TerraformCode, `aws_iam_role_policy`) {
		t.Fatalf("published file must declare the inline policy:\n%s", *ticket.TerraformCode)
	}
}

// item 23：托管策略走整文件重生成，同样要识别「渲染结果与目标分支一致」。
func TestUpdateManagedPolicyWarnsWhenDeclarationUnchanged(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	const arn = "arn:aws:iam::111122223333:policy/team/Read"
	const policyName = "Read"
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["*"]}]}`)

	existing, err := adapter.AWSAdapter{}.GenerateUpdateManagedPolicyTerraform(policyName, doc, "", "")
	if err != nil {
		t.Fatalf("GenerateUpdateManagedPolicyTerraform() error = %v", err)
	}
	// 现网文档与提交内容不同（变更检测放行），但 main 上的声明文件已经是新内容
	// → 本次渲染结果与目标分支一致 → PR 无差异。
	repository.policyRecords[arn] = json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`)
	seedAppliedPolicyUpdateTicket(repository, "IAM-PRIOR-APPLIED-MANAGED", arn)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/81", fetchFile: existing}
	service := newTestTicketService(t, repository, publisher)

	request := updateManagedPolicyTicketRequest(arn, string(doc))
	request.UpdatePolicy.PolicyName = policyName
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(unchanged managed policy) error = %v", err)
	}
	if !strings.Contains(string(snapshot.Checks), "TERRAFORM_UNCHANGED") {
		t.Fatalf("validation checks missing TERRAFORM_UNCHANGED: %s", snapshot.Checks)
	}
}

// item 23：声明与目标分支逐字节一致时（PR 无差异）必须在发布前明确提示——
// 否则审批人会以为这次 PR 能修好 AWS 侧漂移，实际 apply 什么都不会做。
func TestUpdateRoleInlinePolicyWarnsWhenDeclarationUnchanged(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	const role = "otel-acm-prd-cloudwatch-role"
	const inlineName = "otel-acm-prd-cloudwatch-rolePolicy"
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:PutLogEvents"],"Resource":["*"]}]}`)

	// main 上的现文件：与本次提交的文档一致（已纳管 → 无 import 块）。
	existing, err := adapter.AWSAdapter{}.GenerateUpdateRoleInlinePolicyTerraform(role, inlineName, doc, "", "")
	if err != nil {
		t.Fatalf("GenerateUpdateRoleInlinePolicyTerraform() error = %v", err)
	}
	seedAppliedRoleInlineUpdateTicket(repository, "IAM-PRIOR-APPLIED", role, inlineName)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/80", fetchFile: existing}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleInlinePolicyTicketRequest(role, inlineName, string(doc))
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(unchanged declaration) error = %v", err)
	}
	if !strings.Contains(string(snapshot.Checks), "TERRAFORM_UNCHANGED") {
		t.Fatalf("validation checks missing TERRAFORM_UNCHANGED: %s", snapshot.Checks)
	}
	if !strings.Contains(string(snapshot.Checks), "PR 无差异") {
		t.Fatalf("TERRAFORM_UNCHANGED check must explain the missing diff: %s", snapshot.Checks)
	}

	// 文档有变化时不得出现该提示（有差异 = PR 有内容）。
	changed := updateRoleInlinePolicyTicketRequest(role, inlineName,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:PutRetentionPolicy"],"Resource":["*"]}]}`)
	changedSnapshot, err := service.PreviewValidation(context.Background(), "requester", changed)
	if err != nil {
		t.Fatalf("PreviewValidation(changed declaration) error = %v", err)
	}
	if strings.Contains(string(changedSnapshot.Checks), "TERRAFORM_UNCHANGED") {
		t.Fatalf("changed declaration must not report TERRAFORM_UNCHANGED: %s", changedSnapshot.Checks)
	}
}

// seedAppliedPolicyUpdateTicket seeds an already-applied policy update ticket
// so the second update for the same policy skips the import block.
func seedAppliedPolicyUpdateTicket(repository *memoryTicketRepository, ticketNo, arn string) {
	status := TicketStatusClosed
	reason := ClosureReasonApplied
	ticketType := TicketTypeUpdateManagedPolicy
	accountID := int64(1)
	principal := "team-read"
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:      stringPointer(ticketNo),
		TicketType:    &ticketType,
		AccountID:     &accountID,
		PrincipalName: &principal,
		Status:        &status,
		ClosureReason: &reason,
		RequestPolicy: model.JSONB(`{"ticket_type":"` + ticketType + `","account_id":1,"principal_name":"` + principal + `","update_policy":{"policy_arn":"` + arn + `"}}`),
	}
}

// seedAppliedRoleInlineUpdateTicket seeds an applied role inline-policy update
// so a repeat update for the same identity is treated as already-managed (no
// import block) — mirrors CountAppliedUpdatePolicyTickets' identity match.
func seedAppliedRoleInlineUpdateTicket(repository *memoryTicketRepository, ticketNo, role, inlineName string) {
	status := TicketStatusClosed
	reason := ClosureReasonApplied
	ticketType := TicketTypeUpdateGroupInlinePolicy
	accountID := int64(1)
	principal := role
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:      stringPointer(ticketNo),
		TicketType:    &ticketType,
		AccountID:     &accountID,
		PrincipalName: &principal,
		Status:        &status,
		ClosureReason: &reason,
		RequestPolicy: model.JSONB(`{"ticket_type":"` + ticketType + `","account_id":1,"principal_type":"Role","principal_name":"` + role + `","update_policy":{"role_name":"` + role + `","inline_policy_name":"` + inlineName + `"}}`),
	}
}

// item 23 回归（cloudwatch-role 内嵌策略被删事故的完整重现）：对野生角色内嵌
// 策略的第二次更新必须在 main 上的现文件上原地 patch——历史随机 label 保留
// （Terraform 地址不变，不再 destroy+recreate），首次纳管残留的 import 块被
// 剔除，校验预览与发布产物字节一致。
func TestUpdateRoleInlinePolicySecondUpdatePatchesFileInPlace(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	const role = "otel-acm-prd-cloudwatch-role"
	const inlineName = "otel-acm-prd-cloudwatch-rolePolicy"
	repository.policyRecords["role/"+role+"/"+inlineName] = json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:GetMetricData"],"Resource":["*"]}]}`)
	seedAppliedRoleInlineUpdateTicket(repository, "IAM-PRIOR-APPLIED", role, inlineName)

	const legacyFile = `# First-time adoption: import the pre-existing inline policy into
# Terraform state, then apply the declared document (Terraform >= 1.5).
import {
	id = "otel-acm-prd-cloudwatch-role:otel-acm-prd-cloudwatch-rolePolicy"
	to = aws_iam_role_policy.role_otel-acm-prd-cloudwatch-role_xbdih_policy
}

resource "aws_iam_role_policy" "role_otel-acm-prd-cloudwatch-role_xbdih_policy" {
	name   = "otel-acm-prd-cloudwatch-rolePolicy"
	role   = "otel-acm-prd-cloudwatch-role"
	policy = jsonencode({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:GetMetricData"],"Resource":["*"]}]})
}
`
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/50", fetchFile: legacyFile}
	service := newTestTicketService(t, repository, publisher)

	request := updateRoleInlinePolicyTicketRequest(role, inlineName,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:PutLogEvents"],"Resource":["*"]}]}`)
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(inline update) error = %v", err)
	}
	if !strings.Contains(snapshot.TerraformPreview, `resource "aws_iam_role_policy" "role_otel-acm-prd-cloudwatch-role_xbdih_policy"`) {
		t.Fatalf("preview must patch the existing file in place (legacy label preserved):\n%s", snapshot.TerraformPreview)
	}
	if strings.Contains(snapshot.TerraformPreview, "import {") {
		t.Fatalf("preview must not re-import an already-managed policy:\n%s", snapshot.TerraformPreview)
	}

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(inline update) error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	published := *ticket.TerraformCode
	if !strings.Contains(published, `resource "aws_iam_role_policy" "role_otel-acm-prd-cloudwatch-role_xbdih_policy"`) {
		t.Fatalf("published file must keep the legacy label (no address drift):\n%s", published)
	}
	if strings.Contains(published, "import {") || strings.Contains(published, "First-time adoption") {
		t.Fatalf("published file must not re-import an already-managed policy:\n%s", published)
	}
	if !strings.Contains(published, "logs:PutLogEvents") || strings.Contains(published, "cloudwatch:GetMetricData") {
		t.Fatalf("published file must carry only the new document:\n%s", published)
	}
	if published != snapshot.TerraformPreview {
		t.Fatalf("preview and publication must be byte-identical:\n--- preview ---\n%s\n--- published ---\n%s",
			snapshot.TerraformPreview, published)
	}
}

// 更新类工单必须携带真实变更：与现网文档语义一致（key 序/空白无关）时校验
// 阻断（空 MR + 无意义审批不该发生）；有差异时 checks 附 CHANGE_DETECTION
// 摘要——审批人不看 git 也能确定「有变化、变了多少」。
func TestPolicyUpdateChangeDetection(t *testing.T) {
	arn := "arn:aws:iam::111122223333:policy/team-read"

	newService := func(t *testing.T, liveDocument string) *TicketService {
		t.Helper()
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		repository.policyRecords[arn] = json.RawMessage(liveDocument)
		return newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/30"})
	}

	t.Run("rejects semantically identical document", func(t *testing.T) {
		service := newService(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
		// key 顺序不同、内容一致：语义对比必须识别为 no-op。
		request := updateManagedPolicyTicketRequest(arn,
			`{"Statement":[{"Resource":"*","Action":"s3:GetObject","Effect":"Allow"}],"Version":"2012-10-17"}`)
		_, err := service.PreviewValidation(context.Background(), "requester", request)
		if err == nil {
			t.Fatal("PreviewValidation should reject a no-op policy update")
		}
		if !strings.Contains(err.Error(), "identical to the current live policy") {
			t.Errorf("error = %v, want identical-document rejection", err)
		}
	})

	t.Run("summarizes real changes in checks", func(t *testing.T) {
		service := newService(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
		request := updateManagedPolicyTicketRequest(arn,
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"},{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]}`)
		snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
		if err != nil {
			t.Fatalf("PreviewValidation error = %v", err)
		}
		if !strings.Contains(string(snapshot.Checks), "CHANGE_DETECTION") ||
			!strings.Contains(string(snapshot.Checks), "statements: 1 → 2") {
			t.Errorf("checks should carry the change summary, got: %s", snapshot.Checks)
		}
	})
}

func TestCreateUpdateManagedPolicyTicketPublishesImportAndSnapshot(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/team-read"
	repository.policyRecords[arn] = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/30"}
	service := newTestTicketService(t, repository, publisher)

	request := updateManagedPolicyTicketRequest(arn,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`)
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_MANAGED_POLICY) error = %v", err)
	}
	// principal_name derived from the policy ARN for display.
	if ticket.PrincipalName == nil || *ticket.PrincipalName != "team-read" {
		t.Fatalf("principal_name = %v, want derived policy name team-read", ticket.PrincipalName)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	// First update of this policy → import block for first-time adoption.
	if !strings.Contains(*ticket.TerraformCode, "import {") ||
		!strings.Contains(*ticket.TerraformCode, arn) {
		t.Fatalf("first-time update should carry an import block:\n%s", *ticket.TerraformCode)
	}
	if !strings.Contains(*ticket.TerraformCode, `resource "aws_iam_policy" "managed_policy_team-read"`) {
		t.Fatalf("published Terraform missing aws_iam_policy resource:\n%s", *ticket.TerraformCode)
	}
	if !strings.Contains(*ticket.TerraformCode, "s3:PutObject") {
		t.Fatalf("published Terraform missing new document:\n%s", *ticket.TerraformCode)
	}
	// Snapshot captured at publication: the PRE-update document from inventory.
	published, ok := repository.tickets[*ticket.TicketNo]
	if !ok || len(published.RoleSnapshot) == 0 {
		t.Fatal("policy snapshot was not captured at publication")
	}
	if !strings.Contains(string(published.RoleSnapshot), "s3:GetObject") {
		t.Fatalf("snapshot should hold the pre-update document: %s", published.RoleSnapshot)
	}
}

func TestSecondUpdateManagedPolicyTicketSkipsImport(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/team-read"
	repository.policyRecords[arn] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	seedAppliedPolicyUpdateTicket(repository, "IAM-PRIOR-UPDATE-001", arn)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/31"})

	ticket, err := service.CreateTicket(context.Background(), "requester",
		updateManagedPolicyTicketRequest(arn, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`))
	if err != nil {
		t.Fatalf("CreateTicket(second update) error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil || strings.Contains(*ticket.TerraformCode, "import {") {
		t.Fatalf("policy already managed → no import block expected:\n%v", ticket.TerraformCode)
	}
}

// Abandoned (CLOSED + ABANDONED) policy-update tickets never published a
// Terraform file, so they must NOT suppress the first-time import block.
func TestAbandonedPolicyUpdateDoesNotSuppressImport(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/team-read"
	repository.policyRecords[arn] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)

	// Seed a CLOSED + ABANDONED policy update (draft abandoned before publish).
	abandonedStatus := TicketStatusClosed
	abandonedReason := ClosureReasonAbandoned
	abandonedType := TicketTypeUpdateManagedPolicy
	accountID := int64(1)
	principal := "team-read"
	repository.tickets["IAM-ABANDONED-UPDATE"] = model.IAMTicket{
		TicketNo:      stringPointer("IAM-ABANDONED-UPDATE"),
		TicketType:    &abandonedType,
		AccountID:     &accountID,
		PrincipalName: &principal,
		Status:        &abandonedStatus,
		ClosureReason: &abandonedReason,
		RequestPolicy: model.JSONB(
			`{"ticket_type":"` + abandonedType + `","account_id":1,"principal_name":"` + principal +
				`","update_policy":{"policy_arn":"` + arn + `"}}`),
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/40"})

	ticket, err := service.CreateTicket(context.Background(), "requester",
		updateManagedPolicyTicketRequest(arn, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`))
	if err != nil {
		t.Fatalf("CreateTicket after abandoned ticket: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil || !strings.Contains(*ticket.TerraformCode, "import {") {
		t.Fatalf("abandoned ticket must not suppress the first-time import block:\n%v", ticket.TerraformCode)
	}
}

func TestUpdateManagedPolicyValidationRejects(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	// AWS-managed policy → rejected.
	request := updateManagedPolicyTicketRequest("arn:aws:iam::aws:policy/ReadOnlyAccess",
		`{"Version":"2012-10-17","Statement":[]}`)
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "AWS-managed policies cannot be updated") {
		t.Fatalf("expected AWS-managed rejection, got %v", err)
	}

	// Policy missing from inventory → rejected.
	request = updateManagedPolicyTicketRequest("arn:aws:iam::111122223333:policy/ghost",
		`{"Version":"2012-10-17","Statement":[]}`)
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "not found in account inventory") {
		t.Fatalf("expected inventory-missing rejection, got %v", err)
	}

	// Concurrency lock: a second active update for the same policy → rejected.
	arn := "arn:aws:iam::111122223333:policy/team-read"
	repository.policyRecords[arn] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	activeStatus := TicketStatusApproving
	activeType := TicketTypeUpdateManagedPolicy
	accountID := int64(1)
	repository.tickets["IAM-ACTIVE-UPDATE"] = model.IAMTicket{
		TicketNo:      stringPointer("IAM-ACTIVE-UPDATE"),
		TicketType:    &activeType,
		AccountID:     &accountID,
		Status:        &activeStatus,
		RequestPolicy: model.JSONB(`{"ticket_type":"` + activeType + `","account_id":1,"update_policy":{"policy_arn":"` + arn + `"}}`),
	}
	request = updateManagedPolicyTicketRequest(arn, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "policy already has a change ticket") {
		t.Fatalf("expected concurrency-lock rejection, got %v", err)
	}
}

func TestCreateUpdateGroupInlinePolicyTicketPublishesTerraform(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.policyRecords["group/tdfos-prod-group/InlineRead"] = json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/32"})

	request := updateGroupInlinePolicyTicketRequest("tdfos-prod-group", "InlineRead",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`)
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_GROUP_INLINE_POLICY) error = %v", err)
	}
	// principal_name derived from the group; principal_type forced to Group.
	if ticket.PrincipalName == nil || *ticket.PrincipalName != "tdfos-prod-group" {
		t.Fatalf("principal_name = %v, want group name", ticket.PrincipalName)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	// First update of this inline policy → import block with <group>:<name>
	// (aws_iam_group_policy 的 import ID 用冒号，attachment 类才用斜杠)。
	if !strings.Contains(*ticket.TerraformCode, "import {") ||
		!strings.Contains(*ticket.TerraformCode, "tdfos-prod-group:InlineRead") {
		t.Fatalf("first-time inline update should carry an import block:\n%s", *ticket.TerraformCode)
	}
	// 标签为 group_<group>_<rand5>_<policy>（随机后缀，断言前缀+后缀）。
	if !strings.Contains(*ticket.TerraformCode, `resource "aws_iam_group_policy" "group_tdfos-prod-group_`) ||
		!strings.Contains(*ticket.TerraformCode, `_InlineRead" {`) {
		t.Fatalf("published Terraform missing aws_iam_group_policy resource:\n%s", *ticket.TerraformCode)
	}
	// 资源标签随工单请求持久化（resource_name），保证预览与发布一致。
	stored, ok := repository.tickets[*ticket.TicketNo]
	if !ok || !strings.Contains(string(stored.RequestPolicy), `"resource_name":"group_tdfos-prod-group_`) {
		t.Fatalf("resource_name not stored on ticket request: %s", stored.RequestPolicy)
	}
}

func TestUpdateGroupInlinePolicyValidationRejects(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	// Inline policy not present on the group → 不再硬拦（GitOps 自愈：Terraform
	// 侧按声明重建），校验结果给出 INLINE_POLICY_ABSENT 提示。
	request := updateGroupInlinePolicyTicketRequest("tdfos-prod-group", "Ghost",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`)
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(missing inline policy) error = %v", err)
	}
	if !strings.Contains(string(snapshot.Checks), "INLINE_POLICY_ABSENT") {
		t.Fatalf("validation checks missing INLINE_POLICY_ABSENT: %s", snapshot.Checks)
	}

	// User inline policies are not supported: only Group and Role principals.
	request = updateGroupInlinePolicyTicketRequest("tdfos-prod-group", "InlineRead",
		`{"Version":"2012-10-17","Statement":[]}`)
	request.PrincipalType = "User"
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "principal_type must be Group or Role") {
		t.Fatalf("expected group/role-only rejection, got %v", err)
	}
}

// A role inline policy is a first-class target: the ticket must validate against
// the role's inventory entry and publish an aws_iam_role_policy resource with a
// "<role>:<policyName>" import id (colon-separated) for first-time adoption.
func TestCreateUpdateRoleInlinePolicyTicketPublishesTerraform(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.policyRecords["role/otel-acm-prd-cloudwatch-role/otel-acm-prd-cloudwatch-rolePolicy"] = json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:GetMetricData","Resource":"*"}]}`)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/34"})

	request := updateRoleInlinePolicyTicketRequest("otel-acm-prd-cloudwatch-role", "otel-acm-prd-cloudwatch-rolePolicy",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:GetMetricData","Resource":"*"},{"Effect":"Allow","Action":"logs:DescribeLogGroups","Resource":"*"}]}`)
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(UPDATE_GROUP_INLINE_POLICY on role) error = %v", err)
	}
	if ticket.PrincipalName == nil || *ticket.PrincipalName != "otel-acm-prd-cloudwatch-role" {
		t.Fatalf("principal_name = %v, want role name", ticket.PrincipalName)
	}
	// principal_type lives inside the stored request payload, not on the ticket row.
	var storedRequest CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &storedRequest); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if storedRequest.PrincipalType != "Role" {
		t.Fatalf("principal_type = %q, want Role", storedRequest.PrincipalType)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	if !strings.Contains(*ticket.TerraformCode, "import {") ||
		!strings.Contains(*ticket.TerraformCode, "otel-acm-prd-cloudwatch-role:otel-acm-prd-cloudwatch-rolePolicy") {
		t.Fatalf("first-time role inline update should carry an import block:\n%s", *ticket.TerraformCode)
	}
	// 标签为 role_<role>_<rand5>_policy（随机后缀，策略名只出现在 name 属性）。
	if !strings.Contains(*ticket.TerraformCode, `resource "aws_iam_role_policy" "role_otel-acm-prd-cloudwatch-role_`) ||
		!strings.Contains(*ticket.TerraformCode, `_policy" {`) {
		t.Fatalf("published Terraform missing aws_iam_role_policy resource:\n%s", *ticket.TerraformCode)
	}
	if strings.Contains(*ticket.TerraformCode, `_otel-acm-prd-cloudwatch-rolePolicy" {`) {
		t.Fatalf("role inline label must omit the AWS policy name:\n%s", *ticket.TerraformCode)
	}
	if strings.Contains(*ticket.TerraformCode, `aws_iam_group_policy`) {
		t.Fatalf("role inline update must not emit a group policy resource:\n%s", *ticket.TerraformCode)
	}
}

func TestUpdateRoleInlinePolicyValidationRejects(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	// Role not in inventory → rejected.
	repository.principalExists = false
	request := updateRoleInlinePolicyTicketRequest("ghost-role", "SomePolicy",
		`{"Version":"2012-10-17","Statement":[]}`)
	if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
		!strings.Contains(err.Error(), "not found in account inventory") {
		t.Fatalf("expected inventory-missing rejection, got %v", err)
	}

	// Inline policy not present on the role → 不再硬拦（GitOps 自愈：Terraform
	// 侧按声明原地更新或重建），校验结果给出 INLINE_POLICY_ABSENT 提示。
	repository.principalExists = true
	repository.policyRecords["role/otel-acm-prd-cloudwatch-role/otel-acm-prd-cloudwatch-rolePolicy"] = json.RawMessage(
		`{"Version":"2012-10-17","Statement":[]}`)
	request = updateRoleInlinePolicyTicketRequest("otel-acm-prd-cloudwatch-role", "Ghost",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`)
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(missing inline policy) error = %v", err)
	}
	if !strings.Contains(string(snapshot.Checks), "INLINE_POLICY_ABSENT") {
		t.Fatalf("validation checks missing INLINE_POLICY_ABSENT: %s", snapshot.Checks)
	}
}

// A group and a role may share a name; the concurrency lock must not conflate
// them, otherwise an in-flight group update would block a role update.
func TestUpdateInlinePolicyLockDistinguishesGroupFromRole(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.policyRecords["group/shared-name/InlineRead"] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	repository.policyRecords["role/shared-name/InlineRead"] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	activeStatus := TicketStatusApproving
	activeType := TicketTypeUpdateGroupInlinePolicy
	accountID := int64(1)
	repository.tickets["IAM-ACTIVE-GROUP-UPDATE"] = model.IAMTicket{
		TicketNo:      stringPointer("IAM-ACTIVE-GROUP-UPDATE"),
		TicketType:    &activeType,
		AccountID:     &accountID,
		Status:        &activeStatus,
		RequestPolicy: model.JSONB(`{"ticket_type":"UPDATE_GROUP_INLINE_POLICY","account_id":1,"principal_type":"Group","principal_name":"shared-name","update_policy":{"group_name":"shared-name","inline_policy_name":"InlineRead"}}`),
	}

	// Same name, different principal type → the group lock must not block the role.
	request := updateRoleInlinePolicyTicketRequest("shared-name", "InlineRead",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	if _, err := service.CreateTicket(context.Background(), "requester", request); err != nil {
		t.Fatalf("role update blocked by same-named group lock: %v", err)
	}
}

func TestRollbackUpdateManagedPolicyRestoresSnapshot(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/team-read"
	repository.policyRecords[arn] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	seedAppliedPolicyUpdateTicket(repository, "IAM-POLICY-UPDATE-APPLIED", arn)
	// The applied update carries the pre-update snapshot.
	prior := repository.tickets["IAM-POLICY-UPDATE-APPLIED"]
	prior.RoleSnapshot = model.JSONB(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	repository.tickets["IAM-POLICY-UPDATE-APPLIED"] = prior
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/33"})

	ticket, err := service.CreateTicket(context.Background(), "requester",
		rollbackTicketRequest("IAM-POLICY-UPDATE-APPLIED"))
	if err != nil {
		t.Fatalf("CreateTicket(ROLLBACK policy update) error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	// Rollback regenerates the policy file from the snapshot document, with no
	// import block (the resource is already in Terraform state).
	if !strings.Contains(*ticket.TerraformCode, "s3:GetObject") {
		t.Fatalf("rollback Terraform should restore the snapshot document:\n%s", *ticket.TerraformCode)
	}
	if strings.Contains(*ticket.TerraformCode, "import {") {
		t.Fatalf("rollback must not emit an import block:\n%s", *ticket.TerraformCode)
	}
}

func TestDetachPolicyRejectsWildAttachmentAndPublishesClearFile(t *testing.T) {
	t.Run("wild attachment rejected with guidance", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		repository.attachments["Group/developers/arn:aws:iam::111122223333:policy/team-read"] = ""
		service := newTestTicketService(t, repository, &memoryTicketPublisher{})

		request := attachPolicyTicketRequest("Group", "developers")
		request.ManagedPolicyARN = "arn:aws:iam::111122223333:policy/team-read"
		request.Operation = OperationDetach
		_, err := service.CreateTicket(context.Background(), "requester", request)
		var wild *WildAttachmentError
		if !errors.As(err, &wild) {
			t.Fatalf("expected WildAttachmentError, got %v", err)
		}
		// 引导文案：死胡同报错必须给出可行的两段路径（先挂载纳管再解绑）。
		if !strings.Contains(err.Error(), "先发起「挂载」工单") {
			t.Fatalf("wild detach guidance missing in message: %v", err)
		}
	})

	t.Run("platform-managed detach clears the source attach file", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		arn := "arn:aws:iam::111122223333:policy/team-read"
		repository.attachments["Group/developers/"+arn] = "IAM-SOURCE-ATTACH-001"
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/34"})

		request := attachPolicyTicketRequest("Group", "developers")
		request.ManagedPolicyARN = arn
		request.Operation = OperationDetach
		ticket, err := service.CreateTicket(context.Background(), "requester", request)
		if err != nil {
			t.Fatalf("CreateTicket(detach) error = %v", err)
		}
		var stored CreateIAMTicketRequest
		if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
			t.Fatalf("decode stored request: %v", err)
		}
		if stored.SourceTicketNo != "IAM-SOURCE-ATTACH-001" {
			t.Fatalf("source_ticket_no = %q, want IAM-SOURCE-ATTACH-001", stored.SourceTicketNo)
		}

		ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
		if err != nil {
			t.Fatalf("first approval: %v", err)
		}
		ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
		if err != nil {
			t.Fatalf("final approval: %v", err)
		}
		// The detach ticket writes a comment-only file to the source attach
		// ticket's path, so terraform plan destroys the attachment.
		if ticket.TerraformCode == nil ||
			strings.Contains(*ticket.TerraformCode, `resource "aws_iam_group_policy_attachment"`) {
			t.Fatalf("detach must clear the attach declarations:\n%v", ticket.TerraformCode)
		}
		if !strings.Contains(*ticket.TerraformCode, "DETACH") {
			t.Fatalf("detach file should carry the detach marker:\n%s", *ticket.TerraformCode)
		}
	})

	t.Run("attach of an already platform-attached policy is rejected", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		arn := "arn:aws:iam::111122223333:policy/team-read"
		repository.attachments["Group/developers/"+arn] = "IAM-SOURCE-ATTACH-001"
		service := newTestTicketService(t, repository, &memoryTicketPublisher{})

		request := attachPolicyTicketRequest("Group", "developers")
		request.ManagedPolicyARN = arn
		if _, err := service.CreateTicket(context.Background(), "requester", request); err == nil ||
			!strings.Contains(err.Error(), "该策略已挂载") {
			t.Fatalf("expected already-attached rejection, got %v", err)
		}
	})

	t.Run("wild attach adopts the attachment with an import block", func(t *testing.T) {
		repository := newMemoryTicketRepository()
		repository.principalExists = true
		arn := "arn:aws:iam::111122223333:policy/team-read"
		repository.attachments["Group/developers/"+arn] = "" // wild
		service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/35"})

		request := attachPolicyTicketRequest("Group", "developers")
		request.ManagedPolicyARN = arn
		ticket, err := service.CreateTicket(context.Background(), "requester", request)
		if err != nil {
			t.Fatalf("CreateTicket(wild attach) error = %v", err)
		}
		ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
		if err != nil {
			t.Fatalf("first approval: %v", err)
		}
		ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
		if err != nil {
			t.Fatalf("final approval: %v", err)
		}
		if ticket.TerraformCode == nil ||
			!strings.Contains(*ticket.TerraformCode, "import {") ||
			!strings.Contains(*ticket.TerraformCode, "developers/"+arn) {
			t.Fatalf("wild attach should carry an import block:\n%v", ticket.TerraformCode)
		}
		// 预览 == 发布：校验快照里的预览同样带 import 块。
		preview := repository.validationChecks[*ticket.TicketNo].TerraformPreview
		if !strings.Contains(preview, "import {") || !strings.Contains(preview, "developers/"+arn) {
			t.Fatalf("validation preview should carry the same import block:\n%s", preview)
		}
	})
}

func TestRollbackDetachReattachesIntoSourceFile(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::111122223333:policy/team-read"
	repository.attachments["Group/developers/"+arn] = "IAM-SOURCE-ATTACH-001"

	// Seed the applied detach ticket (CLOSED + APPLIED) targeting the source.
	detachStatus := TicketStatusClosed
	detachReason := ClosureReasonApplied
	detachType := TicketTypeAttachUserPolicy
	accountID := int64(1)
	detachRequest, _ := json.Marshal(CreateIAMTicketRequest{
		TicketType:       TicketTypeAttachUserPolicy,
		AccountID:        1,
		PrincipalName:    "developers",
		PrincipalType:    "Group",
		ManagedPolicyARN: arn,
		Operation:        OperationDetach,
		SourceTicketNo:   "IAM-SOURCE-ATTACH-001",
	})
	repository.tickets["IAM-DETACH-APPLIED"] = model.IAMTicket{
		TicketNo:      stringPointer("IAM-DETACH-APPLIED"),
		TicketType:    &detachType,
		AccountID:     &accountID,
		PrincipalName: stringPointer("developers"),
		Status:        &detachStatus,
		ClosureReason: &detachReason,
		RequestPolicy: model.JSONB(detachRequest),
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{url: "https://github.example/iac/pull/36"})

	ticket, err := service.CreateTicket(context.Background(), "requester",
		rollbackTicketRequest("IAM-DETACH-APPLIED"))
	if err != nil {
		t.Fatalf("CreateTicket(ROLLBACK detach) error = %v", err)
	}
	// Rollback of a detach re-attaches: operation flips back to attach and the
	// source attach ticket is inherited.
	var stored CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &stored); err != nil {
		t.Fatalf("decode stored request: %v", err)
	}
	if stored.Operation != OperationAttach || stored.SourceTicketNo != "IAM-SOURCE-ATTACH-001" {
		t.Fatalf("rollback request = %+v, want operation=attach with source ticket", stored)
	}

	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if ticket.TerraformCode == nil ||
		!strings.Contains(*ticket.TerraformCode, `resource "aws_iam_group_policy_attachment"`) {
		t.Fatalf("rollback of detach should re-declare the attachment:\n%v", ticket.TerraformCode)
	}
}

func TestPolicyFileTicketNoIsDeterministic(t *testing.T) {
	managed := CreateIAMTicketRequest{
		TicketType: TicketTypeUpdateManagedPolicy,
		UpdatePolicy: &adapter.UpdatePolicyConfig{
			PolicyARN:  "arn:aws:iam::111122223333:policy/Team/Read",
			PolicyName: "Read",
			Document:   json.RawMessage(`{}`),
		},
	}
	if key := managed.terraformFileTicketNo("IAM-FALLBACK"); key != "policy-read" {
		t.Fatalf("managed policy file key = %q, want policy-read", key)
	}

	inline := CreateIAMTicketRequest{
		TicketType: TicketTypeUpdateGroupInlinePolicy,
		UpdatePolicy: &adapter.UpdatePolicyConfig{
			GroupName:        "tdfos-prod-group",
			InlinePolicyName: "InlineRead",
			Document:         json.RawMessage(`{}`),
		},
	}
	if key := inline.terraformFileTicketNo("IAM-FALLBACK"); key != "group-tdfos-prod-group-policy-inlineread" {
		t.Fatalf("inline policy file key = %q", key)
	}

	// Rollback inherits the target identity → same file key.
	rollback := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-X",
		UpdatePolicy:   managed.UpdatePolicy,
	}
	if key := rollback.terraformFileTicketNo("IAM-FALLBACK"); key != "policy-read" {
		t.Fatalf("rollback policy file key = %q, want policy-read", key)
	}

	// Non-policy requests fall back to the ticket number.
	plain := CreateIAMTicketRequest{TicketType: TicketTypeCreateRole}
	if key := plain.terraformFileTicketNo("IAM-FALLBACK"); key != "IAM-FALLBACK" {
		t.Fatalf("plain file key = %q, want IAM-FALLBACK", key)
	}

	// ③ 野生 UPDATE_ROLE 及其回滚：独立稳定文件 role-<name>。
	wild := CreateIAMTicketRequest{TicketType: TicketTypeUpdateRole, PrincipalName: "kms-irsa-role"}
	if key := wild.terraformFileTicketNo("IAM-FALLBACK"); key != "role-kms-irsa-role" {
		t.Fatalf("wild role file key = %q, want role-kms-irsa-role", key)
	}
	// 有源文件仍走源 CREATE 工单文件（② 路径）。
	sourceBased := CreateIAMTicketRequest{
		TicketType:     TicketTypeUpdateRole,
		PrincipalName:  "kms-irsa-role",
		SourceTicketNo: "IAM-SOURCE1",
	}
	if key := sourceBased.terraformFileTicketNo("IAM-FALLBACK"); key != "IAM-SOURCE1" {
		t.Fatalf("source-based role file key = %q, want IAM-SOURCE1", key)
	}
	// 野生回滚（PrincipalType=Role 由 prepareRollbackTarget 标记）指向同一文件。
	wildRollback := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-X",
		PrincipalType:  "Role",
		PrincipalName:  "kms-irsa-role",
	}
	if key := wildRollback.terraformFileTicketNo("IAM-FALLBACK"); key != "role-kms-irsa-role" {
		t.Fatalf("wild role rollback file key = %q, want role-kms-irsa-role", key)
	}
	// CREATE 回滚不受影响：清空目标工单文件 → destroy。
	createRollback := CreateIAMTicketRequest{TicketType: TicketTypeRollback, TargetTicketNo: "IAM-CREATE1"}
	if key := createRollback.terraformFileTicketNo("IAM-FALLBACK"); key != "IAM-CREATE1" {
		t.Fatalf("create rollback file key = %q, want IAM-CREATE1", key)
	}
}

func TestPolicyNameFromARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::111122223333:policy/ReadOnlyAccess": "ReadOnlyAccess",
		"arn:aws:iam::111122223333:policy/team/Read":      "Read",
		"arn:aws:iam::aws:policy/AdministratorAccess":     "AdministratorAccess",
		"not-an-arn": "",
	}
	for input, want := range cases {
		if got := PolicyNameFromARN(input); got != want {
			t.Errorf("PolicyNameFromARN(%q) = %q, want %q", input, got, want)
		}
	}
}

// CREATE_ROLE 增强（item 23）：初始挂载托管策略多选（对齐 CREATE_USER /
// CREATE_GROUP）。校验快照给出 POLICY_ATTACHMENT 提示，发布产物声明
// aws_iam_role_policy_attachment。
func TestCreateRoleAttachesManagedPoliciesAtCreation(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/77"}
	service := newTestTicketService(t, repository, publisher)

	const arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
	request := validAbstractPolicyRequest()
	request.Role.PolicyARNs = []string{arn}

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(CREATE_ROLE with attachments) error = %v", err)
	}
	checks := string(repository.validationChecks[*ticket.TicketNo].Checks)
	if !strings.Contains(checks, "POLICY_ATTACHMENT") {
		t.Fatalf("validation checks missing POLICY_ATTACHMENT: %s", checks)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	published := *ticket.TerraformCode
	wantLabel := adapter.DefaultAttachmentLabel("Role", "billing-reader", arn)
	if !strings.Contains(published, `resource "aws_iam_role_policy_attachment" "`+wantLabel+`"`) {
		t.Fatalf("published file missing the initial attachment:\n%s", published)
	}
	if !strings.Contains(published, `policy_arn = "`+arn+`"`) {
		t.Fatalf("published file missing the attachment ARN:\n%s", published)
	}
}

func TestValidateManagedPolicyARNsRequiresCustomerPolicyInInventory(t *testing.T) {
	const customerPolicyARN = "arn:aws:iam::123456789012:policy/team/alert"
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	if err := service.validateManagedPolicyARNs(
		context.Background(), 12, "role.policy_arns", []string{customerPolicyARN},
	); err == nil || !strings.Contains(err.Error(), "not found in the synced IAM inventory") {
		t.Fatalf("missing policy validation error = %v", err)
	}

	repository.policyRecords[customerPolicyARN] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	if err := service.validateManagedPolicyARNs(
		context.Background(), 12, "role.policy_arns", []string{customerPolicyARN},
	); err != nil {
		t.Fatalf("inventory policy validation error = %v", err)
	}

	if err := service.validateManagedPolicyARNs(
		context.Background(), 12, "role.policy_arns", []string{"alert"},
	); err == nil || !strings.Contains(err.Error(), "invalid IAM policy ARN") {
		t.Fatalf("malformed policy ARN validation error = %v", err)
	}

	const awsManagedPolicyARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
	if err := service.validateManagedPolicyARNs(
		context.Background(), 12, "role.policy_arns", []string{awsManagedPolicyARN},
	); err != nil {
		t.Fatalf("AWS-managed policy validation error = %v", err)
	}

	const otherAccountPolicyARN = "arn:aws:iam::999999999999:policy/team/alert"
	repository.policyRecords[otherAccountPolicyARN] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	if err := service.validateManagedPolicyARNs(
		context.Background(), 12, "role.policy_arns", []string{otherAccountPolicyARN},
	); err == nil || !strings.Contains(err.Error(), "does not match selected AWS account") {
		t.Fatalf("cross-account policy validation error = %v", err)
	}
}

func TestCreateRoleRejectsPolicyARNNotInInventory(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := validAbstractPolicyRequest()
	request.Role.PolicyARNs = []string{"arn:aws:iam::123456789012:policy/team/alert"}

	_, err := service.PreviewValidation(context.Background(), "requester", request)
	if err == nil || !strings.Contains(err.Error(), "not found in the synced IAM inventory") {
		t.Fatalf("PreviewValidation error = %v, want missing policy inventory error", err)
	}
}

// CREATE_ROLE 增强（item 23）：权限声明可选——不声明任何权限时创建零权限角色
// （AWS 侧合法），文件里只有角色本体，没有 <role>-policy 内嵌策略资源；
// 校验结果给出非阻断提示 ZERO_PERMISSION_ROLE。
func TestCreateRoleWithoutPolicyCreatesZeroPermissionRole(t *testing.T) {
	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/78"}
	service := newTestTicketService(t, repository, publisher)

	request := CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateRole,
		AccountID:     12,
		PrincipalName: "billing-reader",
		Role:          adapterRole("billing-reader"),
		ApprovalMode:  ApprovalModeManual,
		ApproverIDs:   []string{"alice", "bob"},
	}

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(zero-permission role) error = %v", err)
	}
	if !strings.Contains(snapshot.TerraformPreview, `resource "aws_iam_role" "role_billing-reader"`) {
		t.Fatalf("preview must declare the role:\n%s", snapshot.TerraformPreview)
	}
	if strings.Contains(snapshot.TerraformPreview, "aws_iam_role_policy") {
		t.Fatalf("zero-permission role must not declare an inline policy:\n%s", snapshot.TerraformPreview)
	}
	if !strings.Contains(string(snapshot.Checks), "ZERO_PERMISSION_ROLE") {
		t.Fatalf("validation checks missing the zero-permission hint: %s", snapshot.Checks)
	}

	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(zero-permission role) error = %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	published := *ticket.TerraformCode
	if strings.Contains(published, "aws_iam_role_policy") {
		t.Fatalf("published zero-permission role must not declare an inline policy:\n%s", published)
	}
	if published != snapshot.TerraformPreview {
		t.Fatalf("preview and publication must be byte-identical:\n--- preview ---\n%s\n--- published ---\n%s",
			snapshot.TerraformPreview, published)
	}
}

// 基线纳管的挂载（全量基线发布 + apply 进 state）没有源挂载工单，解绑
// 工单必须放行并改写基线文件——而不是按「野生挂载」拒绝。
func TestDetachPolicyAllowsBaselineOwnedAttachment(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
	// 清单里挂载存在，但没有源工单（野生标记为空）。
	repository.attachments["Role/rds-monitoring-role/"+arn] = ""
	repository.baselineOwnedFiles[AttachmentFileKey("role", "rds-monitoring-role", "AmazonRDSEnhancedMonitoringRole")] = true
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/41"}
	publisher.fetchFile = "# First-time adoption: import the pre-existing attachment into\n" +
		"# Terraform state, then declare it (Terraform >= 1.5).\n" +
		"import {\n" +
		"\tid = \"rds-monitoring-role/" + arn + "\"\n" +
		"\tto = aws_iam_role_policy_attachment.attachment_role_rds-monitoring-role_AmazonRDSEnhancedMonitoringRole\n" +
		"}\n" +
		"\n" +
		"resource \"aws_iam_role_policy_attachment\" \"attachment_role_rds-monitoring-role_AmazonRDSEnhancedMonitoringRole\" {\n" +
		"\trole       = \"rds-monitoring-role\"\n" +
		"\tpolicy_arn = \"" + arn + "\"\n" +
		"}\n"
	service := newTestTicketService(t, repository, publisher)

	request := attachPolicyTicketRequest("Role", "rds-monitoring-role")
	request.ManagedPolicyARN = arn
	request.Operation = OperationDetach
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(baseline-owned detach) error = %v", err)
	}
	// 校验预览 = 基线文件去掉挂载：resource 与 import 块都要消失，
	// 悬空 import 会让 plan 报 Resource not found in configuration。
	snapshot, previewErr := service.PreviewValidation(context.Background(), "requester", request)
	if previewErr != nil {
		t.Fatalf("PreviewValidation(baseline-owned detach) error = %v", previewErr)
	}
	if strings.Contains(snapshot.TerraformPreview, "aws_iam_role_policy_attachment") ||
		strings.Contains(snapshot.TerraformPreview, "import {") {
		t.Fatalf("preview must drop both the resource and the import block:\n%s", snapshot.TerraformPreview)
	}
	if publisher.fetchCalls == 0 {
		t.Fatal("detach must fetch the baseline attachment file from main")
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"}); err != nil {
		t.Fatalf("second approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	published := *ticket.TerraformCode
	if strings.Contains(published, "aws_iam_role_policy_attachment") || strings.Contains(published, "import {") {
		t.Fatalf("published detach must clear the baseline file completely:\n%s", published)
	}
}

// 已由基线纳管的挂载不能再发挂载工单：工单副本会覆写基线文件、破坏
// 归属模型。报错必须直接引导走解绑工单。
func TestAttachPolicyRejectsBaselineOwnedAttachment(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	arn := "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
	repository.attachments["Role/rds-monitoring-role/"+arn] = ""
	repository.baselineOwnedFiles[AttachmentFileKey("role", "rds-monitoring-role", "AmazonRDSEnhancedMonitoringRole")] = true
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request := attachPolicyTicketRequest("Role", "rds-monitoring-role")
	request.ManagedPolicyARN = arn
	_, err := service.CreateTicket(context.Background(), "requester", request)
	if err == nil {
		t.Fatal("expected rejection for baseline-owned attachment")
	}
	if !strings.Contains(err.Error(), "已由全量基线纳管") || !strings.Contains(err.Error(), "解绑工单") {
		t.Fatalf("error should direct to a detach ticket: %v", err)
	}
}

func membershipTicketRequest(group, operation string, users []string) CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType:   TicketTypeUpdateGroupMembership,
		AccountID:    1,
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"alice", "bob"},
		UpdateMembership: &UpdateMembershipConfig{
			GroupName: group,
			Operation: operation,
			Users:     users,
		},
	}
}

func seededMembershipFile(members ...string) string {
	var hcl strings.Builder
	hcl.WriteString("resource \"aws_iam_group_membership\" \"group_devs_membership\" {\n")
	hcl.WriteString("\tname  = \"devs-membership\"\n")
	hcl.WriteString("\tgroup = \"devs\"\n")
	hcl.WriteString("\tusers = [\n")
	for _, member := range members {
		hcl.WriteString("\t\t\"" + member + "\",\n")
	}
	hcl.WriteString("\t]\n}\n")
	return hcl.String()
}

// 已被基线纳管的组成员文件原地改写：add 把新成员追加进 users 列表，
// 资源 label / membership name / group 字节保持不动（地址永不漂移）。
func TestUpdateGroupMembershipAddPatchesManagedFile(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.groupMembers = map[string][]string{"devs": {"alice"}}
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/42"}
	publisher.fetchFile = seededMembershipFile("alice")
	service := newTestTicketService(t, repository, publisher)

	request := membershipTicketRequest("devs", MembershipOperationAdd, []string{"bob", "carol"})
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(membership add) error = %v", err)
	}
	for _, want := range []string{"\"bob\",", "\"carol\",", "\"alice\",", "group_devs_membership", "\"devs-membership\""} {
		if !strings.Contains(snapshot.TerraformPreview, want) {
			t.Errorf("preview missing %q:\n%s", want, snapshot.TerraformPreview)
		}
	}
	if publisher.fetchCalls == 0 {
		t.Fatal("membership update must fetch the managed membership file from main")
	}
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(membership add) error = %v", err)
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"}); err != nil {
		t.Fatalf("second approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if ticket.TerraformCode == nil {
		t.Fatal("published Terraform missing")
	}
	published := *ticket.TerraformCode
	for _, want := range []string{"group_devs_membership", "name  = \"devs-membership\"", "group = \"devs\"", "\"bob\",", "\"carol\",", "\"alice\","} {
		if !strings.Contains(published, want) {
			t.Errorf("published membership file missing %q:\n%s", want, published)
		}
	}
}

// 移除组的最后一名成员：清空文件 → 注释空文件 → terraform plan 销毁
// membership 资源（文件里不能留下 0 元素的 users 声明，Terraform 会拒绝）。
func TestUpdateGroupMembershipRemoveLastMemberDestroys(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.groupMembers = map[string][]string{"devs": {"alice"}}
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/43"}
	publisher.fetchFile = seededMembershipFile("alice")
	service := newTestTicketService(t, repository, publisher)

	request := membershipTicketRequest("devs", MembershipOperationRemove, []string{"alice"})
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(membership remove last) error = %v", err)
	}
	if strings.Contains(snapshot.TerraformPreview, "resource \"aws_iam_group_membership\"") {
		t.Fatalf("empty membership must not keep a resource declaration:\n%s", snapshot.TerraformPreview)
	}
	if !strings.Contains(snapshot.TerraformPreview, "devs") {
		t.Fatalf("emptied file must still explain the ticket:\n%s", snapshot.TerraformPreview)
	}
	ticket, err := service.CreateTicket(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateTicket(membership remove last) error = %v", err)
	}
	if _, err := service.Decide(context.Background(), *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "LGTM"}); err != nil {
		t.Fatalf("second approval: %v", err)
	}
	ticket, err = service.Decide(context.Background(), *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "LGTM"})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if ticket.TerraformCode == nil || strings.Contains(*ticket.TerraformCode, "resource \"aws_iam_group_membership\"") {
		t.Fatalf("published emptied membership file unexpected:\n%v", ticket.TerraformCode)
	}
}

// 校验拒绝：remove 的用户不在清单成员里 / 组有进行中的成员变更工单。
func TestUpdateGroupMembershipValidationRejects(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	repository.groupMembers = map[string][]string{"devs": {"alice"}}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	notMember := membershipTicketRequest("devs", MembershipOperationRemove, []string{"mallory"})
	if _, err := service.PreviewValidation(context.Background(), "requester", notMember); err == nil {
		t.Fatal("expected rejection for removing a non-member")
	} else if !strings.Contains(err.Error(), "are not members of group") {
		t.Fatalf("error should name the non-member: %v", err)
	}

	repository.activeMembershipTickets = map[string]int{"devs": 1}
	inFlight := membershipTicketRequest("devs", MembershipOperationAdd, []string{"bob"})
	if _, err := service.PreviewValidation(context.Background(), "requester", inFlight); err == nil {
		t.Fatal("expected rejection for in-flight membership ticket")
	} else if !strings.Contains(err.Error(), "membership change ticket in progress") {
		t.Fatalf("error should mention the concurrency lock: %v", err)
	}
}

func TestCreateGroupAdoptionRejectsAlreadyAdopted(t *testing.T) {
	request := CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateGroup,
		AccountID:     1,
		PrincipalName: "platform-readonly",
		AdoptExisting: true,
		CreateGroup:   &adapter.IAMGroupInfo{Name: "platform-readonly", Path: "/"},
	}
	seed := func() *memoryTicketRepository {
		repository := newMemoryTicketRepository()
		repository.existingPrincipals = map[string]bool{"Group/platform-readonly": true}
		repository.groupAdoptionSnapshot = adapter.IAMGroupInfo{Name: "platform-readonly", Path: "/"}
		return repository
	}

	// ① main 上已有该组的声明文件（非空）→ 拒绝导入。
	repository := seed()
	publisher := &memoryTicketPublisher{fetchFile: `resource "aws_iam_group" "group_platform-readonly" {}`}
	service := newTestTicketService(t, repository, publisher)
	_, err := service.PreviewValidation(context.Background(), "requester", request)
	if err == nil {
		t.Fatal("adopting a group whose declaration file already exists on main must fail")
	}
	if !strings.Contains(err.Error(), "已纳管") {
		t.Fatalf("error should say the group is already adopted: %v", err)
	}

	// ② 基线台账（PUBLISHED/MERGED）已覆盖声明文件 → 拒绝导入。
	repository2 := seed()
	repository2.baselineOwnedResourceFiles["group-platform-readonly"] = true
	service2 := newTestTicketService(t, repository2, &memoryTicketPublisher{})
	_, err = service2.PreviewValidation(context.Background(), "requester", request)
	if err == nil {
		t.Fatal("adopting a baseline-covered group must fail")
	}
	if !strings.Contains(err.Error(), "已由全量基线纳管") {
		t.Fatalf("error should mention the baseline: %v", err)
	}

	// ③ 声明文件不在 main（fetch 404）→ 放行，走既有采纳路径。
	repository3 := seed()
	publisher3 := &memoryTicketPublisher{fetchErr: fmt.Errorf("wrapped: %w", ErrTerraformFileNotFound)}
	service3 := newTestTicketService(t, repository3, publisher3)
	if _, err := service3.PreviewValidation(context.Background(), "requester", request); err != nil {
		t.Fatalf("adopting a not-yet-declared group must pass the adoption gate: %v", err)
	}

	// ④ main 上的文件已被清空成注释（资源已销毁）→ 放行重新导入。
	repository4 := seed()
	publisher4 := &memoryTicketPublisher{fetchFile: "# comment-only file after destroy"}
	service4 := newTestTicketService(t, repository4, publisher4)
	if _, err := service4.PreviewValidation(context.Background(), "requester", request); err != nil {
		t.Fatalf("re-adopting a destroyed resource must pass: %v", err)
	}
}

// A1 预留接口：CI 自动 apply 后的回调语义。
func TestRecordCIApplyResult(t *testing.T) {
	newService := func(t *testing.T) (*TicketService, *memoryTicketRepository) {
		t.Helper()
		repository := newMemoryTicketRepository()
		service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil)
		if err != nil {
			t.Fatalf("NewTicketService() error = %v", err)
		}
		return service, repository
	}

	t.Run("succeeded closes ticket as APPLIED", func(t *testing.T) {
		service, repository := newService(t)
		seedApprovedTicketWithPR(repository, "IAM-CI-1", "team/iac", "21")
		ticket, closed, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-1", "ci-runner",
			CIApplyResult{Status: CIApplyStatusSucceeded, CommitSHA: "abc123"})
		if err != nil || !closed {
			t.Fatalf("RecordCIApplyResult() = closed %v, error %v", closed, err)
		}
		if ticket.Status == nil || *ticket.Status != TicketStatusClosed || *ticket.ClosureReason != ClosureReasonApplied {
			t.Fatalf("ticket = %+v", ticket)
		}
	})

	t.Run("failed leaves ticket open but marks apply FAILED", func(t *testing.T) {
		service, repository := newService(t)
		seedApprovedTicketWithPR(repository, "IAM-CI-2", "team/iac", "22")
		ticket, closed, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-2", "ci-runner",
			CIApplyResult{
				Status:    CIApplyStatusFailed,
				CommitSHA: "deadbeef",
				CIURL:     "https://ci.example.com/run/2",
				Note:      "Error: creating IAM User: EntityAlreadyExists",
			})
		if err != nil || closed {
			t.Fatalf("RecordCIApplyResult() = closed %v, error %v", closed, err)
		}
		if ticket.Status == nil || *ticket.Status != TicketStatusApproved {
			t.Fatalf("ticket status = %v, want APPROVED", ticket.Status)
		}
		// A12②：失败必须落在工单上，前端靠它渲染横幅。
		if ticket.GitApplyResult == nil || *ticket.GitApplyResult != "FAILED" {
			t.Errorf("git_apply_result = %v, want FAILED", ticket.GitApplyResult)
		}
		if ticket.GitCIState == nil || *ticket.GitCIState != "FAILED" {
			t.Errorf("git_ci_state = %v, want FAILED", ticket.GitCIState)
		}
		if len(repository.ciApplyFailures) != 1 {
			t.Fatalf("recorded failures = %d, want 1", len(repository.ciApplyFailures))
		}
		recorded := repository.ciApplyFailures[0]
		if recorded.CIURL != "https://ci.example.com/run/2" || recorded.CommitSHA != "deadbeef" {
			t.Errorf("recorded failure = %+v", recorded)
		}
	})

	t.Run("failed does not overwrite an already closed ticket", func(t *testing.T) {
		service, repository := newService(t)
		seedApprovedTicketWithPR(repository, "IAM-CI-5", "team/iac", "25")
		if _, _, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-5", "ci-runner",
			CIApplyResult{Status: CIApplyStatusSucceeded}); err != nil {
			t.Fatalf("succeeded callback error = %v", err)
		}
		ticket, closed, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-5", "ci-runner",
			CIApplyResult{Status: CIApplyStatusFailed, Note: "stale retry"})
		if err != nil || !closed {
			t.Fatalf("failed retry = closed %v, error %v", closed, err)
		}
		if ticket.Status == nil || *ticket.Status != TicketStatusClosed {
			t.Fatalf("ticket status = %v, want CLOSED (terminal wins)", ticket.Status)
		}
		if ticket.GitApplyResult != nil && *ticket.GitApplyResult == "FAILED" {
			t.Errorf("closed ticket must not be marked FAILED: %v", ticket.GitApplyResult)
		}
		// 迟到失败必须留证据：状态不动，但失败现场要可回溯（审计要求）。
		if len(repository.ciApplyFailures) != 1 {
			t.Fatalf("late failure evidence = %d, want 1", len(repository.ciApplyFailures))
		}
		if repository.ciApplyFailures[0].Note != "stale retry" {
			t.Errorf("late failure note = %q", repository.ciApplyFailures[0].Note)
		}
	})

	t.Run("idempotent for already closed ticket", func(t *testing.T) {
		service, repository := newService(t)
		seedApprovedTicketWithPR(repository, "IAM-CI-3", "team/iac", "23")
		if _, _, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-3", "ci-runner",
			CIApplyResult{Status: CIApplyStatusSucceeded}); err != nil {
			t.Fatalf("first callback error = %v", err)
		}
		_, closed, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-3", "ci-runner",
			CIApplyResult{Status: CIApplyStatusSucceeded})
		if err != nil || !closed {
			t.Fatalf("retry callback = closed %v, error %v", closed, err)
		}
	})

	t.Run("rejects invalid status", func(t *testing.T) {
		service, repository := newService(t)
		seedApprovedTicketWithPR(repository, "IAM-CI-4", "team/iac", "24")
		if _, _, err := service.RecordCIApplyResult(context.Background(), "IAM-CI-4", "ci-runner",
			CIApplyResult{Status: "whatever"}); !apperr.IsValidationError(err) {
			t.Fatalf("expected validation error, got %v", err)
		}
	})
}
