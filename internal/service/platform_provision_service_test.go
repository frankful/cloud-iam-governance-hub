package service

import (
	"context"
	"strings"
	"testing"
)

// TestProvisionUserCreatesOneTicketPerAccount：每个目标账号一张
// CREATE_USER 工单，IAM 用户名 = 平台用户 ID，重复账号去重。
func TestProvisionUserCreatesOneTicketPerAccount(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	results, err := service.ProvisionUser(context.Background(), "admin", "test02", ProvisionUserRequest{
		Accounts:     []int64{1, 2, 1},
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"bob"},
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2 (deduplicated)", results)
	}
	for index, result := range results {
		if result.Error != "" || result.TicketNo == "" {
			t.Fatalf("result[%d] = %+v, want a ticket number without error", index, result)
		}
	}
	tickets, total, err := service.ListTickets(context.Background(), TicketListFilter{
		TicketType: TicketTypeCreateUser, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListTickets() error = %v", err)
	}
	if total != 2 || len(tickets) != 2 {
		t.Fatalf("created tickets = %d (total %d), want 2", len(tickets), total)
	}
	for _, ticket := range tickets {
		if ticket.PrincipalName == nil || *ticket.PrincipalName != "test02" {
			t.Fatalf("ticket principal = %+v, want test02", ticket.PrincipalName)
		}
	}
}

// TestProvisionUserValidatesInput：输入校验在创建任何工单之前发生。
func TestProvisionUserValidatesInput(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	ctx := context.Background()

	cases := []struct {
		name    string
		userID  string
		request ProvisionUserRequest
	}{
		{"no accounts", "test02", ProvisionUserRequest{ApprovalMode: ApprovalModeAuto}},
		{"bad account id", "test02", ProvisionUserRequest{Accounts: []int64{0}, ApprovalMode: ApprovalModeAuto}},
		{"too many accounts", "test02", ProvisionUserRequest{Accounts: makeAccounts(ProvisionUserMaxAccounts + 1), ApprovalMode: ApprovalModeAuto}},
		{"bad approval mode", "test02", ProvisionUserRequest{Accounts: []int64{1}, ApprovalMode: "SOMETIMES"}},
		{"manual without approvers", "test02", ProvisionUserRequest{Accounts: []int64{1}, ApprovalMode: ApprovalModeManual}},
		{"invalid iam name", "bad name!", ProvisionUserRequest{Accounts: []int64{1}, ApprovalMode: ApprovalModeAuto}},
		{"empty user id", "", ProvisionUserRequest{Accounts: []int64{1}, ApprovalMode: ApprovalModeAuto}},
	}
	for _, testCase := range cases {
		if _, err := service.ProvisionUser(ctx, "admin", testCase.userID, testCase.request); err == nil {
			t.Errorf("ProvisionUser(%s) expected an error", testCase.name)
		}
	}
	_, total, err := service.ListTickets(ctx, TicketListFilter{TicketType: TicketTypeCreateUser, Limit: 10})
	if err != nil {
		t.Fatalf("ListTickets() error = %v", err)
	}
	if total != 0 {
		t.Fatalf("tickets created during validation failures = %d, want 0", total)
	}
}

// TestProvisionUserSurfacesInlineErrors：工单创建失败逐账号内联返回，
// 批量本身不报错——调用方能看到每张失败工单的具体原因。同名冲突时
// 打上 conflict 标记，并给出「改用导入工单」的可执行提示。
func TestProvisionUserSurfacesInlineErrors(t *testing.T) {
	repository := newMemoryTicketRepository()
	// 两个账号同名主体都会撞上「已存在」校验 → 全部失败但逐账号内联。
	repository.existingPrincipals = map[string]bool{"User/test02": true}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	results, err := service.ProvisionUser(context.Background(), "admin", "test02", ProvisionUserRequest{
		Accounts:     []int64{1, 2},
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"bob"},
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v (batch must not abort)", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2", results)
	}
	for _, result := range results {
		if result.TicketNo != "" || result.Error == "" {
			t.Fatalf("result for account %d = %+v, want inline error without ticket", result.AccountID, result)
		}
		if result.Conflict != ProvisionConflictUserExists {
			t.Fatalf("result for account %d = %+v, want conflict %q", result.AccountID, result, ProvisionConflictUserExists)
		}
		if !strings.Contains(result.Error, "adopt_existing") {
			t.Fatalf("result error = %q, want an adopt_existing hint", result.Error)
		}
	}
	// 冲突账号不得留下任何草稿工单。
	if _, total, err := service.ListTickets(context.Background(), TicketListFilter{
		TicketType: TicketTypeCreateUser, Limit: 10,
	}); err != nil {
		t.Fatalf("ListTickets() error = %v", err)
	} else if total != 0 {
		t.Fatalf("tickets created for conflicting accounts = %d, want 0", total)
	}
}

func makeAccounts(count int) []int64 {
	accounts := make([]int64, 0, count)
	for index := 1; index <= count; index++ {
		accounts = append(accounts, int64(index))
	}
	return accounts
}

// TestProvisionUserSkipsDisabledAccounts：停用/未接入的账号不生成工单，
// 返回 account_disabled 冲突与可执行提示。
func TestProvisionUserSkipsDisabledAccounts(t *testing.T) {
	repository := newMemoryTicketRepository()
	disabled := false
	repository.accountSyncEnabled = &disabled
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	results, err := service.ProvisionUser(context.Background(), "admin", "test03", ProvisionUserRequest{
		Accounts:     []int64{1},
		ApprovalMode: ApprovalModeManual,
		ApproverIDs:  []string{"bob"},
	})
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %+v, want 1", results)
	}
	result := results[0]
	if result.TicketNo != "" || result.Conflict != ProvisionConflictAccountDisabled {
		t.Fatalf("result = %+v, want account_disabled without ticket", result)
	}
	if !strings.Contains(result.Error, "同步管理 → 账号") {
		t.Fatalf("error = %q, want guidance pointing at Sync Management → Accounts", result.Error)
	}

	// 全部账号不可用时不创建任何工单。
	tickets, total, err := service.ListTickets(context.Background(), TicketListFilter{
		TicketType: TicketTypeCreateUser, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListTickets() error = %v", err)
	}
	if total != 0 || len(tickets) != 0 {
		t.Fatalf("created tickets = %d (total %d), want 0", len(tickets), total)
	}
}
