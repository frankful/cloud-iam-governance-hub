package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
)

// 回滚能力（台账 C14）。回滚只有在「反向操作能落到目标工单自己写过的文件」
// 时才有意义；映射不出来的类型以前会落到兜底分支，按工单号生成一份注释空文件，
// PR 合并、plan 零变更、工单却显示已回滚。这些用例锁定「明确拒绝」，而不是
// 给出空操作的成功。

func TestRollbackSupportedTargetTypes(t *testing.T) {
	supported := []string{
		TicketTypeCreateRole, TicketTypeCreateUser, TicketTypeCreateGroup,
		TicketTypeCreateManagedPolicy, TicketTypeUpdateRole,
		TicketTypeUpdateManagedPolicy, TicketTypeUpdateGroupInlinePolicy,
		TicketTypeUpdateGroupMembership, TicketTypeAttachUserPolicy,
	}
	for _, ticketType := range supported {
		if !RollbackSupportedTargetType(ticketType) {
			t.Errorf("RollbackSupportedTargetType(%q) = false, want true", ticketType)
		}
	}
	unsupported := []string{
		TicketTypeAdoptRoleInlinePolicies,
		TicketTypeRollback,
		"",
	}
	for _, ticketType := range unsupported {
		if RollbackSupportedTargetType(ticketType) {
			t.Errorf("RollbackSupportedTargetType(%q) = true, want false", ticketType)
		}
	}
}

// 批量纳管的声明按策略拆成多份文件，回滚没有「单个文件」可清空。
func TestRollbackRejectsBatchAdoptionTarget(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-ADOPT", CreateIAMTicketRequest{
		TicketType:    TicketTypeAdoptRoleInlinePolicies,
		AccountID:     1,
		PrincipalName: "app",
	})
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, err := service.validateRequestShape(context.Background(), CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-ADOPT",
		AccountID:      1,
	})
	if err == nil {
		t.Fatal("expected the batch-adoption rollback to be rejected")
	}
	var validationError *apperr.ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error = %v, want a validation error (400, not 500)", err)
	}
	if !strings.Contains(err.Error(), "does not support rollback") {
		t.Fatalf("error = %v, want it to say the ticket type cannot be rolled back", err)
	}
	// 文案要给出可执行的替代路径，否则用户只知道「不行」。
	if !strings.Contains(err.Error(), TicketTypeAttachUserPolicy) {
		t.Fatalf("error = %v, want it to point at the detach path", err)
	}
}

// 回滚一张回滚工单同样没有定义（自我抵消的语义还没设计）。
func TestRollbackRejectsRollbackTarget(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-ROLLBACK-OLD", CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		AccountID:      1,
		PrincipalName:  "app",
		TargetTicketNo: "IAM-CREATE-ROLE",
	})
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, err := service.validateRequestShape(context.Background(), CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-ROLLBACK-OLD",
		AccountID:      1,
	})
	if err == nil || !strings.Contains(err.Error(), "does not support rollback") {
		t.Fatalf("error = %v, want the rollback-of-rollback to be rejected", err)
	}
}

// 回滚「挂载」应当是卸载，但卸载走独立链路（定位源挂载 + 基线归属检查），
// 回滚工单不复用；以前它会静默落成空文件。
func TestRollbackRejectsAttachTarget(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-ATTACH", CreateIAMTicketRequest{
		TicketType:       TicketTypeAttachUserPolicy,
		AccountID:        1,
		PrincipalName:    "app",
		PrincipalType:    "User",
		Operation:        OperationAttach,
		ManagedPolicyARN: "arn:aws:iam::123456789012:policy/demo",
	})
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, err := service.validateRequestShape(context.Background(), CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-ATTACH",
		AccountID:      1,
	})
	if err == nil {
		t.Fatal("expected the attach rollback to be rejected")
	}
	if !strings.Contains(err.Error(), "detach ticket") {
		t.Fatalf("error = %v, want it to name the detach path", err)
	}
}

// 兜底不再生成空文件：即使有人绕过 validateRequestShape 直接调生成器，
// 也必须拿到错误而不是一份「什么都没撤销」的注释文件。
func TestBuildRollbackTerraformRejectsUnmappedShape(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-ADOPT", CreateIAMTicketRequest{
		TicketType:    TicketTypeAdoptRoleInlinePolicies,
		AccountID:     1,
		PrincipalName: "app",
	})
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	code, err := service.buildRollbackTerraform(context.Background(), "IAM-ROLLBACK", CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-ADOPT",
		AccountID:      1,
		PrincipalName:  "app",
	})
	if err == nil {
		t.Fatalf("expected an error, got a Terraform file %q that would destroy nothing", code)
	}
	var validationError *apperr.ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error = %v, want a validation error", err)
	}
}
