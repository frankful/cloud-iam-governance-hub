package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// 整文件重写的归属检查（台账 C6，设计文档 §5）。回滚会把目标文件整份清空，
// 这些用例锁定三件事：
//   1. 文件键只能由目标工单推导，请求体里的 target_file_key 一律忽略；
//   2. 只有当主文件（目标工单自己的资源声明）当前仍由它声明时，才允许清空；
//   3. membership 这类副作用文件不参与判断：基线维护的成员关系里清掉最后一名
//      成员，是回滚本身必须做的事。

func seedCreateUserTarget(t *testing.T, repository *memoryTicketRepository) {
	t.Helper()
	seedAppliedRequestTicket(t, repository, "IAM-CREATE-USER", CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateUser,
		AccountID:     1,
		PrincipalName: "app-deployer",
		CreateUser:    &adapter.IAMUserInfo{Name: "app-deployer"},
	})
}

// 请求体里的 target_file_key 是服务端字段：带进来必须被忽略，否则回滚就成了
// 「清空任意文件」的入口（填 role-admin 就能删掉基线的声明）。
func TestRollbackIgnoresClientSuppliedTargetFileKey(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-UPDATE-ROLE", CreateIAMTicketRequest{
		TicketType:     TicketTypeUpdateRole,
		AccountID:      1,
		PrincipalName:  "app",
		SourceTicketNo: "IAM-CREATE-ROLE",
	})
	target := repository.tickets["IAM-UPDATE-ROLE"]
	target.RoleSnapshot = model.JSONB(`{"name":"app","description":"","max_session_duration":3600}`)
	repository.tickets["IAM-UPDATE-ROLE"] = target
	service := newTestTicketService(t, repository, &memoryTicketPublisher{
		fetchFile: "resource \"aws_iam_role\" \"app\" {\n  name = \"app\"\n}\n",
	})

	request := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-UPDATE-ROLE",
		AccountID:      1,
		PrincipalName:  "app",
		TargetFileKey:  "role-someone-else",
	}
	cleaned, err := service.validateRequestShape(context.Background(), request)
	if err != nil {
		t.Fatalf("validateRequestShape(ROLLBACK) error = %v", err)
	}
	if cleaned.TargetFileKey != "" {
		t.Fatalf("target_file_key = %q, want it cleared: the client must not choose the file", cleaned.TargetFileKey)
	}
	if key := cleaned.terraformFileTicketNo("IAM-ROLLBACK"); key != "IAM-CREATE-ROLE" {
		t.Fatalf("rollback file key = %q, want the source ticket file", key)
	}
}

// 文件已被基线发布纳管时，回滚不能整份清空它。
func TestRollbackRefusesToEmptyBaselineOwnedFile(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedCreateUserTarget(t, repository)
	repository.fileDeclarationOwners["user-app-deployer"] = []int64{0}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, _, err := service.buildTicketTerraformFiles(
		context.Background(),
		validationStubTicket(CreateIAMTicketRequest{AccountID: 1}),
		CreateIAMTicketRequest{
			TicketType:     TicketTypeRollback,
			TargetTicketNo: "IAM-CREATE-USER",
			AccountID:      1,
			PrincipalName:  "app-deployer",
			TargetFileKey:  "user-app-deployer",
		},
		false,
	)
	if err == nil {
		t.Fatal("expected the rollback to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "全量基线纳管") {
		t.Fatalf("error = %v, want it to explain the file belongs to the baseline", err)
	}
}

// 文件被另一张工单接管时同样拒绝：清空它等于替那张工单删声明。
func TestRollbackRefusesToEmptyFileDeclaredByAnotherTicket(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedCreateUserTarget(t, repository)
	repository.tickets["IAM-CREATE-USER"] = withTicketID(repository.tickets["IAM-CREATE-USER"], 77)
	repository.fileDeclarationOwners["user-app-deployer"] = []int64{99}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, _, err := service.buildTicketTerraformFiles(
		context.Background(),
		validationStubTicket(CreateIAMTicketRequest{AccountID: 1}),
		CreateIAMTicketRequest{
			TicketType:     TicketTypeRollback,
			TargetTicketNo: "IAM-CREATE-USER",
			AccountID:      1,
			PrincipalName:  "app-deployer",
			TargetFileKey:  "user-app-deployer",
		},
		false,
	)
	if err == nil {
		t.Fatal("expected the rollback to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "另一张工单") {
		t.Fatalf("error = %v, want it to name the other ticket as the owner", err)
	}
}

// 文件仍归被回滚的工单时正常放行（不能把正常回滚一起挡住）。
func TestRollbackAllowsEmptyingOwnFile(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedCreateUserTarget(t, repository)
	repository.tickets["IAM-CREATE-USER"] = withTicketID(repository.tickets["IAM-CREATE-USER"], 77)
	repository.fileDeclarationOwners["user-app-deployer"] = []int64{77}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, files, err := service.buildTicketTerraformFiles(
		context.Background(),
		validationStubTicket(CreateIAMTicketRequest{AccountID: 1}),
		CreateIAMTicketRequest{
			TicketType:     TicketTypeRollback,
			TargetTicketNo: "IAM-CREATE-USER",
			AccountID:      1,
			PrincipalName:  "app-deployer",
			TargetFileKey:  "user-app-deployer",
		},
		false,
	)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v, want the owner to be allowed", err)
	}
	if len(files) != 0 {
		t.Fatalf("files = %+v, want the single-file rollback path", files)
	}
}

// 没有声明快照的存量文件（P2 之前）放行：拒绝会让历史回滚全部失败。
func TestRollbackAllowsEmptyingFileWithoutDeclarationSnapshot(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedCreateUserTarget(t, repository)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	if _, _, err := service.buildTicketTerraformFiles(
		context.Background(),
		validationStubTicket(CreateIAMTicketRequest{AccountID: 1}),
		CreateIAMTicketRequest{
			TicketType:     TicketTypeRollback,
			TargetTicketNo: "IAM-CREATE-USER",
			AccountID:      1,
			PrincipalName:  "app-deployer",
			TargetFileKey:  "user-app-deployer",
		},
		false,
	); err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v, want legacy files to pass", err)
	}
}

// 目标工单自己推导出的文件键与请求里的不一致时，buildCreateRollbackBundle
// 必须拒绝 —— 防止将来出现绕过 validateRequestShape 的调用方。
func TestRollbackRejectsMismatchedTargetFileKey(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedCreateUserTarget(t, repository)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	_, _, err := service.buildCreateRollbackBundle(context.Background(), "IAM-ROLLBACK", CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-CREATE-USER",
		AccountID:      1,
		PrincipalName:  "app-deployer",
		TargetFileKey:  "role-victim",
	})
	if err == nil {
		t.Fatal("expected the mismatched file key to be rejected")
	}
	var validationError *apperr.ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error = %v, want a validation error", err)
	}
}

func withTicketID(ticket model.IAMTicket, id int64) model.IAMTicket {
	ticket.ID = id
	return ticket
}

// 回滚被删用户时，若该用户恰是基线维护的组成员关系里的最后一名成员，
// membership 文件会被清空——这是回滚本身的效果，不能因此拦住整张工单。
func TestRollbackAllowsEmptyingBaselineMembershipFileAsSideEffect(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-CREATE-USER", CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateUser,
		AccountID:     1,
		PrincipalName: "app-deployer",
		CreateUser: &adapter.IAMUserInfo{
			Name:       "app-deployer",
			GroupNames: []string{"outreadonly"},
		},
	})
	repository.tickets["IAM-CREATE-USER"] = withTicketID(repository.tickets["IAM-CREATE-USER"], 1)
	repository.fileDeclarationOwners["user-app-deployer"] = []int64{1}
	// 成员关系文件由基线声明：清空它不等于「删了别人的资源」，而是回滚的必然结果。
	repository.fileDeclarationOwners["group-outreadonly-membership"] = []int64{0}
	publisher := &memoryTicketPublisher{fetchFile: `resource "aws_iam_group_membership" "group_outreadonly_membership" {
	name  = "outreadonly-membership"
	group = "outreadonly"
	users = [
		"app-deployer",
	]
}
`}
	service := newTestTicketService(t, repository, publisher)

	_, files, err := service.buildTicketTerraformFiles(
		context.Background(),
		validationStubTicket(CreateIAMTicketRequest{AccountID: 1}),
		CreateIAMTicketRequest{
			TicketType:     TicketTypeRollback,
			TargetTicketNo: "IAM-CREATE-USER",
			AccountID:      1,
			PrincipalName:  "app-deployer",
			TargetFileKey:  "user-app-deployer",
		},
		false,
	)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v, want the membership side effect to pass", err)
	}
	if len(files) != 2 || files[1].Key != "group-outreadonly-membership" {
		t.Fatalf("files = %+v, want the emptied membership file next to the user file", files)
	}
}
