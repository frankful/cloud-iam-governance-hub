package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// seedAppliedRequestTicket 造一张已 apply 关闭的目标工单，request_policy 存
// 原始请求（回滚要从中读出资源文件键与初始组）。
func seedAppliedRequestTicket(t *testing.T, repository *memoryTicketRepository, ticketNo string, request CreateIAMTicketRequest) {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal target request: %v", err)
	}
	status := TicketStatusClosed
	reason := ClosureReasonApplied
	principal := request.PrincipalName
	accountID := request.AccountID
	ticketType := request.TicketType
	repository.tickets[ticketNo] = model.IAMTicket{
		TicketNo:      stringPointer(ticketNo),
		TicketType:    &ticketType,
		AccountID:     &accountID,
		PrincipalName: &principal,
		Status:        &status,
		ClosureReason: &reason,
		RequestPolicy: model.JSONB(payload),
	}
}

const declaredMembershipFixture = `resource "aws_iam_group_membership" "group_deployers_membership" {
	name  = "deployers-membership"
	group = "deployers"
	users = [
		"alice",
		"app-deployer",
	]
}
`

// TestCreateUserRollbackCleansUpMembershipFiles：回滚建用户工单必须把该用户从
// 组声明里移除。否则 destroy 用户之后 membership 仍在声明一个不存在的 user，
// apply 直接失败（A8 把成员关系收敛到组文件后新增的依赖）。
func TestCreateUserRollbackCleansUpMembershipFiles(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-CREATE-USER", CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateUser,
		AccountID:     1,
		PrincipalName: "app-deployer",
		CreateUser: &adapter.IAMUserInfo{
			Name:       "app-deployer",
			GroupNames: []string{"deployers"},
		},
	})
	publisher := &memoryTicketPublisher{fetchFile: declaredMembershipFixture}
	service := newTestTicketService(t, repository, publisher)
	request := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-CREATE-USER",
		AccountID:      1,
		PrincipalName:  "app-deployer",
		TargetFileKey:  "user-app-deployer",
	}

	preview, files, err := service.buildTicketTerraformFiles(
		context.Background(), validationStubTicket(request), request, false,
	)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %+v, want user file + membership file", files)
	}
	if files[0].Key != "user-app-deployer" || !strings.Contains(files[0].Content, "ROLLBACK of IAM ticket IAM-CREATE-USER") {
		t.Fatalf("user file = %+v, want rollback comment under the resource file key", files[0])
	}
	if files[1].Key != "group-deployers-membership" {
		t.Fatalf("membership file key = %q", files[1].Key)
	}
	if strings.Contains(files[1].Content, `"app-deployer"`) {
		t.Errorf("rolled back user still declared as a member:\n%s", files[1].Content)
	}
	if !strings.Contains(files[1].Content, `"alice"`) {
		t.Errorf("other members must survive the rollback:\n%s", files[1].Content)
	}
	if !strings.Contains(preview, "# File: group-deployers-membership.tf") {
		t.Errorf("preview must name every file:\n%s", preview)
	}
}

// TestCreateUserRollbackEmptiesMembershipWhenLastMember：只剩这名用户时，移除
// 后成员列表为空 → 落成注释空文件，plan 才会销毁 membership 资源。
func TestCreateUserRollbackEmptiesMembershipWhenLastMember(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-CREATE-SOLO", CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateUser,
		AccountID:     1,
		PrincipalName: "solo",
		CreateUser: &adapter.IAMUserInfo{
			Name:       "solo",
			GroupNames: []string{"solo-group"},
		},
	})
	publisher := &memoryTicketPublisher{fetchFile: `resource "aws_iam_group_membership" "group_solo-group_membership" {
	name  = "solo-group-membership"
	group = "solo-group"
	users = [
		"solo",
	]
}
`}
	service := newTestTicketService(t, repository, publisher)
	request := CreateIAMTicketRequest{
		TicketType:     TicketTypeRollback,
		TargetTicketNo: "IAM-CREATE-SOLO",
		AccountID:      1,
		PrincipalName:  "solo",
		TargetFileKey:  "user-solo",
	}

	_, files, err := service.buildTicketTerraformFiles(
		context.Background(), validationStubTicket(request), request, false,
	)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %+v, want user file + emptied membership file", files)
	}
	emptied := files[1].Content
	if strings.Contains(emptied, `resource "aws_iam_group_membership"`) {
		t.Errorf("membership declaration must be gone to destroy the resource:\n%s", emptied)
	}
	if !strings.Contains(emptied, "GROUP MEMBERSHIP emptied") {
		t.Errorf("emptied file must explain itself:\n%s", emptied)
	}
}

// TestRollbackTargetFileKeyResolvesResourceFile：回滚写的是目标资源命名的
// 文件（user-<name>.tf），不是「以工单号命名」的历史文件；否则空文件落在别
// 的路径上，plan 什么都不会销毁。
func TestRollbackTargetFileKeyResolvesResourceFile(t *testing.T) {
	repository := newMemoryTicketRepository()
	seedAppliedRequestTicket(t, repository, "IAM-CREATE-USER", CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateUser,
		AccountID:     1,
		PrincipalName: "app-deployer",
		CreateUser:    &adapter.IAMUserInfo{Name: "app-deployer"},
	})
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	request, err := service.validateRequestShape(
		context.Background(), rollbackTicketRequest("IAM-CREATE-USER"),
	)
	if err != nil {
		t.Fatalf("validateRequestShape(ROLLBACK) error = %v", err)
	}
	if request.TargetFileKey != "user-app-deployer" {
		t.Fatalf("target_file_key = %q, want user-app-deployer", request.TargetFileKey)
	}
	if key := request.terraformFileTicketNo("IAM-ROLLBACK"); key != "user-app-deployer" {
		t.Fatalf("rollback Terraform file key = %q, want the resource file", key)
	}
}
