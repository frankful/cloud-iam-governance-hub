package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

func createPolicyRequest(name string, adopt bool) CreateIAMTicketRequest {
	return CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateManagedPolicy,
		AccountID:     1,
		ApprovalMode:  ApprovalModeAuto,
		AdoptExisting: adopt,
		CreatePolicy: &adapter.ManagedPolicyInfo{
			Name: name,
			Path: "/",
			Document: json.RawMessage(`{
				"Version": "2012-10-17",
				"Statement": [{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::example/*"}]
			}`),
			Tags: map[string]string{"team": "platform"},
		},
	}
}

func TestCreateManagedPolicyTicketAndPreview(t *testing.T) {
	repository := newMemoryTicketRepository()
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := createPolicyRequest("s3-readonly", false)

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_policy" "managed_policy_s3-readonly"`,
		`name   = "s3-readonly"`,
		`"team" = "platform"`,
	} {
		if !strings.Contains(snapshot.TerraformPreview, want) {
			t.Errorf("preview missing %q:\n%s", want, snapshot.TerraformPreview)
		}
	}

	draft, err := service.CreateDraft(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateDraft() error = %v", err)
	}
	if draft.PrincipalName == nil || *draft.PrincipalName != "s3-readonly" {
		t.Fatalf("draft principal_name = %v, want s3-readonly", draft.PrincipalName)
	}
	if got := draftPrincipalType(t, draft); got != "Policy" {
		t.Fatalf("draft principal_type = %q, want Policy", got)
	}
}

func TestCreateManagedPolicyRejectsExistingUnlessAdopted(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.policyRecords["arn:aws:iam::123456789012:policy/s3-readonly"] = json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})

	if _, err := service.CreateDraft(context.Background(), "requester", createPolicyRequest("s3-readonly", false)); err == nil {
		t.Fatal("creating an existing policy without adopt_existing must fail")
	}

	snapshot, err := service.PreviewValidation(context.Background(), "requester", createPolicyRequest("s3-readonly", true))
	if err != nil {
		t.Fatalf("PreviewValidation(adopt) error = %v", err)
	}
	if !strings.Contains(snapshot.TerraformPreview, `import {`) ||
		!strings.Contains(snapshot.TerraformPreview, `to = aws_iam_policy.managed_policy_s3-readonly`) {
		t.Errorf("adoption preview must contain import block:\n%s", snapshot.TerraformPreview)
	}
}

func TestCreateUserTicketWithMembershipAndAttachments(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.existingPrincipals = map[string]bool{
		"Group/deployers":   true,
		"User/app-deployer": false,
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := CreateIAMTicketRequest{
		TicketType:   TicketTypeCreateUser,
		AccountID:    1,
		ApprovalMode: ApprovalModeAuto,
		CreateUser: &adapter.IAMUserInfo{
			Name:       "app-deployer",
			Path:       "/platform/",
			Tags:       map[string]string{"team": "platform"},
			GroupNames: []string{"deployers"},
			PolicyARNs: []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		},
	}

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation() error = %v", err)
	}
	for _, want := range []string{
		`# File: user-app-deployer.tf`,
		`resource "aws_iam_user" "user_app-deployer"`,
		`# File: group-deployers-membership.tf`,
		`resource "aws_iam_group_membership" "group_deployers_membership"`,
		`"app-deployer"`,
		`resource "aws_iam_user_policy_attachment" "attachment_user_app-deployer_ReadOnlyAccess"`,
	} {
		if !strings.Contains(snapshot.TerraformPreview, want) {
			t.Errorf("preview missing %q:\n%s", want, snapshot.TerraformPreview)
		}
	}
	// 成员关系只有一个 owner：用户文件不能同时声明 user 维度成员关系。
	if strings.Contains(snapshot.TerraformPreview, `aws_iam_user_group_membership`) {
		t.Errorf("preview must not declare aws_iam_user_group_membership:\n%s", snapshot.TerraformPreview)
	}
	if strings.Contains(strings.ToLower(snapshot.TerraformPreview), "access_key") {
		t.Errorf("user creation must not create credentials:\n%s", snapshot.TerraformPreview)
	}

	draft, err := service.CreateDraft(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateDraft() error = %v", err)
	}
	if got := draftPrincipalType(t, draft); got != "User" {
		t.Fatalf("draft principal_type = %q, want User", got)
	}

	// 发布产物是两个文件：用户本体 + 组 membership（成员关系只有一个 owner）。
	_, files, err := service.buildTicketTerraformFiles(context.Background(), draft, request, false)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v", err)
	}
	keys := make([]string, 0, len(files))
	for _, file := range files {
		keys = append(keys, file.Key)
	}
	if len(files) != 2 || keys[0] != "user-app-deployer" || keys[1] != "group-deployers-membership" {
		t.Fatalf("bundle files = %v, want [user-app-deployer group-deployers-membership]", keys)
	}
}

// TestCreateUserMembershipFilePatchesDeclaredUsers：main 上已有 membership 文件
// 时，创建用户工单必须原地追加（保留既有成员与资源 label），而不是覆盖成
// 只有新用户——否则 apply 会把手工维护的成员全部移出组。
func TestCreateUserMembershipFilePatchesDeclaredUsers(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.existingPrincipals = map[string]bool{
		"Group/deployers":   true,
		"User/app-deployer": false,
	}
	publisher := &memoryTicketPublisher{fetchFile: `resource "aws_iam_group_membership" "group_deployers_membership" {
	name  = "deployers-membership"
	group = "deployers"
	users = [
		"alice",
	]
}
`}
	service := newTestTicketService(t, repository, publisher)
	request := CreateIAMTicketRequest{
		TicketType:   TicketTypeCreateUser,
		AccountID:    1,
		ApprovalMode: ApprovalModeAuto,
		CreateUser: &adapter.IAMUserInfo{
			Name:       "app-deployer",
			GroupNames: []string{"deployers"},
		},
	}

	_, files, err := service.buildTicketTerraformFiles(context.Background(), validationStubTicket(request), request, false)
	if err != nil {
		t.Fatalf("buildTicketTerraformFiles() error = %v", err)
	}
	if publisher.fetchRequest.UpdateMembership == nil ||
		publisher.fetchRequest.UpdateMembership.GroupName != "deployers" {
		t.Fatalf("membership fetch must target group deployers, got %+v", publisher.fetchRequest.UpdateMembership)
	}
	if len(files) != 2 {
		t.Fatalf("files = %+v, want 2", files)
	}
	membership := files[1].Content
	for _, want := range []string{
		`"group_deployers_membership"`,
		`"app-deployer"`,
		`"alice"`,
	} {
		if !strings.Contains(membership, want) {
			t.Errorf("patched membership missing %q:\n%s", want, membership)
		}
	}
	if strings.Count(membership, `resource "aws_iam_group_membership"`) != 1 {
		t.Errorf("membership must stay a single declaration:\n%s", membership)
	}
}

func TestCreateUserRejectsExistingAndAdoptionAssociations(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.existingPrincipals = map[string]bool{
		"Group/deployers":   true,
		"User/app-deployer": true,
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := CreateIAMTicketRequest{
		TicketType:   TicketTypeCreateUser,
		AccountID:    1,
		ApprovalMode: ApprovalModeAuto,
		CreateUser: &adapter.IAMUserInfo{
			Name: "app-deployer",
		},
	}
	if _, err := service.CreateDraft(context.Background(), "requester", request); err == nil {
		t.Fatal("creating an existing user without adopt_existing must fail")
	}

	request.AdoptExisting = true
	request.CreateUser.GroupNames = []string{"deployers"}
	if _, err := service.CreateDraft(context.Background(), "requester", request); err == nil {
		t.Fatal("adoption with group membership must fail")
	}
}

func TestCreateGroupTicketWithMembersAndAttachments(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.existingPrincipals = map[string]bool{
		"User/alice":              true,
		"User/bob":                true,
		"Group/platform-readonly": false,
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := CreateIAMTicketRequest{
		TicketType:   TicketTypeCreateGroup,
		AccountID:    1,
		ApprovalMode: ApprovalModeAuto,
		CreateGroup: &adapter.IAMGroupInfo{
			Name:            "platform-readonly",
			Path:            "/platform/",
			Tags:            map[string]string{"team": "platform"},
			MemberUserNames: []string{"alice", "bob"},
			PolicyARNs:      []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		},
	}

	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_group" "group_platform-readonly"`,
		`resource "aws_iam_group_membership" "group_platform-readonly_membership"`,
		`resource "aws_iam_group_policy_attachment" "attachment_group_platform-readonly_ReadOnlyAccess"`,
		`"alice"`,
		`"bob"`,
	} {
		if !strings.Contains(snapshot.TerraformPreview, want) {
			t.Errorf("preview missing %q:\n%s", want, snapshot.TerraformPreview)
		}
	}
	if !strings.Contains(string(snapshot.Checks), "GROUP_MEMBERSHIP") {
		t.Errorf("group creation must record membership impact evidence: %s", snapshot.Checks)
	}

	draft, err := service.CreateDraft(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("CreateDraft() error = %v", err)
	}
	if got := draftPrincipalType(t, draft); got != "Group" {
		t.Fatalf("draft principal_type = %q, want Group", got)
	}
}

func draftPrincipalType(t *testing.T, ticket model.IAMTicket) string {
	t.Helper()
	var request CreateIAMTicketRequest
	if err := json.Unmarshal(ticket.RequestPolicy, &request); err != nil {
		t.Fatalf("decode draft request: %v", err)
	}
	return request.PrincipalType
}

func TestCreateGroupRejectsMissingMember(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.existingPrincipals = map[string]bool{
		"User/alice":              true,
		"Group/platform-readonly": false,
	}
	service := newTestTicketService(t, repository, &memoryTicketPublisher{})
	request := CreateIAMTicketRequest{
		TicketType:   TicketTypeCreateGroup,
		AccountID:    1,
		ApprovalMode: ApprovalModeAuto,
		CreateGroup: &adapter.IAMGroupInfo{
			Name:            "platform-readonly",
			MemberUserNames: []string{"alice", "missing-user"},
		},
	}
	if _, err := service.CreateDraft(context.Background(), "requester", request); err == nil {
		t.Fatal("creating a group with a missing member must fail")
	}
}
