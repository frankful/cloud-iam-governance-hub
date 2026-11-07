package service

import (
	"context"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// 文件 key 改造（item 24）：按资源而非按工单编号落文件——全量基线与后续工单
// 必须写同一个文件，否则同一资源会在两个文件里各声明一次（Terraform 报重复
// 资源，整个配置都不可用）。
func TestTerraformFileKeyIsResourceDerived(t *testing.T) {
	role := CreateIAMTicketRequest{
		TicketType: TicketTypeCreateRole,
		Role:       adapter.AWSRoleInfo{Name: "billing-reader"},
	}
	if key := role.terraformFileTicketNo("IAM-123"); key != "role-billing-reader" {
		t.Fatalf("CREATE_ROLE file key = %q, want role-billing-reader", key)
	}

	user := CreateIAMTicketRequest{
		TicketType: TicketTypeCreateUser,
		CreateUser: &adapter.IAMUserInfo{Name: "alice"},
	}
	if key := user.terraformFileTicketNo("IAM-124"); key != "user-alice" {
		t.Fatalf("CREATE_USER file key = %q, want user-alice", key)
	}

	group := CreateIAMTicketRequest{
		TicketType:  TicketTypeCreateGroup,
		CreateGroup: &adapter.IAMGroupInfo{Name: "devs"},
	}
	if key := group.terraformFileTicketNo("IAM-125"); key != "group-devs" {
		t.Fatalf("CREATE_GROUP file key = %q, want group-devs", key)
	}

	// 托管策略：创建与更新必须落在同一个文件，否则同一 aws_iam_policy 地址
	// 会出现在两个文件里（Terraform 直接报重复资源）。
	createKey := CreateIAMTicketRequest{
		TicketType:   TicketTypeCreateManagedPolicy,
		CreatePolicy: &adapter.ManagedPolicyInfo{Name: "TeamRead"},
	}.terraformFileTicketNo("IAM-126")
	updateKey := CreateIAMTicketRequest{
		TicketType: TicketTypeUpdateManagedPolicy,
		UpdatePolicy: &adapter.UpdatePolicyConfig{
			PolicyARN: "arn:aws:iam::111122223333:policy/TeamRead",
		},
	}.terraformFileTicketNo("IAM-127")
	if createKey != updateKey {
		t.Fatalf("managed policy create/update file keys differ: %q vs %q", createKey, updateKey)
	}

	attach := CreateIAMTicketRequest{
		TicketType:      TicketTypeAttachUserPolicy,
		PrincipalType:   "Role",
		PrincipalName:   "billing-reader",
		ManagedPolicyARN: "arn:aws:iam::aws:policy/ReadOnlyAccess",
	}
	if key := attach.terraformFileTicketNo("IAM-128"); key != "attachment-role-billing-reader-readonlyaccess" {
		t.Fatalf("ATTACH file key = %q", key)
	}
}

// 托管策略更新必须原地 patch：整文件重生成会丢掉 path/description/tags，
// 而 path 在 AWS provider 里是 ForceNew —— 一次「改文档」会变成策略重建，
// ARN 变化、所有挂载随之断裂。
func TestUpdateManagedPolicyPatchesFileKeepingMetadata(t *testing.T) {
	repository := newMemoryTicketRepository()
	repository.principalExists = true
	const arn = "arn:aws:iam::111122223333:policy/TeamRead"
	const existing = `resource "aws_iam_policy" "policy_TeamRead" {
	name        = "TeamRead"
	path        = "/finance/"
	description = "finance read access"
	policy      = jsonencode({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]})

	tags = {
		"owner" = "finance"
	}
}
`
	publisher := &memoryTicketPublisher{url: "https://github.example/iac/pull/60", fetchFile: existing}
	service := newTestTicketService(t, repository, publisher)
	// 清单里有这条策略（现网文档与提交内容不同 → 变更检测放行）
	repository.policyRecords[arn] = []byte(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`)

	request := updateManagedPolicyTicketRequest(arn,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["*"]}]}`)
	request.UpdatePolicy.PolicyName = "TeamRead"
	snapshot, err := service.PreviewValidation(context.Background(), "requester", request)
	if err != nil {
		t.Fatalf("PreviewValidation(managed policy update) error = %v", err)
	}
	preview := snapshot.TerraformPreview
	for _, want := range []string{
		`path        = "/finance/"`,
		`description = "finance read access"`,
		`"owner" = "finance"`,
	} {
		if !strings.Contains(preview, want) {
			t.Fatalf("patched file lost %q:\n%s", want, preview)
		}
	}
	if !strings.Contains(preview, "s3:PutObject") {
		t.Fatalf("patched file missing the new document:\n%s", preview)
	}
	if strings.Contains(preview, "s3:GetObject") {
		t.Fatalf("patched file still carries the old document:\n%s", preview)
	}
}
