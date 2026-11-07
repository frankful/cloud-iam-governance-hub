package adapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateCreateManagedPolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	policy := ManagedPolicyInfo{
		Name:        "s3-readonly",
		Description: "read only bucket access",
		Path:        "/platform/",
		Document: json.RawMessage(`{
			"Version": "2012-10-17",
			"Statement": [{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::example/*"}]
		}`),
		Tags: map[string]string{"team": "platform"},
	}
	hcl, err := adapter.GenerateCreateManagedPolicyTerraform(policy, "")
	if err != nil {
		t.Fatalf("GenerateCreateManagedPolicyTerraform() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_policy" "managed_policy_s3-readonly"`,
		`name   = "s3-readonly"`,
		`path   = "/platform/"`,
		`description = "read only bucket access"`,
		`jsonencode(`,
		`"team" = "platform"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("managed policy file missing %q:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "import {") {
		t.Errorf("new policy must not import:\n%s", hcl)
	}

	hcl, err = adapter.GenerateCreateManagedPolicyTerraform(policy, "arn:aws:iam::123456789012:policy/platform/s3-readonly")
	if err != nil {
		t.Fatalf("GenerateCreateManagedPolicyTerraform(import) error = %v", err)
	}
	if !strings.Contains(hcl, `import {`) ||
		!strings.Contains(hcl, `to = aws_iam_policy.managed_policy_s3-readonly`) ||
		!strings.Contains(hcl, `arn:aws:iam::123456789012:policy/platform/s3-readonly`) {
		t.Errorf("adopted policy must emit import block:\n%s", hcl)
	}
}

func TestGenerateCreateUserTerraformKeepsCredentialsOut(t *testing.T) {
	adapter := AWSAdapter{}
	user := IAMUserInfo{
		Name:       "app-deployer",
		Path:       "/platform/",
		Tags:       map[string]string{"team": "platform"},
		GroupNames: []string{"deployers", "readers"},
		PolicyARNs: []string{
			"arn:aws:iam::aws:policy/ReadOnlyAccess",
			"arn:aws:iam::123456789012:policy/s3-readonly",
		},
	}
	hcl, err := adapter.GenerateCreateUserTerraform(user, "")
	if err != nil {
		t.Fatalf("GenerateCreateUserTerraform() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_user" "user_app-deployer"`,
		// 组归属由各组的 membership 文件声明；用户文件只留一行指向说明。
		`# Group membership is owned by each group's own file`,
		`deployers, readers`,
		`resource "aws_iam_user_policy_attachment" "attachment_user_app-deployer_ReadOnlyAccess"`,
		`resource "aws_iam_user_policy_attachment" "attachment_user_app-deployer_s3-readonly"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("user file missing %q:\n%s", want, hcl)
		}
	}
	// 同一 (user, group) 边只能有一个 owner：用户文件不得再声明 user 维度的成员关系。
	if strings.Contains(hcl, `aws_iam_user_group_membership`) {
		t.Errorf("user file must not declare aws_iam_user_group_membership (membership is group-owned):\n%s", hcl)
	}
	for _, forbidden := range []string{"aws_iam_access_key", "aws_iam_user_login_profile", "password"} {
		if strings.Contains(strings.ToLower(hcl), forbidden) {
			t.Errorf("user file must not contain credentials (%s):\n%s", forbidden, hcl)
		}
	}

	// Removing one attachment must leave the user and the other attachment.
	updated, err := adapter.RemoveAttachmentFromTerraform(
		hcl, "User", "app-deployer", "arn:aws:iam::aws:policy/ReadOnlyAccess",
	)
	if err != nil {
		t.Fatalf("RemoveAttachmentFromTerraform() error = %v", err)
	}
	if strings.Contains(updated, `"attachment_user_app-deployer_ReadOnlyAccess"`) {
		t.Errorf("removed attachment block still present:\n%s", updated)
	}
	if !strings.Contains(updated, `resource "aws_iam_user" "user_app-deployer"`) ||
		!strings.Contains(updated, `"attachment_user_app-deployer_s3-readonly"`) {
		t.Errorf("removal must preserve user and sibling attachment:\n%s", updated)
	}
}

func TestGenerateCreateGroupTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	group := IAMGroupInfo{
		Name:            "platform-readonly",
		Path:            "/platform/",
		Tags:            map[string]string{"team": "platform"},
		MemberUserNames: []string{"alice", "bob"},
		PolicyARNs:      []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		InlinePolicies: []IAMInlinePolicy{{
			Name:     "InlineReadOnly",
			Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`),
		}},
	}
	hcl, err := adapter.GenerateCreateGroupTerraform(group, "")
	if err != nil {
		t.Fatalf("GenerateCreateGroupTerraform() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_group" "group_platform-readonly"`,
		`# Membership is owned by group-<group>-membership.tf`,
		`alice, bob`,
		`resource "aws_iam_group_policy_attachment" "attachment_group_platform-readonly_ReadOnlyAccess"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("group file missing %q:\n%s", want, hcl)
		}
	}
	// 组文件不再声明成员关系：与基线的 group-<group>-membership.tf 会撞同一个
	// Terraform 地址（A8）。
	if strings.Contains(hcl, `resource "aws_iam_group_membership"`) {
		t.Errorf("group file must not declare aws_iam_group_membership:\n%s", hcl)
	}

	hcl, err = adapter.GenerateCreateGroupTerraform(group, "platform-readonly")
	if err != nil {
		t.Fatalf("GenerateCreateGroupTerraform(import) error = %v", err)
	}
	if !strings.Contains(hcl, `to = aws_iam_group.group_platform-readonly`) {
		t.Errorf("adopted group must emit import block:\n%s", hcl)
	}
	for _, want := range []string{
		`to = aws_iam_group.group_platform-readonly`,
		`id = "platform-readonly/arn:aws:iam::aws:policy/ReadOnlyAccess"`,
		`to = aws_iam_group_policy_attachment.attachment_group_platform-readonly_ReadOnlyAccess`,
		`id = "platform-readonly/InlineReadOnly"`,
		`to = aws_iam_group_policy.group_platform-readonly_pfmot_InlineReadOnly`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("adopted group must import existing group relationships; missing %q:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, `to = aws_iam_group_membership.`) {
		t.Errorf("aws_iam_group_membership does not support import; no import block expected:\n%s", hcl)
	}
	// 纳管时成员同样由 membership 文件声明（工单会一并渲染），组文件不写。
	if strings.Contains(hcl, `aws_iam_group_membership`) {
		t.Errorf("adopted group file must not declare membership:\n%s", hcl)
	}
}

func TestCreateResourceValidation(t *testing.T) {
	if err := ValidateIAMResourceName("user", "bad name"); err == nil {
		t.Error("name with a space must be rejected")
	}
	if _, err := NormalizeIAMPath("platform"); err == nil {
		t.Error("path without leading/trailing slash must be rejected")
	}
	if _, err := BuildManagedPolicyARN("123456789012", "/", "readonly"); err != nil {
		t.Fatalf("BuildManagedPolicyARN() error = %v", err)
	}
	if err := ValidateIAMTags(map[string]string{"aws:reserved": "x"}); err == nil {
		t.Error("reserved aws: tag prefix must be rejected")
	}
}
