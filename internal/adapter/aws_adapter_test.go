package adapter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

func TestTranslatePermission(t *testing.T) {
	permission := model.AbstractPermission{
		Permissions: []model.PermissionGrant{
			{
				Action:   model.ActionStorageRead,
				Resource: "storage://reports/monthly",
				Conditions: map[string]interface{}{
					"StringEquals": map[string]interface{}{
						"aws:RequestedRegion": "us-east-1",
					},
				},
			},
			{
				Action:   model.ActionEC2Read,
				Resource: "*",
			},
		},
	}

	policy, err := (AWSAdapter{}).TranslatePermission(permission)
	if err != nil {
		t.Fatalf("TranslatePermission() error = %v", err)
	}
	if policy.Version != "2012-10-17" {
		t.Errorf("Version = %q, want 2012-10-17", policy.Version)
	}
	if got, want := strings.Join(policy.Statement[0].Action, ","), "s3:GetObject,s3:ListBucket"; got != want {
		t.Errorf("first statement actions = %q, want %q", got, want)
	}
	if got, want := policy.Statement[0].Resource[0], "arn:aws:s3:::reports/monthly"; got != want {
		t.Errorf("first statement resource = %q, want %q", got, want)
	}
	if policy.Statement[0].Condition == nil {
		t.Fatal("condition was not preserved")
	}
	if got, want := policy.Statement[1].Action[0], "ec2:DescribeInstances"; got != want {
		t.Errorf("second statement action = %q, want %q", got, want)
	}
}

func TestTranslatePermissionRejectsUnsupportedInput(t *testing.T) {
	tests := []struct {
		name       string
		permission model.AbstractPermission
	}{
		{
			name: "empty grants",
		},
		{
			name: "unknown action",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: "iam:admin", Resource: "*"},
			}},
		},
		{
			name: "empty resource",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: model.ActionEC2Read},
			}},
		},
		{
			name: "empty storage bucket",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: model.ActionStorageRead, Resource: "storage://"},
			}},
		},
		{
			name: "unsupported URI",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: model.ActionEC2Read, Resource: "azure://container"},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := (AWSAdapter{}).TranslatePermission(test.permission); err == nil {
				t.Fatal("TranslatePermission() expected an error")
			}
		})
	}
}

func TestGeneratePolicyJSON(t *testing.T) {
	permission := model.AbstractPermission{
		Permissions: []model.PermissionGrant{
			{Action: model.ActionEC2Read, Resource: "*"},
		},
	}

	document, err := (AWSAdapter{}).GeneratePolicyJSON(permission)
	if err != nil {
		t.Fatalf("GeneratePolicyJSON() error = %v", err)
	}

	var policy IAMPolicyDocument
	if err := json.Unmarshal(document, &policy); err != nil {
		t.Fatalf("generated policy is not valid JSON: %v", err)
	}
	if policy.Version != iamPolicyVersion || len(policy.Statement) != 1 {
		t.Fatalf("unexpected policy document: %s", document)
	}
}

func TestCheckPolicyRisk(t *testing.T) {
	tests := []struct {
		name      string
		policy    IAMPolicyDocument
		wantScore int
		wantCount int
	}{
		{
			name: "no wildcard",
			policy: IAMPolicyDocument{Statement: []IAMPolicyStatement{
				{Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::reports"}},
			}},
		},
		{
			name: "wildcard action",
			policy: IAMPolicyDocument{Statement: []IAMPolicyStatement{
				{Action: []string{"s3:Get*"}, Resource: []string{"arn:aws:s3:::reports"}},
			}},
			wantScore: 50,
			wantCount: 1,
		},
		{
			name: "wildcard resource",
			policy: IAMPolicyDocument{Statement: []IAMPolicyStatement{
				{Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::*"}},
			}},
			// 通配资源是 MEDIUM 级：记录 finding 但不加分（不阻断）
			wantScore: 0,
			wantCount: 1,
		},
		{
			name: "both wildcard categories",
			policy: IAMPolicyDocument{Statement: []IAMPolicyStatement{
				{Action: []string{"*"}, Resource: []string{"*"}},
			}},
			// 仅通配动作贡献阻断分
			wantScore: 50,
			wantCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			risk := (AWSAdapter{}).CheckPolicyRisk(test.policy)
			if risk.Score != test.wantScore || len(risk.Findings) != test.wantCount {
				t.Errorf("CheckPolicyRisk() = %+v, want score %d and %d findings", risk, test.wantScore, test.wantCount)
			}
		})
	}
}

func TestGenerateTerraform(t *testing.T) {
	permission := model.AbstractPermission{
		Permissions: []model.PermissionGrant{
			{Action: model.ActionStorageRead, Resource: "storage://reports"},
		},
	}
	role := AWSRoleInfo{
		Name:        "reports-reader",
		TrustPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
		Description: "Read ${reports} data",
	}

	terraform, err := (AWSAdapter{}).GenerateTerraform(permission, role)
	if err != nil {
		t.Fatalf("GenerateTerraform() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_role" "role_reports-reader"`,
		`resource "aws_iam_role_policy" "role_reports-reader_policy"`,
		`aws_iam_role.role_reports-reader.id`,
		`arn:aws:s3:::reports`,
		`$${reports}`,
	} {
		if !strings.Contains(terraform, want) {
			t.Errorf("Terraform output missing %q:\n%s", want, terraform)
		}
	}
}

func TestGenerateTerraformRejectsRiskyOrInvalidRole(t *testing.T) {
	trustPolicy := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	tests := []struct {
		name       string
		permission model.AbstractPermission
		role       AWSRoleInfo
	}{
		{
			name: "missing role name",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: model.ActionEC2Read, Resource: "arn:aws:ec2:us-east-1:123456789012:instance/i-123"},
			}},
			role: AWSRoleInfo{TrustPolicy: trustPolicy},
		},
		{
			name: "invalid trust policy",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: model.ActionEC2Read, Resource: "arn:aws:ec2:us-east-1:123456789012:instance/i-123"},
			}},
			role: AWSRoleInfo{Name: "reader", TrustPolicy: json.RawMessage(`{invalid}`)},
		},
		{
			name: "wildcard action",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: "*", Resource: "*"},
			}},
			role: AWSRoleInfo{Name: "reader", TrustPolicy: trustPolicy},
		},
		{
			name: "wildcard trust principal",
			permission: model.AbstractPermission{Permissions: []model.PermissionGrant{
				{Action: model.ActionEC2Read, Resource: "arn:aws:ec2:us-east-1:123456789012:instance/i-123"},
			}},
			role: AWSRoleInfo{
				Name: "reader",
				TrustPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[
					{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}
				]}`),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := (AWSAdapter{}).GenerateTerraform(test.permission, test.role); err == nil {
				t.Fatal("GenerateTerraform() expected an error")
			}
		})
	}
}

// 通配资源是 MEDIUM 级：不阻断 Terraform 生成（大量 AWS 服务无资源级 ARN）
func TestGenerateTerraformAllowsWildcardResource(t *testing.T) {
	trustPolicy := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	permission := model.AbstractPermission{Permissions: []model.PermissionGrant{
		{Action: model.ActionEC2Read, Resource: "*"},
	}}
	role := AWSRoleInfo{Name: "reader", TrustPolicy: trustPolicy}

	terraform, err := (AWSAdapter{}).GenerateTerraform(permission, role)
	if err != nil {
		t.Fatalf("GenerateTerraform() with wildcard resource error = %v", err)
	}
	if !strings.Contains(terraform, `"*"`) {
		t.Errorf("Terraform output missing wildcard resource:\n%s", terraform)
	}
}

func TestGenerateAttachUserPolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}

	t.Run("AWS-managed policy", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachUserPolicyTerraform("iam-readonly", "arn:aws:iam::aws:policy/IAMReadOnlyAccess")
		if err != nil {
			t.Fatalf("GenerateAttachUserPolicyTerraform() error = %v", err)
		}
		for _, want := range []string{
			`resource "aws_iam_user_policy_attachment" "attachment_user_iam-readonly_IAMReadOnlyAccess"`,
			`user       = "iam-readonly"`,
			`policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
	})

	t.Run("customer-managed policy", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachUserPolicyTerraform("app-user", "arn:aws:iam::123456789012:policy/team-policy")
		if err != nil {
			t.Fatalf("GenerateAttachUserPolicyTerraform() error = %v", err)
		}
		if !strings.Contains(hcl, `arn:aws:iam::123456789012:policy/team-policy`) {
			t.Errorf("generated HCL missing customer-managed ARN:\n%s", hcl)
		}
	})

	t.Run("empty user name", func(t *testing.T) {
		if _, err := adapter.GenerateAttachUserPolicyTerraform("  ", "arn:aws:iam::aws:policy/IAMReadOnlyAccess"); err == nil {
			t.Fatal("GenerateAttachUserPolicyTerraform() should reject empty user name")
		}
	})

	t.Run("invalid policy ARN", func(t *testing.T) {
		if _, err := adapter.GenerateAttachUserPolicyTerraform("user", "not-an-arn"); err == nil {
			t.Fatal("GenerateAttachUserPolicyTerraform() should reject invalid policy ARN")
		}
	})
}

func TestGenerateAttachGroupPolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}

	t.Run("group attachment", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachPolicyTerraform("Group", "developers", "arn:aws:iam::aws:policy/ReadOnlyAccess", "", "")
		if err != nil {
			t.Fatalf("GenerateAttachPolicyTerraform(Group) error = %v", err)
		}
		for _, want := range []string{
			`resource "aws_iam_group_policy_attachment" "attachment_group_developers_ReadOnlyAccess"`,
			`group      = "developers"`,
			`policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
		if strings.Contains(hcl, "aws_iam_user_policy_attachment") {
			t.Errorf("group attachment must not emit a user attachment resource:\n%s", hcl)
		}
		if strings.Contains(hcl, "import {") {
			t.Errorf("empty importID must not emit an import block:\n%s", hcl)
		}
	})

	t.Run("wild attachment adoption via import block", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachPolicyTerraform(
			"Group", "developers", "arn:aws:iam::111122223333:policy/ReadOnlyAccess",
			"developers/arn:aws:iam::111122223333:policy/ReadOnlyAccess", "")
		if err != nil {
			t.Fatalf("GenerateAttachPolicyTerraform(import) error = %v", err)
		}
		for _, want := range []string{
			"import {",
			`id = "developers/arn:aws:iam::111122223333:policy/ReadOnlyAccess"`,
			"to = aws_iam_group_policy_attachment.attachment_group_developers_ReadOnlyAccess",
			`resource "aws_iam_group_policy_attachment" "attachment_group_developers_ReadOnlyAccess"`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
	})

	t.Run("user attachment via generic method", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachPolicyTerraform("User", "app-user", "arn:aws:iam::aws:policy/IAMReadOnlyAccess", "", "")
		if err != nil {
			t.Fatalf("GenerateAttachPolicyTerraform(User) error = %v", err)
		}
		if !strings.Contains(hcl, `resource "aws_iam_user_policy_attachment"`) {
			t.Errorf("user attachment resource missing:\n%s", hcl)
		}
	})

	t.Run("empty group name", func(t *testing.T) {
		if _, err := adapter.GenerateAttachPolicyTerraform("Group", "  ", "arn:aws:iam::aws:policy/ReadOnlyAccess", "", ""); err == nil {
			t.Fatal("GenerateAttachPolicyTerraform() should reject empty group name")
		}
	})

	t.Run("unsupported principal type", func(t *testing.T) {
		if _, err := adapter.GenerateAttachPolicyTerraform("Service", "some-service", "arn:aws:iam::aws:policy/ReadOnlyAccess", "", ""); err == nil {
			t.Fatal("GenerateAttachPolicyTerraform() should reject unsupported principal type")
		}
	})
}

// ④ 角色挂载：principal_type=Role → aws_iam_role_policy_attachment，
// 野生挂载 import id 为 <role>/<policyARN>（provider 文档格式）。
func TestGenerateAttachRolePolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	arn := "arn:aws:iam::111122223333:policy/example-app-prod-AWSLoadBalancerControllerIAMPolicy"

	t.Run("role attachment with wild-adoption import", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachPolicyTerraform(
			"Role", "example-app-prod-kms-irsa-role", arn, "example-app-prod-kms-irsa-role/"+arn, "")
		if err != nil {
			t.Fatalf("GenerateAttachPolicyTerraform(Role) error = %v", err)
		}
		for _, want := range []string{
			`resource "aws_iam_role_policy_attachment" "attachment_role_example-app-prod-kms-irsa-role_example-app-prod-AWSLoadBalancerControllerIAMPolicy"`,
			`role       = "example-app-prod-kms-irsa-role"`,
			`policy_arn = "` + arn + `"`,
			"import {",
			`id = "example-app-prod-kms-irsa-role/` + arn + `"`,
			"to = aws_iam_role_policy_attachment.",
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
		if strings.Contains(hcl, "aws_iam_user_policy_attachment") ||
			strings.Contains(hcl, "aws_iam_group_policy_attachment") {
			t.Errorf("role attachment must not emit user/group attachment resources:\n%s", hcl)
		}
	})

	t.Run("plain create emits no import block", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachPolicyTerraform("Role", "new-role", arn, "", "")
		if err != nil {
			t.Fatalf("GenerateAttachPolicyTerraform(Role) error = %v", err)
		}
		if strings.Contains(hcl, "import {") {
			t.Errorf("empty importID must not emit an import block:\n%s", hcl)
		}
	})
}

func TestGenerateUpdateManagedPolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)

	t.Run("customer-managed policy", func(t *testing.T) {
		hcl, err := adapter.GenerateUpdateManagedPolicyTerraform("team-policy", doc, "", "")
		if err != nil {
			t.Fatalf("GenerateUpdateManagedPolicyTerraform() error = %v", err)
		}
		for _, want := range []string{
			`resource "aws_iam_policy" "managed_policy_team-policy"`,
			`name   = "team-policy"`,
			`s3:GetObject`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
	})

	t.Run("empty policy name", func(t *testing.T) {
		if _, err := adapter.GenerateUpdateManagedPolicyTerraform("  ", doc, "", ""); err == nil {
			t.Fatal("GenerateUpdateManagedPolicyTerraform() should reject empty policy name")
		}
	})

	t.Run("first-time adoption emits import block", func(t *testing.T) {
		arn := "arn:aws:iam::111122223333:policy/team-policy"
		hcl, err := adapter.GenerateUpdateManagedPolicyTerraform("team-policy", doc, arn, "")
		if err != nil {
			t.Fatalf("GenerateUpdateManagedPolicyTerraform() error = %v", err)
		}
		for _, want := range []string{
			"import {",
			`id = "arn:aws:iam::111122223333:policy/team-policy"`,
			"to = aws_iam_policy.managed_policy_team-policy",
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
	})

	t.Run("invalid document", func(t *testing.T) {
		if _, err := adapter.GenerateUpdateManagedPolicyTerraform("p", json.RawMessage(`{`), "", ""); err == nil {
			t.Fatal("GenerateUpdateManagedPolicyTerraform() should reject invalid JSON")
		}
		if _, err := adapter.GenerateUpdateManagedPolicyTerraform("p", json.RawMessage(`{}`), "", ""); err == nil {
			t.Fatal("GenerateUpdateManagedPolicyTerraform() should reject empty object")
		}
		if _, err := adapter.GenerateUpdateManagedPolicyTerraform("p", nil, "", ""); err == nil {
			t.Fatal("GenerateUpdateManagedPolicyTerraform() should reject empty document")
		}
	})
}

func TestGenerateUpdateGroupInlinePolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`)

	t.Run("group inline policy", func(t *testing.T) {
		hcl, err := adapter.GenerateUpdateGroupInlinePolicyTerraform("developers", "InlineS3", doc, "", "")
		if err != nil {
			t.Fatalf("GenerateUpdateGroupInlinePolicyTerraform() error = %v", err)
		}
		for _, want := range []string{
			`name   = "InlineS3"`,
			`group  = "developers"`,
			`s3:ListBucket`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
		// 标签为 group_<group>_<rand5>_<policy>：角色/组可能有多个内嵌策略，
		// 每个策略一个文件，随机后缀保证账号内唯一。
		if !strings.Contains(hcl, `resource "aws_iam_group_policy" "group_developers_`) ||
			!strings.Contains(hcl, `_InlineS3" {`) {
			t.Errorf("group inline label must be group_<group>_<rand5>_<policy>:\n%s", hcl)
		}
	})

	t.Run("empty group name", func(t *testing.T) {
		if _, err := adapter.GenerateUpdateGroupInlinePolicyTerraform("  ", "p", doc, "", ""); err == nil {
			t.Fatal("should reject empty group name")
		}
	})

	t.Run("empty inline policy name", func(t *testing.T) {
		if _, err := adapter.GenerateUpdateGroupInlinePolicyTerraform("g", "  ", doc, "", ""); err == nil {
			t.Fatal("should reject empty inline policy name")
		}
	})
}

func TestValidateIAMPolicyARN(t *testing.T) {
	valid := []string{
		"arn:aws:iam::aws:policy/IAMReadOnlyAccess",
		"arn:aws:iam::aws:policy/service-role/AmazonS3ReadOnlyAccess",
		"arn:aws:iam::123456789012:policy/my-policy",
		"arn:aws-cn:iam::aws:policy/IAMReadOnlyAccess",
	}
	for _, arn := range valid {
		if err := ValidateIAMPolicyARN(arn); err != nil {
			t.Errorf("ValidateIAMPolicyARN(%q) error = %v", arn, err)
		}
	}

	invalid := []string{
		"",
		"not-an-arn",
		"arn:aws:iam::aws:role/my-role",
		"arn:aws:s3:::my-bucket",
		"arn:aws:iam::aws:policy/",
		"arn:aws:ec2:us-east-1:123456789012:instance/i-123",
		"arn:aws:iam::12345:policy/too-short-account",
	}
	for _, arn := range invalid {
		if err := ValidateIAMPolicyARN(arn); err == nil {
			t.Errorf("ValidateIAMPolicyARN(%q) should return error", arn)
		}
	}
}

func TestValidateTerraformHCL(t *testing.T) {
	if err := validateTerraformHCL("resource \"x\" \"y\" {\n"); err == nil {
		t.Error("validateTerraformHCL() should reject unclosed block")
	}
	if err := validateTerraformHCL("   \n"); err == nil {
		t.Error("validateTerraformHCL() should reject blank code")
	}
	// 注：hclwrite 对 unquoted block labels 等语义细节是宽容的；
	// 更严格的语义检查属于 terraform validate（CI 层）的职责，
	// 本校验的定位是生成器模板拼接错误的语法兜底。

	good := "resource \"aws_iam_user_policy_attachment\" \"a\" {\n  user       = \"u\"\n  policy_arn = \"arn:aws:iam::aws:policy/IAMReadOnlyAccess\"\n}\n"
	if err := validateTerraformHCL(good); err != nil {
		t.Errorf("validateTerraformHCL() rejected valid HCL: %v", err)
	}
}

// TestPolicyDocumentJSONEncode verifies that policy documents are emitted as
// jsonencode({...}) expressions: readable HCL object syntax with proper
// string escaping and no heredoc delimiters. jsonencode handles Terraform
// template interpolation natively, so no ${%{ escaping footgun remains.
func TestPolicyDocumentJSONEncode(t *testing.T) {
	adapter := AWSAdapter{}
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)

	// All generators that embed a policy document must use jsonencode.
	generators := []struct {
		name string
		code string
	}{
		{"UpdateGroupInlinePolicy", func() string {
			code, err := adapter.GenerateUpdateGroupInlinePolicyTerraform("devs", "InlineS3", doc, "", "")
			if err != nil {
				t.Fatalf("GenerateUpdateGroupInlinePolicyTerraform() error = %v", err)
			}
			return code
		}()},
		{"UpdateRoleInlinePolicy", func() string {
			code, err := adapter.GenerateUpdateRoleInlinePolicyTerraform("my-role", "InlineS3", doc, "", "")
			if err != nil {
				t.Fatalf("GenerateUpdateRoleInlinePolicyTerraform() error = %v", err)
			}
			return code
		}()},
		{"UpdateManagedPolicy", func() string {
			code, err := adapter.GenerateUpdateManagedPolicyTerraform("team-policy", doc, "", "")
			if err != nil {
				t.Fatalf("GenerateUpdateManagedPolicyTerraform() error = %v", err)
			}
			return code
		}()},
	}

	for _, gen := range generators {
		t.Run(gen.name, func(t *testing.T) {
			if !strings.Contains(gen.code, "jsonencode({") {
				t.Errorf("expected jsonencode({ in output:\n%s", gen.code)
			}
			if strings.Contains(gen.code, "<<-EOF") {
				t.Errorf("heredoc marker should be replaced by jsonencode:\n%s", gen.code)
			}
			// The document keys must appear as HCL object keys.
			if !strings.Contains(gen.code, `"Version" = "2012-10-17"`) {
				t.Errorf("expected Version key in output:\n%s", gen.code)
			}
			if !strings.Contains(gen.code, `"Action" = `) {
				t.Errorf("expected Action key in output:\n%s", gen.code)
			}
			if !strings.Contains(gen.code, `"Effect" = "Allow"`) {
				t.Errorf("expected Effect key in output:\n%s", gen.code)
			}
		})
	}
}

// TestTerraformStringEscapesTemplateMarkers verifies strings embedded in
// jsonencode output escape Terraform template markers, so a literal ${ in a
// policy string survives as literal text instead of an interpolation.
func TestTerraformStringEscapesTemplateMarkers(t *testing.T) {
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Sid":"literal ${var} and %{if}"}]}`)
	expr, err := terraformJSONEncode(doc)
	if err != nil {
		t.Fatalf("terraformJSONEncode() error = %v", err)
	}
	if !strings.Contains(expr, `$${var}`) || !strings.Contains(expr, `%%{if}`) {
		t.Errorf("template markers must be escaped in jsonencode strings:\n%s", expr)
	}
	// The expression must parse as valid HCL (generator-level validateTerraformHCL
	// runs on full files; this checks the raw expression).
	if !strings.Contains(expr, `literal "`) && !strings.Contains(expr, `literal $${var}`) {
		t.Errorf("expected escaped literal in expression:\n%s", expr)
	}
}

// TestNormalizePolicyDocument verifies policy documents are validated and
// normalized to canonical AWS format before Terraform generation: platform
// DSL documents are translated, AWS documents are rebuilt with a default
// Version and array Statement, and non-printable-ASCII content is rejected
// (the AWS IAM APIs reject it with an opaque error at apply time).
func TestNormalizePolicyDocument(t *testing.T) {
	adapter := AWSAdapter{}

	t.Run("platform DSL is translated to AWS format", func(t *testing.T) {
		dsl := json.RawMessage(`{
			"name": "eks-upgrade-backup-policy",
			"statements": [
				{"effect": "Allow", "actions": ["eks:DescribeCluster"], "resources": ["arn:aws:eks:ap-southeast-1:111122223333:cluster/c"]},
				{"effect": "Allow", "actions": ["backup:CreateRecoveryPoint"], "resources": ["*"]}
			],
			"description": "EKS upgrade backup policy"
		}`)
		doc, err := adapter.normalizePolicyDocument(dsl)
		if err != nil {
			t.Fatalf("normalizePolicyDocument(DSL) error = %v", err)
		}
		normalized := string(doc)
		for _, want := range []string{
			`"Version": "2012-10-17"`,
			`"Statement": [`,
			`"Effect": "Allow"`,
			`"Action": [`,
			`"eks:DescribeCluster"`,
			`"arn:aws:eks:ap-southeast-1:111122223333:cluster/c"`,
			`"Resource": [`,
		} {
			if !strings.Contains(normalized, want) {
				t.Errorf("translated document missing %q:\n%s", want, normalized)
			}
		}
		// DSL-only keys must not leak into the AWS document.
		for _, unwanted := range []string{`"name"`, `"statements"`, `"effect"`, `"actions"`, `"resources"`, `"description"`} {
			if strings.Contains(normalized, unwanted) {
				t.Errorf("translated document leaked DSL key %q:\n%s", unwanted, normalized)
			}
		}
	})

	t.Run("AWS document defaults Version and keeps statements", func(t *testing.T) {
		doc, err := adapter.normalizePolicyDocument(json.RawMessage(
			`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`))
		if err != nil {
			t.Fatalf("normalizePolicyDocument(AWS) error = %v", err)
		}
		normalized := string(doc)
		if !strings.Contains(normalized, `"Version": "2012-10-17"`) {
			t.Errorf("missing default Version:\n%s", normalized)
		}
		if !strings.Contains(normalized, `"Statement": [`) {
			t.Errorf("Statement must be an array:\n%s", normalized)
		}
	})

	t.Run("single-object Statement is wrapped in array", func(t *testing.T) {
		doc, err := adapter.normalizePolicyDocument(json.RawMessage(
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`))
		if err != nil {
			t.Fatalf("normalizePolicyDocument(single) error = %v", err)
		}
		if !strings.Contains(string(doc), `"Statement": [`) {
			t.Errorf("single Statement must be wrapped in array:\n%s", string(doc))
		}
	})

	t.Run("non-ASCII document is rejected", func(t *testing.T) {
		if _, err := adapter.normalizePolicyDocument(json.RawMessage(
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*","Sid":"中文"}]}`)); err == nil {
			t.Error("normalizePolicyDocument should reject non-ASCII characters")
		}
	})

	t.Run("escaped control character is rejected", func(t *testing.T) {
		if _, err := adapter.normalizePolicyDocument(json.RawMessage(
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*","Sid":"ab"}]}`)); err == nil {
			t.Error("normalizePolicyDocument should reject escaped control characters")
		}
	})

	t.Run("DSL with not_actions is rejected", func(t *testing.T) {
		if _, err := adapter.normalizePolicyDocument(json.RawMessage(
			`{"name":"p","statements":[{"effect":"Deny","not_actions":["s3:*"],"resources":["*"]}]}`)); err == nil {
			t.Error("normalizePolicyDocument should reject not_actions/not_resources DSL")
		}
	})

	t.Run("malformed documents are rejected", func(t *testing.T) {
		for _, doc := range []json.RawMessage{
			nil,
			json.RawMessage(`{}`),
			json.RawMessage(`{"foo":1}`),
			json.RawMessage(`{"Version":"2012-10-17"}`),
			json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`),
			json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"s3:*","Resource":"*"}]}`),
			json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"*"}]}`),
			json.RawMessage(`not json`),
		} {
			if _, err := adapter.normalizePolicyDocument(doc); err == nil {
				t.Errorf("normalizePolicyDocument(%s) should fail", string(doc))
			}
		}
	})
}

// TestUpdatePolicyResourceLabels verifies standalone policy files get
// unique labels: a role or group may own several inline policies (one file
// each), so labels carry a random suffix, and the import block references the
// same label. Role labels intentionally omit the policy name (docs item 18);
// group labels keep the historical policy-name suffix.
func TestUpdatePolicyResourceLabels(t *testing.T) {
	adapter := AWSAdapter{}
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)

	t.Run("role labels omit the policy name", func(t *testing.T) {
		for _, role := range []string{"role_a", "role_b"} {
			hcl, err := adapter.GenerateUpdateRoleInlinePolicyTerraform(role, "inline-x", doc, "", "")
			if err != nil {
				t.Fatalf("GenerateUpdateRoleInlinePolicyTerraform() error = %v", err)
			}
			wantPrefix := "resource \"aws_iam_role_policy\" \"role_" + role + "_"
			if !strings.Contains(hcl, wantPrefix) ||
				!strings.Contains(hcl, "_policy\" {") ||
				strings.Contains(hcl, "_inline-x\" {") {
				t.Errorf("role inline label must be role_<role>_<rand5>_policy:\n%s", hcl)
			}
			if !strings.Contains(hcl, `name   = "inline-x"`) {
				t.Errorf("AWS policy name must remain in the name attribute:\n%s", hcl)
			}
		}
		label := InlinePolicyResourceLabel("role", "my-role", "inline-x")
		if !strings.HasPrefix(label, "role_my-role_") || !strings.HasSuffix(label, "_policy") ||
			strings.Contains(label, "inline-x") {
			t.Errorf("InlinePolicyResourceLabel(role) = %q, want role_my-role_<rand5>_policy", label)
		}
	})

	t.Run("explicit label is honored and import matches", func(t *testing.T) {
		hcl, err := adapter.GenerateUpdateRoleInlinePolicyTerraform("my-role", "my-policy", doc, "my-role:my-policy", "custom_label")
		if err != nil {
			t.Fatalf("GenerateUpdateRoleInlinePolicyTerraform() error = %v", err)
		}
		for _, want := range []string{
			`resource "aws_iam_role_policy" "custom_label"`,
			"to = aws_iam_role_policy.custom_label",
			`id = "my-role:my-policy"`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
	})

	t.Run("managed policy label is deterministic", func(t *testing.T) {
		hcl, err := adapter.GenerateUpdateManagedPolicyTerraform("team-policy", doc, "", "")
		if err != nil {
			t.Fatalf("GenerateUpdateManagedPolicyTerraform() error = %v", err)
		}
		if !strings.Contains(hcl, `resource "aws_iam_policy" "managed_policy_team-policy"`) {
			t.Errorf("managed policy label must be managed_policy_<name>:\n%s", hcl)
		}
	})

	t.Run("attachment label is deterministic", func(t *testing.T) {
		hcl, err := adapter.GenerateAttachPolicyTerraform("User", "app-user", "arn:aws:iam::123456789012:policy/team-policy", "", "")
		if err != nil {
			t.Fatalf("GenerateAttachPolicyTerraform() error = %v", err)
		}
		if !strings.Contains(hcl, `resource "aws_iam_user_policy_attachment" "attachment_user_app-user_team-policy"`) {
			t.Errorf("attachment label must be attachment_<type>_<principal>_<policy>:\n%s", hcl)
		}
	})
}

// TestGenerateRoleWithPolicyTerraform verifies the shared writer used by
// CREATE_ROLE and source-file inline policy updates: role plus a single
// inline policy with a fixed managed_policy label, document normalized.
func TestGenerateRoleWithPolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	role := AWSRoleInfo{
		Name:        "my-role",
		TrustPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"backup.amazonaws.com"}}]}`),
	}

	t.Run("renders role and its inline policy with normalized document", func(t *testing.T) {
		hcl, err := adapter.GenerateRoleWithPolicyTerraform(role, json.RawMessage(
			`{"name":"p","statements":[{"effect":"Allow","actions":["s3:GetObject"],"resources":["*"]}]}`))
		if err != nil {
			t.Fatalf("GenerateRoleWithPolicyTerraform() error = %v", err)
		}
		for _, want := range []string{
			`resource "aws_iam_role" "role_my-role"`,
			`resource "aws_iam_role_policy" "role_my-role_policy"`,
			`name   = "my-role-policy"`,
			`role   = aws_iam_role.role_my-role.id`,
			`"Version"`,
			`"s3:GetObject"`,
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("generated HCL missing %q:\n%s", want, hcl)
			}
		}
	})

	t.Run("missing trust policy is rejected", func(t *testing.T) {
		if _, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{Name: "r"}, json.RawMessage(`{}`)); err == nil {
			t.Error("GenerateRoleWithPolicyTerraform should reject empty trust policy")
		}
	})
}

// patchBaseFile is a CREATE_ROLE-shaped file (role block + the role's own
// inline policy) used as the patch base in block-patch tests.
const patchBaseFile = `resource "aws_iam_role" "managed_role" {
	name               = "my-role"
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
	description = "old description"
}

resource "aws_iam_role_policy" "managed_policy" {
	name   = "my-role-policy"
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

// TestPatchRoleAttributes verifies the UPDATE_ROLE generation primitive:
// only the submitted attributes change; everything else (inline policy,
// name, comments) keeps its bytes.
func TestPatchRoleAttributes(t *testing.T) {
	adapter := AWSAdapter{}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"rds.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	newDescription := "new description"
	duration := 7200
	tags := map[string]string{"team": "otel", "env": "prod"}

	out, err := adapter.PatchRoleAttributes(patchBaseFile, &RoleAttrPatch{
		TrustPolicy:        &trust,
		Description:        &newDescription,
		MaxSessionDuration: &duration,
		Tags:               &tags,
	}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes() error = %v", err)
	}
	for _, want := range []string{
		`"Service" = "rds.amazonaws.com"`,
		`description = "new description"`,
		`max_session_duration = 7200`,
		`"team" = "otel"`,
		`name               = "my-role"`,
		`resource "aws_iam_role_policy" "managed_policy"`,
		`"Action" = ["iam:GetRole"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("patched HCL missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "old description") || strings.Contains(out, `"Service" = "ec2.amazonaws.com"`) {
		t.Errorf("patched HCL must not keep replaced values:\n%s", out)
	}
}

// TestPatchRoleAttributesPreservesTagsWhenOnlyDescriptionChanges is the
// docs item 20 regression guard: a patch that does not carry Tags must leave
// the existing tags attribute byte-for-byte intact (Terraform tags are a full
// overwrite, so dropping it would delete the role's AWS tags on apply).
func TestPatchRoleAttributesPreservesTagsWhenOnlyDescriptionChanges(t *testing.T) {
	adapter := AWSAdapter{}
	description := "new description"
	base := `resource "aws_iam_role" "managed_role" {
	name               = "my-role"
	assume_role_policy = jsonencode({"Version":"2012-10-17","Statement":[]})
	description        = "old description"
	tags = {
		"team" = "otel"
		"env"  = "prod"
	}
}
`
	out, err := adapter.PatchRoleAttributes(base, &RoleAttrPatch{
		Description: &description,
	}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes() error = %v", err)
	}
	for _, want := range []string{`description        = "new description"`, `"team" = "otel"`, `"env"  = "prod"`} {
		if !strings.Contains(out, want) {
			t.Errorf("patch must preserve existing tags %q:\n%s", want, out)
		}
	}
}

// TestPatchRoleAttributesAppendIndent verifies a newly appended attribute is
// indented like its siblings (one tab). The live preview of a wild-role file
// exposed a double tab, which shows up as pure formatting noise in `terraform
// fmt` diffs.
func TestPatchRoleAttributesAppendIndent(t *testing.T) {
	adapter := AWSAdapter{}
	description := "added"
	duration := 3600
	base := `resource "aws_iam_role" "managed_role" {
	name               = "my-role"
	assume_role_policy = jsonencode({"Version":"2012-10-17","Statement":[]})
}
`

	out, err := adapter.PatchRoleAttributes(base, &RoleAttrPatch{
		Description:        &description,
		MaxSessionDuration: &duration,
	}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes() error = %v", err)
	}
	for _, want := range []string{"\tdescription = \"added\"\n", "\tmax_session_duration = 3600\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("appended attribute not indented with one tab (%q):\n%s", want, out)
		}
	}
}

// TestPatchRoleAttributesSkipsUnchangedTrust verifies the no-op guard: a
// semantically identical trust policy (different key order) leaves the
// attribute bytes untouched, so 「只改描述」 produces no trust diff.
func TestPatchRoleAttributesSkipsUnchangedTrust(t *testing.T) {
	adapter := AWSAdapter{}
	reordered := `{"Statement":[{"Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"},"Effect":"Allow"}],"Version":"2012-10-17"}`
	description := "changed only"

	out, err := adapter.PatchRoleAttributes(patchBaseFile, &RoleAttrPatch{
		TrustPolicy: &reordered,
		Description: &description,
	}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes() error = %v", err)
	}
	if !strings.Contains(out, `"Version" = "2012-10-17"`) || !strings.Contains(out, `"Statement" = [`) {
		t.Errorf("unchanged trust must keep its original formatting:\n%s", out)
	}
	if !strings.Contains(out, `description = "changed only"`) {
		t.Errorf("description change missing:\n%s", out)
	}
}

// TestPatchRoleAttributesRemoveSemantics verifies ROLLBACK restoration:
// empty values remove attributes so a pre-update absence is restored.
func TestPatchRoleAttributesRemoveSemantics(t *testing.T) {
	adapter := AWSAdapter{}
	emptyDescription := ""
	emptyTags := map[string]string{}

	out, err := adapter.PatchRoleAttributes(patchBaseFile, &RoleAttrPatch{
		Description: &emptyDescription,
		Tags:        &emptyTags,
	}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes() error = %v", err)
	}
	if strings.Contains(out, "description") {
		t.Errorf("empty description must remove the attribute:\n%s", out)
	}
	if strings.Contains(out, "tags") {
		t.Errorf("empty tags must remove the attribute:\n%s", out)
	}
}

// TestPatchRoleAttributesErrors verifies failure modes: unparseable file and
// a missing role block.
func TestPatchRoleAttributesErrors(t *testing.T) {
	adapter := AWSAdapter{}
	if _, err := adapter.PatchRoleAttributes("resource \"broken\"", &RoleAttrPatch{}, "my-role"); err == nil {
		t.Error("unparseable file must be rejected")
	}
	if _, err := adapter.PatchRoleAttributes("# no resources\n", &RoleAttrPatch{}, "my-role"); err == nil {
		t.Error("missing role block must be rejected")
	}
}

// assertAttributeValue reports whether text assigns value to the HCL
// attribute name. A splice keeps the original `=` alignment padding, so the
// check must not depend on single-space formatting.
func assertAttributeValue(t *testing.T, text, name, value string) {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		attr, expr, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(attr) == name && strings.TrimSpace(expr) == value {
			return
		}
	}
	t.Errorf("attribute %s = %s missing:\n%s", name, value, text)
}

// TestPatchRoleAttributesFindsBlockByRoleName verifies the docs item 15
// fix: the role block is located by its name attribute, not by resource
// label — so legacy files (managed_role), operator-renamed labels
// (managed_role11, the layout currently in the iam-baseline repo) and the new
// role_<name> labels all patch cleanly.
func TestPatchRoleAttributesFindsBlockByRoleName(t *testing.T) {
	adapter := AWSAdapter{}
	description := "patched"
	newLabelFile := `resource "aws_iam_role" "role_my-role" {
	name               = "my-role"
	assume_role_policy = jsonencode({"Version":"2012-10-17","Statement":[]})
	description        = "old description"
}

resource "aws_iam_role_policy" "role_my-role_policy" {
	name   = "my-role-policy"
	role   = aws_iam_role.role_my-role.id
	policy = jsonencode({"Version":"2012-10-17","Statement":[]})
}
`
	out, err := adapter.PatchRoleAttributes(newLabelFile, &RoleAttrPatch{Description: &description}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes(new label file) error = %v", err)
	}
	assertAttributeValue(t, out, "description", `"patched"`)

	renamedLabelFile := strings.ReplaceAll(patchBaseFile, `"managed_role"`, `"managed_role11"`)
	renamedLabelFile = strings.ReplaceAll(renamedLabelFile, `aws_iam_role.managed_role.id`, `aws_iam_role.managed_role11.id`)
	out, err = adapter.PatchRoleAttributes(renamedLabelFile, &RoleAttrPatch{Description: &description}, "my-role")
	if err != nil {
		t.Fatalf("PatchRoleAttributes(renamed label file) error = %v", err)
	}
	assertAttributeValue(t, out, "description", `"patched"`)
	if !strings.Contains(out, `resource "aws_iam_role_policy" "managed_policy"`) {
		t.Errorf("renamed-label patch must keep sibling bytes:\n%s", out)
	}
}

// TestRoleResourceLabel verifies the unique role label scheme (docs item 15):
// prefix + sanitized name, non-name characters collapsed to underscores.
func TestRoleResourceLabel(t *testing.T) {
	if got := RoleResourceLabel("eks-upgrade-backup-role"); got != "role_eks-upgrade-backup-role" {
		t.Errorf("RoleResourceLabel(dashed name) = %q", got)
	}
	if got := RoleResourceLabel("otel.acm+prd"); got != "role_otel_acm_prd" {
		t.Errorf("RoleResourceLabel(special chars) = %q", got)
	}
}

// TestHasRoleResourceBlock verifies the wild-path presence probe.
func TestHasRoleResourceBlock(t *testing.T) {
	if !HasRoleResourceBlock(patchBaseFile) {
		t.Error("file with role block must be reported present")
	}
	if HasRoleResourceBlock("# rollback placeholder, no resources\n") {
		t.Error("comment-only file must be reported absent")
	}
	if HasRoleResourceBlock("resource \"broken\"") {
		t.Error("unparseable file must be reported absent")
	}
}

// TestPatchRoleInlinePolicy verifies the B-path primitive: only the target
// inline policy's document changes; the role block and other policies are
// byte-identical.
func TestPatchRoleInlinePolicy(t *testing.T) {
	adapter := AWSAdapter{}
	out, err := adapter.PatchRoleInlinePolicy(
		patchBaseFile,
		"my-role-policy",
		json.RawMessage(`{"name":"p","statements":[{"effect":"Allow","actions":["s3:ListBucket"],"resources":["*"]}]}`),
	)
	if err != nil {
		t.Fatalf("PatchRoleInlinePolicy() error = %v", err)
	}
	for _, want := range []string{
		`"s3:ListBucket"`,
		`"Service" = "ec2.amazonaws.com"`,
		`name               = "my-role"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("patched HCL missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"Action" = ["iam:GetRole"]`) {
		t.Errorf("old inline document must be replaced:\n%s", out)
	}
	if _, err := adapter.PatchRoleInlinePolicy(patchBaseFile, "missing-policy", json.RawMessage(`{}`)); err == nil {
		t.Error("unknown inline policy must be rejected")
	}
}

// item 23 回归：内嵌策略 label 必须按 (owner, policyName) 确定性派生。每张工单
// 随机后缀会让同一条策略在反复更新时地址漂移，apply 从原地更新退化成
// destroy+recreate（cloudwatch-role 内嵌策略因此被删）。
func TestInlinePolicyResourceLabelDeterministic(t *testing.T) {
	first := InlinePolicyResourceLabel("role", "my-role", "inline-x")
	second := InlinePolicyResourceLabel("role", "my-role", "inline-x")
	if first != second {
		t.Fatalf("role label must be deterministic: %q vs %q", first, second)
	}
	if other := InlinePolicyResourceLabel("role", "my-role", "inline-y"); other == first {
		t.Fatalf("two policies of one role must not share a label: %q", first)
	}
	if !strings.HasPrefix(first, "role_my-role_") || !strings.HasSuffix(first, "_policy") {
		t.Fatalf("role label shape must stay role_<owner>_<suffix>_policy: %q", first)
	}
	groupFirst := InlinePolicyResourceLabel("group", "devs", "InlineS3")
	groupSecond := InlinePolicyResourceLabel("group", "devs", "InlineS3")
	if groupFirst != groupSecond {
		t.Fatalf("group label must be deterministic: %q vs %q", groupFirst, groupSecond)
	}
	if !strings.HasPrefix(groupFirst, "group_devs_") || !strings.HasSuffix(groupFirst, "_InlineS3") {
		t.Fatalf("group label shape must stay <kind>_<owner>_<suffix>_<policy>: %q", groupFirst)
	}
}

// legacyInlinePolicyFile 模拟 item-23 事故现场：历史随机 label 的独立内嵌策略
// 文件，且带着首次纳管后残留在 config 里的 import 块。
const legacyInlinePolicyFile = `# First-time adoption: import the pre-existing inline policy into
# Terraform state, then apply the declared document (Terraform >= 1.5).
import {
	id = "my-role:old-inline"
	to = aws_iam_role_policy.role_my-role_xbdih_policy
}

resource "aws_iam_role_policy" "role_my-role_xbdih_policy" {
	name   = "old-inline"
	role   = "my-role"
	policy = jsonencode({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:GetMetricData"],"Resource":["*"]}]})
}
`

// item 23 回归：patch 独立内嵌策略文件只换 policy 文档——历史随机 label 原样
// 保留（Terraform 地址不变），已消费的 import 块（及其注释头）被剔除，
// 文件里的其他 import（如角色声明的）不受影响。
func TestPatchInlinePolicyDocument(t *testing.T) {
	adapter := AWSAdapter{}
	newDoc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:PutLogEvents"],"Resource":["*"]}]}`)

	t.Run("patch keeps legacy label and drops stale import", func(t *testing.T) {
		out, err := adapter.PatchInlinePolicyDocument(legacyInlinePolicyFile, "aws_iam_role_policy", "old-inline", newDoc, "")
		if err != nil {
			t.Fatalf("PatchInlinePolicyDocument() error = %v", err)
		}
		if !strings.Contains(out, `resource "aws_iam_role_policy" "role_my-role_xbdih_policy"`) {
			t.Errorf("legacy resource label must be preserved:\n%s", out)
		}
		if !strings.Contains(out, "logs:PutLogEvents") {
			t.Errorf("patched document missing:\n%s", out)
		}
		if strings.Contains(out, "cloudwatch:GetMetricData") {
			t.Errorf("old document must be replaced:\n%s", out)
		}
		if strings.Contains(out, "import {") || strings.Contains(out, "First-time adoption") {
			t.Errorf("stale import block (and its header) must be removed:\n%s", out)
		}
	})

	t.Run("non-empty importID writes the canonical import block", func(t *testing.T) {
		out, err := adapter.PatchInlinePolicyDocument(legacyInlinePolicyFile, "aws_iam_role_policy", "old-inline", newDoc, "my-role:old-inline")
		if err != nil {
			t.Fatalf("PatchInlinePolicyDocument() error = %v", err)
		}
		for _, want := range []string{
			`id = "my-role:old-inline"`,
			"to = aws_iam_role_policy.role_my-role_xbdih_policy",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("generated import block missing %q:\n%s", want, out)
			}
		}
		if strings.Count(out, "import {") != 1 {
			t.Errorf("exactly one import block must remain:\n%s", out)
		}
	})

	t.Run("imports of other resource types are untouched", func(t *testing.T) {
		const sourceFile = `import {
	id = "my-role"
	to = aws_iam_role.managed_role
}

resource "aws_iam_role" "managed_role" {
	name = "my-role"
}

resource "aws_iam_role_policy" "old-inline" {
	name   = "old-inline"
	role   = aws_iam_role.managed_role.id
	policy = jsonencode({"Version":"2012-10-17"})
}
`
		out, err := adapter.PatchInlinePolicyDocument(sourceFile, "aws_iam_role_policy", "old-inline", newDoc, "")
		if err != nil {
			t.Fatalf("PatchInlinePolicyDocument() error = %v", err)
		}
		if !strings.Contains(out, "to = aws_iam_role.managed_role") {
			t.Errorf("role import block must be preserved:\n%s", out)
		}
	})

	t.Run("group policy resources patch too", func(t *testing.T) {
		const groupFile = `resource "aws_iam_group_policy" "group_devs_abcde_InlineS3" {
	name   = "InlineS3"
	group  = "devs"
	policy = jsonencode({"Version":"2012-10-17"})
}
`
		out, err := adapter.PatchInlinePolicyDocument(groupFile, "aws_iam_group_policy", "InlineS3", newDoc, "")
		if err != nil {
			t.Fatalf("PatchInlinePolicyDocument() error = %v", err)
		}
		if !strings.Contains(out, `resource "aws_iam_group_policy" "group_devs_abcde_InlineS3"`) ||
			!strings.Contains(out, "logs:PutLogEvents") {
			t.Errorf("group patch unexpected:\n%s", out)
		}
	})

	t.Run("missing policy name is rejected", func(t *testing.T) {
		if _, err := adapter.PatchInlinePolicyDocument(legacyInlinePolicyFile, "aws_iam_role_policy", "ghost", newDoc, ""); err == nil {
			t.Error("unknown inline policy must be rejected")
		}
	})
}

func TestScanInlinePolicyResourceBlock(t *testing.T) {
	label, found, hasResources, err := ScanInlinePolicyResourceBlock(legacyInlinePolicyFile, "aws_iam_role_policy", "old-inline")
	if err != nil || !found || !hasResources {
		t.Fatalf("scan legacy file: label=%q found=%v hasResources=%v err=%v", label, found, hasResources, err)
	}
	if label != "role_my-role_xbdih_policy" {
		t.Fatalf("scanned label = %q, want the legacy random label", label)
	}

	// 回滚清空后的注释空文件：无块、无资源、无错误 → 调用方走全新生成。
	const emptied = "# Rolled back by ticket IAM-0001\n# target: IAM-0002\n"
	if _, found, hasResources, err := ScanInlinePolicyResourceBlock(emptied, "aws_iam_role_policy", "old-inline"); err != nil || found || hasResources {
		t.Fatalf("comment-only file must scan as empty: found=%v hasResources=%v err=%v", found, hasResources, err)
	}

	// 文件里是别的资源声明：报 hasResources，供调用方拒绝覆盖。
	const otherResource = `resource "aws_iam_policy" "managed_policy_other" {
	name = "other"
}
`
	_, found, hasResources, err = ScanInlinePolicyResourceBlock(otherResource, "aws_iam_role_policy", "old-inline")
	if err != nil || found || !hasResources {
		t.Fatalf("other-resource file: found=%v hasResources=%v err=%v", found, hasResources, err)
	}

	// 真正损坏的 HCL 必须冒泡，绝不允许静默重新生成覆盖。
	if _, _, _, err := ScanInlinePolicyResourceBlock("resource {\n", "aws_iam_role_policy", "old-inline"); err == nil {
		t.Fatal("broken HCL must surface a parse error")
	}
}

// TestRoleAttrPatchFromConfig verifies the nil-means-untouched contract and
// the empty-map-means-remove distinction.
func TestRoleAttrPatchFromConfig(t *testing.T) {
	patch := RoleAttrPatchFromConfig(&UpdateRoleConfig{})
	if patch.TrustPolicy != nil || patch.Description != nil || patch.MaxSessionDuration != nil || patch.Tags != nil {
		t.Fatalf("empty config must produce an all-nil patch: %+v", patch)
	}
	emptyTags := map[string]string{}
	patch = RoleAttrPatchFromConfig(&UpdateRoleConfig{Tags: emptyTags})
	if patch.Tags == nil {
		t.Fatal("present-but-empty tags must become a remove directive")
	}
	patch = RoleAttrPatchFromConfig(nil)
	if patch == nil {
		t.Fatal("nil config must produce a usable empty patch")
	}
}

// TestGenerateWildRoleTerraform verifies the ③ wild-role file: optional
// first-time import block, role-only declaration (never inline policies or
// attachments), submitted attributes rendered, trust provider-required.
func TestGenerateWildRoleTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	trust := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{"Effect": "Allow", "Principal": map[string]interface{}{"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
		},
	}
	description := "desc"
	duration := 3600

	hcl, err := adapter.GenerateWildRoleTerraform("my-role", &UpdateRoleConfig{
		TrustPolicy:        &trust,
		Description:        &description,
		MaxSessionDuration: &duration,
		Tags:               map[string]string{"team": "otel"},
	}, "my-role", RoleIdentity{
		Path:                   "/app/",
		PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/boundary",
	})
	if err != nil {
		t.Fatalf("GenerateWildRoleTerraform() error = %v", err)
	}
	for _, want := range []string{
		`import {`,
		`id = "my-role"`,
		`to = aws_iam_role.role_my-role`,
		`resource "aws_iam_role" "role_my-role"`,
		`name                 = "my-role"`,
		`"Service" = "ec2.amazonaws.com"`,
		`path                 = "/app/"`,
		`permissions_boundary = "arn:aws:iam::123456789012:policy/boundary"`,
		`description          = "desc"`,
		`max_session_duration = 3600`,
		`"team" = "otel"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("wild role file missing %q:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "aws_iam_role_policy") || strings.Contains(hcl, "policy_attachment") {
		t.Errorf("wild role file must never declare inline policies or attachments:\n%s", hcl)
	}

	// 二次更新（无 import）：只声明角色块。
	hcl, err = adapter.GenerateWildRoleTerraform("my-role", &UpdateRoleConfig{TrustPolicy: &trust}, "", RoleIdentity{})
	if err != nil {
		t.Fatalf("GenerateWildRoleTerraform() without import error = %v", err)
	}
	if strings.Contains(hcl, "import {") {
		t.Errorf("empty importID must render no import block:\n%s", hcl)
	}
	// 库存里没有 path/boundary 时不写这两个属性（存量输出不变）。
	if strings.Contains(hcl, "path ") || strings.Contains(hcl, "permissions_boundary") {
		t.Errorf("absent identity attributes must be omitted:\n%s", hcl)
	}

	// 信任 provider 必填：缺失拒绝。
	if _, err := adapter.GenerateWildRoleTerraform("my-role", &UpdateRoleConfig{}, "", RoleIdentity{}); err == nil {
		t.Error("missing trust policy must be rejected")
	}
	// 非法 path / boundary 拒绝渲染，不能让无效 Terraform 进入 PR。
	if _, err := adapter.GenerateWildRoleTerraform("my-role", &UpdateRoleConfig{TrustPolicy: &trust}, "",
		RoleIdentity{Path: "app"}); err == nil {
		t.Error("invalid path must be rejected")
	}
	if _, err := adapter.GenerateWildRoleTerraform("my-role", &UpdateRoleConfig{TrustPolicy: &trust}, "",
		RoleIdentity{PermissionsBoundaryARN: "nope"}); err == nil {
		t.Error("invalid permissions boundary must be rejected")
	}
}

// CREATE_ROLE 增强（item 23）：初始挂载托管策略 + 权限可选（零权限角色）。
// 零权限角色在 AWS 侧合法：文件里只声明角色本体，不生成 <role>-policy 资源。
func TestGenerateRoleWithPolicyTerraformOptionalPolicy(t *testing.T) {
	adapter := AWSAdapter{}
	trust := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)

	roleOnly, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{
		Name:        "billing-reader",
		TrustPolicy: trust,
	}, nil)
	if err != nil {
		t.Fatalf("GenerateRoleWithPolicyTerraform() role-only error = %v", err)
	}
	if !strings.Contains(roleOnly, `resource "aws_iam_role" "role_billing-reader"`) {
		t.Errorf("role declaration missing:\n%s", roleOnly)
	}
	if strings.Contains(roleOnly, "aws_iam_role_policy") {
		t.Errorf("zero-permission role must not declare an inline policy:\n%s", roleOnly)
	}

	withPolicy, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{
		Name:        "billing-reader",
		TrustPolicy: trust,
	}, json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`))
	if err != nil {
		t.Fatalf("GenerateRoleWithPolicyTerraform() error = %v", err)
	}
	if !strings.Contains(withPolicy, `resource "aws_iam_role_policy" "role_billing-reader_policy"`) {
		t.Errorf("inline policy declaration missing:\n%s", withPolicy)
	}
}

// 初始挂载的托管策略渲染为 aws_iam_role_policy_attachment，label 与后续
// ATTACH_USER_POLICY 工单一致（同一地址，不会互相覆盖）。
func TestGenerateRoleWithPolicyTerraformManagedPolicyAttachments(t *testing.T) {
	adapter := AWSAdapter{}
	trust := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	arn := "arn:aws:iam::aws:policy/ReadOnlyAccess"

	hcl, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{
		Name:        "billing-reader",
		TrustPolicy: trust,
		PolicyARNs:  []string{arn, arn, " "},
	}, nil)
	if err != nil {
		t.Fatalf("GenerateRoleWithPolicyTerraform() error = %v", err)
	}
	wantLabel := DefaultAttachmentLabel("Role", "billing-reader", arn)
	if !strings.Contains(hcl, `resource "aws_iam_role_policy_attachment" "`+wantLabel+`"`) {
		t.Errorf("attachment declaration missing (label %s):\n%s", wantLabel, hcl)
	}
	if !strings.Contains(hcl, `policy_arn = "`+arn+`"`) {
		t.Errorf("attachment policy ARN missing:\n%s", hcl)
	}
	if strings.Count(hcl, "aws_iam_role_policy_attachment") != 1 {
		t.Errorf("duplicate ARNs must render one attachment:\n%s", hcl)
	}

	// 非法 ARN 必须拒绝，不能渲染成无效 Terraform。
	if _, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{
		Name:        "billing-reader",
		TrustPolicy: trust,
		PolicyARNs:  []string{"not-an-arn"},
	}, nil); err == nil {
		t.Error("invalid policy ARN must be rejected")
	}
}

// path / permissions_boundary 在 AWS provider 里是 ForceNew：声明里漏掉它们，
// plan 会显示「删除属性」并重建角色（新 ARN -> 所有挂载与实例 profile 断裂）。
// 因此生成器必须能把库存里的真实值原样写出来。
func TestGenerateRoleWithPolicyTerraformDeclaresForceNewAttributes(t *testing.T) {
	adapter := AWSAdapter{}
	trust := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	boundary := "arn:aws:iam::123456789012:policy/app-boundary"

	hcl, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{
		Name:                   "billing-reader",
		TrustPolicy:            trust,
		Path:                   "/app/",
		PermissionsBoundaryARN: boundary,
		Tags:                   map[string]string{"team": "otel", "env": "prod"},
	}, nil)
	if err != nil {
		t.Fatalf("GenerateRoleWithPolicyTerraform() error = %v", err)
	}
	for _, want := range []string{
		`path                 = "/app/"`,
		`permissions_boundary = "` + boundary + `"`,
		`"env" = "prod"`,
		`"team" = "otel"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("generated role is missing %q:\n%s", want, hcl)
		}
	}
	// 标签必须按 key 排序：同一库存两次生成要逐字节一致。
	if strings.Index(hcl, `"env"`) > strings.Index(hcl, `"team"`) {
		t.Errorf("tags are not sorted by key:\n%s", hcl)
	}

	// 未提供的属性保持不写出（存量 CREATE_ROLE 输出不变）。
	plain, err := adapter.GenerateRoleWithPolicyTerraform(AWSRoleInfo{
		Name: "billing-reader", TrustPolicy: trust,
	}, nil)
	if err != nil {
		t.Fatalf("GenerateRoleWithPolicyTerraform() error = %v", err)
	}
	if strings.Contains(plain, "path ") || strings.Contains(plain, "permissions_boundary") ||
		strings.Contains(plain, "tags") {
		t.Errorf("attributes must be omitted when not provided:\n%s", plain)
	}

	for name, role := range map[string]AWSRoleInfo{
		"path without slashes":   {Name: "r", TrustPolicy: trust, Path: "app"},
		"invalid boundary ARN":   {Name: "r", TrustPolicy: trust, PermissionsBoundaryARN: "not-an-arn"},
		"invalid tag characters": {Name: "r", TrustPolicy: trust, Tags: map[string]string{"k": "v\x00"}},
	} {
		if _, err := adapter.GenerateRoleWithPolicyTerraform(role, nil); err == nil {
			t.Errorf("%s must be rejected instead of rendering invalid Terraform", name)
		}
	}
}

// 从 CREATE_ROLE 文件里移除初始挂载（解绑工单走同一条路径）。
func TestRemoveAttachmentFromTerraformRole(t *testing.T) {
	adapter := AWSAdapter{}
	const file = `resource "aws_iam_role" "role_billing-reader" {
	name = "billing-reader"
}

resource "aws_iam_role_policy_attachment" "attachment_role_billing-reader_ReadOnlyAccess" {
	role       = "billing-reader"
	policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
`
	out, err := adapter.RemoveAttachmentFromTerraform(
		file, "Role", "billing-reader", "arn:aws:iam::aws:policy/ReadOnlyAccess",
	)
	if err != nil {
		t.Fatalf("RemoveAttachmentFromTerraform() error = %v", err)
	}
	if strings.Contains(out, "aws_iam_role_policy_attachment") {
		t.Errorf("attachment block must be removed:\n%s", out)
	}
	if !strings.Contains(out, `resource "aws_iam_role" "role_billing-reader"`) {
		t.Errorf("role declaration must survive:\n%s", out)
	}
}

// 基线纳管的挂载文件 = 注释头 + import 块 + resource 块。解绑必须三者全清：
// 悬空 import 让 plan 报错，孤儿注释则让 PR 里留下误导性的「First-time
// adoption」字样。全清后文件为空是合法结果（调用方落成注释空文件）。
func TestRemoveAttachmentFromTerraformClearsImportAndAdoptionComments(t *testing.T) {
	adapter := AWSAdapter{}
	const file = `# First-time adoption: import the pre-existing attachment into
# Terraform state, then declare it (Terraform >= 1.5).
import {
	id = "rds-monitoring-role/arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
	to = aws_iam_role_policy_attachment.attachment_role_rds-monitoring-role_AmazonRDSEnhancedMonitoringRole
}

resource "aws_iam_role_policy_attachment" "attachment_role_rds-monitoring-role_AmazonRDSEnhancedMonitoringRole" {
	role       = "rds-monitoring-role"
	policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
`
	out, err := adapter.RemoveAttachmentFromTerraform(
		file, "Role", "rds-monitoring-role",
		"arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
	)
	if err != nil {
		t.Fatalf("RemoveAttachmentFromTerraform() error = %v", err)
	}
	if strings.Contains(out, "import {") {
		t.Errorf("import block must be removed:\n%s", out)
	}
	if strings.Contains(out, "First-time adoption") {
		t.Errorf("adoption comment header must be removed:\n%s", out)
	}
	if strings.Contains(out, "aws_iam_role_policy_attachment") {
		t.Errorf("attachment resource must be removed:\n%s", out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("single-attachment file must be emptied, got:\n%s", out)
	}
}

// 基线纳管的 role 文件带首次纳管 import 块，apply 后已消费。UPDATE_ROLE 原地
// patch 必须把已消费的 import 块（及其注释头）一并剔除——残留会让每次 plan
// 都报 "Resource already managed"（item-23 内嵌策略同款约定）。指向其他资源
// 类型的 import 不受影响。
func TestPatchRoleAttributesStripsConsumedImport(t *testing.T) {
	adapter := AWSAdapter{}
	const file = `# First-time adoption: import the pre-existing role into
# Terraform state, then declare it (Terraform >= 1.5).
import {
	id = "example-eks-nodegroup-role-6e24d61"
	to = aws_iam_role.role_example-eks-nodegroup-role-6e24d61
}

resource "aws_iam_role" "role_example-eks-nodegroup-role-6e24d61" {
	name                 = "example-eks-nodegroup-role-6e24d61"
	assume_role_policy   = jsonencode({"Version" = "2012-10-17"})
	path                 = "/"
	max_session_duration = 3600
}
`
	out, err := adapter.PatchRoleAttributes(file, &RoleAttrPatch{
		MaxSessionDuration: func() *int { v := 7200; return &v }(),
	}, "example-eks-nodegroup-role-6e24d61")
	if err != nil {
		t.Fatalf("PatchRoleAttributes() error = %v", err)
	}
	if strings.Contains(out, "import {") {
		t.Errorf("consumed import block must be removed:\n%s", out)
	}
	if strings.Contains(out, "First-time adoption") {
		t.Errorf("adoption comment header must be removed:\n%s", out)
	}
	if !strings.Contains(out, "max_session_duration = 7200") {
		t.Errorf("patched attribute missing:\n%s", out)
	}
	if !strings.Contains(out, `resource "aws_iam_role" "role_example-eks-nodegroup-role-6e24d61"`) {
		t.Errorf("resource label must be preserved:\n%s", out)
	}
}
