package adapter

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestGenerateInstanceProfileTerraform 验证实例配置文件的基线声明：
// import ID 是 profile 名，role 用名字字符串而不是 Terraform 引用
// （绑定的角色可能被排除出基线，悬空引用会毁掉整个模块），
// path 只在非根时声明（ForceNew，必须来自库存）。
func TestGenerateInstanceProfileTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	hcl, err := adapter.GenerateInstanceProfileTerraform(
		"infra-node-profile", "/app/", "infra-node-role", "infra-node-profile",
	)
	if err != nil {
		t.Fatalf("GenerateInstanceProfileTerraform() error = %v", err)
	}
	for _, want := range []string{
		`import {`,
		`id = "infra-node-profile"`,
		`to = aws_iam_instance_profile.instance_profile_infra-node-profile`,
		`resource "aws_iam_instance_profile" "instance_profile_infra-node-profile"`,
		`name = "infra-node-profile"`,
		`role = "infra-node-role"`,
		`path = "/app/"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("instance profile file missing %q:\n%s", want, hcl)
		}
	}

	// 无 import：不渲染 import 块。
	hcl, err = adapter.GenerateInstanceProfileTerraform("p", "/", "r", "")
	if err != nil {
		t.Fatalf("GenerateInstanceProfileTerraform() without import error = %v", err)
	}
	if strings.Contains(hcl, "import {") {
		t.Errorf("empty importID must render no import block:\n%s", hcl)
	}
	// 根 path 不声明：与 AWS 默认一致，避免无意义的属性。
	if strings.Contains(hcl, "path") {
		t.Errorf("root path must be omitted:\n%s", hcl)
	}

	if _, err := adapter.GenerateInstanceProfileTerraform("p", "/", "", ""); err == nil {
		t.Error("missing bound role must be rejected")
	}
	if _, err := adapter.GenerateInstanceProfileTerraform("", "/", "r", ""); err == nil {
		t.Error("missing name must be rejected")
	}
	if _, err := adapter.GenerateInstanceProfileTerraform("p", "app", "r", ""); err == nil {
		t.Error("invalid path must be rejected")
	}
}

// TestGenerateOIDCProviderTerraform 验证 OIDC provider：url 与 client_id_list
// 是 ForceNew 属性，必须原样来自库存；空列表省略而不是强制 []。
func TestGenerateOIDCProviderTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	arn := "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com"
	hcl, err := adapter.GenerateOIDCProviderTerraform(
		"https://oidc.eks.us-east-1.amazonaws.com",
		[]string{"STAGING"},
		[]string{"9e99fdc48a974c9b8b7b"},
		nil,
		arn,
	)
	if err != nil {
		t.Fatalf("GenerateOIDCProviderTerraform() error = %v", err)
	}
	for _, want := range []string{
		`import {`,
		`id = "` + arn + `"`,
		`resource "aws_iam_openid_connect_provider" "identity_provider_https___oidc_eks_us-east-1_amazonaws_com"`,
		`url             = "https://oidc.eks.us-east-1.amazonaws.com"`,
		`client_id_list  = ["STAGING"]`,
		`thumbprint_list = ["9e99fdc48a974c9b8b7b"]`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("OIDC provider file missing %q:\n%s", want, hcl)
		}
	}

	// 空列表省略。
	hcl, err = adapter.GenerateOIDCProviderTerraform("https://token.actions.githubusercontent.com", nil, nil, nil, "")
	if err != nil {
		t.Fatalf("GenerateOIDCProviderTerraform() without lists error = %v", err)
	}
	if strings.Contains(hcl, "client_id_list") || strings.Contains(hcl, "thumbprint_list") {
		t.Errorf("empty lists must be omitted:\n%s", hcl)
	}

	if _, err := adapter.GenerateOIDCProviderTerraform("http://insecure.example.com", nil, nil, nil, ""); err == nil {
		t.Error("non-https URL must be rejected")
	}
	if _, err := adapter.GenerateOIDCProviderTerraform("", nil, nil, nil, ""); err == nil {
		t.Error("empty URL must be rejected")
	}
}

// TestGenerateOIDCProviderTerraformTags 声明 tags 后输出必须通过 HCL 校验，
// 且 tag 原样出现。曾把含 "tags =" 前缀的整段声明当 value 传给
// writeHCLAttributes，生成 "tags = tags = {...}"，HCL 校验失败导致
// 基线静默漏掉 tags，plan 会把实态 tag 整体清空。
func TestGenerateOIDCProviderTerraformTags(t *testing.T) {
	adapter := AWSAdapter{}
	hcl, err := adapter.GenerateOIDCProviderTerraform(
		"https://oidc.eks.us-east-1.amazonaws.com",
		[]string{"STAGING"},
		[]string{"9e99fdc48a974c9b8b7b"},
		map[string]string{"Owner": "platform-team"},
		"",
	)
	if err != nil {
		t.Fatalf("GenerateOIDCProviderTerraform() with tags error = %v", err)
	}
	if !strings.Contains(hcl, `"Owner" = "platform-team"`) {
		t.Errorf("tags must be declared verbatim:\n%s", hcl)
	}
	if strings.Count(hcl, "\ttags") != 1 {
		t.Errorf("tags attribute must appear exactly once:\n%s", hcl)
	}

	// 多个 tag 键也要通过校验（键排序、多行块与结尾大括号的拼接）。
	if _, err := adapter.GenerateOIDCProviderTerraform(
		"https://oidc.eks.us-east-1.amazonaws.com",
		nil, nil,
		map[string]string{
			"alpha.eksctl.io/cluster-name":   "demo",
			"alpha.eksctl.io/eksctl-version": "0.221.0",
		},
		"",
	); err != nil {
		t.Fatalf("GenerateOIDCProviderTerraform() with multi-key tags error = %v", err)
	}
}

// TestGenerateSAMLProviderTerraform 验证 SAML provider：metadata 文档是
// ForceNew 的 XML 字符串，import ID 是 ARN。
func TestGenerateSAMLProviderTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	arn := "arn:aws:iam::123456789012:saml-provider/Okta"
	metadata := `<EntityDescriptor entityID="https://okta.example.com"></EntityDescriptor>`
	hcl, err := adapter.GenerateSAMLProviderTerraform("Okta", metadata, arn)
	if err != nil {
		t.Fatalf("GenerateSAMLProviderTerraform() error = %v", err)
	}
	for _, want := range []string{
		`import {`,
		`id = "` + arn + `"`,
		`resource "aws_iam_saml_provider" "identity_provider_Okta"`,
		`name                   = "Okta"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("SAML provider file missing %q:\n%s", want, hcl)
		}
	}
	if !strings.Contains(hcl, "EntityDescriptor") {
		t.Errorf("metadata document must be declared verbatim:\n%s", hcl)
	}

	if _, err := adapter.GenerateSAMLProviderTerraform("Okta", "", ""); err == nil {
		t.Error("empty metadata document must be rejected")
	}
}

// TestGenerateBaselineInlinePolicyTerraform 验证内联策略基线声明：kind 决定
// 资源类型，import ID 是 Terraform 的 <主体>:<策略> 约定，label 与工单链路
// 的 InlinePolicyResourceLabel 一致。
func TestGenerateBaselineInlinePolicyTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	document := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)

	cases := []struct {
		kind         string
		resourceType string
	}{
		{"role", "aws_iam_role_policy"},
		{"user", "aws_iam_user_policy"},
		{"group", "aws_iam_group_policy"},
	}
	for _, testCase := range cases {
		hcl, err := adapter.GenerateBaselineInlinePolicyTerraform(
			testCase.kind, "my-owner", "read-only", document, "my-owner:read-only",
		)
		if err != nil {
			t.Fatalf("kind %s: GenerateBaselineInlinePolicyTerraform() error = %v", testCase.kind, err)
		}
		for _, want := range []string{
			`import {`,
			`id = "my-owner:read-only"`,
			`to = ` + testCase.resourceType + `.`,
			`resource "` + testCase.resourceType + `"`,
			`name   = "read-only"`,
			testCase.kind + "   = \"my-owner\"",
		} {
			if !strings.Contains(hcl, want) {
				t.Errorf("kind %s: file missing %q:\n%s", testCase.kind, want, hcl)
			}
		}
	}

	if _, err := adapter.GenerateBaselineInlinePolicyTerraform(
		"policy", "o", "p", document, "",
	); err == nil {
		t.Error("invalid kind must be rejected")
	}
	if _, err := adapter.GenerateBaselineInlinePolicyTerraform(
		"role", "", "p", document, "",
	); err == nil {
		t.Error("missing owner must be rejected")
	}
	if _, err := adapter.GenerateBaselineInlinePolicyTerraform(
		"role", "o", "", document, "",
	); err == nil {
		t.Error("missing policy name must be rejected")
	}
}

func TestGenerateBaselineMembershipTerraform(t *testing.T) {
	adapter := AWSAdapter{}
	code, err := adapter.GenerateBaselineMembershipTerraform(
		"release-managers", []string{"deploy-bot", "ci-bot", "deploy-bot", " "})
	if err != nil {
		t.Fatalf("GenerateBaselineMembershipTerraform() error = %v", err)
	}
	for _, want := range []string{
		`resource "aws_iam_group_membership" "group_release-managers_membership" {`,
		`name  = "release-managers-membership"`,
		`group = "release-managers"`,
		`"deploy-bot",`,
		`"ci-bot",`,
	} {
		if !strings.Contains(code, want) {
			t.Errorf("membership file missing %q:/n%s", want, code)
		}
	}
	if strings.Contains(code, "import {") {
		t.Errorf("aws_iam_group_membership does not support import; no import block expected:/n%s", code)
	}
	if _, err := adapter.GenerateBaselineMembershipTerraform("g", nil); err == nil {
		t.Error("empty membership should be rejected: the declaration would detach every member")
	}
}
