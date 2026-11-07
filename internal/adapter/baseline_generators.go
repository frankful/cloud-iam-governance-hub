package adapter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
)

// 本文件是全量基线（phase3）专用的声明生成器：为「已存在于 AWS、首次被平台
// 接管」的资源渲染 Terraform 文件。与工单生成器的区别在于它们必须原样声明
// 库存里的当前值（包括 ForceNew 属性），让首个 plan 只剩 import，不产生任何
// 变更；工单生成器则按用户输入声明新值。
//
// 每个生成器都遵循同一骨架：可选的首次接管 import 块 + 单一资源块 +
// validateTerraformHCL 校验。地址 label 必须与报告预测的地址一致
// （见各 ResourceLabel 函数），否则会出现同一地址两个文件。

// InstanceProfileResourceLabel derives the Terraform label for an instance
// profile declaration: "instance_profile_<sanitized-name>". Exported so the
// baseline candidate report predicts the same address the generator emits.
func InstanceProfileResourceLabel(name string) string {
	return "instance_profile_" + sanitizedLabelToken(name)
}

// IdentityProviderResourceLabel derives the Terraform label for an OIDC or
// SAML provider declaration: "identity_provider_<sanitized-name>". Both
// provider kinds share the namespace: provider names are unique across kinds
// in practice (OIDC names are URLs, SAML names are chosen identifiers), and a
// shared prefix keeps the diff readable. Exported for the same reason as the
// other label helpers.
func IdentityProviderResourceLabel(providerName string) string {
	return "identity_provider_" + sanitizedLabelToken(providerName)
}

// GenerateInstanceProfileTerraform renders an aws_iam_instance_profile for
// first-time adoption. The role is declared as a plain name string, not a
// Terraform reference: the bound role may be excluded from the baseline
// (service-linked, AWS lifecycle), and a dangling reference would break the
// whole module. The name string keeps the profile valid even when its role is
// only referenced. path is a ForceNew attribute — it must come from the
// inventory so the first plan is import-only. IAM instance profiles do not
// support tags, so none are declared.
func (adapter AWSAdapter) GenerateInstanceProfileTerraform(
	name, path, roleName, importID string,
) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("instance profile name must not be empty")
	}
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return "", apperr.Validationf("instance profile %q: bound role name must not be empty", name)
	}
	attributes := []hclAttribute{
		{"name", terraformString(name)},
		{"role", terraformString(roleName)},
	}
	if normalizedPath := strings.TrimSpace(path); normalizedPath != "" && normalizedPath != "/" {
		path, err := NormalizeIAMPath(normalizedPath)
		if err != nil {
			return "", fmt.Errorf("instance profile %q: %w", name, err)
		}
		attributes = append(attributes, hclAttribute{"path", terraformString(path)})
	}
	label := InstanceProfileResourceLabel(name)

	var hcl strings.Builder
	if trimmed := strings.TrimSpace(importID); trimmed != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing instance profile into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(trimmed))
		hcl.WriteString("\n\tto = aws_iam_instance_profile." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_instance_profile\" \"" + label + "\" {\n")
	writeHCLAttributes(&hcl, attributes)
	hcl.WriteString("}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateOIDCProviderTerraform renders an aws_iam_openid_connect_provider
// for first-time adoption. url is ForceNew — it must be the inventory's
// current value, or the first plan proposes replacing the provider (new ARN,
// every role trust policy referencing it breaks). client_id_list is also
// ForceNew; thumbprint_list is updatable in place, so declaring the inventory
// value keeps the first plan clean while later drift stays fixable. Both
// lists are omitted when the inventory has none, matching "no value" instead
// of forcing an empty-list update.
func (adapter AWSAdapter) GenerateOIDCProviderTerraform(
	url string,
	clientIDList []string,
	thumbprintList []string,
	tags map[string]string,
	importID string,
) (string, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return "", fmt.Errorf("OIDC provider URL must not be empty")
	}
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return "", fmt.Errorf("OIDC provider URL must be https: %q", url)
	}
	attributes := []hclAttribute{{"url", terraformString(url)}}
	if len(clientIDList) > 0 {
		expression, err := terraformStringList(clientIDList)
		if err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"client_id_list", expression})
	}
	if len(thumbprintList) > 0 {
		expression, err := terraformStringList(thumbprintList)
		if err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"thumbprint_list", expression})
	}
	// OIDC provider 支持 tag；漏写会把实态 tag 整体清空（eksctl 等工具
	// 打的集群标记 tag 也在其中），必须原样声明。value 只放表达式本体
	//（terraformTagsExpression 不带 "tags =" 前缀），名字与等号由
	// writeHCLAttributes 负责拼接——把整段声明当 value 会生成
	// "tags = tags = {...}"，HCL 校验直接失败。
	if len(tags) > 0 {
		attributes = append(attributes, hclAttribute{"tags", terraformTagsExpression(tags)})
	}
	label := IdentityProviderResourceLabel(url)

	var hcl strings.Builder
	if trimmed := strings.TrimSpace(importID); trimmed != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing OIDC provider into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(trimmed))
		hcl.WriteString("\n\tto = aws_iam_openid_connect_provider." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_openid_connect_provider\" \"" + label + "\" {\n")
	writeHCLAttributes(&hcl, attributes)
	hcl.WriteString("}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateSAMLProviderTerraform renders an aws_iam_saml_provider for
// first-time adoption. The metadata document is the SAML XML as a string;
// it is ForceNew, so it must come from the inventory unchanged. Import ID is
// the provider ARN.
func (adapter AWSAdapter) GenerateSAMLProviderTerraform(
	name, metadataDocument, importID string,
) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("SAML provider name must not be empty")
	}
	if strings.TrimSpace(metadataDocument) == "" {
		return "", fmt.Errorf("SAML provider %q: metadata document must not be empty", name)
	}
	label := IdentityProviderResourceLabel(name)

	var hcl strings.Builder
	if trimmed := strings.TrimSpace(importID); trimmed != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing SAML provider into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(trimmed))
		hcl.WriteString("\n\tto = aws_iam_saml_provider." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_saml_provider\" \"" + label + "\" {\n")
	writeHCLAttributes(&hcl, []hclAttribute{
		{"name", terraformString(name)},
		{"saml_metadata_document", terraformString(strings.TrimSpace(metadataDocument))},
	})
	hcl.WriteString("}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateBaselineInlinePolicyTerraform renders one inline policy of a
// role/user/group for first-time adoption. kind selects the Terraform
// resource type (aws_iam_role_policy / aws_iam_user_policy /
// aws_iam_group_policy); importID follows Terraform's
// "<principal-name>:<policy-name>" convention. The owner is declared as a
// name string for the same reason as instance profiles: the owner may be
// excluded from the baseline, and a dangling reference would break the module.
func (adapter AWSAdapter) GenerateBaselineInlinePolicyTerraform(
	kind, owner, policyName string,
	document json.RawMessage,
	importID string,
) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	resourceType := map[string]string{
		"role":  "aws_iam_role_policy",
		"user":  "aws_iam_user_policy",
		"group": "aws_iam_group_policy",
	}[kind]
	if resourceType == "" {
		return "", fmt.Errorf("inline policy kind must be role, user or group, got %q", kind)
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", fmt.Errorf("inline policy owner must not be empty")
	}
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", fmt.Errorf("inline policy name must not be empty")
	}
	normalized, err := adapter.normalizePolicyDocument(document)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}
	policyExpr, err := terraformJSONEncode(normalized)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}
	label := InlinePolicyResourceLabel(kind, owner, policyName)

	var hcl strings.Builder
	if trimmed := strings.TrimSpace(importID); trimmed != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing inline policy into\n")
		hcl.WriteString("# Terraform state, then apply the declared document (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(trimmed))
		hcl.WriteString("\n\tto = " + resourceType + "." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"" + resourceType + "\" \"" + label + "\" {\n")
	hcl.WriteString("\tname   = ")
	hcl.WriteString(terraformString(policyName))
	hcl.WriteString("\n\t" + kind + "   = ")
	hcl.WriteString(terraformString(owner))
	hcl.WriteString("\n\tpolicy = ")
	hcl.WriteString(policyExpr)
	hcl.WriteString("\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateBaselineMembershipTerraform renders a group's membership as an
// aws_iam_group_membership. The resource does not support Terraform import,
// so there is no import block: the member list is the inventory snapshot and
// the first apply "adopts" the existing members by declaring them (removing
// someone from the list is exactly how membership is managed later). The
// label and membership name follow GenerateCreateGroupTerraform's conventions
// (group_<name>_membership / <group>-membership) so a group file and its
// membership file never disagree on the declaration the platform owns.
func (adapter AWSAdapter) GenerateBaselineMembershipTerraform(
	group string,
	members []string,
) (string, error) {
	group = strings.TrimSpace(group)
	if group == "" {
		return "", apperr.Validation("group name must not be empty")
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(members))
	for _, member := range members {
		member = strings.TrimSpace(member)
		if member == "" || seen[member] {
			continue
		}
		seen[member] = true
		unique = append(unique, member)
	}
	if len(unique) == 0 {
		return "", fmt.Errorf("group %q: membership needs at least one member", group)
	}
	label := GroupResourceLabel(group) + "_membership"

	var hcl strings.Builder
	hcl.WriteString("# aws_iam_group_membership does not support import; the members below\n")
	hcl.WriteString("# are the current inventory snapshot, so the first apply adopts the\n")
	hcl.WriteString("# existing membership without removing anyone.\n")
	hcl.WriteString("resource \"aws_iam_group_membership\" \"" + label + "\" {\n")
	hcl.WriteString("\tname  = " + terraformString(group+"-membership") + "\n")
	hcl.WriteString("\tgroup = " + terraformString(group) + "\n")
	hcl.WriteString("\tusers = [\n")
	for _, member := range unique {
		hcl.WriteString("\t\t" + terraformString(member) + ",\n")
	}
	hcl.WriteString("\t]\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// terraformStringList renders a non-empty list of strings as a Terraform list
// expression. An empty list must never reach here: the generators omit empty
// attributes instead of forcing an update to [].
func terraformStringList(values []string) (string, error) {
	if len(values) == 0 {
		return "", fmt.Errorf("string list must not be empty")
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, terraformString(value))
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}
