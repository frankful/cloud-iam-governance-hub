package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

const (
	iamPolicyVersion = "2012-10-17"
	maxRiskScore     = 100
)

// AWSAdapter translates the internal permission DSL to AWS IAM resources.
type AWSAdapter struct{}

// AWSRoleInfo contains the inputs required to generate an aws_iam_role.
type AWSRoleInfo struct {
	Name        string          `json:"name"`
	TrustPolicy json.RawMessage `json:"trust_policy"`
	Description string          `json:"description,omitempty"`
	// Path is ForceNew in the AWS provider. A declaration that omits a
	// non-root path makes Terraform plan a replacement (new role ARN, every
	// attachment breaks), so adoption and baseline generation must carry it.
	// Empty keeps the historical output (attribute omitted).
	Path string `json:"path,omitempty"`
	// PermissionsBoundaryARN is also ForceNew; empty means "no boundary".
	PermissionsBoundaryARN string `json:"permissions_boundary_arn,omitempty"`
	// Tags are the role's tags; declared so re-sync does not drop them.
	Tags map[string]string `json:"tags,omitempty"`
	// PolicyARNs are managed policies attached to the role at creation time.
	// They render as aws_iam_role_policy_attachment resources in the same
	// file, mirroring CREATE_USER / CREATE_GROUP.
	PolicyARNs []string `json:"policy_arns,omitempty"`
}

// ManagedPolicyInfo contains the inputs required to create or adopt a
// customer-managed IAM policy. Document accepts either an AWS policy document
// or the platform DSL; generation normalizes it to AWS format.
type ManagedPolicyInfo struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Path        string            `json:"path,omitempty"`
	Document    json.RawMessage   `json:"document"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// IAMUserInfo contains the inputs required to create or adopt an IAM user.
// GroupNames and PolicyARNs are only allowed for new users: adopting an
// existing user while declaring a full membership/attachment set would let
// Terraform remove relationships the platform does not own.
type IAMUserInfo struct {
	Name       string            `json:"name"`
	Path       string            `json:"path,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	GroupNames []string          `json:"group_names,omitempty"`
	PolicyARNs []string          `json:"policy_arns,omitempty"`
}

// IAMGroupInfo contains the inputs required to create or adopt an IAM group.
type IAMGroupInfo struct {
	Name            string            `json:"name"`
	Path            string            `json:"path,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	MemberUserNames []string          `json:"member_user_names,omitempty"`
	PolicyARNs      []string          `json:"policy_arns,omitempty"`
	InlinePolicies  []IAMInlinePolicy `json:"inline_policies,omitempty"`
}

type IAMInlinePolicy struct {
	Name     string          `json:"name"`
	Document json.RawMessage `json:"document"`
}

// UpdateRoleConfig describes the desired full state for an UPDATE_ROLE
// ticket: trust policy, inline policies, managed policy ARNs, description,
// max session duration, and tags. All fields the user did not change must be
// backfilled to their current values by the caller before generation.
type UpdateRoleConfig struct {
	TrustPolicy        *map[string]interface{} `json:"trust_policy,omitempty"`
	InlinePolicies     map[string]interface{}  `json:"inline_policies,omitempty"` // policy name → document
	ManagedPolicyARNs  []string                `json:"managed_policy_arns,omitempty"`
	Description        *string                 `json:"description,omitempty"`
	MaxSessionDuration *int                    `json:"max_session_duration,omitempty"`
	Tags               map[string]string       `json:"tags,omitempty"`
}

// IAMPolicyDocument is the AWS IAM policy shape generated from the DSL.
type IAMPolicyDocument struct {
	Version   string               `json:"Version"`
	Statement []IAMPolicyStatement `json:"Statement"`
}

// IAMPolicyStatement represents one translated permission grant.
type IAMPolicyStatement struct {
	Effect    string                 `json:"Effect"`
	Action    []string               `json:"Action"`
	Resource  []string               `json:"Resource"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

// PolicyRisk describes wildcard findings and their aggregate score.
type PolicyRisk struct {
	Score    int      `json:"score"`
	Findings []string `json:"findings"`
}

// TranslatePermission converts abstract actions and resources into an IAM policy.
func (AWSAdapter) TranslatePermission(permission model.AbstractPermission) (IAMPolicyDocument, error) {
	if len(permission.Permissions) == 0 {
		return IAMPolicyDocument{}, fmt.Errorf("permission must contain at least one grant")
	}

	policy := IAMPolicyDocument{
		Version:   iamPolicyVersion,
		Statement: make([]IAMPolicyStatement, 0, len(permission.Permissions)),
	}

	for index, grant := range permission.Permissions {
		actions, ok := model.AbstractActionAWSMap[grant.Action]
		if !ok || len(actions) == 0 {
			return IAMPolicyDocument{}, fmt.Errorf("permission %d: unsupported abstract action %q", index, grant.Action)
		}

		resource, err := translateResource(grant.Resource)
		if err != nil {
			return IAMPolicyDocument{}, fmt.Errorf("permission %d: %w", index, err)
		}

		policy.Statement = append(policy.Statement, IAMPolicyStatement{
			Effect:    "Allow",
			Action:    append([]string(nil), actions...),
			Resource:  []string{resource},
			Condition: grant.Conditions,
		})
	}

	return policy, nil
}

// GeneratePolicyJSON translates the DSL and returns its compact IAM JSON document.
func (adapter AWSAdapter) GeneratePolicyJSON(permission model.AbstractPermission) ([]byte, error) {
	policy, err := adapter.TranslatePermission(permission)
	if err != nil {
		return nil, err
	}

	document, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("marshal IAM policy: %w", err)
	}
	return document, nil
}

// CheckPolicyRisk detects wildcard actions and resources and scores the findings.
// Only blocking-severity findings add score: a wildcard ACTION is high risk and
// adds 50 points, while a wildcard RESOURCE is medium risk — many AWS services
// expose no resource-level ARN and legitimately require "*" — so it is reported
// as a finding without blocking Terraform generation.
func (AWSAdapter) CheckPolicyRisk(policy IAMPolicyDocument) PolicyRisk {
	risk := PolicyRisk{Findings: make([]string, 0, 2)}
	hasWildcardAction, hasWildcardResource := false, false

	for _, statement := range policy.Statement {
		for _, action := range statement.Action {
			if strings.Contains(action, "*") {
				hasWildcardAction = true
				break
			}
		}
		for _, resource := range statement.Resource {
			if strings.Contains(resource, "*") {
				hasWildcardResource = true
				break
			}
		}
	}

	if hasWildcardAction {
		risk.Score += 50
		risk.Findings = append(risk.Findings, "wildcard action detected")
	}
	if hasWildcardResource {
		// 不加分：通配资源是 MEDIUM 级（静态扫描层同规则），仅记录
		risk.Findings = append(risk.Findings, "wildcard resource detected")
	}
	if risk.Score > maxRiskScore {
		risk.Score = maxRiskScore
	}
	return risk
}

// CheckTrustPolicyRisk detects a wildcard principal in a role trust policy.
func (AWSAdapter) CheckTrustPolicyRisk(trustPolicy json.RawMessage) (PolicyRisk, error) {
	var document struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if !json.Valid(trustPolicy) || len(bytes.TrimSpace(trustPolicy)) == 0 {
		return PolicyRisk{}, fmt.Errorf("trust policy must be valid JSON")
	}
	if err := json.Unmarshal(trustPolicy, &document); err != nil {
		return PolicyRisk{}, fmt.Errorf("decode trust policy: %w", err)
	}

	var statements []map[string]json.RawMessage
	if len(document.Statement) == 0 {
		return PolicyRisk{}, fmt.Errorf("trust policy must contain Statement")
	}
	statementJSON := bytes.TrimSpace(document.Statement)
	if len(statementJSON) == 0 {
		return PolicyRisk{}, fmt.Errorf("trust policy must contain Statement")
	}
	if statementJSON[0] == '[' {
		if err := json.Unmarshal(statementJSON, &statements); err != nil {
			return PolicyRisk{}, fmt.Errorf("decode trust policy statements: %w", err)
		}
	} else {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(statementJSON, &statement); err != nil {
			return PolicyRisk{}, fmt.Errorf("decode trust policy statement: %w", err)
		}
		statements = []map[string]json.RawMessage{statement}
	}
	if len(statements) == 0 {
		return PolicyRisk{}, fmt.Errorf("trust policy must contain at least one Statement")
	}

	for _, statement := range statements {
		if len(statement["Effect"]) == 0 || len(statement["Action"]) == 0 ||
			(len(statement["Principal"]) == 0 && len(statement["NotPrincipal"]) == 0) {
			return PolicyRisk{}, fmt.Errorf("trust policy statements must include Effect, Action, and Principal or NotPrincipal")
		}
		if hasWildcardPrincipal(statement["Principal"]) {
			return PolicyRisk{
				Score:    50,
				Findings: []string{"wildcard trust principal detected"},
			}, nil
		}
		if hasWildcardPrincipal(statement["NotPrincipal"]) {
			return PolicyRisk{
				Score:    50,
				Findings: []string{"wildcard trust NotPrincipal detected"},
			}, nil
		}
	}
	return PolicyRisk{Findings: []string{}}, nil
}

// GenerateTerraform produces role and inline-policy resources for GitOps review.
// Wildcard actions are rejected so high-risk policies cannot be emitted as
// Terraform by this adapter; wildcard resources only warn (see CheckPolicyRisk).
func (adapter AWSAdapter) GenerateTerraform(permission model.AbstractPermission, role AWSRoleInfo) (string, error) {
	roleName := strings.TrimSpace(role.Name)
	if roleName == "" {
		return "", apperr.Validation("role name must not be empty")
	}
	if !json.Valid(role.TrustPolicy) || len(bytes.TrimSpace(role.TrustPolicy)) == 0 {
		return "", fmt.Errorf("role trust policy must be valid JSON")
	}
	trustRisk, err := adapter.CheckTrustPolicyRisk(role.TrustPolicy)
	if err != nil {
		return "", err
	}
	if trustRisk.Score > 0 {
		return "", fmt.Errorf("refusing to generate Terraform for risky IAM trust policy (score %d): %s",
			trustRisk.Score, strings.Join(trustRisk.Findings, ", "))
	}

	policy, err := adapter.TranslatePermission(permission)
	if err != nil {
		return "", err
	}
	if risk := adapter.CheckPolicyRisk(policy); risk.Score > 0 {
		return "", fmt.Errorf("refusing to generate Terraform for risky IAM policy (score %d): %s",
			risk.Score, strings.Join(risk.Findings, ", "))
	}

	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal IAM policy for Terraform: %w", err)
	}

	return adapter.GenerateRoleWithPolicyTerraform(role, policyJSON)
}

// TranslateAbstractPolicy 将新的 AbstractPolicy 转换为 AWS IAM 策略文档
// 这是多云架构的核心转换方法，支持跨云统一的抽象策略模型
func (adapter AWSAdapter) TranslateAbstractPolicy(policy *abstractiam.AbstractPolicy) (IAMPolicyDocument, error) {
	if policy == nil {
		return IAMPolicyDocument{}, fmt.Errorf("abstract policy must not be nil")
	}
	if len(policy.Statements) == 0 {
		return IAMPolicyDocument{}, fmt.Errorf("abstract policy must contain at least one statement")
	}

	iamPolicy := IAMPolicyDocument{
		Version:   iamPolicyVersion,
		Statement: make([]IAMPolicyStatement, 0, len(policy.Statements)),
	}

	for index, statement := range policy.Statements {
		if statement.Effect != "Allow" && statement.Effect != "Deny" {
			return IAMPolicyDocument{}, fmt.Errorf("statement %d has unsupported effect %q", index, statement.Effect)
		}

		// 转换动作：使用统一动作映射表
		var actions []string
		for _, abstractAction := range statement.Actions {
			awsActions, ok := abstractiam.GetActionsForProvider(abstractAction, "aws")
			if !ok {
				// 如果不是抽象动作，假设已经是 AWS 动作
				awsActions = []string{abstractAction}
			}
			actions = append(actions, awsActions...)
		}

		// 转换资源
		var resources []string
		for _, resource := range statement.Resources {
			awsResource, err := translateResource(resource)
			if err != nil {
				return IAMPolicyDocument{}, fmt.Errorf("statement %d: %w", index, err)
			}
			resources = append(resources, awsResource)
		}

		// 转换条件
		var condition map[string]interface{}
		if len(statement.Conditions) > 0 {
			condition = make(map[string]interface{})
			for _, cond := range statement.Conditions {
				operatorConditions := make(map[string]interface{})
				operatorConditions[cond.Key] = cond.Values
				condition[cond.Operator] = operatorConditions
			}
		}

		iamPolicy.Statement = append(iamPolicy.Statement, IAMPolicyStatement{
			Effect:    statement.Effect,
			Action:    actions,
			Resource:  resources,
			Condition: condition,
		})
	}

	return iamPolicy, nil
}

// GenerateRoleWithPolicyTerraform renders the canonical Terraform file for a
// platform-created role: the aws_iam_role declaration plus its single inline
// policy (named "<role>-policy"). Resource labels are derived from the role
// name (role_<role> / role_<role>_policy) so two CREATE files in the same
// module never collide — the historical hard-coded managed_role/managed_policy
// labels produced duplicate Terraform addresses once a second CREATE file
// landed (state drift → destroy+recreate, docs item 15). Only CREATE_ROLE
// generation writes whole files; in-place updates patch existing bytes, so
// files generated before the label change keep their original addresses. The
// document is normalized (AWS format or platform DSL) before rendering.
//
// An empty document means the ticket declared no permissions at all: the file
// then declares only the role (a zero-permission role is a valid AWS object)
// and no <role>-policy resource. Managed policies attached at creation time
// (role.PolicyARNs) are rendered as aws_iam_role_policy_attachment resources
// in the same file, mirroring CREATE_USER / CREATE_GROUP.
func (adapter AWSAdapter) GenerateRoleWithPolicyTerraform(
	role AWSRoleInfo,
	document json.RawMessage,
) (string, error) {
	roleName := strings.TrimSpace(role.Name)
	if roleName == "" {
		return "", apperr.Validation("role name must not be empty")
	}
	if !json.Valid(role.TrustPolicy) || len(bytes.TrimSpace(role.TrustPolicy)) == 0 {
		return "", fmt.Errorf("role trust policy must be valid JSON")
	}

	policyExpr := ""
	policyDeclared := len(bytes.TrimSpace(document)) > 0 && string(bytes.TrimSpace(document)) != "null"
	if policyDeclared {
		policyJSON, err := adapter.normalizePolicyDocument(document)
		if err != nil {
			return "", err
		}
		policyExpr, err = terraformJSONEncode(policyJSON)
		if err != nil {
			return "", err
		}
	}
	trustExpr, err := terraformJSONEncode(role.TrustPolicy)
	if err != nil {
		return "", err
	}

	roleLabel := RoleResourceLabel(roleName)
	policyLabel := roleLabel + "_policy"

	attributes := []hclAttribute{{"name", terraformString(roleName)}, {"assume_role_policy", trustExpr}}
	if strings.TrimSpace(role.Path) != "" {
		path, err := NormalizeIAMPath(role.Path)
		if err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"path", terraformString(path)})
	}
	if strings.TrimSpace(role.PermissionsBoundaryARN) != "" {
		boundary := strings.TrimSpace(role.PermissionsBoundaryARN)
		if err := ValidateIAMPolicyARN(boundary); err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"permissions_boundary", terraformString(boundary)})
	}
	if role.Description != "" {
		attributes = append(attributes, hclAttribute{"description", terraformString(role.Description)})
	}
	if len(role.Tags) > 0 {
		if err := ValidateIAMTags(role.Tags); err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"tags", terraformTagsExpression(role.Tags)})
	}

	var hcl strings.Builder
	hcl.WriteString("resource \"aws_iam_role\" \"" + roleLabel + "\" {\n")
	writeHCLAttributes(&hcl, attributes)
	hcl.WriteString("}\n")

	if policyDeclared {
		hcl.WriteString("\n")
		hcl.WriteString("resource \"aws_iam_role_policy\" \"" + policyLabel + "\" {\n")
		hcl.WriteString("\tname   = ")
		hcl.WriteString(terraformString(roleName + "-policy"))
		hcl.WriteString("\n\trole   = aws_iam_role." + roleLabel + ".id\n")
		hcl.WriteString("\tpolicy = ")
		hcl.WriteString(policyExpr)
		hcl.WriteString("\n}\n")
	}

	for _, policyARN := range uniqueTrimmedStrings(role.PolicyARNs) {
		if err := ValidateIAMPolicyARN(policyARN); err != nil {
			return "", err
		}
		attachmentLabel := DefaultAttachmentLabel("Role", roleName, policyARN)
		hcl.WriteString("\n")
		hcl.WriteString("resource \"aws_iam_role_policy_attachment\" \"" + attachmentLabel + "\" {\n")
		hcl.WriteString("\trole       = ")
		hcl.WriteString(terraformString(roleName))
		hcl.WriteString("\n\tpolicy_arn = ")
		hcl.WriteString(terraformString(policyARN))
		hcl.WriteString("\n}\n")
	}

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// RoleIdentity carries the attributes a role's Terraform declaration must
// reproduce verbatim even though no ticket edits them. path and
// permissions_boundary are ForceNew in the AWS provider: for an imported role,
// omitting them makes plan read "delete the attribute" and replace the role
// (new ARN → every attachment and instance profile breaks). Callers fill this
// from the inventory, never from user input.
type RoleIdentity struct {
	Path                   string
	PermissionsBoundaryARN string
}

// GenerateWildRoleTerraform renders the standalone Terraform file for a wild
// role (not created via this platform): an optional first-time import block
// plus a role block declaring only the attributes the ticket manages. The
// file never declares the role's inline policies or attachments — those
// belong to other modules and other files — so apply touches role attributes
// only and attachments stay zero-contact. Trust is provider-required, so the
// file always declares it (the caller fills the inventory's current value
// when the ticket does not change it). identity carries the ForceNew
// attributes from the inventory for the same reason. The role label is
// derived from the role name (role_<name>) so two wild-role files never
// collide; callers whose file already exists patch it in place instead of
// regenerating, so existing addresses (including legacy managed_role) never
// drift.
func (adapter AWSAdapter) GenerateWildRoleTerraform(
	roleName string,
	config *UpdateRoleConfig,
	importID string,
	identity RoleIdentity,
) (string, error) {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return "", apperr.Validation("role name must not be empty")
	}
	if config == nil || config.TrustPolicy == nil {
		return "", errors.New("update_role.trust_policy is required to render a role file")
	}
	trustJSON, err := json.Marshal(config.TrustPolicy)
	if err != nil || !json.Valid(trustJSON) {
		return "", fmt.Errorf("trust policy must be valid JSON")
	}
	trustExpr, err := terraformJSONEncode(trustJSON)
	if err != nil {
		return "", err
	}

	attributes := []hclAttribute{{"name", terraformString(roleName)}, {"assume_role_policy", trustExpr}}
	if strings.TrimSpace(identity.Path) != "" {
		path, err := NormalizeIAMPath(identity.Path)
		if err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"path", terraformString(path)})
	}
	if strings.TrimSpace(identity.PermissionsBoundaryARN) != "" {
		boundary := strings.TrimSpace(identity.PermissionsBoundaryARN)
		if err := ValidateIAMPolicyARN(boundary); err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"permissions_boundary", terraformString(boundary)})
	}
	if config.Description != nil && strings.TrimSpace(*config.Description) != "" {
		attributes = append(attributes, hclAttribute{"description", terraformString(*config.Description)})
	}
	if config.MaxSessionDuration != nil && *config.MaxSessionDuration > 0 {
		attributes = append(attributes, hclAttribute{"max_session_duration", strconv.Itoa(*config.MaxSessionDuration)})
	}
	if config.Tags != nil && len(config.Tags) > 0 {
		if err := ValidateIAMTags(config.Tags); err != nil {
			return "", err
		}
		attributes = append(attributes, hclAttribute{"tags", terraformTagsExpression(config.Tags)})
	}

	roleLabel := RoleResourceLabel(roleName)
	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing role into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_role." + roleLabel + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_role\" \"" + roleLabel + "\" {\n")
	writeHCLAttributes(&hcl, attributes)
	hcl.WriteString("}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateTerraformFromAbstractPolicy 使用新的 AbstractPolicy 生成 Terraform 代码
// 这是多云架构的核心生成方法，支持从抽象策略生成 AWS IAM 资源
//
// policy 为 nil 表示工单没有声明任何权限（零权限角色）：只生成角色本体与
// 初始挂载，不生成内嵌策略资源。
func (adapter AWSAdapter) GenerateTerraformFromAbstractPolicy(policy *abstractiam.AbstractPolicy, role AWSRoleInfo) (string, error) {
	roleName := strings.TrimSpace(role.Name)
	if roleName == "" {
		return "", apperr.Validation("role name must not be empty")
	}
	if !json.Valid(role.TrustPolicy) || len(bytes.TrimSpace(role.TrustPolicy)) == 0 {
		return "", fmt.Errorf("role trust policy must be valid JSON")
	}

	trustRisk, err := adapter.CheckTrustPolicyRisk(role.TrustPolicy)
	if err != nil {
		return "", err
	}
	if trustRisk.Score > 0 {
		return "", fmt.Errorf("refusing to generate Terraform for risky IAM trust policy (score %d): %s",
			trustRisk.Score, strings.Join(trustRisk.Findings, ", "))
	}

	if policy == nil {
		return adapter.GenerateRoleWithPolicyTerraform(role, nil)
	}

	iamPolicy, err := adapter.TranslateAbstractPolicy(policy)
	if err != nil {
		return "", err
	}

	if risk := adapter.CheckPolicyRisk(iamPolicy); risk.Score > 0 {
		return "", fmt.Errorf("refusing to generate Terraform for risky IAM policy (score %d): %s",
			risk.Score, strings.Join(risk.Findings, ", "))
	}

	policyJSON, err := json.MarshalIndent(iamPolicy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal IAM policy for Terraform: %w", err)
	}

	return adapter.GenerateRoleWithPolicyTerraform(role, policyJSON)
}

// validateTerraformHCL verifies that generated Terraform code parses as valid
// HCL, catching syntax errors at generation time instead of at plan time.
func validateTerraformHCL(code string) error {
	if strings.TrimSpace(code) == "" {
		return errors.New("generated Terraform code is empty")
	}
	_, diags := hclwrite.ParseConfig([]byte(code), "", hcl.InitialPos)
	if diags.HasErrors() {
		return fmt.Errorf("generated Terraform failed HCL validation: %s", diags.Error())
	}
	return nil
}

// GenerateAttachUserPolicyTerraform generates Terraform that attaches an
// existing IAM policy (AWS-managed or customer-managed) to an existing IAM user.
func (adapter AWSAdapter) GenerateAttachUserPolicyTerraform(userName, policyARN string) (string, error) {
	return adapter.GenerateAttachPolicyTerraform("User", userName, policyARN, "", "")
}

// GenerateAttachPolicyTerraform generates Terraform that attaches an existing
// IAM policy to an IAM principal. principalType "User" yields an
// aws_iam_user_policy_attachment; "Group" yields an
// aws_iam_group_policy_attachment (group attachment is the common way
// permissions are granted in AWS); "Role" yields an
// aws_iam_role_policy_attachment. When importID is non-empty
// ("<principalName>/<policyARN>" for a pre-existing platform-unmanaged
// attachment — the provider import id is the principal name and the policy
// ARN separated by "/"), an `import` block is emitted so a single apply adopts
// the attachment into Terraform state (Terraform >= 1.5). resourceLabel
// overrides the default label (attachment_<type>_<principal>_<policyName>) so
// distinct attachments never collide in the account's Terraform module.
func (adapter AWSAdapter) GenerateAttachPolicyTerraform(
	principalType, principalName, policyARN, importID string,
	resourceLabel string,
) (string, error) {
	principalType = strings.TrimSpace(principalType)
	principalName = strings.TrimSpace(principalName)
	if principalName == "" {
		return "", apperr.Validationf("%s name must not be empty", strings.ToLower(principalType))
	}
	if err := ValidateIAMPolicyARN(policyARN); err != nil {
		return "", err
	}

	var resourceType, principalAttr string
	switch principalType {
	case "User", "":
		resourceType, principalAttr = "aws_iam_user_policy_attachment", "user"
	case "Group":
		resourceType, principalAttr = "aws_iam_group_policy_attachment", "group"
	case "Role":
		resourceType, principalAttr = "aws_iam_role_policy_attachment", "role"
	default:
		return "", fmt.Errorf("unsupported principal type %q for policy attachment", principalType)
	}

	label := strings.TrimSpace(resourceLabel)
	if label == "" {
		label = DefaultAttachmentLabel(principalType, principalName, policyARN)
	}
	label = sanitizedLabelToken(label)

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing attachment into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = " + resourceType + "." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"" + resourceType + "\" \"" + label + "\" {\n")
	hcl.WriteString("\t" + principalAttr + strings.Repeat(" ", 11-len(principalAttr)) + "= ")
	hcl.WriteString(terraformString(principalName))
	hcl.WriteString("\n\tpolicy_arn = ")
	hcl.WriteString(terraformString(strings.TrimSpace(policyARN)))
	hcl.WriteString("\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// RoleAttrPatch describes surgical changes to the aws_iam_role block of an
// existing Terraform file. A nil field leaves the attribute untouched; a
// non-nil pointer to an empty string, a non-positive duration, or an empty
// tag map removes the attribute (ROLLBACK uses this to restore a pre-update
// absence).
type RoleAttrPatch struct {
	TrustPolicy        *string
	Description        *string
	MaxSessionDuration *int
	Tags               *map[string]string
}

// RoleAttrPatchFromConfig converts an UPDATE_ROLE config (ticket request or
// decoded pre-update snapshot) into a patch: every field the config carries
// becomes a set-or-remove directive; fields it omits stay untouched. That is
// what makes 「留空 = 不修改」 a real semantics and lets ROLLBACK restore each
// captured attribute to its pre-update value.
func RoleAttrPatchFromConfig(config *UpdateRoleConfig) *RoleAttrPatch {
	patch := &RoleAttrPatch{}
	if config == nil {
		return patch
	}
	if config.TrustPolicy != nil {
		if policyJSON, err := json.Marshal(config.TrustPolicy); err == nil {
			value := string(policyJSON)
			patch.TrustPolicy = &value
		}
	}
	patch.Description = config.Description
	patch.MaxSessionDuration = config.MaxSessionDuration
	if config.Tags != nil {
		tags := config.Tags
		patch.Tags = &tags
	}
	return patch
}

// PatchRoleAttributes applies a RoleAttrPatch to the aws_iam_role block of an
// existing Terraform file, leaving every other byte (inline policies,
// managed_policy_arns, attachments, comments) untouched. This is the
// generation primitive for UPDATE_ROLE after the scope narrowing: only the
// attributes the user submitted change, so「留空 = 不修改」 holds and the
// mutual-clobber between UPDATE_ROLE and inline-policy updates is gone
// (each module owns disjoint bytes of the file). The target block is located
// by its name attribute (roleName), never by resource label — labels differ
// between legacy files (managed_role), operator-renamed ones, and newly
// generated role_<name> files.
//
// First-time-adoption import blocks pointing at aws_iam_role.* are removed
// together with their comment header: once the resource is applied into
// state a leftover import makes every later `terraform plan` fail with
// "Resource already managed" (same convention as PatchInlinePolicyDocument,
// item 23). Imports targeting other resource types stay untouched.
//
// Implementation: hclsyntax parses the file and reports byte ranges for the
// attributes; patches are textual splices over those ranges. hclwrite's node
// rendering re-indents the whole file (2-space + aligned `=`), which would
// turn a one-attribute change into a whole-file diff — the opposite of a
// surgical GitOps patch.
func (adapter AWSAdapter) PatchRoleAttributes(fileContent string, patch *RoleAttrPatch, roleName string) (string, error) {
	if patch == nil {
		patch = &RoleAttrPatch{}
	}
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "role.tf", hcl.InitialPos)
	if diags.HasErrors() {
		return "", fmt.Errorf("parse role Terraform file: %w", diags)
	}
	root := file.Body.(*hclsyntax.Body)
	roleBlock := findHCLRoleBlock(root, fileContent, roleName)
	if roleBlock == nil {
		if strings.TrimSpace(roleName) == "" {
			return "", errors.New(`resource "aws_iam_role" block not found in Terraform file`)
		}
		return "", fmt.Errorf(`resource "aws_iam_role" named %q not found in Terraform file`, roleName)
	}
	// 消费型清理：role 文件里 to 指向 aws_iam_role.* 的首次纳管 import 块，
	// 资源 apply 进 state 后必须剔除——残留的 import 会让后续每次 plan 都报
	// "Resource already managed"。与内嵌策略 patch 的 item-23 约定一致；
	// 指向其他资源类型的 import（同文件多声明的场景）保持不动。
	var consumedImports []attrSplice
	for _, block := range root.Blocks {
		if block.Type != "import" {
			continue
		}
		toAttr := block.Body.Attributes["to"]
		if toAttr == nil {
			continue
		}
		to := strings.TrimSpace(fileContent[toAttr.Expr.Range().Start.Byte:toAttr.Expr.Range().End.Byte])
		if !strings.HasPrefix(to, "aws_iam_role.") {
			continue
		}
		start, end := commentAwareBlockSpan(fileContent, block)
		consumedImports = append(consumedImports, attrSplice{start: start, end: end})
	}
	return applyRoleAttrSplices(fileContent, roleBlock, patch, consumedImports)
}

// HasRoleResourceBlock reports whether the file declares an aws_iam_role
// resource. The wild-role UPDATE path uses it to choose between patching the
// existing file in place and generating a fresh one: a fetched file without a
// role block (rollback-emptied or comment-only) cannot be patched, while a
// file that does declare one must keep its address (regenerating would risk
// a different label → destroy+recreate).
func HasRoleResourceBlock(fileContent string) bool {
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "role.tf", hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	root := file.Body.(*hclsyntax.Body)
	for _, block := range root.Blocks {
		if block.Type == "resource" && len(block.Labels) == 2 && block.Labels[0] == "aws_iam_role" {
			return true
		}
	}
	return false
}

// PatchInlinePolicyDocument replaces the document of one inline-policy
// resource (aws_iam_role_policy / aws_iam_group_policy) in an existing
// Terraform file, matched by its name attribute, leaving every other byte
// untouched — the resource label included, so the Terraform address never
// drifts. A label change would make an in-place document update apply as
// destroy+recreate of the very same AWS object.
//
// importID normalizes the file's first-time-adoption import block for the
// patched resource type: "" removes a stale/consumed import block
// (re-importing an already-managed resource makes `terraform plan` fail),
// a non-empty id writes the canonical block. Import blocks of other resource
// types (for example a source CREATE file's own declarations) are never
// touched.
func (adapter AWSAdapter) PatchInlinePolicyDocument(
	fileContent, resourceType, policyName string,
	document json.RawMessage,
	importID string,
) (string, error) {
	resourceType = strings.TrimSpace(resourceType)
	policyName = strings.TrimSpace(policyName)
	if resourceType == "" {
		return "", errors.New("resource type must not be empty")
	}
	if policyName == "" {
		return "", apperr.Validation("inline policy name must not be empty")
	}
	normalized, err := adapter.normalizePolicyDocument(document)
	if err != nil {
		return "", fmt.Errorf("inline policy %s: %w", policyName, err)
	}
	newExpr, err := terraformJSONEncode(normalized)
	if err != nil {
		return "", err
	}
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "inline-policy.tf", hcl.InitialPos)
	if diags.HasErrors() {
		return "", fmt.Errorf("parse Terraform file: %w", diags)
	}
	root := file.Body.(*hclsyntax.Body)

	var (
		splices       []attrSplice
		matched       bool
		resourceLabel string
		policyAttr    *hclsyntax.Attribute
	)
	for _, block := range root.Blocks {
		switch {
		case block.Type == "import":
			// 消费型清理：import 块只在 to 指向本资源类型时移除；
			// 其他类型（如角色声明自带的 import）保持不动。
			toAttr := block.Body.Attributes["to"]
			if toAttr == nil {
				continue
			}
			to := strings.TrimSpace(fileContent[toAttr.Expr.Range().Start.Byte:toAttr.Expr.Range().End.Byte])
			if !strings.HasPrefix(to, resourceType+".") {
				continue
			}
			start, end := commentAwareBlockSpan(fileContent, block)
			splices = append(splices, attrSplice{start: start, end: end})
		case block.Type == "resource" && len(block.Labels) == 2 && block.Labels[0] == resourceType:
			if matched {
				continue
			}
			nameAttr := block.Body.Attributes["name"]
			if nameAttr == nil {
				continue
			}
			currentName := strings.Trim(fileContent[nameAttr.Expr.Range().Start.Byte:nameAttr.Expr.Range().End.Byte], `"`)
			if currentName != policyName {
				continue
			}
			matched = true
			resourceLabel = block.Labels[1]
			policyAttr = block.Body.Attributes["policy"]
		}
	}
	if !matched {
		return "", fmt.Errorf("inline policy %q not found as a %s in Terraform file", policyName, resourceType)
	}
	if policyAttr == nil {
		return "", fmt.Errorf("inline policy %q has no policy attribute in Terraform file", policyName)
	}
	splices = append(splices, attrSplice{
		start: policyAttr.Expr.Range().Start.Byte,
		end:   policyAttr.Expr.Range().End.Byte,
		text:  newExpr,
	})
	// 自后向前套用 splice：更靠后的替换不会位移更靠前的偏移。
	sort.Slice(splices, func(i, j int) bool { return splices[i].start > splices[j].start })
	patched := fileContent
	for _, item := range splices {
		patched = splice(patched, item.start, item.end, item.text)
	}
	if trimmed := strings.TrimSpace(importID); trimmed != "" {
		patched = firstTimeAdoptionImportHeader(resourceType, resourceLabel, trimmed) + patched
	}
	if err := validateTerraformHCL(patched); err != nil {
		return "", err
	}
	return patched, nil
}

// PatchRoleInlinePolicy replaces the document of one inline-policy resource
// (aws_iam_role_policy) in an existing Terraform file, matched by its name
// attribute, leaving every other byte untouched. Inline-policy updates share
// the CREATE_ROLE ticket's file; patching only the policy attribute keeps
// trust/attribute changes made by other tickets from being reverted (the
// B-path half of the mutual-clobber fix). Source CREATE files never carry a
// policy-import block, so import normalization is a no-op here.
func (adapter AWSAdapter) PatchRoleInlinePolicy(fileContent, policyName string, document json.RawMessage) (string, error) {
	return adapter.PatchInlinePolicyDocument(fileContent, "aws_iam_role_policy", policyName, document, "")
}

// ScanInlinePolicyResourceBlock reports whether fileContent declares an
// inline-policy resource (resourceType, e.g. "aws_iam_role_policy") whose
// name attribute equals policyName, returning the block's Terraform label.
// hasResources reports whether the file declares any resource blocks at all —
// callers refuse to overwrite such a file when the target block is missing.
// Comment-only/blank files (rollback-emptied) scan as no blocks; real parse
// errors bubble so broken HCL is never silently regenerated over.
func ScanInlinePolicyResourceBlock(fileContent, resourceType, policyName string) (label string, found bool, hasResources bool, err error) {
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "inline-policy.tf", hcl.InitialPos)
	if diags.HasErrors() {
		if commentOrBlankOnly(fileContent) {
			return "", false, false, nil
		}
		return "", false, false, fmt.Errorf("parse Terraform file: %w", diags)
	}
	root := file.Body.(*hclsyntax.Body)
	policyName = strings.TrimSpace(policyName)
	for _, block := range root.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 {
			continue
		}
		hasResources = true
		if block.Labels[0] != resourceType {
			continue
		}
		nameAttr := block.Body.Attributes["name"]
		if nameAttr == nil {
			continue
		}
		currentName := strings.Trim(fileContent[nameAttr.Expr.Range().Start.Byte:nameAttr.Expr.Range().End.Byte], `"`)
		if currentName == policyName {
			return block.Labels[1], true, true, nil
		}
	}
	return "", false, hasResources, nil
}

// commentOrBlankOnly reports whether the file consists solely of HCL comment
// lines (# or //) and blank lines — the shape a rollback leaves behind when it
// empties a ticket's Terraform file. Parse failures on such files mean "no
// declarations", never broken content to protect.
func commentOrBlankOnly(fileContent string) bool {
	for _, line := range strings.Split(fileContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		return false
	}
	return true
}

// HasActiveDeclaration reports whether the Terraform file still carries any
// non-comment content — i.e. it declares something, as opposed to the
// comment-only file a destroy path (detach / rollback / emptied membership)
// leaves behind. Service-layer adoption gates use it to decide whether a
// resource is still declared on main.
func HasActiveDeclaration(fileContent string) bool {
	return !commentOrBlankOnly(fileContent)
}

// commentAwareBlockSpan returns the byte span covering a top-level block plus
// the contiguous comment lines directly above it (the "# First-time adoption"
// header) and one trailing blank line, so removing an import block leaves no
// orphaned comments or gaps behind.
func commentAwareBlockSpan(fileContent string, block *hclsyntax.Block) (int, int) {
	start := block.TypeRange.Start.Byte
	// 只在块关键字独占一行时向上吃注释（生成器把 `import {` 放在行首）。
	if lineStart := strings.LastIndexByte(fileContent[:start], '\n') + 1; strings.TrimSpace(fileContent[lineStart:start]) == "" {
		start = lineStart
		for start > 0 {
			prevLineStart := strings.LastIndexByte(fileContent[:start-1], '\n') + 1
			trimmed := strings.TrimSpace(fileContent[prevLineStart : start-1])
			if !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
				break
			}
			start = prevLineStart
		}
	}
	end := block.CloseBraceRange.End.Byte
	// 吃掉 `}` 之后的换行与紧随的一个空行。
	if end < len(fileContent) && fileContent[end] == '\r' {
		end++
	}
	if end < len(fileContent) && fileContent[end] == '\n' {
		end++
		if end < len(fileContent) {
			lineEnd := strings.IndexByte(fileContent[end:], '\n')
			if lineEnd < 0 {
				lineEnd = len(fileContent)
			} else {
				lineEnd = end + lineEnd + 1
			}
			if strings.TrimSpace(fileContent[end:lineEnd]) == "" {
				end = lineEnd
			}
		}
	}
	return start, end
}

// firstTimeAdoptionImportHeader renders the canonical first-time-adoption
// comment + import block the inline-policy update generators emit, so a
// patched file stays byte-identical to a regenerated one.
func firstTimeAdoptionImportHeader(resourceType, label, importID string) string {
	return "# First-time adoption: import the pre-existing inline policy into\n" +
		"# Terraform state, then apply the declared document (Terraform >= 1.5).\n" +
		"import {\n\tid = " + terraformString(importID) +
		"\n\tto = " + resourceType + "." + label + "\n}\n\n"
}

// findHCLRoleBlock locates the resource "aws_iam_role" block whose name
// attribute equals roleName. Matching is done on the name attribute, not the
// resource label: labels differ across generations (hard-coded managed_role,
// operator renames such as managed_role11, and the role_<name> labels
// generated now), while the name attribute is the AWS identity. Legacy
// safety net: when nothing matches by name but the file declares exactly one
// aws_iam_role block (the single-role-per-file invariant every generator
// maintains), that block is returned; roleName may be empty, in which case
// only the fallback applies.
func findHCLRoleBlock(body *hclsyntax.Body, fileContent, roleName string) *hclsyntax.Block {
	var single *hclsyntax.Block
	roleBlocks := 0
	for _, block := range body.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 || block.Labels[0] != "aws_iam_role" {
			continue
		}
		roleBlocks++
		single = block
		if strings.TrimSpace(roleName) == "" {
			continue
		}
		nameAttr := block.Body.Attributes["name"]
		if nameAttr == nil {
			continue
		}
		current := strings.Trim(fileContent[nameAttr.Expr.Range().Start.Byte:nameAttr.Expr.Range().End.Byte], `"`)
		if strings.TrimSpace(current) == strings.TrimSpace(roleName) {
			return block
		}
	}
	if roleBlocks == 1 {
		return single
	}
	return nil
}

// attrSplice is one textual replacement: fileContent[start:end] becomes text.
// Applied back-to-front so earlier offsets stay valid.
type attrSplice struct {
	start, end int
	text       string
}

// applyRoleAttrSplices rewrites the role block's attributes in place. Each
// patch field is either a value splice over the existing attribute's
// expression range, a whole-line removal (empty value), or an append before
// the block's closing brace. Splices are applied back-to-front so earlier
// offsets stay valid.
func applyRoleAttrSplices(fileContent string, roleBlock *hclsyntax.Block, patch *RoleAttrPatch, extra []attrSplice) (string, error) {
	var splices []attrSplice
	splices = append(splices, extra...)
	// 多个新增属性在同一个插入点（块尾）合并成一个 splice，否则后插的
	// 偏移会被先插的位移（back-to-front 只对不相交 splice 安全）。
	var pendingAppends []string

	if patch.TrustPolicy != nil {
		newDocument := json.RawMessage(*patch.TrustPolicy)
		if !json.Valid(newDocument) {
			return "", errors.New("trust policy must be valid JSON")
		}
		attr := roleBlock.Body.Attributes["assume_role_policy"]
		if attr == nil {
			newExpr, err := terraformJSONEncode(newDocument)
			if err != nil {
				return "", err
			}
			pendingAppends = append(pendingAppends, "assume_role_policy = "+newExpr)
		} else {
			current := fileContent[attr.Expr.Range().Start.Byte:attr.Expr.Range().End.Byte]
			// 语义相同时不动该属性（文件里的信任可能是原始键序，解码后重排
			// 会造成伪 diff）；只在确有变化时才重写。
			if !hclJSONAttrEqual(current, newDocument) {
				newExpr, err := terraformJSONEncode(newDocument)
				if err != nil {
					return "", err
				}
				splices = append(splices, attrSplice{
					start: attr.Expr.Range().Start.Byte,
					end:   attr.Expr.Range().End.Byte,
					text:  newExpr,
				})
			}
		}
	}
	if patch.Description != nil {
		attr := roleBlock.Body.Attributes["description"]
		if *patch.Description == "" {
			if attr != nil {
				splices = append(splices, removeAttrSplice(fileContent, attr))
			}
		} else if attr != nil {
			splices = append(splices, attrSplice{
				start: attr.Expr.Range().Start.Byte,
				end:   attr.Expr.Range().End.Byte,
				text:  terraformString(*patch.Description),
			})
		} else {
			pendingAppends = append(pendingAppends, "description = "+terraformString(*patch.Description))
		}
	}
	if patch.MaxSessionDuration != nil {
		attr := roleBlock.Body.Attributes["max_session_duration"]
		if *patch.MaxSessionDuration <= 0 {
			if attr != nil {
				splices = append(splices, removeAttrSplice(fileContent, attr))
			}
		} else if attr != nil {
			splices = append(splices, attrSplice{
				start: attr.Expr.Range().Start.Byte,
				end:   attr.Expr.Range().End.Byte,
				text:  strconv.Itoa(*patch.MaxSessionDuration),
			})
		} else {
			pendingAppends = append(pendingAppends, "max_session_duration = "+strconv.Itoa(*patch.MaxSessionDuration))
		}
	}
	if patch.Tags != nil {
		attr := roleBlock.Body.Attributes["tags"]
		if len(*patch.Tags) == 0 {
			if attr != nil {
				splices = append(splices, removeAttrSplice(fileContent, attr))
			}
		} else {
			keys := make([]string, 0, len(*patch.Tags))
			for k := range *patch.Tags {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var b strings.Builder
			b.WriteString("{ ")
			for i, k := range keys {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(terraformString(k))
				b.WriteString(" = ")
				b.WriteString(terraformString((*patch.Tags)[k]))
			}
			b.WriteString(" }")
			if attr != nil {
				splices = append(splices, attrSplice{
					start: attr.Expr.Range().Start.Byte,
					end:   attr.Expr.Range().End.Byte,
					text:  b.String(),
				})
			} else {
				pendingAppends = append(pendingAppends, "tags = "+b.String())
			}
		}
	}

	if len(pendingAppends) > 0 {
		splices = append(splices, appendAttrsSplice(fileContent, roleBlock, pendingAppends))
	}

	// Back-to-front so earlier offsets stay valid.
	sort.Slice(splices, func(i, j int) bool { return splices[i].start > splices[j].start })
	out := fileContent
	for _, sp := range splices {
		out = splice(out, sp.start, sp.end, sp.text)
	}
	if err := validateTerraformHCL(out); err != nil {
		return "", err
	}
	return out, nil
}

// appendAttrsSplice builds one insertion splice placing several new
// attributes on their own lines before the block's closing brace, indented
// like their siblings.
func appendAttrsSplice(fileContent string, roleBlock *hclsyntax.Block, attrs []string) attrSplice {
	indent := bodyAttrIndent(fileContent, roleBlock.Body)
	if indent == "" {
		indent = "\t"
	}
	closeOffset := roleBlock.CloseBraceRange.Start.Byte
	var b strings.Builder
	for _, attr := range attrs {
		b.WriteString(indent)
		b.WriteString(attr)
		b.WriteString("\n")
	}
	return attrSplice{
		start: closeOffset,
		end:   closeOffset,
		text:  b.String(),
	}
}

// bodyAttrIndent extracts the indentation of the body's last attribute line
// (the new attribute matches its siblings), defaulting to one tab.
func bodyAttrIndent(fileContent string, body *hclsyntax.Body) string {
	attrs := body.Attributes
	if len(attrs) == 0 {
		return ""
	}
	var last *hclsyntax.Attribute
	for _, attr := range attrs {
		if last == nil || attr.Range().Start.Byte > last.Range().Start.Byte {
			last = attr
		}
	}
	start := last.Range().Start.Byte
	for start > 0 && fileContent[start-1] != '\n' {
		start--
	}
	line := fileContent[start:last.Range().Start.Byte]
	trimmed := strings.TrimLeft(line, " \t")
	if len(trimmed) != 0 {
		return "" // unexpected layout; fall back to no extra indent
	}
	return line
}

// removeAttrSplice builds a splice that deletes an attribute's whole line
// (leading indentation through the trailing newline).
func removeAttrSplice(fileContent string, attr *hclsyntax.Attribute) attrSplice {
	start := attr.Range().Start.Byte
	for start > 0 && fileContent[start-1] != '\n' {
		start--
	}
	end := attr.Range().End.Byte
	if end < len(fileContent) && fileContent[end] == '\n' {
		end++
	}
	return attrSplice{start: start, end: end}
}

// splice replaces fileContent[start:end] with text.
func splice(fileContent string, start, end int, text string) string {
	if start < 0 || end > len(fileContent) || start > end {
		return fileContent
	}
	return fileContent[:start] + text + fileContent[end:]
}

// hclJSONAttrEqual reports whether a jsonencode(...) attribute expression in
// the file carries the same document as newDocument, compared semantically
// (key order and whitespace ignored). Used to skip rewriting a trust policy
// whose decoded form merely reorders keys.
func hclJSONAttrEqual(currentExprText string, newDocument json.RawMessage) bool {
	inner := strings.TrimSpace(currentExprText)
	inner = strings.TrimPrefix(inner, "jsonencode(")
	inner = strings.TrimSuffix(inner, ")")
	expr, diags := hclsyntax.ParseExpression([]byte(inner), "current", hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	val, diags := expr.Value(nil)
	if diags.HasErrors() {
		return false
	}
	currentJSON, err := ctyjson.Marshal(val, val.Type())
	if err != nil {
		return false
	}
	var current, next interface{}
	if json.Unmarshal(currentJSON, &current) != nil {
		return false
	}
	if json.Unmarshal(newDocument, &next) != nil {
		return false
	}
	return reflect.DeepEqual(current, next)
}

// UpdatePolicyConfig describes the desired document for an existing policy
// being updated in place: a customer-managed policy (aws_iam_policy) or a
// group inline policy (aws_iam_group_policy).
type UpdatePolicyConfig struct {
	// PolicyARN is the customer-managed policy ARN (UPDATE_MANAGED_POLICY).
	PolicyARN string `json:"policy_arn,omitempty"`
	// PolicyName is the customer-managed policy name, derived from the ARN.
	PolicyName string `json:"policy_name,omitempty"`
	// GroupName is the IAM group owning the inline policy
	// (UPDATE_INLINE_POLICY).
	GroupName string `json:"group_name,omitempty"`
	// RoleName is the IAM role owning the inline policy. Exactly one of
	// GroupName / RoleName is set, decided by the ticket's principal_type.
	RoleName string `json:"role_name,omitempty"`
	// InlinePolicyName is the inline policy name on the group or role.
	InlinePolicyName string `json:"inline_policy_name,omitempty"`
	// Document is the full desired IAM policy document.
	Document json.RawMessage `json:"document"`
	// ResourceName is the Terraform resource label for the generated policy
	// file, resolved once by the service when the ticket is created and stored
	// on the request so the approval preview and the published file always
	// match. Empty lets the adapter derive a default.
	ResourceName string `json:"resource_name,omitempty"`
}

// GenerateUpdateManagedPolicyTerraform generates a complete aws_iam_policy
// resource declaration with the desired document, used to upsert the policy's
// Terraform file (GitOps in-place update). When importID is non-empty (the
// policy ARN), an `import` block is emitted so a single apply first imports
// the pre-existing policy into Terraform state and then converges it to the
// declared document (Terraform >= 1.5). resourceLabel overrides the default
// label (managed_policy_<name>) so repeat updates keep their original address.
func (adapter AWSAdapter) GenerateUpdateManagedPolicyTerraform(
	policyName string,
	document json.RawMessage,
	importID string,
	resourceLabel string,
) (string, error) {
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", apperr.Validation("policy name must not be empty")
	}
	normalized, err := adapter.normalizePolicyDocument(document)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}
	label := strings.TrimSpace(resourceLabel)
	if label == "" {
		label = DefaultManagedPolicyLabel(policyName)
	}
	label = sanitizedLabelToken(label)
	policyExpr, err := terraformJSONEncode(normalized)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing policy into\n")
		hcl.WriteString("# Terraform state, then apply the declared document (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_policy." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_policy\" \"" + label + "\" {\n")
	hcl.WriteString("\tname   = ")
	hcl.WriteString(terraformString(policyName))
	hcl.WriteString("\n\tpolicy = ")
	hcl.WriteString(policyExpr)
	hcl.WriteString("\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateUpdateGroupInlinePolicyTerraform generates a complete
// aws_iam_group_policy resource declaration with the desired document, used
// to upsert the inline policy's Terraform file (GitOps in-place update).
// When importID is non-empty ("<group>/<policyName>"), an `import` block is
// emitted for first-time adoption (Terraform >= 1.5).
func (adapter AWSAdapter) GenerateUpdateGroupInlinePolicyTerraform(
	groupName, policyName string,
	document json.RawMessage,
	importID string,
	resourceLabel string,
) (string, error) {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return "", apperr.Validation("group name must not be empty")
	}
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", apperr.Validation("inline policy name must not be empty")
	}
	normalized, err := adapter.normalizePolicyDocument(document)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}
	label := strings.TrimSpace(resourceLabel)
	if label == "" {
		label = InlinePolicyResourceLabel("group", groupName, policyName)
	}
	label = sanitizedLabelToken(label)
	policyExpr, err := terraformJSONEncode(normalized)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing inline policy into\n")
		hcl.WriteString("# Terraform state, then apply the declared document (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_group_policy." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_group_policy\" \"" + label + "\" {\n")
	hcl.WriteString("\tname   = ")
	hcl.WriteString(terraformString(policyName))
	hcl.WriteString("\n\tgroup  = ")
	hcl.WriteString(terraformString(groupName))
	hcl.WriteString("\n\tpolicy = ")
	hcl.WriteString(policyExpr)
	hcl.WriteString("\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateUpdateRoleInlinePolicyTerraform is the role counterpart of
// GenerateUpdateGroupInlinePolicyTerraform: it renders an aws_iam_role_policy
// resource. The import block id is "<role>:<policyName>" (colon-separated),
// which is the identity Terraform uses for aws_iam_role_policy.
func (adapter AWSAdapter) GenerateUpdateRoleInlinePolicyTerraform(
	roleName, policyName string,
	document json.RawMessage,
	importID string,
	resourceLabel string,
) (string, error) {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return "", apperr.Validation("role name must not be empty")
	}
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", apperr.Validation("inline policy name must not be empty")
	}
	normalized, err := adapter.normalizePolicyDocument(document)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}
	label := strings.TrimSpace(resourceLabel)
	if label == "" {
		label = InlinePolicyResourceLabel("role", roleName, policyName)
	}
	label = sanitizedLabelToken(label)
	policyExpr, err := terraformJSONEncode(normalized)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing inline policy into\n")
		hcl.WriteString("# Terraform state, then apply the declared document (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_role_policy." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_role_policy\" \"" + label + "\" {\n")
	hcl.WriteString("\tname   = ")
	hcl.WriteString(terraformString(policyName))
	hcl.WriteString("\n\trole   = ")
	hcl.WriteString(terraformString(roleName))
	hcl.WriteString("\n\tpolicy = ")
	hcl.WriteString(policyExpr)
	hcl.WriteString("\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// NormalizePolicyDocument exposes the adapter's AWS/DSL policy normalization
// for service-level validation and risk scanning.
func (adapter AWSAdapter) NormalizePolicyDocument(document json.RawMessage) (json.RawMessage, error) {
	return adapter.normalizePolicyDocument(document)
}

// GenerateCreateManagedPolicyTerraform renders a customer-managed
// aws_iam_policy. When importID is non-empty (the policy ARN), the file first
// imports an existing policy instead of trying to create it.
func (adapter AWSAdapter) GenerateCreateManagedPolicyTerraform(
	policy ManagedPolicyInfo,
	importID string,
) (string, error) {
	name := strings.TrimSpace(policy.Name)
	if err := ValidateIAMResourceName("policy", name); err != nil {
		return "", err
	}
	path, err := NormalizeIAMPath(policy.Path)
	if err != nil {
		return "", err
	}
	if err := ValidateIAMTags(policy.Tags); err != nil {
		return "", err
	}
	normalized, err := adapter.normalizePolicyDocument(policy.Document)
	if err != nil {
		return "", fmt.Errorf("policy document: %w", err)
	}
	policyExpr, err := terraformJSONEncode(normalized)
	if err != nil {
		return "", err
	}
	label := DefaultManagedPolicyLabel(name)

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing policy into\n")
		hcl.WriteString("# Terraform state, then apply the declared document (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_policy." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_policy\" \"" + label + "\" {\n")
	hcl.WriteString("\tname   = ")
	hcl.WriteString(terraformString(name))
	hcl.WriteString("\n\tpath   = ")
	hcl.WriteString(terraformString(path))
	hcl.WriteString("\n\tpolicy = ")
	hcl.WriteString(policyExpr)
	if description := strings.TrimSpace(policy.Description); description != "" {
		hcl.WriteString("\n\tdescription = ")
		hcl.WriteString(terraformString(description))
	}
	writeTerraformTags(&hcl, policy.Tags)
	hcl.WriteString("\n}\n")

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateCreateUserTerraform renders an aws_iam_user plus its managed-policy
// attachments. The user's credentials are deliberately never declared: AWS
// access keys and passwords must be created outside the platform.
//
// Group membership is deliberately absent: aws_iam_user_group_membership would
// declare the same (user, group) edge that the group's own declaration
// (aws_iam_group_membership in group-<group>-membership.tf) owns, and the two
// resources then fight over it — every apply of one restores its own list and
// the plan diff never converges (docs/pending-issues A8). Callers that need
// initial groups render the group membership files instead (the ticket flow
// does this in buildCreateMembershipBundle), so each edge has exactly one
// owner.
func (adapter AWSAdapter) GenerateCreateUserTerraform(
	user IAMUserInfo,
	importID string,
) (string, error) {
	name := strings.TrimSpace(user.Name)
	if err := ValidateIAMResourceName("user", name); err != nil {
		return "", err
	}
	path, err := NormalizeIAMPath(user.Path)
	if err != nil {
		return "", err
	}
	if err := ValidateIAMTags(user.Tags); err != nil {
		return "", err
	}
	label := UserResourceLabel(name)

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing IAM user into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_user." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_user\" \"" + label + "\" {\n")
	hcl.WriteString("\tname = ")
	hcl.WriteString(terraformString(name))
	hcl.WriteString("\n\tpath = ")
	hcl.WriteString(terraformString(path))
	writeTerraformTags(&hcl, user.Tags)
	hcl.WriteString("\n}\n")

	groups := uniqueTrimmedStrings(user.GroupNames)
	if len(groups) > 0 {
		// 组归属写在组的 membership 文件里（单一 owner，见函数注释）。这里
		// 留一行说明，避免审阅的人以为成员关系被漏掉了。
		hcl.WriteString("\n# Group membership is owned by each group's own file\n")
		hcl.WriteString("# (group-<group>-membership.tf); this ticket adds this user to: ")
		hcl.WriteString(strings.Join(groups, ", "))
		hcl.WriteString("\n")
	}
	for _, policyARN := range uniqueTrimmedStrings(user.PolicyARNs) {
		if err := ValidateIAMPolicyARN(policyARN); err != nil {
			return "", err
		}
		attachmentLabel := DefaultAttachmentLabel("User", name, policyARN)
		hcl.WriteString("\nresource \"aws_iam_user_policy_attachment\" \"" + attachmentLabel + "\" {\n")
		hcl.WriteString("\tuser       = " + terraformString(name) + "\n")
		hcl.WriteString("\tpolicy_arn = " + terraformString(policyARN) + "\n")
		hcl.WriteString("}\n")
	}

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}
	return hcl.String(), nil
}

// GenerateCreateGroupTerraform renders an aws_iam_group plus its optional
// managed-policy attachments and inline policies. When adopting, attachments
// and inline policies are imported alongside the group.
//
// Membership is not declared here: the aws_iam_group_membership resource lives
// in its own file (group-<group>-membership.tf) so a membership has exactly one
// owner — the same rule as GenerateCreateUserTerraform (docs/pending-issues
// A8). The ticket flow renders that file from group.MemberUserNames.
func (adapter AWSAdapter) GenerateCreateGroupTerraform(
	group IAMGroupInfo,
	importID string,
) (string, error) {
	name := strings.TrimSpace(group.Name)
	if err := ValidateIAMResourceName("group", name); err != nil {
		return "", err
	}
	path, err := NormalizeIAMPath(group.Path)
	if err != nil {
		return "", err
	}
	if err := ValidateIAMTags(group.Tags); err != nil {
		return "", err
	}
	label := GroupResourceLabel(name)

	var hcl strings.Builder
	if strings.TrimSpace(importID) != "" {
		hcl.WriteString("# First-time adoption: import the pre-existing IAM group into\n")
		hcl.WriteString("# Terraform state, then declare it (Terraform >= 1.5).\n")
		hcl.WriteString("import {\n\tid = ")
		hcl.WriteString(terraformString(strings.TrimSpace(importID)))
		hcl.WriteString("\n\tto = aws_iam_group." + label + "\n}\n\n")
	}
	hcl.WriteString("resource \"aws_iam_group\" \"" + label + "\" {\n")
	hcl.WriteString("\tname = ")
	hcl.WriteString(terraformString(name))
	hcl.WriteString("\n\tpath = ")
	hcl.WriteString(terraformString(path))
	writeTerraformTags(&hcl, group.Tags)
	hcl.WriteString("\n}\n")

	members := uniqueTrimmedStrings(group.MemberUserNames)
	if len(members) > 0 {
		// 与 CREATE_USER 同一取舍：成员关系只由 membership 文件声明。若这里
		// 也生成 aws_iam_group_membership，基线的 group-<group>-membership.tf
		// 会声明同一个地址，Terraform 直接拒绝整个配置。
		hcl.WriteString("\n# Membership is owned by group-<group>-membership.tf; that file\n")
		hcl.WriteString("# declares the users this ticket adds: ")
		hcl.WriteString(strings.Join(members, ", "))
		hcl.WriteString("\n")
	}
	for _, policyARN := range uniqueTrimmedStrings(group.PolicyARNs) {
		if err := ValidateIAMPolicyARN(policyARN); err != nil {
			return "", err
		}
		attachmentLabel := DefaultAttachmentLabel("Group", name, policyARN)
		if strings.TrimSpace(importID) != "" {
			hcl.WriteString("\nimport {\n\tid = ")
			hcl.WriteString(terraformString(name + "/" + policyARN))
			hcl.WriteString("\n\tto = aws_iam_group_policy_attachment." + attachmentLabel + "\n}\n")
		}
		hcl.WriteString("\nresource \"aws_iam_group_policy_attachment\" \"" + attachmentLabel + "\" {\n")
		hcl.WriteString("\tgroup      = " + terraformString(name) + "\n")
		hcl.WriteString("\tpolicy_arn = " + terraformString(policyARN) + "\n")
		hcl.WriteString("}\n")
	}
	for _, policy := range group.InlinePolicies {
		inlineImportID := ""
		if strings.TrimSpace(importID) != "" {
			inlineImportID = name + "/" + policy.Name
		}
		policyHCL, err := adapter.GenerateUpdateGroupInlinePolicyTerraform(
			name, policy.Name, policy.Document, inlineImportID, "",
		)
		if err != nil {
			return "", fmt.Errorf("render inline policy %q: %w", policy.Name, err)
		}
		hcl.WriteString("\n")
		hcl.WriteString(policyHCL)
	}

	if err := validateTerraformHCL(hcl.String()); err != nil {
		return "", err
	}

	return hcl.String(), nil
}

// RemoveAttachmentFromTerraform removes one managed-policy attachment block
// from a create-user/create-group Terraform file. Detach tickets use it to
// destroy only the relationship while preserving the user/group and any other
// attachments declared in the same file.
func (adapter AWSAdapter) RemoveAttachmentFromTerraform(
	fileContent, principalType, principalName, policyARN string,
) (string, error) {
	principalType = strings.TrimSpace(principalType)
	resourceType := ""
	principalAttr := ""
	switch principalType {
	case "User", "":
		resourceType, principalAttr = "aws_iam_user_policy_attachment", "user"
	case "Group":
		resourceType, principalAttr = "aws_iam_group_policy_attachment", "group"
	case "Role":
		resourceType, principalAttr = "aws_iam_role_policy_attachment", "role"
	default:
		return "", fmt.Errorf("unsupported principal type %q for attachment removal", principalType)
	}
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "create.tf", hcl.InitialPos)
	if diags.HasErrors() {
		return "", fmt.Errorf("parse create Terraform file: %w", diags)
	}
	root := file.Body.(*hclsyntax.Body)
	for _, block := range root.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 || block.Labels[0] != resourceType {
			continue
		}
		if hclStringAttribute(fileContent, block.Body, principalAttr) != strings.TrimSpace(principalName) {
			continue
		}
		if hclStringAttribute(fileContent, block.Body, "policy_arn") != strings.TrimSpace(policyARN) {
			continue
		}
		// 基线纳管的挂载文件带 import 块（to 指向本资源地址）。只删
		// resource 会留下悬空 import，plan 直接报 "Resource not found in
		// configuration"，所以匹配的 import 块一并移除。
		address := resourceType + "." + block.Labels[1]
		// 资源块：按行扩展剪除（保留其上方与挂载无关的注释）。
		resourceStart, resourceEnd := block.Range().Start.Byte, block.Range().End.Byte
		removals := [][2]int{{lineSpanStart(fileContent, resourceStart), lineSpanEnd(fileContent, resourceEnd)}}
		for _, candidate := range root.Blocks {
			if candidate.Type != "import" {
				continue
			}
			if to := hclStringAttribute(fileContent, candidate.Body, "to"); to == address {
				// 基线纳管的挂载文件带 import 块（to 指向本资源地址）。只删
				// resource 会留下悬空 import，plan 直接报 "Resource not found in
				// configuration"，所以匹配的 import 块一并移除；注释感知 span
				// 连同其上方的「First-time adoption」注释头一起清掉，不留孤儿注释。
				start, end := commentAwareBlockSpan(fileContent, candidate)
				removals = append(removals, [2]int{start, end})
			}
		}
		// 从后往前按字节区间剪除，避免前面的删除移动后面区间的偏移。
		sort.Slice(removals, func(i, j int) bool {
			return removals[i][0] > removals[j][0]
		})
		updated := fileContent
		for _, removal := range removals {
			updated = updated[:removal[0]] + updated[removal[1]:]
		}
		// 单挂载文件的资源块和 import 块全部移除后剩空内容是合法结果
		// （调用方负责把空文件落成注释空文件），只对非空结果做 HCL 校验。
		if strings.TrimSpace(updated) != "" {
			if err := validateTerraformHCL(updated); err != nil {
				return "", err
			}
		}
		return updated, nil
	}
	return "", fmt.Errorf("managed policy attachment %s → %s not found in create Terraform file", policyARN, principalName)
}

// lineSpanStart expands a byte offset back to the start of its line (used to
// clip a block range to whole lines before splicing it out of the file).
func lineSpanStart(fileContent string, offset int) int {
	for offset > 0 && fileContent[offset-1] != '\n' {
		offset--
	}
	return offset
}

// lineSpanEnd expands a byte offset forward past the end of its line,
// including the trailing newline.
func lineSpanEnd(fileContent string, offset int) int {
	for offset < len(fileContent) && fileContent[offset] != '\n' {
		offset++
	}
	if offset < len(fileContent) {
		offset++
	}
	return offset
}

// ScanGroupMembershipUsers reports the users list declared by the
// aws_iam_group_membership block of a Terraform file. found=false means the
// file carries no membership declaration (comment-only emptied files scan as
// not found); real parse errors bubble.
func ScanGroupMembershipUsers(fileContent string) (label string, users []string, found bool, err error) {
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "membership.tf", hcl.InitialPos)
	if diags.HasErrors() {
		if commentOrBlankOnly(fileContent) {
			return "", nil, false, nil
		}
		return "", nil, false, fmt.Errorf("parse Terraform file: %w", diags)
	}
	root := file.Body.(*hclsyntax.Body)
	for _, block := range root.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 || block.Labels[0] != "aws_iam_group_membership" {
			continue
		}
		usersAttr := block.Body.Attributes["users"]
		if usersAttr == nil {
			return "", nil, false, fmt.Errorf("aws_iam_group_membership.%s has no users attribute", block.Labels[1])
		}
		tuple, ok := usersAttr.Expr.(*hclsyntax.TupleConsExpr)
		if !ok {
			return "", nil, false, fmt.Errorf("aws_iam_group_membership.%s users is not a list literal", block.Labels[1])
		}
		for _, expr := range tuple.Exprs {
			raw := strings.TrimSpace(fileContent[expr.Range().Start.Byte:expr.Range().End.Byte])
			users = append(users, strings.Trim(raw, `"`))
		}
		return block.Labels[1], users, true, nil
	}
	return "", nil, false, nil
}

// PatchGroupMembershipUsers rewrites the users attribute of the
// aws_iam_group_membership block in place, keeping every other byte (resource
// label, membership name, group) untouched so the Terraform address never
// drifts. The list must be non-empty: removing the last member destroys the
// resource, and the caller lands that as a comment-only emptied file instead
// of an invalid zero-element declaration.
func (adapter AWSAdapter) PatchGroupMembershipUsers(fileContent string, users []string) (string, error) {
	trimmed := make([]string, 0, len(users))
	seen := map[string]bool{}
	for _, user := range users {
		user = strings.TrimSpace(user)
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		trimmed = append(trimmed, user)
	}
	if len(trimmed) == 0 {
		return "", errors.New("group membership needs at least one member; empty the file instead to destroy the membership")
	}
	file, diags := hclsyntax.ParseConfig([]byte(fileContent), "membership.tf", hcl.InitialPos)
	if diags.HasErrors() {
		return "", fmt.Errorf("parse Terraform file: %w", diags)
	}
	root := file.Body.(*hclsyntax.Body)
	for _, block := range root.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 || block.Labels[0] != "aws_iam_group_membership" {
			continue
		}
		usersAttr := block.Body.Attributes["users"]
		if usersAttr == nil {
			return "", fmt.Errorf("aws_iam_group_membership.%s has no users attribute", block.Labels[1])
		}
		tuple, ok := usersAttr.Expr.(*hclsyntax.TupleConsExpr)
		if !ok {
			return "", fmt.Errorf("aws_iam_group_membership.%s users is not a list literal", block.Labels[1])
		}
		var hcl strings.Builder
		hcl.WriteString("[\n")
		for _, user := range trimmed {
			hcl.WriteString("\t\t" + terraformString(user) + ",\n")
		}
		hcl.WriteString("\t]")
		updated := fileContent[:tuple.Range().Start.Byte] + hcl.String() + fileContent[tuple.Range().End.Byte:]
		if err := validateTerraformHCL(updated); err != nil {
			return "", err
		}
		return updated, nil
	}
	return "", errors.New(`resource "aws_iam_group_membership" block not found in Terraform file`)
}

func hclStringAttribute(fileContent string, body *hclsyntax.Body, name string) string {
	attribute := body.Attributes[name]
	if attribute == nil {
		return ""
	}
	raw := strings.TrimSpace(fileContent[attribute.Expr.Range().Start.Byte:attribute.Expr.Range().End.Byte])
	if unquoted, err := strconv.Unquote(raw); err == nil {
		return unquoted
	}
	return strings.Trim(raw, `"`)
}

func writeTerraformTags(hcl *strings.Builder, tags map[string]string) {
	if len(tags) == 0 {
		return
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hcl.WriteString("\n\ttags = {\n")
	for _, key := range keys {
		hcl.WriteString("\t\t" + terraformString(key) + " = " + terraformString(tags[key]) + "\n")
	}
	hcl.WriteString("\t}")
}

// hclAttribute is one attribute line of a generated resource block. Values are
// pre-rendered expressions; the writer only handles indentation and alignment.
type hclAttribute struct {
	name  string
	value string
}

// writeHCLAttributes renders attributes indented by one tab with the "="
// column aligned. Generated files are reviewed as pull requests, so the output
// stays readable, and the alignment is derived from the attribute set rather
// than hand-counted spaces — the same input always produces the same bytes.
func writeHCLAttributes(hcl *strings.Builder, attributes []hclAttribute) {
	width := 0
	for _, attribute := range attributes {
		if len(attribute.name) > width {
			width = len(attribute.name)
		}
	}
	for _, attribute := range attributes {
		hcl.WriteString("\t" + attribute.name + strings.Repeat(" ", width-len(attribute.name)) +
			" = " + attribute.value + "\n")
	}
}

// terraformTagsExpression renders a tag map as an HCL object with sorted keys
// so generation is deterministic (same inventory → same bytes).
func terraformTagsExpression(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var expression strings.Builder
	expression.WriteString("{\n")
	for _, key := range keys {
		expression.WriteString("\t\t" + terraformString(key) + " = " + terraformString(tags[key]) + "\n")
	}
	expression.WriteString("\t}")
	return expression.String()
}

func uniqueTrimmedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

// normalizePolicyDocument validates a policy document for Terraform
// generation and normalizes it to canonical AWS IAM format:
//   - AWS documents ({"Version": ..., "Statement": ...}) are validated and
//     rebuilt canonically (default Version, Statement always an array);
//   - platform DSL documents ({"name": ..., "statements": [...]}) are
//     translated to AWS format via the abstract IAM model;
//   - anything else is rejected with format guidance.
//
// The result must contain only printable ASCII characters: the AWS IAM
// Put*Policy APIs reject other bytes with an opaque validation error, so the
// platform enforces the constraint up front with a clear message.
func (adapter AWSAdapter) normalizePolicyDocument(document json.RawMessage) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) == 0 {
		return nil, errors.New("policy document must not be empty")
	}
	if !json.Valid(trimmed) {
		return nil, errors.New("policy document must be valid JSON")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil, fmt.Errorf("policy document must be a JSON object: %w", err)
	}
	if len(probe) == 0 {
		return nil, errors.New("policy document must not be an empty object")
	}
	if _, ok := probe["Statement"]; ok {
		return adapter.normalizeAWSPolicyDocument(probe)
	}
	if _, ok := probe["statements"]; ok {
		return adapter.translateDSLPolicyDocument(trimmed)
	}
	return nil, errors.New(`policy document must be an AWS IAM policy document ({"Version": "2012-10-17", "Statement": [...]}) or a platform policy DSL ({"name": "...", "statements": [...]})`)
}

// normalizeAWSPolicyDocument validates an AWS-format policy document and
// rebuilds it canonically: Version defaults to 2012-10-17 and Statement is
// always emitted as an array of the original statement objects.
func (adapter AWSAdapter) normalizeAWSPolicyDocument(probe map[string]json.RawMessage) (json.RawMessage, error) {
	version := iamPolicyVersion
	if raw, ok := probe["Version"]; ok {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || value == "" {
			return nil, errors.New("policy document Version must be a non-empty string")
		}
		version = value
	}

	rawStatement, ok := probe["Statement"]
	if !ok {
		return nil, errors.New("policy document must contain a Statement")
	}
	var stmts []json.RawMessage
	if err := json.Unmarshal(rawStatement, &stmts); err != nil {
		var single json.RawMessage
		if err2 := json.Unmarshal(rawStatement, &single); err2 != nil {
			return nil, errors.New("policy document Statement must be an array of statement objects")
		}
		stmts = []json.RawMessage{single}
	}
	if len(stmts) == 0 {
		return nil, errors.New("policy document Statement must not be empty")
	}

	normalized := make([]map[string]json.RawMessage, 0, len(stmts))
	for i, raw := range stmts {
		var stmt map[string]json.RawMessage
		if err := json.Unmarshal(raw, &stmt); err != nil {
			return nil, fmt.Errorf("policy document Statement[%d] must be a JSON object", i)
		}
		var effect string
		if err := json.Unmarshal(stmt["Effect"], &effect); err != nil || (effect != "Allow" && effect != "Deny") {
			return nil, fmt.Errorf("policy document Statement[%d] must have Effect \"Allow\" or \"Deny\"", i)
		}
		if !hasNonEmptyValue(stmt, "Action", "NotAction") {
			return nil, fmt.Errorf("policy document Statement[%d] must have a non-empty Action or NotAction", i)
		}
		if !hasNonEmptyValue(stmt, "Resource", "NotResource") {
			return nil, fmt.Errorf("policy document Statement[%d] must have a non-empty Resource or NotResource", i)
		}
		normalized = append(normalized, stmt)
	}

	doc, err := json.MarshalIndent(struct {
		Version   string                       `json:"Version"`
		Statement []map[string]json.RawMessage `json:"Statement"`
	}{Version: version, Statement: normalized}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal normalized policy document: %w", err)
	}
	if err := checkPolicyDocumentASCII(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// translateDSLPolicyDocument converts a platform policy DSL document
// ({"name": ..., "statements": [{effect, actions, resources, ...}]}) to a
// canonical AWS IAM policy document. Statements using not_actions /
// not_resources are rejected: the abstract model cannot translate them
// losslessly and silently dropping deny rules would be dangerous.
func (adapter AWSAdapter) translateDSLPolicyDocument(trimmed json.RawMessage) (json.RawMessage, error) {
	var dsl abstractiam.AbstractPolicy
	if err := json.Unmarshal(trimmed, &dsl); err != nil {
		return nil, fmt.Errorf("decode platform policy DSL: %w", err)
	}
	if len(dsl.Statements) == 0 {
		return nil, errors.New("platform policy DSL must contain at least one statement")
	}
	for i, statement := range dsl.Statements {
		if len(statement.NotActions) > 0 || len(statement.NotResources) > 0 {
			return nil, fmt.Errorf("platform policy DSL statement %d uses not_actions/not_resources, which cannot be translated to AWS format; submit an AWS policy document instead", i)
		}
	}
	translated, err := adapter.TranslateAbstractPolicy(&dsl)
	if err != nil {
		return nil, fmt.Errorf("translate platform policy DSL: %w", err)
	}
	doc, err := json.MarshalIndent(translated, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal translated policy document: %w", err)
	}
	if err := checkPolicyDocumentASCII(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// hasNonEmptyValue reports whether stmt holds a non-empty string or non-empty
// JSON array under at least one of the given keys. AWS IAM allows Action /
// Resource (and their Not* counterparts) to be either a string or an array.
func hasNonEmptyValue(stmt map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		if raw, ok := stmt[key]; ok {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
				return true
			}
			var str string
			if err := json.Unmarshal(raw, &str); err == nil && str != "" {
				return true
			}
		}
	}
	return false
}

// checkPolicyDocumentASCII verifies every string in the decoded document is
// printable ASCII (newlines, carriage returns and tabs are tolerated). The
// AWS IAM Put*Policy APIs reject other bytes — including non-ASCII text and
// control characters escaped as \uXXXX — with an opaque validation error.
func checkPolicyDocumentASCII(document json.RawMessage) error {
	var decoded interface{}
	if err := json.Unmarshal(document, &decoded); err != nil {
		return fmt.Errorf("policy document must be valid JSON: %w", err)
	}
	var walk func(node interface{}) error
	walk = func(node interface{}) error {
		switch value := node.(type) {
		case map[string]interface{}:
			for _, item := range value {
				if err := walk(item); err != nil {
					return err
				}
			}
		case []interface{}:
			for _, item := range value {
				if err := walk(item); err != nil {
					return err
				}
			}
		case string:
			for _, r := range value {
				if r > 0x7E || (r < 0x20 && r != '\n' && r != '\r' && r != '\t') {
					return fmt.Errorf("policy document contains non-printable-ASCII character %q (U+%04X); AWS IAM only accepts printable ASCII characters", string(r), r)
				}
			}
		}
		return nil
	}
	return walk(decoded)
}

// sanitizedLabelToken keeps characters that are safe inside a quoted HCL
// resource label; anything else becomes an underscore.
func sanitizedLabelToken(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	token := b.String()
	if token == "" {
		return "x"
	}
	return token
}

const labelRandomLetters = "abcdefghijklmnopqrstuvwxyz"

// stableLabelSuffix returns five deterministic lowercase letters derived from
// value (sha256 mapped onto the label alphabet). Same value → same suffix, so
// repeated tickets for one policy resolve the same Terraform address instead
// of drifting per ticket; 26^5 keeps accidental collisions negligible.
func stableLabelSuffix(value string) string {
	sum := sha256.Sum256([]byte(value))
	suffix := make([]byte, 5)
	for i := range suffix {
		suffix[i] = labelRandomLetters[int(sum[i])%len(labelRandomLetters)]
	}
	return string(suffix)
}

// InlinePolicyResourceLabel builds the resource label for a standalone
// inline-policy file. A role or group may own several inline policies — each
// gets its own Terraform file — so the label must stay unique across the
// account's whole Terraform module. The suffix is derived deterministically
// from the policy name (stableLabelSuffix), NOT randomized per ticket: a
// random suffix changes the Terraform address on every update ticket, turning
// an in-place document change into destroy+recreate of the AWS resource.
//
// Role inline-policy labels use "role_<owner>_<suffix>_policy": the AWS policy
// name is already rendered in the resource's name attribute and is not part
// of the Terraform address (docs item 18); the suffix keeps two policies of
// the same role distinct. Group inline-policy labels keep
// the historical "<kind>_<owner>_<suffix>_<policy>" shape.
func InlinePolicyResourceLabel(kind, owner, policyName string) string {
	if strings.EqualFold(strings.TrimSpace(kind), "role") {
		return "role_" + sanitizedLabelToken(owner) + "_" + stableLabelSuffix(policyName) + "_policy"
	}
	return kind + "_" + sanitizedLabelToken(owner) + "_" + stableLabelSuffix(policyName) + "_" + sanitizedLabelToken(policyName)
}

// RoleResourceLabel derives the Terraform resource label for a role
// declaration: "role_<sanitized-role-name>". Role names are unique per AWS
// account, so the label is unique across the whole module without a random
// suffix. It replaces the historical hard-coded "managed_role", which
// collided between files (two roles, one label) and turned address drift
// into destroy+recreate — docs item 15.
func RoleResourceLabel(roleName string) string {
	return "role_" + sanitizedLabelToken(roleName)
}

// UserResourceLabel derives the Terraform resource label for a user
// declaration: "user_<sanitized-user-name>". Exported so the baseline
// candidate report computes the same address the generator will emit.
func UserResourceLabel(userName string) string {
	return "user_" + sanitizedLabelToken(userName)
}

// GroupResourceLabel derives the Terraform resource label for a group
// declaration: "group_<sanitized-group-name>".
func GroupResourceLabel(groupName string) string {
	return "group_" + sanitizedLabelToken(groupName)
}

// DefaultManagedPolicyLabel derives a resource label for a customer-managed
// policy file. Customer-managed policy names are unique per AWS account, so
// no random suffix is needed.
func DefaultManagedPolicyLabel(policyName string) string {
	return "managed_policy_" + sanitizedLabelToken(policyName)
}

// DefaultAttachmentLabel derives a resource label for a policy attachment
// file: attachment_<type>_<principal>_<policyName>. Principal + policy name
// identify the attachment, so the label is unique across the module.
func DefaultAttachmentLabel(principalType, principalName, policyARN string) string {
	return "attachment_" + sanitizedLabelToken(strings.ToLower(principalType)) + "_" +
		sanitizedLabelToken(principalName) + "_" + sanitizedLabelToken(policyNameFromARNString(policyARN))
}

func policyNameFromARNString(policyARN string) string {
	if idx := strings.LastIndex(policyARN, "policy/"); idx >= 0 {
		return policyARN[idx+len("policy/"):]
	}
	return policyARN
}

// ValidateIAMPolicyARN validates an IAM policy ARN such as the AWS-managed
// policy arn:aws:iam::aws:policy/IAMReadOnlyAccess or a customer-managed
// policy arn:aws:iam::123456789012:policy/my-policy.
func ValidateIAMPolicyARN(policyARN string) error {
	policyARN = strings.TrimSpace(policyARN)
	if policyARN == "" {
		return errors.New("policy ARN must not be empty")
	}
	// arn:<partition>:iam:<region>:<account>:policy/<name>
	// IAM is a global service, so the region segment is always empty.
	parts := strings.Split(policyARN, ":")
	if len(parts) != 6 {
		return fmt.Errorf("invalid IAM policy ARN %q: expected arn:<partition>:iam::<account>:policy/<name>", policyARN)
	}
	if parts[0] != "arn" {
		return fmt.Errorf("invalid IAM policy ARN %q: must start with arn", policyARN)
	}
	if parts[1] != "aws" && parts[1] != "aws-cn" && parts[1] != "aws-us-gov" {
		return fmt.Errorf("invalid IAM policy ARN %q: unsupported partition %q", policyARN, parts[1])
	}
	if parts[2] != "iam" {
		return fmt.Errorf("invalid IAM policy ARN %q: service must be iam", policyARN)
	}
	if parts[3] != "" {
		return fmt.Errorf("invalid IAM policy ARN %q: region must be empty for IAM", policyARN)
	}
	if parts[4] != "aws" && !is12DigitAccountID(parts[4]) {
		return fmt.Errorf("invalid IAM policy ARN %q: account must be aws or a 12-digit account ID", policyARN)
	}
	if !strings.HasPrefix(parts[5], "policy/") || len(parts[5]) == len("policy/") {
		return fmt.Errorf("invalid IAM policy ARN %q: resource must be policy/<name>", policyARN)
	}
	return nil
}

func is12DigitAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ValidateIAMResourceName validates the AWS IAM name shape shared by users,
// groups and customer-managed policies.
func ValidateIAMResourceName(kind, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return apperr.Validationf("%s name must not be empty", kind)
	}
	if len(name) > 128 {
		return apperr.Validationf("%s name %q is longer than 128 characters", kind, name)
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("+=,.@_-", r) {
			continue
		}
		return apperr.Validationf("%s name %q contains invalid character %q", kind, name, string(r))
	}
	return nil
}

// NormalizeIAMPath validates an IAM path. Empty and "/" both mean the root
// path. Every non-root path must start and end with "/".
func NormalizeIAMPath(value string) (string, error) {
	path := strings.TrimSpace(value)
	if path == "" || path == "/" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/") {
		return "", apperr.Validationf("IAM path %q must start and end with '/'", path)
	}
	if len(path) > 512 {
		return "", apperr.Validation("IAM path is longer than 512 characters")
	}
	for _, r := range path {
		if r == '/' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("+=,.@_-", r) {
			continue
		}
		return "", apperr.Validationf("IAM path %q contains invalid character %q", path, string(r))
	}
	return path, nil
}

// BuildManagedPolicyARN builds the ARN of a customer-managed policy from the
// account ID, IAM path and policy name.
func BuildManagedPolicyARN(accountID, path, name string) (string, error) {
	if !is12DigitAccountID(strings.TrimSpace(accountID)) {
		return "", fmt.Errorf("AWS account ID %q must be 12 digits", accountID)
	}
	if err := ValidateIAMResourceName("policy", name); err != nil {
		return "", err
	}
	normalizedPath, err := NormalizeIAMPath(path)
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if normalizedPath == "/" {
		return "arn:aws:iam::" + strings.TrimSpace(accountID) + ":policy/" + name, nil
	}
	return "arn:aws:iam::" + strings.TrimSpace(accountID) + ":policy" + normalizedPath + name, nil
}

// ValidateIAMTags applies the basic AWS tag constraints. It deliberately
// rejects the reserved "aws:" prefix so Terraform plan fails locally instead
// of at the AWS API.
func ValidateIAMTags(tags map[string]string) error {
	for key, value := range tags {
		if strings.TrimSpace(key) == "" {
			return errors.New("IAM tag key must not be empty")
		}
		if len(key) > 128 || len(value) > 256 {
			return fmt.Errorf("IAM tag %q exceeds the 128/256 character key/value limit", key)
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), "aws:") {
			return fmt.Errorf("IAM tag key %q uses the reserved aws: prefix", key)
		}
		for _, text := range []string{key, value} {
			for _, r := range text {
				if r < 0x20 || r > 0x7E {
					return fmt.Errorf("IAM tag %q contains a non-printable-ASCII character", key)
				}
			}
		}
	}
	return nil
}

func translateResource(resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", fmt.Errorf("resource must not be empty")
	}

	if strings.HasPrefix(resource, "storage://") {
		bucket := strings.TrimPrefix(resource, "storage://")
		if bucket == "" {
			return "", fmt.Errorf("storage resource must include a bucket name")
		}
		return "arn:aws:s3:::" + bucket, nil
	}

	if strings.Contains(resource, "://") && !strings.HasPrefix(resource, "arn:") {
		return "", fmt.Errorf("unsupported resource URI %q", resource)
	}
	return resource, nil
}

func hasWildcardPrincipal(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return containsWildcardPrincipal(value)
}

func containsWildcardPrincipal(value interface{}) bool {
	switch value := value.(type) {
	case string:
		return strings.Contains(value, "*")
	case []interface{}:
		for _, item := range value {
			if containsWildcardPrincipal(item) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range value {
			if containsWildcardPrincipal(item) {
				return true
			}
		}
	}
	return false
}

// terraformJSONEncode renders a policy document as a jsonencode({...}) HCL
// expression. Terraform's jsonencode handles all string escaping natively,
// removing the ${%{ interpolation footgun that heredocs carry, and the AWS
// provider normalizes policies before comparing, so semantic content — not
// textual representation — determines state diffs.
func terraformJSONEncode(document json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(document)
	var decoded interface{}
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return "", fmt.Errorf("marshal policy for jsonencode: %w", err)
	}
	var b strings.Builder
	b.WriteString("jsonencode(")
	// Base indent 1: continuation lines sit one level inside the resource
	// block, so the closing }) aligns under the attribute name (fmt style).
	writeHCLValue(&b, decoded, 1)
	b.WriteString(")")
	return b.String(), nil
}

// writeHCLValue emits a decoded JSON value as the HCL literal form
// jsonencode accepts: objects as { key = value }, arrays as [ ... ], and
// strings via strconv.Quote (valid HCL escapes for the printable-ASCII-only
// documents the platform emits).
func writeHCLValue(b *strings.Builder, value interface{}, indent int) {
	switch v := value.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// Convention: Version first when present (only top-level docs carry it).
		for i, k := range keys {
			if k == "Version" && i > 0 {
				copy(keys[1:i+1], keys[0:i])
				keys[0] = k
				break
			}
		}
		for _, k := range keys {
			b.WriteString(strings.Repeat("\t", indent+1))
			b.WriteString(terraformString(k))
			b.WriteString(" = ")
			writeHCLValue(b, v[k], indent+1)
			b.WriteString("\n")
		}
		b.WriteString(strings.Repeat("\t", indent))
		b.WriteString("}")
	case []interface{}:
		if len(v) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, item := range v {
			b.WriteString(strings.Repeat("\t", indent+1))
			writeHCLValue(b, item, indent+1)
			if i < len(v)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(strings.Repeat("\t", indent))
		b.WriteString("]")
	case string:
		b.WriteString(terraformString(v))
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case float64:
		b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
	default:
		b.WriteString("null")
	}
}

func terraformString(value string) string {
	// Escape Terraform template markers before applying Go's string escaping.
	value = strings.ReplaceAll(value, "${", "$${")
	value = strings.ReplaceAll(value, "%{", "%%{")
	return strconv.Quote(value)
}
