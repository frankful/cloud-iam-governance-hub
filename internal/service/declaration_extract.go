package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// 本文件把「发布出去的 Terraform 内容」反解成声明快照（0032）。
//
// 为什么从内容反解，而不是为每种工单类型写一遍 request → 属性的映射：
//
//   - 工单有十几种（创建/更新/挂载/成员/回滚/采纳…），每种都会改写文件，
//     而 UPDATE_ROLE / UPDATE_MANAGED_POLICY 这类是「块级 patch」——请求里
//     只有用户改过的字段，完整声明要拿 main 上的现文件合并才知道。
//   - 工单和基线用的是同一组生成器，内容才是「到底声明了什么」的唯一事实。
//     从内容反解，新工单类型不需要在这里加代码，也不会与生成器走偏。
//   - 回滚/清空文件天然正确：没有块就没有声明，旧声明按文件整体作废。
//
// 属性名沿用声明表的既有词汇（trust_policy / document / members …），与
// 基线侧 P2a 落库的形状一致：同一个资源无论由基线还是工单声明，比对器
// （P3）看到的都是同一套字段。

// Terraform 资源类型常量：只有这些块会进声明。其余（import / terraform /
// locals / provider）是脚手架，不是资源声明。
const (
	terraformIAMRole                    = "aws_iam_role"
	terraformIAMUser                    = "aws_iam_user"
	terraformIAMGroup                   = "aws_iam_group"
	terraformIAMPolicy                  = "aws_iam_policy"
	terraformIAMRolePolicy              = "aws_iam_role_policy"
	terraformIAMUserPolicy              = "aws_iam_user_policy"
	terraformIAMGroupPolicy             = "aws_iam_group_policy"
	terraformIAMRolePolicyAttachment    = "aws_iam_role_policy_attachment"
	terraformIAMUserPolicyAttachment    = "aws_iam_user_policy_attachment"
	terraformIAMGroupPolicyAttachment   = "aws_iam_group_policy_attachment"
	terraformIAMGroupMembership         = "aws_iam_group_membership"
	terraformIAMInstanceProfile         = "aws_iam_instance_profile"
	terraformIAMOpenIDConnectProvider   = "aws_iam_openid_connect_provider"
	terraformIAMSAMLProvider            = "aws_iam_saml_provider"
	declarationAttributeDocument        = "document"
	declarationAttributePrincipalKind   = "principal_kind"
	declarationAttributePrincipal       = "principal"
	declarationAttributePolicyARN       = "policy_arn"
	declarationAttributeOwnerKind       = "owner_kind"
	declarationAttributeOwner           = "owner"
	declarationAttributePolicyName      = "policy"
	declarationAttributeGroup           = "group"
	declarationAttributeMembers         = "members"
	declarationAttributePath            = "path"
	declarationAttributeDescription     = "description"
	declarationAttributeTags            = "tags"
	declarationAttributeTrustPolicy     = "trust_policy"
	declarationAttributeMaxSession      = "max_session_duration"
	declarationAttributeBoundary        = "permissions_boundary"
	declarationAttributeAssumeRole      = "assume_role_policy"
	declarationAttributeURL             = "url"
	declarationAttributeClientIDs       = "client_ids"
	declarationAttributeThumbprints     = "thumbprints"
	declarationAttributeSAMLMetadata    = "metadata"
	declarationAttributeInstanceProfile = "role"
)

// DeclarationLabels 是 Terraform 资源 label → IAM 名称的索引。声明里的
// 主体身份（内联策略属于谁、挂载挂给谁）只出现在引用里
// （aws_iam_role.role_foo.id），而 label 是净化过的、大小写丢失的字符串，
// 反解不能只靠它——必须由构建方把「label 是哪个名字」告诉这里。
//
// 索引按文件批次构建（同批文件里的主体块自带字面量 name），跨文件的引用
// （attachment-*.tf 引用 role-*.tf 的角色）靠调用方的提示兜底。
type DeclarationLabels map[string]string

// Add 登记一个 label → 名称映射。resourceType 是 Terraform 资源类型
// （aws_iam_role 等），label 是该资源块的第二个标签。
func (labels DeclarationLabels) Add(resourceType, label, name string) {
	resourceType = strings.TrimSpace(resourceType)
	label = strings.TrimSpace(label)
	name = strings.TrimSpace(name)
	if resourceType == "" || label == "" || name == "" {
		return
	}
	labels[resourceType+"."+label] = name
}

func (labels DeclarationLabels) resolve(resourceType, label string) (string, bool) {
	name, ok := labels[resourceType+"."+label]
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// DeclarationGap 是一条「这块声明没法反解」的记录：不影响发布（已经合并
// 的内容不会被回滚），但必须可见——漂移检测的覆盖范围少了这一块，页面
// 与日志都要说清楚，不能让人以为「全账号已覆盖」。
type DeclarationGap struct {
	FileKey  string `json:"file_key"`
	Resource string `json:"resource,omitempty"`
	Detail   string `json:"detail"`
}

// declarationEvalContext 是反解属性值的求值上下文：生成器只会写
// jsonencode(jsondecode) 与 merge 这几种纯函数，不引用变量——文件是自包含
// 的，求值不需要 Terraform 运行时。
var declarationEvalContext = &hcl.EvalContext{
	Functions: map[string]function.Function{
		"jsonencode": stdlib.JSONEncodeFunc,
		"jsondecode": stdlib.JSONDecodeFunc,
		"merge":      stdlib.MergeFunc,
	},
}

// ExtractDeclarations 把一批已发布文件反解成声明快照。返回的 gap 是没能
// 反解的资源（解析失败、引用解析不到、缺字面量身份），调用方应记日志并
// 交给页面展示覆盖缺口。
func ExtractDeclarations(
	files []TerraformBundleFile,
	hints DeclarationLabels,
) ([]BaselineDeclaration, []DeclarationGap) {
	labels := make(DeclarationLabels, len(files)+len(hints))
	for key, value := range hints {
		labels[key] = value
	}
	type parsedFile struct {
		key  string
		body *hclsyntax.Body
	}
	parsed := make([]parsedFile, 0, len(files))
	gaps := make([]DeclarationGap, 0)
	for _, file := range files {
		if strings.TrimSpace(file.Content) == "" {
			continue
		}
		hclFile, diagnostics := hclsyntax.ParseConfig(
			[]byte(file.Content), file.Key+".tf", hcl.InitialPos)
		if diagnostics.HasErrors() {
			gaps = append(gaps, DeclarationGap{
				FileKey: file.Key,
				Detail:  "Terraform 内容解析失败，本文件不纳入声明：" + diagnostics.Error(),
			})
			continue
		}
		body, ok := hclFile.Body.(*hclsyntax.Body)
		if !ok {
			gaps = append(gaps, DeclarationGap{
				FileKey: file.Key,
				Detail:  "Terraform 内容没有可读的顶层块，本文件不纳入声明",
			})
			continue
		}
		parsed = append(parsed, parsedFile{key: file.Key, body: body})
	}

	// 第一遍：本批文件里的主体块自带字面量 name，先补全 label 索引，让同批
	// 内的引用（角色文件里的内联策略、成员文件里的组）能解析。
	for _, file := range parsed {
		for _, block := range file.body.Blocks {
			resourceType, label, ok := resourceBlockHead(block)
			if !ok {
				continue
			}
			name, ok := attributeString(block, "name")
			if !ok {
				continue
			}
			labels.Add(resourceType, label, name)
		}
	}

	// 第二遍：逐块产出声明。resource_key 在批内必须唯一——同一个资源被两个
	// 文件声明本身已经是生成器 bug（同地址双声明），保留先到的并记 gap。
	declarations := make([]BaselineDeclaration, 0, len(parsed)*2)
	seen := make(map[string]bool, len(parsed)*2)
	for _, file := range parsed {
		for _, block := range file.body.Blocks {
			resourceType, label, ok := resourceBlockHead(block)
			if !ok {
				continue
			}
			extracted, blockGaps := extractResourceDeclaration(file.key, resourceType, label, block, labels)
			gaps = append(gaps, blockGaps...)
			for _, declaration := range extracted {
				if seen[declaration.ResourceKey] {
					gaps = append(gaps, DeclarationGap{
						FileKey:  file.key,
						Resource: declaration.ResourceKey,
						Detail:   "同一资源在本次发布里被声明了两次，保留先出现的文件",
					})
					continue
				}
				seen[declaration.ResourceKey] = true
				declarations = append(declarations, declaration)
			}
		}
	}
	sort.Slice(declarations, func(left, right int) bool {
		return declarations[left].ResourceKey < declarations[right].ResourceKey
	})
	sort.Slice(gaps, func(left, right int) bool {
		if gaps[left].FileKey != gaps[right].FileKey {
			return gaps[left].FileKey < gaps[right].FileKey
		}
		return gaps[left].Resource < gaps[right].Resource
	})
	return declarations, gaps
}

// resourceBlockHead 判断一个顶层块是不是资源声明，并取出类型与 label。
func resourceBlockHead(block *hclsyntax.Block) (resourceType, label string, ok bool) {
	if block == nil || block.Type != "resource" || len(block.Labels) != 2 {
		return "", "", false
	}
	return block.Labels[0], block.Labels[1], true
}

// extractResourceDeclaration 产出一个资源块对应的声明（一个块可能对应多条：
// 目前只有「不属于任何已知类型」的空结果）。身份或关键属性解析不出来时
// 返回 gap 而不是半条声明——带着错 key 的声明会把漂移判定指到另一个资源上。
func extractResourceDeclaration(
	fileKey, resourceType, label string,
	block *hclsyntax.Block,
	labels DeclarationLabels,
) ([]BaselineDeclaration, []DeclarationGap) {
	gap := func(detail string) []DeclarationGap {
		return []DeclarationGap{{FileKey: fileKey, Resource: resourceType + "." + label, Detail: detail}}
	}
	declare := func(resourceKey, kind, name string, attributes map[string]any) ([]BaselineDeclaration, []DeclarationGap) {
		if len(attributes) == 0 {
			return nil, gap("资源块没有可声明的属性")
		}
		encoded, err := canonicalJSON(attributes)
		if err != nil {
			return nil, gap("声明属性无法序列化：" + err.Error())
		}
		return []BaselineDeclaration{{
			ResourceKey: resourceKey,
			FileKey:     fileKey,
			Kind:        kind,
			Name:        name,
			Attributes:  encoded,
		}}, nil
	}

	switch resourceType {
	case terraformIAMRole:
		name, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("角色块缺少 name 字面量")
		}
		attributes := map[string]any{}
		if path, ok := attributeString(block, declarationAttributePath); ok {
			attributes[declarationAttributePath] = path
		}
		if trust, ok := attributeDocument(block, declarationAttributeAssumeRole); ok {
			attributes[declarationAttributeTrustPolicy] = trust
		}
		if description, ok := attributeString(block, declarationAttributeDescription); ok {
			attributes[declarationAttributeDescription] = description
		}
		if maxSession, ok := attributeAny(block, declarationAttributeMaxSession); ok {
			attributes[declarationAttributeMaxSession] = maxSession
		}
		if tags, ok := attributeAny(block, declarationAttributeTags); ok {
			attributes[declarationAttributeTags] = tags
		}
		if boundary, ok := attributeString(block, declarationAttributeBoundary); ok {
			attributes[declarationAttributeBoundary] = boundary
		}
		return declare(BaselineKindRole+":"+name, BaselineKindRole, name, attributes)

	case terraformIAMUser:
		name, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("用户块缺少 name 字面量")
		}
		attributes := map[string]any{}
		if path, ok := attributeString(block, declarationAttributePath); ok {
			attributes[declarationAttributePath] = path
		}
		if tags, ok := attributeAny(block, declarationAttributeTags); ok {
			attributes[declarationAttributeTags] = tags
		}
		return declare(BaselineKindUser+":"+name, BaselineKindUser, name, attributes)

	case terraformIAMGroup:
		name, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("组块缺少 name 字面量")
		}
		attributes := map[string]any{}
		if path, ok := attributeString(block, declarationAttributePath); ok {
			attributes[declarationAttributePath] = path
		}
		return declare(BaselineKindGroup+":"+name, BaselineKindGroup, name, attributes)

	case terraformIAMPolicy:
		name, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("策略块缺少 name 字面量")
		}
		attributes := map[string]any{}
		if path, ok := attributeString(block, declarationAttributePath); ok {
			attributes[declarationAttributePath] = path
		}
		if document, ok := attributeDocument(block, declarationAttributePolicyName); ok {
			attributes[declarationAttributeDocument] = document
		}
		if description, ok := attributeString(block, declarationAttributeDescription); ok {
			attributes[declarationAttributeDescription] = description
		}
		if tags, ok := attributeAny(block, declarationAttributeTags); ok {
			attributes[declarationAttributeTags] = tags
		}
		return declare(BaselineKindPolicy+":"+name, BaselineKindPolicy, name, attributes)

	case terraformIAMRolePolicy, terraformIAMUserPolicy, terraformIAMGroupPolicy:
		ownerKind, ownerAttribute, ownerResourceType := inlinePolicyOwner(resourceType)
		owner, ok := attributePrincipal(block, ownerAttribute, ownerResourceType, labels)
		if !ok {
			return nil, gap("内联策略的属主引用无法解析到主体名称")
		}
		policyName, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("内联策略块缺少 name 字面量")
		}
		attributes := map[string]any{
			declarationAttributeOwnerKind:  ownerKind,
			declarationAttributeOwner:      owner,
			declarationAttributePolicyName: policyName,
		}
		if document, ok := attributeDocument(block, declarationAttributePolicyName); ok {
			attributes[declarationAttributeDocument] = document
		}
		return declare(
			ownerKind+":"+owner+":inline:"+policyName,
			BaselineKindInlinePolicy, policyName, attributes)

	case terraformIAMRolePolicyAttachment, terraformIAMUserPolicyAttachment, terraformIAMGroupPolicyAttachment:
		principalKind, principalAttribute, principalResourceType := attachmentPrincipal(resourceType)
		principal, ok := attributePrincipal(block, principalAttribute, principalResourceType, labels)
		if !ok {
			return nil, gap("挂载的主体引用无法解析到主体名称")
		}
		policyARN, ok := attributeString(block, declarationAttributePolicyARN)
		if !ok {
			return nil, gap("挂载块缺少 policy_arn 字面量")
		}
		policyName := PolicyNameFromARN(policyARN)
		if policyName == "" {
			policyName = policyARN
		}
		attributes := map[string]any{
			declarationAttributePrincipalKind: principalKind,
			declarationAttributePrincipal:     principal,
			declarationAttributePolicyARN:     policyARN,
		}
		return declare("attachment:"+principalKind+":"+principal+":"+policyARN,
			"attachment", policyName, attributes)

	case terraformIAMGroupMembership:
		group, ok := attributePrincipal(block, BaselineKindGroup, terraformIAMGroup, labels)
		if !ok {
			return nil, gap("组成员声明的组引用无法解析到组名称")
		}
		members, ok := attributeAny(block, "users")
		if !ok {
			return nil, gap("组成员声明缺少 users 字面量列表")
		}
		return declare("membership:group:"+group, "membership", group, map[string]any{
			declarationAttributeGroup:   group,
			declarationAttributeMembers: members,
		})

	case terraformIAMInstanceProfile:
		name, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("实例配置文件块缺少 name 字面量")
		}
		attributes := map[string]any{}
		if path, ok := attributeString(block, declarationAttributePath); ok {
			attributes[declarationAttributePath] = path
		}
		if roleName, ok := attributePrincipal(block, "role", terraformIAMRole, labels); ok {
			attributes[declarationAttributeInstanceProfile] = roleName
		}
		return declare(BaselineKindInstanceProfile+":"+name, BaselineKindInstanceProfile, name, attributes)

	case terraformIAMOpenIDConnectProvider:
		// 身份用 url：生成器写的 url 就是 provider 名（归一化后），库存侧
		// 的 provider_name 与它同源。
		url, ok := attributeString(block, declarationAttributeURL)
		if !ok {
			return nil, gap("OIDC provider 块缺少 url 字面量")
		}
		attributes := map[string]any{declarationAttributeURL: url}
		if clientIDs, ok := attributeAny(block, declarationAttributeClientIDs); ok {
			attributes[declarationAttributeClientIDs] = clientIDs
		}
		if thumbprints, ok := attributeAny(block, declarationAttributeThumbprints); ok {
			attributes[declarationAttributeThumbprints] = thumbprints
		}
		if tags, ok := attributeAny(block, declarationAttributeTags); ok {
			attributes[declarationAttributeTags] = tags
		}
		return declare(BaselineKindOIDCProvider+":"+url, BaselineKindOIDCProvider, url, attributes)

	case terraformIAMSAMLProvider:
		name, ok := attributeString(block, "name")
		if !ok {
			return nil, gap("SAML provider 块缺少 name 字面量")
		}
		attributes := map[string]any{}
		if metadata, ok := attributeString(block, declarationAttributeSAMLMetadata); ok {
			attributes[declarationAttributeSAMLMetadata] = metadata
		}
		return declare(BaselineKindSAMLProvider+":"+name, BaselineKindSAMLProvider, name, attributes)
	}
	return nil, nil
}

// inlinePolicyOwner 返回内联策略块的属主种类、引用属主的属性名与属主的
// Terraform 资源类型。
func inlinePolicyOwner(resourceType string) (ownerKind, ownerAttribute, ownerResourceType string) {
	switch resourceType {
	case terraformIAMRolePolicy:
		return BaselineKindRole, "role", terraformIAMRole
	case terraformIAMUserPolicy:
		return BaselineKindUser, "user", terraformIAMUser
	default:
		return BaselineKindGroup, "group", terraformIAMGroup
	}
}

// attachmentPrincipal 返回挂载块的主体种类、引用主体的属性名与主体的
// Terraform 资源类型。
func attachmentPrincipal(resourceType string) (principalKind, principalAttribute, principalResourceType string) {
	switch resourceType {
	case terraformIAMRolePolicyAttachment:
		return BaselineKindRole, "role", terraformIAMRole
	case terraformIAMUserPolicyAttachment:
		return BaselineKindUser, "user", terraformIAMUser
	default:
		return BaselineKindGroup, "group", terraformIAMGroup
	}
}

// attributeAny 求值一个属性表达式并把结果转成可 JSON 化的值。求值失败
// （引用、未知变量）返回 false——调用方按「这个属性没有声明」处理，宁少
// 不多：多出来的错属性会被漂移判定当成「声明值与实态不符」。
func attributeAny(block *hclsyntax.Block, name string) (any, bool) {
	attribute := block.Body.Attributes[name]
	if attribute == nil || attribute.Expr == nil {
		return nil, false
	}
	value, diagnostics := attribute.Expr.Value(declarationEvalContext)
	if diagnostics.HasErrors() || !value.IsKnown() || value.IsNull() {
		return nil, false
	}
	encoded, err := ctyjson.Marshal(value, value.Type())
	if err != nil {
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, false
	}
	return decoded, true
}

// attributeString 取一个字符串属性。jsonencode(...) 的结果也是字符串，但
// 这里只用于 name / path / description 这类字面量属性。
func attributeString(block *hclsyntax.Block, name string) (string, bool) {
	value, ok := attributeAny(block, name)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", false
	}
	return text, true
}

// attributeDocument 取一个策略文档属性：生成器写的是
// jsonencode({...})，求值得到 JSON 文本，这里再解成对象——声明里要的是
// 「文档本身」，不是它的字符串形式（否则比对时类型永远对不上）。
func attributeDocument(block *hclsyntax.Block, name string) (any, bool) {
	value, ok := attributeAny(block, name)
	if !ok {
		return nil, false
	}
	text, isText := value.(string)
	if !isText {
		return value, true
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return nil, false
	}
	return decoded, true
}

// attributePrincipal 取「主体名称」属性。生成器有两种写法：
//
//   - 基线/挂载文件写的是名字字面量（role = "app-server"）——主体声明在
//     别的文件里，引用会跨文件，字面量更稳；
//   - 工单生成的创建/更新文件写的是资源引用（role = aws_iam_role.role_app-server.id）。
//
// 两种都要认：只认引用会让基线的挂载文件全部丢失声明，只认字面量会让工单
// 文件丢失声明。
func attributePrincipal(
	block *hclsyntax.Block,
	attributeName, resourceType string,
	labels DeclarationLabels,
) (string, bool) {
	if literal, ok := attributeString(block, attributeName); ok {
		return literal, true
	}
	return attributeReference(block, attributeName, resourceType, labels)
}

// attributeReference 把一个「资源引用」属性解析成主体名称：
// aws_iam_role.role_foo.id → 查索引得到角色名。label 是净化过的字符串，
// 大小写与符号都已丢失，绝不能拿它当名称用。
func attributeReference(
	block *hclsyntax.Block,
	attributeName, resourceType string,
	labels DeclarationLabels,
) (string, bool) {
	attribute := block.Body.Attributes[attributeName]
	if attribute == nil || attribute.Expr == nil {
		return "", false
	}
	traversal, ok := attribute.Expr.(*hclsyntax.ScopeTraversalExpr)
	if !ok || len(traversal.Traversal) < 2 {
		return "", false
	}
	root, ok := traversal.Traversal[0].(hcl.TraverseRoot)
	if !ok || root.Name != resourceType {
		return "", false
	}
	step, ok := traversal.Traversal[1].(hcl.TraverseAttr)
	if !ok {
		return "", false
	}
	return labels.resolve(resourceType, step.Name)
}

// DeclarationLabelsFromRequest 按工单请求补齐 label 索引：跨文件引用（例如
// 独立挂载文件引用别的文件里的主体）反解不到时用这里的名字兜底。
func DeclarationLabelsFromRequest(request CreateIAMTicketRequest) DeclarationLabels {
	labels := DeclarationLabels{}
	add := func(resourceType, name string, label func(string) string) {
		if strings.TrimSpace(name) == "" {
			return
		}
		labels.Add(resourceType, label(name), name)
	}
	add(terraformIAMRole, request.Role.Name, adapter.RoleResourceLabel)
	add(terraformIAMRole, request.PrincipalName, adapter.RoleResourceLabel)
	add(terraformIAMUser, request.PrincipalName, adapter.UserResourceLabel)
	add(terraformIAMGroup, request.PrincipalName, adapter.GroupResourceLabel)
	if request.CreateUser != nil {
		add(terraformIAMUser, request.CreateUser.Name, adapter.UserResourceLabel)
	}
	if request.CreateGroup != nil {
		add(terraformIAMGroup, request.CreateGroup.Name, adapter.GroupResourceLabel)
	}
	if request.UpdateMembership != nil {
		add(terraformIAMGroup, request.UpdateMembership.GroupName, adapter.GroupResourceLabel)
	}
	if request.UpdatePolicy != nil {
		add(terraformIAMRole, request.UpdatePolicy.RoleName, adapter.RoleResourceLabel)
		add(terraformIAMGroup, request.UpdatePolicy.GroupName, adapter.GroupResourceLabel)
	}
	switch strings.ToLower(strings.TrimSpace(request.PrincipalType)) {
	case "group":
		add(terraformIAMGroup, request.PrincipalName, adapter.GroupResourceLabel)
	case "role":
		add(terraformIAMRole, request.PrincipalName, adapter.RoleResourceLabel)
	default:
		add(terraformIAMUser, request.PrincipalName, adapter.UserResourceLabel)
	}
	return labels
}

func declarationGapSummary(gaps []DeclarationGap) string {
	if len(gaps) == 0 {
		return ""
	}
	descriptions := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		descriptions = append(descriptions, fmt.Sprintf("%s/%s: %s", gap.FileKey, gap.Resource, gap.Detail))
	}
	return strings.Join(descriptions, "; ")
}
