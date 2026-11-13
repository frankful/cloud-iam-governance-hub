package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// TestLoadPoliciesOnlyIncludesReferencedAWSManagedPolicies 回归 C2：同步会把
// 上千条 AWS 托管策略目录写进 iam_policy。差异清单只应看到本账号真正挂载的
// 官方策略，否则预览页会被不可声明的目录行淹没。
func TestLoadPoliciesOnlyIncludesReferencedAWSManagedPolicies(t *testing.T) {
	fake := &bundleFakeDB{}
	fake.add("OR (policy_arn LIKE 'arn:aws:iam::aws:policy/%'", nil, [][]driver.Value{
		{"app-logs", "arn:aws:iam::123456789012:policy/app-logs", "platform", "", nil},
		{"ReadOnlyAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess", "unknown", "", nil},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselineCandidateService(database)
	resources, err := service.loadPolicies(context.Background(), 7, "123456789012")
	if err != nil {
		t.Fatalf("loadPolicies: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("resource count = %d, want 2", len(resources))
	}
	if resources[1].Kind != BaselineKindAWSManagedPolicy {
		t.Errorf("AWS-managed policy kind = %q", resources[1].Kind)
	}

	queries := strings.Join(fake.recordedQueries(), "\n")
	for _, want := range []string{
		"iam_principal_policy",
		"iam_group_policy",
		"p.account_id = $2",
		"g.account_id = $2",
		"p.is_deleted = FALSE",
	} {
		if !strings.Contains(queries, want) {
			t.Errorf("policy query is missing %q:\n%s", want, queries)
		}
	}
}

func TestClassifyBaselineResourcePriority(t *testing.T) {
	cases := []struct {
		name            string
		kind            string
		resourceName    string
		arn             string
		path            string
		managedBy       string
		tags            map[string]string
		roleTags        map[string]string
		alreadyDeclared bool
		wantDecision    string
	}{
		{
			name:         "service-linked role 即使标注 platform 也不声明",
			kind:         BaselineKindRole,
			resourceName: "AWSServiceRoleForAmazonEKS",
			path:         "/aws-service-role/eks.amazonaws.com/",
			managedBy:    "platform",
			wantDecision: BaselineDecisionSkippedServiceLinked,
		},
		{
			name:         "未标注但名字是 AWSServiceRoleFor 前缀也判定为 service-linked",
			kind:         BaselineKindRole,
			resourceName: "AWSServiceRoleForRDS",
			path:         "/",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionSkippedServiceLinked,
		},
		{
			name:         "AWS 托管策略本体不可声明",
			kind:         BaselineKindAWSManagedPolicy,
			resourceName: "AdministratorAccess",
			arn:          "arn:aws:iam::aws:policy/AdministratorAccess",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionSkippedAWSManagedPolicy,
		},
		{
			name:         "external 归属跳过",
			kind:         BaselineKindRole,
			resourceName: "cfn-created-role",
			path:         "/",
			managedBy:    "external",
			wantDecision: BaselineDecisionSkippedExternal,
		},
		{
			name:            "已有工单声明过的资源跳过",
			kind:            BaselineKindUser,
			resourceName:    "app-deployer",
			path:            "/",
			managedBy:       "platform",
			alreadyDeclared: true,
			wantDecision:    BaselineDecisionSkippedAlreadyDeclared,
		},
		{
			name:         "unknown 归属进基线",
			kind:         BaselineKindRole,
			resourceName: "otel-acm-prd-cloudwatch-role",
			path:         "/",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionCandidate,
		},
		{
			name:         "Path 非根的普通角色仍进基线",
			kind:         BaselineKindRole,
			resourceName: "app-role",
			path:         "/app/",
			managedBy:    "platform",
			wantDecision: BaselineDecisionCandidate,
		},
		{
			// unknown 默认纳入（平台定位是统一 IAM 管理），但 tag 里有
			// CloudFormation 栈名就不是「没人表态」了，而是有证据。
			name:         "CloudFormation 创建的角色跳过并写明栈名",
			kind:         BaselineKindRole,
			resourceName: "cfn-ecs-task-role",
			path:         "/",
			managedBy:    "unknown",
			tags: map[string]string{
				"aws:cloudformation:stack-name": "prod-ecs-service",
				"aws:cloudformation:logical-id": "TaskRole",
			},
			wantDecision: BaselineDecisionSkippedExternalSignature,
		},
		{
			// eksctl（alpha.eksctl.io/*）已改为统一纳管：它只在集群创建期写
			// 一次资源，之后不重写，纳管不会互相覆盖。
			name:         "eksctl 建的资源纳管",
			kind:         BaselineKindRole,
			resourceName: "eksctl-cluster-nodegroup-ng-1",
			path:         "/",
			managedBy:    "unknown",
			tags:         map[string]string{"alpha.eksctl.io/cluster-name": "prod-eks"},
			wantDecision: BaselineDecisionCandidate,
		},
		{
			// SSM Quick Setup 建的角色 path 是 /、也没有 CFN/eksctl tag，
			// 只有 QuickSetupManagerArn；漏判就会被接管，而重跑配置会改回去。
			name:         "AWS SSM Quick Setup 创建的角色跳过",
			kind:         BaselineKindRole,
			resourceName: "AWS-SSM-DiagnosisAdminRole-111122223333-ap-southeast-1",
			path:         "/",
			managedBy:    "unknown",
			tags: map[string]string{
				"QuickSetupManagerArn": "arn:aws:ssm-quicksetup:ap-southeast-1:111122223333:configuration-manager/3f91d71c",
			},
			wantDecision: BaselineDecisionSkippedExternalSignature,
		},
		{
			// 平台已经开过工单 = 已经接管，tag 里的历史线索不再改变结论。
			name:            "已声明优先于外部工具签名",
			kind:            BaselineKindRole,
			resourceName:    "cfn-role-adopted-earlier",
			path:            "/",
			managedBy:       "platform",
			tags:            map[string]string{"aws:cloudformation:stack-name": "legacy-stack"},
			alreadyDeclared: true,
			wantDecision:    BaselineDecisionSkippedAlreadyDeclared,
		},
		{
			// 普通业务 tag 不能误判成外部工具。
			name:         "无关 tag 不影响纳入",
			kind:         BaselineKindUser,
			resourceName: "app-user",
			path:         "/",
			managedBy:    "unknown",
			tags:         map[string]string{"team": "otel", "env": "prod"},
			wantDecision: BaselineDecisionCandidate,
		},
		{
			// Quick Setup 的角色有时没有 QuickSetupManagerArn（历史配置或 tag
			// 被清过），但命名空间是 AWS 固定的，名字本身就是证据。
			name:         "Quick Setup 命名空间无 tag 也排除",
			kind:         BaselineKindRole,
			resourceName: "AWS-QuickSetup-SSM-LocalExecutionRole",
			path:         "/",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionSkippedAWSLifecycle,
		},
		{
			// IAM 实例配置文件不支持 tag，EKS 托管节点组只能靠名字认。
			name:         "EKS 托管节点组的实例配置文件排除",
			kind:         BaselineKindInstanceProfile,
			resourceName: "eks-14cfe867-c668-e055-19fa-05277d81a00b",
			path:         "/",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionSkippedAWSLifecycle,
		},
		{
			// 名字像 eks- 但不是 UUID（人建的 profile）必须留在候选集。
			name:         "eks- 前缀但名字不是 UUID 不排除",
			kind:         BaselineKindInstanceProfile,
			resourceName: "eks-nodegroup-bastion",
			path:         "/",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionCandidate,
		},
		{
			// 同一形态的 uuid 如果出现在角色上，说明不是 EKS 的实例配置文件。
			name:         "UUID 命名的角色不按实例配置文件规则排除",
			kind:         BaselineKindRole,
			resourceName: "eks-14cfe867-c668-e055-19fa-05277d81a00b",
			path:         "/",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionCandidate,
		},
		{
			name:         "AWS 自动化代建 + AWS 保留名前缀排除",
			kind:         BaselineKindRole,
			resourceName: "AmazonSSMDirectoryServiceInstanceProfileRole",
			path:         "/",
			managedBy:    "unknown",
			tags: map[string]string{
				"Created By": "AWS Systems Manager Automation",
			},
			wantDecision: BaselineDecisionSkippedAWSLifecycle,
		},
		{
			// 实例配置文件不支持 tag，它与角色成对创建：角色的证据就是它的证据。
			name:         "实例配置文件沿用绑定角色的 AWS 自动化 tag",
			kind:         BaselineKindInstanceProfile,
			resourceName: "AmazonSSMDirectoryServiceInstanceProfileRole",
			path:         "/",
			managedBy:    "unknown",
			roleTags:     map[string]string{"Created By": "AWS Systems Manager Automation"},
			wantDecision: BaselineDecisionSkippedAWSLifecycle,
		},
		{
			// 只有 tag 没有保留名前缀 → 可能只是团队自己的自动化，不能排除。
			name:         "人工 tag 声称 AWS 自动化但名字不保留不排除",
			kind:         BaselineKindRole,
			resourceName: "app-deploy-automation-role",
			path:         "/",
			managedBy:    "unknown",
			tags:         map[string]string{"Created By": "AWS migration automation script"},
			wantDecision: BaselineDecisionCandidate,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decision, _ := classifyBaselineResource(
				BaselineResource{
					Kind:      testCase.kind,
					Name:      testCase.resourceName,
					ARN:       testCase.arn,
					Path:      testCase.path,
					ManagedBy: testCase.managedBy,
					Tags:      testCase.tags,
					RoleTags:  testCase.roleTags,
				},
				testCase.alreadyDeclared,
			)
			if decision != testCase.wantDecision {
				t.Fatalf("decision = %q, want %q", decision, testCase.wantDecision)
			}
		})
	}
}

// AWS 生命周期托管的资源，即使平台早先为它开过工单，结论也必须是「跳过」并
// 提示清理——那条工单本身就是错的，藏进「已声明」会让它永远没人发现。
func TestClassifyAWSLifecycleBeatsAlreadyDeclared(t *testing.T) {
	decision, reason := classifyBaselineResource(BaselineResource{
		Kind:      BaselineKindRole,
		Name:      "AWS-QuickSetup-JITNA-LocalAdministrationRole",
		Path:      "/",
		ManagedBy: "unknown",
	}, true)
	if decision != BaselineDecisionSkippedAWSLifecycle {
		t.Fatalf("decision = %q, want %q", decision, BaselineDecisionSkippedAWSLifecycle)
	}
	if !strings.Contains(reason, "清掉") {
		t.Errorf("reason 应提示清理已生成的工单文件，got %q", reason)
	}
}

func TestDetectBaselineConflicts(t *testing.T) {
	resources := []BaselineResource{
		// 两个名字只差大小写 → 文件名 key 都转小写，撞车。
		{Kind: BaselineKindUser, Name: "Deployer", Decision: BaselineDecisionCandidate,
			FileKey: "user-deployer", Address: "aws_iam_user.user_Deployer"},
		{Kind: BaselineKindUser, Name: "deployer", Decision: BaselineDecisionCandidate,
			FileKey: "user-deployer", Address: "aws_iam_user.user_deployer"},
		// 特殊字符归一化后 label 相同 → 地址撞车。
		{Kind: BaselineKindPolicy, Name: "read.only", Decision: BaselineDecisionCandidate,
			FileKey: "policy-read.only", Address: "aws_iam_policy.managed_policy_read_only"},
		{Kind: BaselineKindPolicy, Name: "read_only", Decision: BaselineDecisionCandidate,
			FileKey: "policy-read_only", Address: "aws_iam_policy.managed_policy_read_only"},
		// 被跳过的资源不写文件，不参与冲突。
		{Kind: BaselineKindRole, Name: "skipped-role", Decision: BaselineDecisionSkippedExternal,
			FileKey: "role-deployer", Address: "aws_iam_user.user_Deployer"},
	}
	conflicts := detectBaselineConflicts(resources)
	if len(conflicts) != 2 {
		t.Fatalf("conflicts = %#v, want 2", conflicts)
	}
	byKind := map[string]BaselineConflict{}
	for _, conflict := range conflicts {
		byKind[conflict.Kind] = conflict
		if len(conflict.Resources) != 2 {
			t.Errorf("conflict %q should list both resources: %#v", conflict.Value, conflict.Resources)
		}
	}
	if _, ok := byKind["file-key"]; !ok {
		t.Error("missing file-key conflict (case-insensitive name collision)")
	}
	if _, ok := byKind["address"]; !ok {
		t.Error("missing address conflict (label sanitization collision)")
	}
}

func TestDetectBaselineConflictsIgnoresSkipped(t *testing.T) {
	resources := []BaselineResource{
		{Kind: BaselineKindRole, Name: "a", Decision: BaselineDecisionSkippedExternal,
			FileKey: "role-x", Address: "aws_iam_role.role_x"},
		{Kind: BaselineKindRole, Name: "b", Decision: BaselineDecisionSkippedAlreadyDeclared,
			FileKey: "role-x", Address: "aws_iam_role.role_x"},
	}
	if conflicts := detectBaselineConflicts(resources); len(conflicts) != 0 {
		t.Fatalf("skipped resources must not conflict: %#v", conflicts)
	}
}

// 基线与工单必须写同一个文件、同一个地址，否则 Terraform 会因为同一地址被两个
// 文件声明而拒绝整个配置。这条测试就是防止两套规则各自漂移。
func TestResourceKeyAndLabelMatchGenerator(t *testing.T) {
	if got, want := ResourceFileKey(BaselineKindRole, "MyRole"), "role-myrole"; got != want {
		t.Errorf("ResourceFileKey(role) = %q, want %q", got, want)
	}
	if got, want := adapter.RoleResourceLabel("MyRole"), "role_MyRole"; got != want {
		t.Errorf("RoleResourceLabel = %q, want %q", got, want)
	}
	if got, want := ResourceFileKey(BaselineKindUser, "App.User"), "user-app.user"; got != want {
		t.Errorf("ResourceFileKey(user) = %q, want %q", got, want)
	}
	if got, want := adapter.UserResourceLabel("App.User"), "user_App_User"; got != want {
		t.Errorf("UserResourceLabel = %q, want %q", got, want)
	}
	if got, want := adapter.GroupResourceLabel("app-devs"), "group_app-devs"; got != want {
		t.Errorf("GroupResourceLabel = %q, want %q", got, want)
	}
	if got, want := adapter.DefaultManagedPolicyLabel("Read.Only"), "managed_policy_Read_Only"; got != want {
		t.Errorf("DefaultManagedPolicyLabel = %q, want %q", got, want)
	}
	// 空名字不产出 key：宁可留空，也不要生成 "role-" 这种会互相覆盖的文件名。
	if got := ResourceFileKey(BaselineKindRole, "   "); got != "" {
		t.Errorf("ResourceFileKey with empty name = %q, want empty", got)
	}
}

func TestPolicyPathFromARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::111122223333:policy/ReadOnly":           "/",
		"arn:aws:iam::111122223333:policy/service-role/Thing": "/service-role/",
		"arn:aws:iam::111122223333:policy/app/nested/Deep":    "/app/nested/",
		"":           "",
		"not-an-arn": "",
	}
	for arn, want := range cases {
		if got := policyPathFromARN(arn); got != want {
			t.Errorf("policyPathFromARN(%q) = %q, want %q", arn, got, want)
		}
	}
}

func TestDecodeResourceTags(t *testing.T) {
	if tags := decodeResourceTags(nil); tags != nil {
		t.Errorf("NULL tags must decode to nil, got %#v", tags)
	}
	// 脏 tag 不能让整份差异清单报不出来。
	if tags := decodeResourceTags([]byte("not json")); tags != nil {
		t.Errorf("invalid JSON must decode to nil, got %#v", tags)
	}
	tags := decodeResourceTags([]byte(`{"aws:cloudformation:stack-name":"prod-ecs"}`))
	if tags["aws:cloudformation:stack-name"] != "prod-ecs" {
		t.Errorf("tags = %#v", tags)
	}
}

// TestInlinePolicyFileKeyAndMembershipKey 验证三个文件 key 约定与工单链路
// 同源：内联策略 key 带主体（策略名只在主体内唯一），membership 独立文件。
func TestInlinePolicyFileKeyAndMembershipKey(t *testing.T) {
	cases := map[string]string{
		InlinePolicyFileKey("role", "My-Role", "ReadOnly"):   "role-my-role-policy-readonly",
		InlinePolicyFileKey("user", "deployer", "S3.List"):   "user-deployer-policy-s3.list",
		InlinePolicyFileKey("group", "Platform Team", "a_b"): "group-platform-team-policy-a_b",
		InlinePolicyFileKey("role", "", "x"):                 "",
		InlinePolicyFileKey("", "o", "x"):                    "",
		MembershipFileKey("Team A"):                          "group-team-a-membership",
		MembershipFileKey(""):                                "",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("file key = %q, want %q", got, want)
		}
	}
	// 组内联更新工单的 key 必须与候选集一致，否则「已声明」判定失效。
	if policyFileKey := (CreateIAMTicketRequest{
		TicketType:   TicketTypeUpdateGroupInlinePolicy,
		UpdatePolicy: &adapter.UpdatePolicyConfig{GroupName: "My-Role", InlinePolicyName: "ReadOnly"},
	}).policyFileKey(); policyFileKey != InlinePolicyFileKey("group", "My-Role", "ReadOnly") {
		t.Errorf("group inline ticket key %q diverges from candidate key", policyFileKey)
	}
}

// TestClassifyInlinePolicyFollowsOwner 验证内联策略的归属继承与主体排除。
func TestClassifyInlinePolicyFollowsOwner(t *testing.T) {
	cases := []struct {
		name          string
		ownerKind     string
		owner         string
		policyName    string
		managedBy     string
		ownerRoleTags map[string]string
		wantDecision  string
	}{
		{
			name:         "普通角色的内联策略进基线",
			ownerKind:    "role",
			owner:        "app-runtime",
			policyName:   "s3-readonly",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionCandidate,
		},
		{
			name:         "策略自己的归属标注优先于主体",
			ownerKind:    "role",
			owner:        "app-runtime",
			policyName:   "s3-readonly",
			managedBy:    "external",
			wantDecision: BaselineDecisionSkippedExternal,
		},
		{
			// 主体是 Quick Setup 角色：策略跟着排除，否则主体消失后基线里
			// 留下指向不存在角色的声明。
			name:         "Quick Setup 角色的内联策略跟随排除",
			ownerKind:    "role",
			owner:        "AWS-QuickSetup-JITNA-LocalExecutionRole",
			policyName:   "bootstrap",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionSkippedAWSLifecycle,
		},
		{
			name:         "service-linked 角色的内联策略跟随排除",
			ownerKind:    "role",
			owner:        "AWSServiceRoleForAmazonEKS",
			policyName:   "eks-policy",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionSkippedServiceLinked,
		},
		{
			name:         "用户/组的内联策略不套用角色判定",
			ownerKind:    "user",
			owner:        "AWSServiceRoleFor-not-a-role",
			policyName:   "legacy",
			managedBy:    "unknown",
			wantDecision: BaselineDecisionCandidate,
		},
	}
	for _, testCase := range cases {
		item := BaselineResource{
			Kind:         BaselineKindInlinePolicy,
			Name:         testCase.policyName,
			Owner:        testCase.owner,
			OwnerKind:    testCase.ownerKind,
			ManagedBy:    testCase.managedBy,
			RoleTags:     testCase.ownerRoleTags,
			ResourceType: "aws_iam_role_policy",
			FileKey:      InlinePolicyFileKey(testCase.ownerKind, testCase.owner, testCase.policyName),
			Address:      "aws_iam_role_policy." + adapter.InlinePolicyResourceLabel(testCase.ownerKind, testCase.owner, testCase.policyName),
			ImportID:     testCase.owner + ":" + testCase.policyName,
		}
		decision, _ := classifyBaselineResource(item, false)
		if decision != testCase.wantDecision {
			t.Errorf("%s: decision = %q, want %q", testCase.name, decision, testCase.wantDecision)
		}
	}
}

// TestInlinePolicyAddressMatchesGeneratorLabel 保证候选集预测的地址与
// 生成器渲染的地址来自同一个函数——双声明类 bug 只能在这里拦住。
func TestInlinePolicyAddressMatchesGeneratorLabel(t *testing.T) {
	owner, policy := "Example-Corp", "Describe-EC2"
	item := BaselineResource{
		Kind:      BaselineKindInlinePolicy,
		Name:      policy,
		Owner:     owner,
		OwnerKind: "role",
		Address:   "aws_iam_role_policy." + adapter.InlinePolicyResourceLabel("role", owner, policy),
	}
	adapterInstance := adapter.AWSAdapter{}
	hcl, err := adapterInstance.GenerateBaselineInlinePolicyTerraform(
		"role", owner, policy,
		json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`),
		owner+":"+policy,
	)
	if err != nil {
		t.Fatalf("GenerateBaselineInlinePolicyTerraform() error = %v", err)
	}
	if !strings.Contains(hcl, "to = "+item.Address) || !strings.Contains(hcl, `resource "aws_iam_role_policy" "`+strings.TrimPrefix(item.Address, "aws_iam_role_policy.")+`"`) {
		t.Errorf("candidate address %s not found in generated file:/n%s", item.Address, hcl)
	}
}

// attachment 文件 key 是基线与挂载工单共用的约定：两条链路各写一份就会
// 出现同一个 aws_iam_*_policy_attachment 地址两个文件。
func TestAttachmentFileKeyMatchesTicketConvention(t *testing.T) {
	cases := []struct{ principalType, principal, policy, want string }{
		{"Role", "app-server", "app-logs", "attachment-role-app-server-app-logs"},
		{"User", "deploy-bot", "ReadOnlyAccess", "attachment-user-deploy-bot-readonlyaccess"},
	}
	for _, testCase := range cases {
		if got := AttachmentFileKey(testCase.principalType, testCase.principal, testCase.policy); got != testCase.want {
			t.Errorf("AttachmentFileKey(%q,%q,%q) = %q, want %q",
				testCase.principalType, testCase.principal, testCase.policy, got, testCase.want)
		}
	}
	for _, empty := range []struct{ principalType, principal, policy string }{
		{"", "x", "y"}, {"role", "", "y"}, {"role", "x", ""},
	} {
		if got := AttachmentFileKey(empty.principalType, empty.principal, empty.policy); got != "" {
			t.Errorf("AttachmentFileKey(%+v) = %q, want empty", empty, got)
		}
	}
}

// TestDeclaredResourcesOnlyCountsSuccessfulTickets 回归 phase4 §5：声明
// 口径收窄为「成功工单」——MERGED、或关单原因为 APPLIED 的 CLOSED。
// 旧口径 status <> 'REJECTED' 会把 DRAFT / PUBLISH_FAILED / 未合并 CLOSED
// 算成已声明，这些工单没有产生任何文件，资源会从基线视野里静默消失。
func TestDeclaredResourcesOnlyCountsSuccessfulTickets(t *testing.T) {
	fake := &bundleFakeDB{}
	fake.add("FROM iam_ticket", []string{
		"ticket_type", "principal_name", "request_policy",
	}, [][]driver.Value{
		// MERGED 的 CREATE_ROLE：声明角色本体。
		{"CREATE_ROLE", "merged-role", nil},
		// CLOSED + APPLIED 的 UPDATE_ROLE（merge 自动关单后的终态）：同样声明。
		{"UPDATE_ROLE", "applied-role", nil},
		// ADOPT_ROLE_INLINE_POLICIES：声明角色本体 + 名下每条内联策略。
		{"ADOPT_ROLE_INLINE_POLICIES", "adopted-role",
			[]byte(`{"role_inline_policies":[{"name":"alpha"},{"name":"beta"}]}`)},
	})
	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselineCandidateService(database)

	declared, err := service.declaredResources(context.Background(), 7)
	if err != nil {
		t.Fatalf("declaredResources: %v", err)
	}
	if !declared[BaselineKindRole]["merged-role"] ||
		!declared[BaselineKindRole]["applied-role"] ||
		!declared[BaselineKindRole]["adopted-role"] {
		t.Errorf("successful tickets must declare their principals: %v", declared[BaselineKindRole])
	}
	if !declared[BaselineKindInlinePolicy]["role-adopted-role-policy-alpha"] ||
		!declared[BaselineKindInlinePolicy]["role-adopted-role-policy-beta"] {
		t.Errorf("adopt ticket must declare inline policies: %v",
			declared[BaselineKindInlinePolicy])
	}

	queries := strings.Join(fake.recordedQueries(), "\n")
	for _, want := range []string{
		"status = 'MERGED'",
		"closure_reason = 'APPLIED'",
	} {
		if !strings.Contains(queries, want) {
			t.Errorf("declared-resources query is missing %q:/n%s", want, queries)
		}
	}
	if strings.Contains(queries, "<> 'REJECTED'") {
		t.Errorf("declared-resources query must not use the old status <> 'REJECTED' scope:/n%s",
			queries)
	}
}

// TestLoadAdoptedKeys 回归台账 25 方案 1：键集合要同时覆盖 resource_key、
// file_key 与冗余的 res:<kind>:<name>；查询必须 join 发布台账并要求
// applied_at 非空（发布未 apply 的行不能算「已进 state」）。
func TestLoadAdoptedKeys(t *testing.T) {
	fake := &bundleFakeDB{}
	fake.add("iam_baseline_declaration d", []string{"kind", "name", "file_key", "resource_key"}, [][]driver.Value{
		{"role", "app-server", "role-app-server", "role:app-server"},
		{"attachment", "app-logs", "attachment-role-app-server-app-logs", "attachment:role:app-server:arn:aws:iam::123456789012:policy/app-logs"},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselineCandidateService(database)
	keys, err := service.loadAdoptedKeys(context.Background(), 7)
	if err != nil {
		t.Fatalf("loadAdoptedKeys: %v", err)
	}
	for _, want := range []string{
		"file:role-app-server",
		"role:app-server",
		"res:role:app-server",
		"attachment:role:app-server:arn:aws:iam::123456789012:policy/app-logs",
	} {
		if !keys[want] {
			t.Errorf("adopted keys missing %q; got %v", want, keys)
		}
	}
	queries := strings.Join(fake.recordedQueries(), "\n")
	for _, want := range []string{
		"iam_baseline_publication p ON p.id = d.publication_id",
		"p.applied_at IS NOT NULL",
		"superseded_at",
	} {
		if strings.Contains(queries, want) != (want != "superseded_at") {
			t.Errorf("adopted query should %s %q:/n%s",
				map[bool]string{true: "contain", false: "not contain"}[want != "superseded_at"],
				want, queries)
		}
	}
}

// TestStripAdoptedImports 回归台账 25 方案 1：candidate 且命中 adopted 键的
// 资源剥离 import（resource_key 与 file 两种键都能命中）；跳过类资源、未
// 命中的资源、ImportID 已空的资源都保持不变。
func TestStripAdoptedImports(t *testing.T) {
	adopted := map[string]bool{
		"role:app-server":      true,
		"file:user-deploy-bot": true,
	}
	resources := []BaselineResource{
		{Kind: BaselineKindRole, Name: "app-server", Decision: BaselineDecisionCandidate, ImportID: "app-server"},
		{Kind: BaselineKindUser, Name: "deploy-bot", Decision: BaselineDecisionCandidate, ImportID: "deploy-bot", FileKey: "user-deploy-bot"},
		{Kind: BaselineKindGroup, Name: "release-managers", Decision: BaselineDecisionCandidate, ImportID: "release-managers"},
		{Kind: BaselineKindPolicy, Name: "app-logs", Decision: BaselineDecisionSkippedExternal, ImportID: "arn:policy"},
		{Kind: BaselineKindRole, Name: "no-import", Decision: BaselineDecisionCandidate},
	}
	stripAdoptedImports(resources, adopted)
	if resources[0].ImportID != "" {
		t.Errorf("adopted role import should be stripped, got %q", resources[0].ImportID)
	}
	if resources[1].ImportID != "" {
		t.Errorf("adopted-by-file user import should be stripped, got %q", resources[1].ImportID)
	}
	if resources[2].ImportID != "release-managers" {
		t.Errorf("un-adopted group import must stay, got %q", resources[2].ImportID)
	}
	if resources[3].ImportID != "arn:policy" {
		t.Errorf("skipped resource must be untouched, got %q", resources[3].ImportID)
	}
	if resources[4].ImportID != "" {
		t.Errorf("empty import must stay empty, got %q", resources[4].ImportID)
	}
}
