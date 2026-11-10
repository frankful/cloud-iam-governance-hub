package service

import (
	"errors"
	"strings"
	"testing"
)

func cleanupByName(t *testing.T, items []CleanupItem) map[string]CleanupItem {
	t.Helper()
	byName := map[string]CleanupItem{}
	for _, item := range items {
		if _, ok := byName[item.Name]; ok {
			t.Fatalf("duplicate cleanup item for %q", item.Name)
		}
		byName[item.Name] = item
	}
	return byName
}

func evidenceText(item CleanupItem) string {
	lines := make([]string, 0, len(item.Evidence))
	for _, line := range item.Evidence {
		lines = append(lines, line.Text)
	}
	return strings.Join(lines, " | ")
}

// 只报「平台声明了、但资源归 AWS 生命周期托管」的：普通候选、被拒工单、
// 以及没有工单的生命周期资源都不该进清理清单。
func TestDeclaredLifecycleFiles(t *testing.T) {
	resources := []BaselineResource{
		{Kind: BaselineKindRole, Name: "AWS-QuickSetup-SSM-LocalExecutionRole",
			FileKey: "role-aws-quicksetup-ssm-localexecutionrole",
			Decision: BaselineDecisionSkippedAWSLifecycle,
			Reason:   "SSM Quick Setup 生成的角色"},
		{Kind: BaselineKindRole, Name: "AWS-QuickSetup-NoTicketRole",
			Decision: BaselineDecisionSkippedAWSLifecycle},
		{Kind: BaselineKindRole, Name: "app-role", Decision: BaselineDecisionCandidate},
	}
	tickets := map[string][]cleanupTicket{
		"aws-quicksetup-ssm-localexecutionrole": {
			{No: "IAM-DRAFT", Type: TicketTypeCreateRole, Status: "DRAFT"},
			{No: "IAM-MERGED", Type: TicketTypeUpdateRole, Status: "CLOSED",
				PRURL: "https://example.com/pr/6", Published: true},
		},
		"app-role": {{No: "IAM-APP", Type: TicketTypeCreateRole, Status: "CLOSED", Published: true}},
	}
	items := declaredLifecycleFiles(resources, tickets)
	if len(items) != 1 {
		t.Fatalf("items = %#v, want 1", items)
	}
	item := items[0]
	if item.Category != CleanupCategoryPlatformFile || item.Confidence != CleanupConfidenceHigh {
		t.Errorf("category/confidence = %q/%q", item.Category, item.Confidence)
	}
	// 必须指向真的发过 PR 的那张单，否则人去删一个不存在的文件。
	if item.TicketNo != "IAM-MERGED" {
		t.Errorf("ticket = %q, want IAM-MERGED", item.TicketNo)
	}
	if item.FileKey != "role-aws-quicksetup-ssm-localexecutionrole.tf" {
		t.Errorf("file key = %q", item.FileKey)
	}
	evidence := evidenceText(item)
	for _, want := range []string{"SSM Quick Setup", "IAM-MERGED", "pr/6", "role-aws-quicksetup-ssm-localexecutionrole.tf"} {
		if !strings.Contains(evidence, want) {
			t.Errorf("evidence 缺少 %q: %s", want, evidence)
		}
	}
	// 每条证据都要带 code，前端才能按语言重新翻译。
	for _, line := range item.Evidence {
		if line.Code == "" {
			t.Errorf("evidence %q 缺少 code", line.Text)
		}
	}
}

// 工单只停在草稿（没有 terraform_code、没有 PR）时也要报，但要说明文件可能不存在。
func TestDeclaredLifecycleFilesDraftOnly(t *testing.T) {
	resources := []BaselineResource{{
		Kind: BaselineKindRole, Name: "AWS-QuickSetup-JITNA-LocalAdministrationRole",
		FileKey:  "role-aws-quicksetup-jitna-localadministrationrole",
		Decision: BaselineDecisionSkippedAWSLifecycle,
	}}
	tickets := map[string][]cleanupTicket{
		"aws-quicksetup-jitna-localadministrationrole": {
			{No: "IAM-PROBE", Type: TicketTypeCreateRole, Status: "CLOSED"},
		},
	}
	items := declaredLifecycleFiles(resources, tickets)
	if len(items) != 1 {
		t.Fatalf("items = %#v, want 1", items)
	}
	if !strings.Contains(evidenceText(items[0]), "没有关联 PR") {
		t.Errorf("evidence 应说明没有 PR: %#v", items[0].Evidence)
	}
}

func TestUnboundInstanceProfiles(t *testing.T) {
	profiles := []instanceProfileRow{
		{Name: "no-role", ARN: "arn:aws:iam::1:instance-profile/no-role"},
		{Name: "dangling", ARN: "arn:aws:iam::1:instance-profile/dangling",
			RoleARN: "arn:aws:iam::1:role/gone"},
		{Name: "healthy", ARN: "arn:aws:iam::1:instance-profile/healthy",
			RoleARN: "arn:aws:iam::1:role/app", RoleName: "app"},
	}
	byName := cleanupByName(t, unboundInstanceProfiles(profiles))
	if len(byName) != 2 {
		t.Fatalf("items = %#v, want 2", byName)
	}
	if byName["no-role"].Confidence != CleanupConfidenceHigh {
		t.Errorf("no-role confidence = %q", byName["no-role"].Confidence)
	}
	if !strings.Contains(byName["dangling"].Reason, "已不存在") {
		t.Errorf("dangling reason = %q", byName["dangling"].Reason)
	}
	if _, ok := byName["healthy"]; ok {
		t.Error("绑定正常的实例配置文件不该进待删清单")
	}
}

// 解析器缺失（nil）时维持旧行为：重复的 eks-<uuid> 全部标为需确认。
func TestEKSCleanupWithoutResolver(t *testing.T) {
	roleARN := "arn:aws:iam::1:role/example-eks-nodegroup-role"
	profiles := []instanceProfileRow{
		{Name: "eks-11111111-1111-1111-1111-111111111111", RoleARN: roleARN, RoleName: "infra"},
		{Name: "eks-22222222-2222-2222-2222-222222222222", RoleARN: roleARN, RoleName: "infra"},
		{Name: "eks-nodegroup-bastion", RoleARN: roleARN, RoleName: "infra"},
	}
	items := eksInstanceProfileCleanup(profiles, nil, nil)
	if len(items) != 2 {
		t.Fatalf("items = %d (%#v), want 2", len(items), items)
	}
	for _, item := range items {
		if item.Confidence != CleanupConfidenceReview {
			t.Errorf("%s confidence = %q, want review", item.Name, item.Confidence)
		}
		if item.ReasonCode != "profile-eks-review" {
			t.Errorf("%s reason code = %q", item.Name, item.ReasonCode)
		}
		if !strings.Contains(item.Action, "launch template") {
			t.Errorf("%s action 缺确认办法: %s", item.Name, item.Action)
		}
	}
}

// 解析成功：被 launch template 引用的在用项不再上榜，其余孤儿升级为 high。
func TestEKSCleanupWithUsage(t *testing.T) {
	roleARN := "arn:aws:iam::1:role/example-eks-nodegroup-role"
	usedProfile := instanceProfileRow{
		Name: "eks-11111111-1111-1111-1111-111111111111",
		ARN:  "arn:aws:iam::1:instance-profile/eks-11111111-1111-1111-1111-111111111111",
		RoleARN: roleARN, RoleName: "infra",
	}
	staleProfile := instanceProfileRow{
		Name: "eks-22222222-2222-2222-2222-222222222222",
		ARN:  "arn:aws:iam::1:instance-profile/eks-22222222-2222-2222-2222-222222222222",
		RoleARN: roleARN, RoleName: "infra",
	}
	orphanRole := "arn:aws:iam::1:role/dead-nodegroup-role"
	orphan := instanceProfileRow{
		Name: "eks-33333333-3333-3333-3333-333333333333",
		ARN:  "arn:aws:iam::1:instance-profile/eks-33333333-3333-3333-3333-333333333333",
		RoleARN: orphanRole, RoleName: "dead",
	}
	liveProfile := instanceProfileRow{
		Name: "eks-44444444-4444-4444-4444-444444444444",
		ARN:  "arn:aws:iam::1:instance-profile/eks-44444444-4444-4444-4444-444444444444",
		RoleARN: "arn:aws:iam::1:role/live-nodegroup-role", RoleName: "live",
	}
	profiles := []instanceProfileRow{usedProfile, staleProfile, orphan, liveProfile}
	usage := &profileUsageResult{
		UsedProfiles: map[string][]string{
			strings.ToLower(usedProfile.ARN): {"被 launch template eks-1 引用"},
			strings.ToLower(liveProfile.ARN): {"被 launch template eks-2 引用"},
		},
		RoleNodegroups: map[string][]string{
			strings.ToLower(roleARN):    {"cluster eks1 / nodegroup ng-app"},
			strings.ToLower(liveProfile.RoleARN): {"cluster eks2 / nodegroup ng-db"},
		},
	}
	byName := cleanupByName(t, eksInstanceProfileCleanup(profiles, usage, nil))

	if _, ok := byName[usedProfile.Name]; ok {
		t.Error("被 launch template 引用的实例配置文件不该出现在待删清单")
	}
	if _, ok := byName[liveProfile.Name]; ok {
		t.Error("单独在用的实例配置文件不该出现在待删清单")
	}
	stale := byName[staleProfile.Name]
	if stale.Confidence != CleanupConfidenceHigh {
		t.Errorf("stale confidence = %q, want high（同角色已有在用项）", stale.Confidence)
	}
	if stale.ReasonCode != "profile-eks-unused" {
		t.Errorf("stale reason code = %q", stale.ReasonCode)
	}
	if !strings.Contains(evidenceText(stale), "在用项") {
		t.Errorf("stale evidence 应说明在用项: %s", evidenceText(stale))
	}
	orph := byName[orphan.Name]
	if orph.Confidence != CleanupConfidenceHigh || orph.ReasonCode != "profile-eks-orphan" {
		t.Errorf("orphan = %s/%s, want high/profile-eks-orphan", orph.Confidence, orph.ReasonCode)
	}
}

// 角色仍被节点组使用、却没有 launch template 引用任何 profile：宁可待确认。
func TestEKSCleanupAmbiguousWhenRoleAlive(t *testing.T) {
	roleARN := "arn:aws:iam::1:role/weird-role"
	profiles := []instanceProfileRow{
		{Name: "eks-aaaaaaaa-1111-1111-1111-111111111111", ARN: "arn:aws:iam::1:instance-profile/eks-aaaaaaaa-1111-1111-1111-111111111111",
			RoleARN: roleARN, RoleName: "weird"},
		{Name: "eks-bbbbbbbb-2222-2222-2222-222222222222", ARN: "arn:aws:iam::1:instance-profile/eks-bbbbbbbb-2222-2222-2222-222222222222",
			RoleARN: roleARN, RoleName: "weird"},
	}
	usage := &profileUsageResult{
		UsedProfiles:   map[string][]string{},
		RoleNodegroups: map[string][]string{strings.ToLower(roleARN): {"cluster eks1 / nodegroup ng-x"}},
	}
	items := eksInstanceProfileCleanup(profiles, usage, nil)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for _, item := range items {
		if item.Confidence != CleanupConfidenceReview || item.ReasonCode != "profile-eks-ambiguous" {
			t.Errorf("%s = %s/%s, want review/profile-eks-ambiguous",
				item.Name, item.Confidence, item.ReasonCode)
		}
	}
}

// 解析失败：清单照常给出，但相关条目退回 review，缺口里写明原因。
func TestRuleGapsReflectResolverState(t *testing.T) {
	failure := errors.New("AccessDenied: eks:ListClusters")
	gaps := ruleGaps(nil, failure)
	joined := strings.Join(gaps, "\n")
	if !strings.Contains(joined, failure.Error()) {
		t.Errorf("gaps 应包含解析失败原因: %s", joined)
	}

	noResolver := ruleGaps(nil, nil)
	if !strings.Contains(strings.Join(noResolver, "\n"), "未配置") {
		t.Errorf("无解析器时 gaps 应说明未配置: %s", strings.Join(noResolver, "\n"))
	}

	available := ruleGaps(&profileUsageResult{
		UsedProfiles:   map[string][]string{},
		RoleNodegroups: map[string][]string{},
		Warnings:       []string{"launch template lt-1 读取版本失败"},
	}, nil)
	joined = strings.Join(available, "\n")
	if !strings.Contains(joined, "lt-1") {
		t.Errorf("gaps 应包含部分失败警告: %s", joined)
	}
	if strings.Contains(joined, "未配置") {
		t.Errorf("解析可用时不应再报未配置: %s", joined)
	}
}

func TestEmptyGroups(t *testing.T) {
	groups := []groupRow{
		{Name: "empty-shell", Members: 0, Policies: 0},
		{Name: "empty-with-policy", Members: 0, Policies: 2},
		{Name: "in-use", Members: 3},
	}
	byName := cleanupByName(t, emptyGroups(groups, nil))
	if len(byName) != 2 {
		t.Fatalf("items = %#v, want 2", byName)
	}
	if byName["empty-shell"].Confidence != CleanupConfidenceHigh {
		t.Errorf("empty-shell confidence = %q, want high", byName["empty-shell"].Confidence)
	}
	if byName["empty-with-policy"].Confidence != CleanupConfidenceReview {
		t.Errorf("empty-with-policy confidence = %q, want review", byName["empty-with-policy"].Confidence)
	}
	if _, ok := byName["in-use"]; ok {
		t.Error("有成员的组不该进待删清单")
	}
}

func TestDeclaredResourcesRouteViaIaC(t *testing.T) {
	declared := map[string]BaselineResource{
		BaselineKindGroup + "/empty-shell": {Kind: BaselineKindGroup, Name: "empty-shell", FileKey: "group/empty-shell", Decision: BaselineDecisionCandidate},
		BaselineKindUser + "/orphan-plain": {Kind: BaselineKindUser, Name: "orphan-plain", FileKey: "user/orphan-plain", Decision: BaselineDecisionCandidate},
	}
	groups := []groupRow{
		{Name: "empty-shell", Members: 0, Policies: 0},
		{Name: "undeclared-shell", Members: 0, Policies: 0},
	}
	byName := cleanupByName(t, emptyGroups(groups, declared))
	if got := byName["empty-shell"].ActionCode; got != "delete-via-iac-group" {
		t.Errorf("declared group action = %q, want delete-via-iac-group", got)
	}
	if got := byName["empty-shell"].FileKey; got != "group/empty-shell.tf" {
		t.Errorf("declared group file key = %q, want group/empty-shell.tf", got)
	}
	if got := byName["undeclared-shell"].ActionCode; got != "delete-group" {
		t.Errorf("undeclared group action = %q, want delete-group", got)
	}
	if len(byName["empty-shell"].Evidence) == 0 {
		t.Fatal("declared group should carry a declared-in-baseline evidence line")
	}
	last := byName["empty-shell"].Evidence[len(byName["empty-shell"].Evidence)-1]
	if last.Code != "declared-in-baseline" {
		t.Errorf("last evidence = %q, want declared-in-baseline", last.Code)
	}

	users := []userRow{{Name: "orphan-plain", Memberships: 0, Policies: 0}}
	userItems := cleanupByName(t, ungroupedUsers(users, declared))
	if got := userItems["orphan-plain"].ActionCode; got != "delete-via-iac-user" {
		t.Errorf("declared user action = %q, want delete-via-iac-user", got)
	}
	if got := userItems["orphan-plain"].FileKey; got != "user/orphan-plain.tf" {
		t.Errorf("declared user file key = %q, want user/orphan-plain.tf", got)
	}

	// case-insensitive name matching between inventory and baseline
	usersLower := []userRow{{Name: "Orphan-Plain", Memberships: 0, Policies: 0}}
	mixed := cleanupByName(t, ungroupedUsers(usersLower, declared))
	if got := mixed["Orphan-Plain"].ActionCode; got != "delete-via-iac-user" {
		t.Errorf("case-mismatch declared user action = %q, want delete-via-iac-user", got)
	}
}

func TestUngroupedUsers(t *testing.T) {
	users := []userRow{
		{Name: "orphan-plain", Memberships: 0, Policies: 0},
		{Name: "orphan-with-policy", Memberships: 0, Policies: 1},
		{Name: "grouped-user", Memberships: 2, Policies: 0},
	}
	byName := cleanupByName(t, ungroupedUsers(users, nil))
	if len(byName) != 2 {
		t.Fatalf("items = %#v, want 2", byName)
	}
	if byName["orphan-plain"].Confidence != CleanupConfidenceHigh {
		t.Errorf("orphan-plain confidence = %q, want high", byName["orphan-plain"].Confidence)
	}
	if byName["orphan-plain"].Kind != BaselineKindUser {
		t.Errorf("orphan-plain kind = %q, want user", byName["orphan-plain"].Kind)
	}
	if byName["orphan-with-policy"].Confidence != CleanupConfidenceReview {
		t.Errorf("orphan-with-policy confidence = %q, want review", byName["orphan-with-policy"].Confidence)
	}
	if _, ok := byName["grouped-user"]; ok {
		t.Error("有组成员的用户不该进待删清单")
	}
}

func TestSortCleanupItems(t *testing.T) {
	items := []CleanupItem{
		{Category: CleanupCategoryAWSResource, Confidence: CleanupConfidenceReview, Kind: BaselineKindGroup, Name: "z"},
		{Category: CleanupCategoryAWSResource, Confidence: CleanupConfidenceHigh, Kind: BaselineKindInstanceProfile, Name: "b"},
		{Category: CleanupCategoryPlatformFile, Confidence: CleanupConfidenceHigh, Kind: BaselineKindRole, Name: "c"},
	}
	sortCleanupItems(items)
	if items[0].Category != CleanupCategoryPlatformFile {
		t.Errorf("平台文件应排在最前: %#v", items[0])
	}
	if items[1].Confidence != CleanupConfidenceHigh || items[2].Confidence != CleanupConfidenceReview {
		t.Errorf("同类别内 high 应在 review 之前: %#v", items)
	}
}

// launch template 里既可能写 ARN 也可能只写名字，两种形态都要能命中。
func TestProfileUsageLookupByNameOrARN(t *testing.T) {
	usage := profileUsageResult{UsedProfiles: map[string][]string{}}
	usage.addProfile("arn:aws:iam::123456789012:instance-profile/eks-abc", "evidence")
	if !usage.isUsed("arn:aws:iam::123456789012:instance-profile/eks-abc", "eks-abc") {
		t.Error("ARN 形态应命中")
	}
	if !usage.isUsed("", "EKS-ABC") {
		t.Error("名字形态（大小写不敏感）应命中")
	}
	if usage.isUsed("arn:aws:iam::123456789012:instance-profile/eks-other", "eks-other") {
		t.Error("不相关的 profile 不应命中")
	}
}

// EKS 权限未授予（EKSUnavailable）时：条目置信度不降级（EC2 证据足够），
// 但理由不得声称「角色也没有节点组在用」，且必须带权限提示证据。
func TestEKSCleanupWithEKSUnavailable(t *testing.T) {
	roleARN := "arn:aws:iam::1:role/hidden-nodegroup-role"
	profile := instanceProfileRow{
		Name:    "eks-cccccccc-3333-3333-3333-333333333333",
		ARN:     "arn:aws:iam::1:instance-profile/eks-cccccccc-3333-3333-3333-333333333333",
		RoleARN: roleARN, RoleName: "hidden",
	}
	usage := &profileUsageResult{
		UsedProfiles:   map[string][]string{},
		RoleNodegroups: map[string][]string{},
		EKSUnavailable: true,
	}
	items := eksInstanceProfileCleanup([]instanceProfileRow{profile}, usage, nil)
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	item := items[0]
	if item.Confidence != CleanupConfidenceHigh {
		t.Errorf("confidence = %q, want high（EC2 证据不受 EKS 权限影响）", item.Confidence)
	}
	if item.ReasonCode != "profile-eks-unused-eks-unchecked" {
		t.Errorf("reason code = %q, want profile-eks-unused-eks-unchecked", item.ReasonCode)
	}
	if strings.Contains(item.Reason, "角色也没有节点组在用") {
		t.Errorf("reason must not fabricate role-level conclusions: %s", item.Reason)
	}
	if !strings.Contains(evidenceText(item), "EKS 只读权限") {
		t.Errorf("evidence should carry the EKS permission hint: %s", evidenceText(item))
	}
}
