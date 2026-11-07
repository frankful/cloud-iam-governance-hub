package service

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// TestExtractDeclarationsMatchesBaselineBundle 基线与工单共用同一组生成器，
// 所以「从内容反解」的声明必须与基线侧（P2a，按生成器入参构造）逐条对齐：
// 资源 key、所属文件、属性形状全部一致。这条测试是两套来源不跑偏的护栏——
// 一旦生成器写了新属性而某一侧没跟上，这里就会红。
func TestExtractDeclarationsMatchesBaselineBundle(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)

	bundleService := NewBaselineBundleService(db, NewBaselineCandidateService(db), nil, "iam")
	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(report.Declarations) == 0 {
		t.Fatal("bundle produced no declarations")
	}

	extracted, gaps := ExtractDeclarations(bundleFilesAsTerraform(report.Files), bundleLabelHints(report))
	if len(gaps) != 0 {
		t.Fatalf("unexpected declaration gaps: %+v", gaps)
	}

	byKey := map[string]BaselineDeclaration{}
	for _, declaration := range report.Declarations {
		byKey[declaration.ResourceKey] = declaration
	}
	for _, declaration := range extracted {
		baseline, ok := byKey[declaration.ResourceKey]
		if !ok {
			t.Errorf("extracted declaration %s is missing from the baseline bundle", declaration.ResourceKey)
			continue
		}
		if baseline.FileKey != declaration.FileKey {
			t.Errorf("%s: file key %q from content, %q from the bundle",
				declaration.ResourceKey, declaration.FileKey, baseline.FileKey)
		}
		if baseline.Kind != declaration.Kind {
			t.Errorf("%s: kind %q from content, %q from the bundle",
				declaration.ResourceKey, declaration.Kind, baseline.Kind)
		}
		if baseline.Name != declaration.Name {
			t.Errorf("%s: name %q from content, %q from the bundle",
				declaration.ResourceKey, declaration.Name, baseline.Name)
		}
		if !jsonEqual(t, baseline.Attributes, declaration.Attributes) {
			t.Errorf("%s: attributes differ\nbundle:   %s\ncontent:  %s",
				declaration.ResourceKey, baseline.Attributes, declaration.Attributes)
		}
		delete(byKey, declaration.ResourceKey)
	}
	for key := range byKey {
		// instance-profile / oidc / saml 只由基线生成，工单侧没有；其余类型
		// 必须能从内容里反解出来。
		if key == "" {
			continue
		}
		t.Errorf("baseline declaration %s was not recovered from the generated files", key)
	}
}

func TestExtractDeclarationsFromTicketFiles(t *testing.T) {
	files := []TerraformBundleFile{
		{Key: "role-app-server", Content: `import {
  id = "app-server"
  to = aws_iam_role.role_app-server
}

resource "aws_iam_role" "role_app-server" {
  name                 = "app-server"
  assume_role_policy   = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  path                 = "/app/"
  max_session_duration = 3600
  tags = {
    "team" = "app"
  }
}

resource "aws_iam_role_policy" "role_app-server_policy" {
  name   = "app-server-policy"
  role   = aws_iam_role.role_app-server.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:ListBucket"], Resource = "*" }]
  })
}

resource "aws_iam_role_policy_attachment" "attachment_role_app-server_app-logs" {
  role       = aws_iam_role.role_app-server.id
  policy_arn = "arn:aws:iam::123456789012:policy/app-logs"
}
`},
		{Key: "group-release-managers-membership", Content: `resource "aws_iam_group_membership" "group_release-managers_membership" {
  name  = "release-managers-membership"
  group = aws_iam_group.group_release-managers.id
  users = ["deploy-bot", "ops-bot"]
}
`},
	}

	labels := DeclarationLabels{}
	labels.Add(terraformIAMGroup, "group_release-managers", "release-managers")

	declarations, gaps := ExtractDeclarations(files, labels)
	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
	byKey := map[string]BaselineDeclaration{}
	for _, declaration := range declarations {
		byKey[declaration.ResourceKey] = declaration
	}
	if len(byKey) != 4 {
		t.Fatalf("declarations = %v, want role + inline + attachment + membership", declarationNames(declarations))
	}

	role, ok := byKey["role:app-server"]
	if !ok {
		t.Fatalf("missing role declaration: %v", declarationNames(declarations))
	}
	var roleAttributes map[string]any
	if err := json.Unmarshal(role.Attributes, &roleAttributes); err != nil {
		t.Fatalf("role attributes: %v", err)
	}
	if roleAttributes["path"] != "/app/" {
		t.Errorf("role path = %v, want /app/", roleAttributes["path"])
	}
	if _, ok := roleAttributes["trust_policy"].(map[string]any); !ok {
		t.Errorf("role declaration must carry the trust policy object: %v", roleAttributes)
	}
	if _, ok := roleAttributes["tags"].(map[string]any); !ok {
		t.Errorf("role declaration must carry tags: %v", roleAttributes)
	}
	if roleAttributes["max_session_duration"] != float64(3600) {
		t.Errorf("max_session_duration = %v, want 3600", roleAttributes["max_session_duration"])
	}

	if _, ok := byKey["role:app-server:inline:app-server-policy"]; !ok {
		t.Errorf("inline policy declaration uses the owner name: %v", declarationNames(declarations))
	}
	attachment, ok := byKey["attachment:role:app-server:arn:aws:iam::123456789012:policy/app-logs"]
	if !ok {
		t.Errorf("attachment declaration missing: %v", declarationNames(declarations))
	} else if attachment.FileKey != "role-app-server" {
		t.Errorf("attachment file key = %q, want the file that declares it", attachment.FileKey)
	}
	membership, ok := byKey["membership:group:release-managers"]
	if !ok {
		t.Fatalf("membership declaration missing: %v", declarationNames(declarations))
	}
	var membershipAttributes map[string]any
	if err := json.Unmarshal(membership.Attributes, &membershipAttributes); err != nil {
		t.Fatalf("membership attributes: %v", err)
	}
	members, _ := membershipAttributes["members"].([]any)
	if len(members) != 2 || members[0] != "deploy-bot" || members[1] != "ops-bot" {
		t.Errorf("membership members = %v, want the declared list", membershipAttributes["members"])
	}
}

// TestExtractDeclarationsEmptiedFileVoids 回滚/移除最后一名成员后文件只剩注释：
// 没有块就没有声明，调用方据此把该文件的旧声明整体作废。
func TestExtractDeclarationsEmptiedFileVoids(t *testing.T) {
	declarations, gaps := ExtractDeclarations([]TerraformBundleFile{
		{Key: "role-app", Content: "# ROLE emptied by rollback ticket T-1\n# nothing to declare\n"},
	}, nil)
	if len(declarations) != 0 || len(gaps) != 0 {
		t.Fatalf("comment-only file must declare nothing, got %v / %v", declarations, gaps)
	}
}

// TestExtractDeclarationsReportsUnresolvedReference label 是净化过的字符串
// （大小写丢失），反解不出主体名称时不能瞎猜：报 gap，让覆盖缺口可见，
// 而不是写一条指向错资源的声明。
func TestExtractDeclarationsReportsUnresolvedReference(t *testing.T) {
	declarations, gaps := ExtractDeclarations([]TerraformBundleFile{{
		Key: "attachment-role-app",
		Content: `resource "aws_iam_role_policy_attachment" "attachment_role_app" {
  role       = aws_iam_role.role_app.id
  policy_arn = "arn:aws:iam::123456789012:policy/app-logs"
}
`,
	}}, nil)
	if len(declarations) != 0 {
		t.Fatalf("unresolved reference must not produce a declaration: %v", declarations)
	}
	if len(gaps) != 1 || gaps[0].FileKey != "attachment-role-app" {
		t.Fatalf("expected one gap for the unresolved principal, got %+v", gaps)
	}

	// 请求侧提示（工单知道自己挂给谁）能补上跨文件引用。
	hints := DeclarationLabels{}
	hints.Add(terraformIAMRole, "role_app", "app")
	declarations, gaps = ExtractDeclarations([]TerraformBundleFile{{
		Key: "attachment-role-app",
		Content: `resource "aws_iam_role_policy_attachment" "attachment_role_app" {
  role       = aws_iam_role.role_app.id
  policy_arn = "arn:aws:iam::123456789012:policy/app-logs"
}
`,
	}}, hints)
	if len(gaps) != 0 || len(declarations) != 1 {
		t.Fatalf("hint must resolve the principal, got %v / %+v", declarations, gaps)
	}
	if declarations[0].ResourceKey != "attachment:role:app:arn:aws:iam::123456789012:policy/app-logs" {
		t.Errorf("resource key = %q", declarations[0].ResourceKey)
	}
}

// TestDeclarationLabelsFromRequest 工单请求里的主体名字要按生成器的 label
// 规则登记，跨文件引用才解析得到（大小写与符号都被 label 净化掉了）。
func TestDeclarationLabelsFromRequest(t *testing.T) {
	labels := DeclarationLabelsFromRequest(CreateIAMTicketRequest{
		TicketType:    TicketTypeCreateUser,
		PrincipalName: "Deploy.Bot",
		PrincipalType: "User",
	})
	if _, ok := labels.resolve(terraformIAMUser, adapter.UserResourceLabel("Deploy.Bot")); !ok {
		t.Fatalf("request must register the principal label, got %v", labels)
	}
}

// bundleLabelHints 按候选集补全 label → 名称索引：基线的挂载/成员文件引用
// 别的主体的 label（role-*.tf 里的角色），跨文件解析靠这里兜底。
func bundleLabelHints(report *BaselineBundleReport) DeclarationLabels {
	labels := DeclarationLabels{}
	for _, declaration := range report.Declarations {
		switch declaration.Kind {
		case BaselineKindRole:
			labels.Add(terraformIAMRole, adapter.RoleResourceLabel(declaration.Name), declaration.Name)
		case BaselineKindUser:
			labels.Add(terraformIAMUser, adapter.UserResourceLabel(declaration.Name), declaration.Name)
		case BaselineKindGroup:
			labels.Add(terraformIAMGroup, adapter.GroupResourceLabel(declaration.Name), declaration.Name)
		}
	}
	return labels
}

func bundleFilesAsTerraform(files []BaselineBundleFile) []TerraformBundleFile {
	converted := make([]TerraformBundleFile, 0, len(files))
	for _, file := range files {
		converted = append(converted, TerraformBundleFile{Key: file.Key, Content: file.Content})
	}
	return converted
}

func declarationNames(declarations []BaselineDeclaration) []string {
	names := make([]string, 0, len(declarations))
	for _, declaration := range declarations {
		names = append(names, declaration.ResourceKey)
	}
	sort.Strings(names)
	return names
}

func jsonEqual(t *testing.T, left, right []byte) bool {
	t.Helper()
	var leftValue, rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatalf("decode left JSON %s: %v", left, err)
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		t.Fatalf("decode right JSON %s: %v", right, err)
	}
	leftText, _ := json.Marshal(leftValue)
	rightText, _ := json.Marshal(rightValue)
	return string(leftText) == string(rightText)
}
