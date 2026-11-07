package service

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildDriftRollbackTicketForRoleAttributeOnlyCarriesChangedFields 只回填
// 真正有差异的字段：把声明里其他本来就一致的属性一起写进工单，只会让审批
// 人面对一份与漂移无关的 diff。
func TestBuildDriftRollbackTicketForRoleAttributeOnlyCarriesChangedFields(t *testing.T) {
	declaration := BaselineDeclaration{
		AWSAccountID: "123456789012",
		ResourceKey:  "role:app-role",
		FileKey:      "role-app-role",
		Kind:         BaselineKindRole,
		Name:         "app-role",
		Attributes: json.RawMessage(`{
			"path": "/",
			"description": "declared description",
			"max_session_duration": 3600,
			"trust_policy": {"Version":"2012-10-17","Statement":[]}
		}`),
	}
	finding := DriftFinding{
		ChangeType:  DriftChangeAttribute,
		ResourceKey: "role:app-role",
		Fields: []DriftFieldDiff{
			{Field: "description", Declared: "declared description", Live: "changed out of band"},
		},
	}
	request, reason := BuildDriftRollbackTicket(finding, &declaration, 7)
	if request == nil {
		t.Fatalf("expected rollback draft, got reason %q", reason)
	}
	if request.TicketType != TicketTypeUpdateRole {
		t.Errorf("ticket type = %s, want %s", request.TicketType, TicketTypeUpdateRole)
	}
	if request.AccountID != 7 || request.PrincipalName != "app-role" {
		t.Errorf("account/principal = %d/%s", request.AccountID, request.PrincipalName)
	}
	if request.UpdateRole == nil || request.UpdateRole.Description == nil {
		t.Fatalf("description not carried: %+v", request.UpdateRole)
	}
	if *request.UpdateRole.Description != "declared description" {
		t.Errorf("description = %q", *request.UpdateRole.Description)
	}
	// max_session_duration 没在差异里，不能顺手写进去。
	if request.UpdateRole.MaxSessionDuration != nil {
		t.Errorf("unchanged field must not be carried: %v", *request.UpdateRole.MaxSessionDuration)
	}
	// AUTO 只决定审批人从账号绑定里解析，不是免审批：草稿仍然要人提交、
	// 走审批与发布。
	if request.ApprovalMode != ApprovalModeAuto {
		t.Errorf("approval mode = %s, want AUTO", request.ApprovalMode)
	}
}

// TestBuildDriftRollbackTicketRejectsNonAttributeFinding 声明缺失 / 未声明多余
// 这类差异没有「改回旧值」的工单语义，必须明确拒绝而不是造一张空草稿。
func TestBuildDriftRollbackTicketRejectsNonAttributeFinding(t *testing.T) {
	declaration := BaselineDeclaration{
		ResourceKey: "role:app-role", Kind: BaselineKindRole, Name: "app-role",
		Attributes: json.RawMessage(`{"path":"/"}`),
	}
	for _, changeType := range []string{
		DriftChangeDeclaredMissing, DriftChangeUndeclaredExtra,
		DriftChangeBaselineStale, DriftChangeFileConflict,
	} {
		finding := DriftFinding{ChangeType: changeType, ResourceKey: "role:app-role"}
		request, reason := BuildDriftRollbackTicket(finding, &declaration, 7)
		if request != nil {
			t.Errorf("%s: expected refusal, got %s ticket", changeType, request.TicketType)
		}
		if reason == "" {
			t.Errorf("%s: refusal must explain itself", changeType)
		}
	}
}

// TestBuildDriftRollbackTicketForManagedPolicy 声明的策略只有 name/path，工单
// 要 ARN 才能定位，ARN 由账号 + 路径拼出来。
func TestBuildDriftRollbackTicketForManagedPolicy(t *testing.T) {
	declaration := BaselineDeclaration{
		AWSAccountID: "123456789012",
		ResourceKey:  "policy:team-readonly",
		Kind:         BaselineKindPolicy,
		Name:         "team-readonly",
		Attributes:   json.RawMessage(`{"path":"/team/","document":{"Version":"2012-10-17","Statement":[]}}`),
	}
	finding := DriftFinding{
		ChangeType:  DriftChangeAttribute,
		ResourceKey: "policy:team-readonly",
		Fields:      []DriftFieldDiff{{Field: "document"}},
	}
	request, reason := BuildDriftRollbackTicket(finding, &declaration, 3)
	if request == nil {
		t.Fatalf("expected rollback draft, got reason %q", reason)
	}
	if request.TicketType != TicketTypeUpdateManagedPolicy {
		t.Fatalf("ticket type = %s", request.TicketType)
	}
	wantARN := "arn:aws:iam::123456789012:policy/team/team-readonly"
	if request.UpdatePolicy == nil || request.UpdatePolicy.PolicyARN != wantARN {
		t.Fatalf("policy arn = %+v, want %s", request.UpdatePolicy, wantARN)
	}
	if len(request.UpdatePolicy.Document) == 0 {
		t.Error("document must be carried")
	}
}

// TestBuildDriftRollbackTicketForInlinePolicy 内联策略按属主类型分到组或角色，
// 并且把属主写进 principal_name —— 校验层靠它回填策略身份。
func TestBuildDriftRollbackTicketForInlinePolicy(t *testing.T) {
	declaration := BaselineDeclaration{
		AWSAccountID: "123456789012",
		ResourceKey:  "role:app-role:inline:extra-access",
		Kind:         BaselineKindInlinePolicy,
		Name:         "extra-access",
		Attributes: json.RawMessage(`{
			"owner_kind":"role","owner":"app-role","policy":"extra-access",
			"document":{"Version":"2012-10-17","Statement":[]}
		}`),
	}
	finding := DriftFinding{
		ChangeType:  DriftChangeAttribute,
		ResourceKey: "role:app-role:inline:extra-access",
		Fields:      []DriftFieldDiff{{Field: "document"}},
	}
	request, reason := BuildDriftRollbackTicket(finding, &declaration, 3)
	if request == nil {
		t.Fatalf("expected rollback draft, got reason %q", reason)
	}
	if request.TicketType != TicketTypeUpdateGroupInlinePolicy {
		t.Fatalf("ticket type = %s", request.TicketType)
	}
	if request.PrincipalType != "Role" || request.PrincipalName != "app-role" {
		t.Errorf("principal = %s/%s", request.PrincipalType, request.PrincipalName)
	}
	if request.UpdatePolicy == nil ||
		request.UpdatePolicy.RoleName != "app-role" ||
		request.UpdatePolicy.InlinePolicyName != "extra-access" {
		t.Fatalf("update policy = %+v", request.UpdatePolicy)
	}
}

// TestDriftRemediationOwnerRestrictsAcknowledge 工单声明的资源重发基线改不动
// （0027 门禁会拒），只能回滚；基线声明的资源两路都给。
func TestDriftRemediationOwnerRestrictsAcknowledge(t *testing.T) {
	finding := DriftFinding{
		ChangeType:  DriftChangeAttribute,
		ResourceKey: "role:app-role",
		Fields:      []DriftFieldDiff{{Field: "description"}},
	}
	baseline := BaselineDeclaration{
		ResourceKey: "role:app-role", Kind: BaselineKindRole, Name: "app-role",
		Attributes: json.RawMessage(`{"description":"x"}`),
	}
	plan := DriftRemediation{}
	evaluateDriftRemediationPlan(&plan, finding, &baseline)
	if plan.Owner != DriftOwnerBaseline || !containsRoute(plan.AllowedRoutes, DriftRouteAcknowledge) ||
		!containsRoute(plan.AllowedRoutes, DriftRouteRollback) {
		t.Fatalf("baseline-owned plan = %+v", plan)
	}

	ticketID := int64(42)
	baseline.TicketID = &ticketID
	plan = DriftRemediation{}
	evaluateDriftRemediationPlan(&plan, finding, &baseline)
	if plan.Owner != DriftOwnerTicket {
		t.Fatalf("owner = %s, want ticket", plan.Owner)
	}
	if containsRoute(plan.AllowedRoutes, DriftRouteAcknowledge) {
		t.Error("ticket-owned resource must not offer baseline re-publication")
	}
	if !containsRoute(plan.AllowedRoutes, DriftRouteRollback) {
		t.Error("ticket-owned resource must still offer rollback")
	}
}

// TestDriftRemediationPlanWithoutDeclaration 没有声明快照（如子资源发现）
// 时只能追认，且 must not 声称能回滚。
func TestDriftRemediationPlanWithoutDeclaration(t *testing.T) {
	plan := DriftRemediation{}
	evaluateDriftRemediationPlan(&plan, DriftFinding{ChangeType: DriftChangeUndeclaredExtra}, nil)
	if !containsRoute(plan.AllowedRoutes, DriftRouteAcknowledge) {
		t.Error("acknowledge must stay available")
	}
	if containsRoute(plan.AllowedRoutes, DriftRouteRollback) {
		t.Error("rollback requires a declaration snapshot")
	}
}

// TestDriftManagedPolicyARNHandlesRootPath 根路径不能拼出双斜杠。
func TestDriftManagedPolicyARNHandlesRootPath(t *testing.T) {
	declaration := BaselineDeclaration{AWSAccountID: "123456789012", Name: "p"}
	for _, item := range []struct{ path, want string }{
		{"/", "arn:aws:iam::123456789012:policy/p"},
		{"/team/", "arn:aws:iam::123456789012:policy/team/p"},
		{"team", "arn:aws:iam::123456789012:policy/team/p"},
	} {
		attributes := map[string]any{"path": item.path}
		if got := driftManagedPolicyARN(&declaration, attributes); got != item.want {
			t.Errorf("path %q: arn = %s, want %s", item.path, got, item.want)
		}
	}
	if got := driftManagedPolicyARN(&declaration, map[string]any{}); !strings.HasSuffix(got, ":policy/p") {
		t.Errorf("missing path must fall back to root, got %s", got)
	}
}
