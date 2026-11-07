package service

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCompareDeclaredAttributesIgnoresPresentationOnly 语义相等、写法不同
// 不算漂移：path 的斜杠、策略文档的键序与数组顺序、数字的 Go 类型。
// 这些差异每天都会出现（声明走 SQL 扫描、库存走 JSONB），如果算漂移，
// 页面第一天就被噪音淹没。
func TestCompareDeclaredAttributesIgnoresPresentationOnly(t *testing.T) {
	declared := map[string]any{
		"path":                 "/",
		"trust_policy":         json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com","lambda.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`),
		"max_session_duration": 3600,
	}
	live := map[string]any{
		"path":                 "",
		"trust_policy":         json.RawMessage(`{"Statement":[{"Action":"sts:AssumeRole","Principal":{"Service":["lambda.amazonaws.com","ec2.amazonaws.com"]},"Effect":"Allow"}],"Version":"2012-10-17"}`),
		"max_session_duration": 3600,
		// 实态多出的字段不在声明里：Terraform 不管它，不该报。
		"tags": map[string]string{"owner": "platform"},
	}
	if diffs := compareDeclaredAttributes(declared, live); len(diffs) != 0 {
		t.Fatalf("presentation-only differences must not be reported, got %+v", diffs)
	}
}

// TestCompareDeclaredAttributesReportsRealChange 真差异必须报出来，并且带
// 声明值与实态值——页面要能直接展示「本该是什么、实际是什么」。
func TestCompareDeclaredAttributesReportsRealChange(t *testing.T) {
	declared := map[string]any{
		"path":         "/",
		"description":  "baseline description",
		"trust_policy": json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`),
	}
	live := map[string]any{
		"path":         "/",
		"description":  "changed out of band",
		"trust_policy": json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`),
	}
	diffs := compareDeclaredAttributes(declared, live)
	if len(diffs) != 2 {
		t.Fatalf("diffs = %+v, want description and trust_policy", diffs)
	}
	fields := map[string]DriftFieldDiff{}
	for _, diff := range diffs {
		fields[diff.Field] = diff
	}
	if fields["description"].Live != "changed out of band" {
		t.Errorf("live value not carried: %+v", fields["description"])
	}
	if fields["trust_policy"].Declared == nil {
		t.Error("declared value must be carried for the remediation draft")
	}
}

func TestDriftSeverityPrioritizesPermissionBoundaries(t *testing.T) {
	cases := []struct {
		changeType string
		kind       string
		fields     []DriftFieldDiff
		want       string
	}{
		{DriftChangeDeclaredMissing, BaselineKindRole, nil, DriftSeverityHigh},
		{DriftChangeBaselineStale, "file", nil, DriftSeverityMedium},
		{DriftChangeAttribute, BaselineKindRole, []DriftFieldDiff{{Field: "trust_policy"}}, DriftSeverityHigh},
		{DriftChangeAttribute, BaselineKindPolicy, []DriftFieldDiff{{Field: "document"}}, DriftSeverityHigh},
		{DriftChangeAttribute, BaselineKindRole, []DriftFieldDiff{{Field: "tags"}}, DriftSeverityLow},
		{DriftChangeAttribute, BaselineKindGroup, []DriftFieldDiff{{Field: "members"}}, DriftSeverityMedium},
	}
	for _, item := range cases {
		if got := driftSeverity(item.changeType, item.kind, item.fields); got != item.want {
			t.Errorf("severity(%s,%s,%+v) = %s, want %s",
				item.changeType, item.kind, item.fields, got, item.want)
		}
	}
}

// TestBuildDriftCandidatesCoversSixLayers 一次把判定流水线的关键分支走完：
// 一致即无发现、字段差异、资源消失、基准过期、在途跳过、工单豁免。
func TestBuildDriftCandidatesCoversSixLayers(t *testing.T) {
	declaredAt := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	roleAttributes := func(description string) json.RawMessage {
		encoded, err := json.Marshal(map[string]any{
			"path":        "/",
			"description": description,
		})
		if err != nil {
			t.Fatalf("marshal role attributes: %v", err)
		}
		return encoded
	}
	publicationID := int64(31)
	declarations := []BaselineDeclaration{
		{ResourceKey: "role:clean", FileKey: "role-clean", Kind: BaselineKindRole,
			Name: "clean", Attributes: roleAttributes("same"), declaredAt: declaredAt,
			PublicationID: &publicationID},
		{ResourceKey: "role:changed", FileKey: "role-changed", Kind: BaselineKindRole,
			Name: "changed", Attributes: roleAttributes("declared"), declaredAt: declaredAt},
		{ResourceKey: "role:deleted", FileKey: "role-deleted", Kind: BaselineKindRole,
			Name: "deleted", Attributes: roleAttributes("gone"), declaredAt: declaredAt},
		{ResourceKey: "role:inflight", FileKey: "role-inflight", Kind: BaselineKindRole,
			Name: "inflight", Attributes: roleAttributes("declared"), declaredAt: declaredAt},
		{ResourceKey: "role:ticketed", FileKey: "role-ticketed", Kind: BaselineKindRole,
			Name: "ticketed", Attributes: roleAttributes("declared"), declaredAt: declaredAt},
		{ResourceKey: "role:stale", FileKey: "role-stale", Kind: BaselineKindRole,
			Name: "stale", Attributes: roleAttributes("declared"), declaredAt: declaredAt,
			PublicationID: &publicationID,
			StaleAt:       &declaredAt, StaleReason: "CONTENT_CHANGED"},
	}
	live := driftLiveSnapshot{resources: map[string]driftLiveResource{
		"role:clean": {ResourceKey: "role:clean", Kind: BaselineKindRole, Name: "clean",
			Attributes: map[string]any{"path": "/", "description": "same"}},
		"role:changed": {ResourceKey: "role:changed", Kind: BaselineKindRole, Name: "changed",
			Attributes: map[string]any{"path": "/", "description": "out-of-band"}},
		"role:inflight": {ResourceKey: "role:inflight", Kind: BaselineKindRole, Name: "inflight",
			Attributes: map[string]any{"path": "/", "description": "out-of-band"}},
		"role:ticketed": {ResourceKey: "role:ticketed", Kind: BaselineKindRole, Name: "ticketed",
			Attributes: map[string]any{"path": "/", "description": "out-of-band"}},
		"role:stale": {ResourceKey: "role:stale", Kind: BaselineKindRole, Name: "stale",
			Attributes: map[string]any{"path": "/", "description": "out-of-band"}},
	}}
	inFlight := map[string]bool{"role-inflight": true}
	activities := map[string]driftTicketActivity{
		"role-ticketed": {
			TicketNo: "IAM-1", Status: TicketStatusClosed, ApplyResult: "SUCCEEDED",
			UpdatedAt: declaredAt.Add(time.Hour),
		},
	}

	candidates, audit := buildDriftCandidates(declarations, live, inFlight, activities, time.Now().UTC())
	if audit.staleFiles != 1 {
		t.Errorf("stale files = %d, want 1", audit.staleFiles)
	}
	if audit.skippedFiles != 1 {
		t.Errorf("skipped files = %d, want 1", audit.skippedFiles)
	}

	byKey := map[string]DriftFinding{}
	for _, candidate := range candidates {
		byKey[candidate.ResourceKey] = candidate
	}
	if _, ok := byKey["role:clean"]; ok {
		t.Error("matching resource must not produce a finding")
	}
	if _, ok := byKey["role:inflight"]; ok {
		t.Error("in-flight file must be skipped: the conclusion can still change")
	}
	if _, ok := byKey["role:deleted"]; !ok {
		t.Fatal("declared but missing resource must be reported")
	}
	if got := byKey["role:deleted"].ChangeType; got != DriftChangeDeclaredMissing {
		t.Errorf("deleted change type = %s, want %s", got, DriftChangeDeclaredMissing)
	}
	if got := byKey["role:changed"].ChangeType; got != DriftChangeAttribute {
		t.Errorf("changed change type = %s, want %s", got, DriftChangeAttribute)
	}
	if len(byKey["role:changed"].Fields) != 1 {
		t.Errorf("changed fields = %+v, want only description", byKey["role:changed"].Fields)
	}
	if got := byKey["role:ticketed"].Status; got != DriftStatusPendingRebaseline {
		t.Errorf("ticket-touched file status = %s, want %s", got, DriftStatusPendingRebaseline)
	}
	stale, ok := byKey["file:role-stale"]
	if !ok {
		t.Fatal("stale declaration must surface as baseline_stale")
	}
	if stale.ChangeType != DriftChangeBaselineStale {
		t.Errorf("stale change type = %s", stale.ChangeType)
	}
	if _, ok := byKey["role:stale"]; ok {
		t.Error("stale declaration must not be compared as drift")
	}
	if stale.BaselinePublicationID == nil || *stale.BaselinePublicationID != publicationID {
		t.Errorf("stale finding must carry the baseline publication id")
	}
}

// TestBuildDriftCandidatesReportsUndeclaredChildren 只对「父资源已声明」的
// 子资源报 undeclared_extra：从未纳管的角色，它的挂载属于未纳管清单，
// 不属于漂移页。
func TestBuildDriftCandidatesReportsUndeclaredChildren(t *testing.T) {
	declarations := []BaselineDeclaration{
		{ResourceKey: "role:managed", FileKey: "role-managed", Kind: BaselineKindRole,
			Name: "managed", Attributes: json.RawMessage(`{"path":"/"}`)},
	}
	live := driftLiveSnapshot{resources: map[string]driftLiveResource{
		"role:managed": {ResourceKey: "role:managed", Kind: BaselineKindRole,
			Name: "managed", Attributes: map[string]any{"path": "/"}},
		"role:unmanaged": {ResourceKey: "role:unmanaged", Kind: BaselineKindRole,
			Name: "unmanaged", Attributes: map[string]any{"path": "/"}},
		"attachment:role:managed:arn:aws:iam::1:policy/extra": {
			ResourceKey: "attachment:role:managed:arn:aws:iam::1:policy/extra",
			Kind:        "attachment", Name: "extra",
			Attributes: map[string]any{
				"principal_kind": "role", "principal": "managed",
				"policy_arn": "arn:aws:iam::1:policy/extra",
			},
		},
		"attachment:role:unmanaged:arn:aws:iam::1:policy/extra": {
			ResourceKey: "attachment:role:unmanaged:arn:aws:iam::1:policy/extra",
			Kind:        "attachment", Name: "extra",
			Attributes: map[string]any{
				"principal_kind": "role", "principal": "unmanaged",
				"policy_arn": "arn:aws:iam::1:policy/extra",
			},
		},
	}}

	candidates, _ := buildDriftCandidates(declarations, live, nil, nil, time.Now().UTC())
	if len(candidates) != 1 {
		t.Fatalf("candidates = %+v, want only the managed role's attachment", candidates)
	}
	finding := candidates[0]
	if finding.ChangeType != DriftChangeUndeclaredExtra {
		t.Errorf("change type = %s, want %s", finding.ChangeType, DriftChangeUndeclaredExtra)
	}
	if finding.ResourceKey != "attachment:role:managed:arn:aws:iam::1:policy/extra" {
		t.Errorf("reported resource = %s", finding.ResourceKey)
	}
	if finding.FileKey != AttachmentFileKey("role", "managed", "extra") {
		t.Errorf("file key = %s, want the same derivation as publishing", finding.FileKey)
	}
}

// TestNextDriftStatusKeepsIgnoredFindingsQuiet 人工忽略不被下一轮检测翻回：
// 忽略是明确决定，只有资源恢复一致才自动关闭。
func TestNextDriftStatusKeepsIgnoredFindingsQuiet(t *testing.T) {
	first := DriftFinding{Status: DriftStatusSuspect, Occurrences: 0}
	if got := nextDriftStatus(first, DriftStatusSuspect); got != DriftStatusSuspect {
		t.Errorf("first sight = %s, want SUSPECT", got)
	}
	second := DriftFinding{Status: DriftStatusSuspect, Occurrences: 1}
	if got := nextDriftStatus(second, DriftStatusSuspect); got != DriftStatusOpen {
		t.Errorf("second sight = %s, want OPEN", got)
	}
	ignored := DriftFinding{Status: DriftStatusIgnored, Occurrences: 5}
	if got := nextDriftStatus(ignored, DriftStatusSuspect); got != DriftStatusIgnored {
		t.Errorf("ignored = %s, want IGNORED", got)
	}
	pending := DriftFinding{Status: DriftStatusPendingRebaseline, Occurrences: 3}
	if got := nextDriftStatus(pending, DriftStatusPendingRebaseline); got != DriftStatusPendingRebaseline {
		t.Errorf("pending rebaseline = %s", got)
	}
}

// TestDriftChildParentDerivesPublishingFileKey 子资源必须用与发布同一个
// 文件 key 推导，否则在途门禁（第 4 层）永远挡不住它。
func TestDriftChildParentDerivesPublishingFileKey(t *testing.T) {
	parent, fileKey := driftChildParent(driftLiveResource{
		Kind: BaselineKindInlinePolicy, Name: "read-logs",
		Attributes: map[string]any{
			"owner_kind": "role", "owner": "app", "policy": "read-logs",
		},
	})
	if parent != "role:app" {
		t.Errorf("parent = %s, want role:app", parent)
	}
	if fileKey != InlinePolicyFileKey("role", "app", "read-logs") {
		t.Errorf("file key = %s, want %s", fileKey, InlinePolicyFileKey("role", "app", "read-logs"))
	}
}

// TestBuildDriftCandidatesPendingWindow 24 小时宽限（§3 第 5 层）：工单
// MERGED 但 apply 未确认时，差异只在窗口内记 PENDING；超窗仍存在则当轮即升
// OPEN——既存发现已有一轮 PENDING 作证据，不再重复稳定窗口。没有这个上限，
// 无 CI 回调的账号会永久停在 PENDING——真实漂移永远不告警，即「PENDING
// 永久滞留」漏报通道。
func TestBuildDriftCandidatesPendingWindow(t *testing.T) {
	declaredAt := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	mergedAt := declaredAt.Add(time.Hour)
	ownTicket := int64(7)
	declarations := []BaselineDeclaration{{
		ResourceKey: "role:changed", FileKey: "role-changed", Kind: BaselineKindRole,
		Name: "changed", Attributes: json.RawMessage(`{"description":"declared"}`),
		declaredAt: declaredAt, TicketID: &ownTicket,
	}}
	live := driftLiveSnapshot{resources: map[string]driftLiveResource{
		"role:changed": {ResourceKey: "role:changed", Kind: BaselineKindRole, Name: "changed",
			Attributes: map[string]any{"description": "out-of-band"}},
	}}

	cases := []struct {
		name        string
		applyResult string
		now         time.Time
		want        string
	}{
		{"merged one hour ago stays pending", "", mergedAt.Add(time.Hour), DriftStatusPending},
		{"merged 23h ago still pending", "", mergedAt.Add(23 * time.Hour), DriftStatusPending},
		{"merged 25h ago escalates to suspect", "", mergedAt.Add(25 * time.Hour), DriftStatusSuspect},
		{"apply succeeded is a real drift", "SUCCEEDED", mergedAt.Add(time.Hour), DriftStatusSuspect},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			activities := map[string]driftTicketActivity{
				"role-changed": {
					TicketID: 7, TicketNo: "IAM-7", Status: TicketStatusMerged,
					ApplyResult: testCase.applyResult, UpdatedAt: mergedAt,
				},
			}
			candidates, _ := buildDriftCandidates(declarations, live, nil, activities, testCase.now)
			if len(candidates) != 1 {
				t.Fatalf("candidates = %+v, want 1", candidates)
			}
			if got := candidates[0].Status; got != testCase.want {
				t.Errorf("status = %s, want %s", got, testCase.want)
			}
		})
	}
}

// TestBuildDriftCandidatesExemptsOwnTicket 工单不豁免自己：工单的 merge
// 时间必然晚于它自己的声明落库时间，按时间戳判会导致工单自有文件上的真实
// 控制台改动被永久标成 PENDING_REBASELINE，而 0027 又禁止对这类文件重发
// 基线——追认被拒、只剩回滚。
func TestBuildDriftCandidatesExemptsOwnTicket(t *testing.T) {
	declaredAt := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	ownTicket := int64(7)
	declarations := []BaselineDeclaration{{
		ResourceKey: "role:changed", FileKey: "role-changed", Kind: BaselineKindRole,
		Name: "changed", Attributes: json.RawMessage(`{"description":"declared"}`),
		declaredAt: declaredAt, TicketID: &ownTicket,
	}}
	live := driftLiveSnapshot{resources: map[string]driftLiveResource{
		"role:changed": {ResourceKey: "role:changed", Kind: BaselineKindRole, Name: "changed",
			Attributes: map[string]any{"description": "out-of-band"}},
	}}
	now := declaredAt.Add(48 * time.Hour)

	cases := []struct {
		name     string
		ticketID int64
		want     string
	}{
		{"own ticket does not exempt itself", ownTicket, DriftStatusSuspect},
		{"another ticket still means rebaseline", 8, DriftStatusPendingRebaseline},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			activities := map[string]driftTicketActivity{
				"role-changed": {
					TicketID: testCase.ticketID, TicketNo: "IAM-8", Status: TicketStatusClosed,
					ApplyResult: "SUCCEEDED", UpdatedAt: declaredAt.Add(time.Hour),
				},
			}
			candidates, _ := buildDriftCandidates(declarations, live, nil, activities, now)
			if len(candidates) != 1 {
				t.Fatalf("candidates = %+v, want 1", candidates)
			}
			if got := candidates[0].Status; got != testCase.want {
				t.Errorf("status = %s, want %s", got, testCase.want)
			}
		})
	}
}

// 子资源（undeclared_extra）分支与主循环共用同一套豁免与宽限规则，只是
// 声明时间/工单取父声明的。以下两个测试各镜像主循环的对应用例。
func childResourceFixture() ([]BaselineDeclaration, driftLiveSnapshot) {
	declaredAt := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	ownTicket := int64(7)
	declarations := []BaselineDeclaration{{
		ResourceKey: "role:managed", FileKey: "role-managed", Kind: BaselineKindRole,
		Name: "managed", Attributes: json.RawMessage(`{"path":"/"}`),
		declaredAt: declaredAt, TicketID: &ownTicket,
	}}
	live := driftLiveSnapshot{resources: map[string]driftLiveResource{
		"role:managed": {ResourceKey: "role:managed", Kind: BaselineKindRole,
			Name: "managed", Attributes: map[string]any{"path": "/"}},
		"attachment:role:managed:arn:aws:iam::1:policy/extra": {
			ResourceKey: "attachment:role:managed:arn:aws:iam::1:policy/extra",
			Kind:        "attachment", Name: "extra",
			Attributes: map[string]any{
				"principal_kind": "role", "principal": "managed",
				"policy_arn": "arn:aws:iam::1:policy/extra",
			},
		},
	}}
	return declarations, live
}

// TestBuildDriftCandidatesChildPendingWindow 子资源的 24 小时宽限：父声明
// 由工单产出时，该工单自己的 merge 活动必然晚于父声明时间——若不判
// ownTicket、不看窗口，控制台后加的挂载会被永久死标 PENDING_REBASELINE。
func TestBuildDriftCandidatesChildPendingWindow(t *testing.T) {
	declarations, live := childResourceFixture()
	declaredAt := declarations[0].declaredAt
	mergedAt := declaredAt.Add(time.Hour)
	childFileKey := AttachmentFileKey("role", "managed", "extra")

	cases := []struct {
		name        string
		applyResult string
		now         time.Time
		want        string
	}{
		{"merged one hour ago stays pending", "", mergedAt.Add(time.Hour), DriftStatusPending},
		{"merged 25h ago escalates to suspect", "", mergedAt.Add(25 * time.Hour), DriftStatusSuspect},
		{"apply succeeded is a real drift", "SUCCEEDED", mergedAt.Add(time.Hour), DriftStatusSuspect},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			activities := map[string]driftTicketActivity{
				childFileKey: {
					TicketID: 7, TicketNo: "IAM-7", Status: TicketStatusMerged,
					ApplyResult: testCase.applyResult, UpdatedAt: mergedAt,
				},
			}
			candidates, _ := buildDriftCandidates(declarations, live, nil, activities, testCase.now)
			if len(candidates) != 1 {
				t.Fatalf("candidates = %+v, want 1", candidates)
			}
			if got := candidates[0].Status; got != testCase.want {
				t.Errorf("status = %s, want %s", got, testCase.want)
			}
		})
	}
}

// TestBuildDriftCandidatesChildExemptsOwnTicket 工单不豁免自己在子资源分支
// 同样成立：工单 7 声明了父角色，随后它自己的 merge/close 触发同文件活动，
// 子资源不能被打上「基线该更新」的死标——0027 拒绝对工单文件重发基线。
func TestBuildDriftCandidatesChildExemptsOwnTicket(t *testing.T) {
	declarations, live := childResourceFixture()
	declaredAt := declarations[0].declaredAt
	now := declaredAt.Add(48 * time.Hour)
	childFileKey := AttachmentFileKey("role", "managed", "extra")

	cases := []struct {
		name     string
		ticketID int64
		want     string
	}{
		{"own ticket does not exempt itself", 7, DriftStatusSuspect},
		{"another ticket still means rebaseline", 8, DriftStatusPendingRebaseline},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			activities := map[string]driftTicketActivity{
				childFileKey: {
					TicketID: testCase.ticketID, TicketNo: "IAM-8", Status: TicketStatusClosed,
					ApplyResult: "SUCCEEDED", UpdatedAt: declaredAt.Add(time.Hour),
				},
			}
			candidates, _ := buildDriftCandidates(declarations, live, nil, activities, now)
			if len(candidates) != 1 {
				t.Fatalf("candidates = %+v, want 1", candidates)
			}
			if got := candidates[0].Status; got != testCase.want {
				t.Errorf("status = %s, want %s", got, testCase.want)
			}
		})
	}
}
