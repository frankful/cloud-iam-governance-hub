package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestVoidRestoresPreviousDeclaration 作废一次没落地的发布后，被它取代的
// 上一条有效声明必须回到「当前」：main 上本来还是那一版内容，只作废不恢复
// 就把这些资源变成「有实态、无基准」的覆盖空洞。
func TestVoidRestoresPreviousDeclaration(t *testing.T) {
	fake := &publishFakeDB{}
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "WHERE ticket_id = $1 AND superseded_at IS NULL",
		columns: []string{"id", "account_id", "resource_key", "file_key"},
		rows: [][]driver.Value{
			{int64(1001), int64(7), "role:app", "role-app"},
			// 这张工单新造的资源没有上一版声明：作废后就是无基准，不许凭空恢复。
			{int64(1002), int64(7), "role:brand-new", "role-new"},
		},
	})
	// 只有 role:app 有可恢复的历史行；第二次查询（role:brand-new）落到
	// 空响应，也就是 sql.ErrNoRows。
	fake.addOnce("ORDER BY (file_key = $3) DESC", []string{"id"}, [][]driver.Value{{int64(900)}})

	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	if err := declarations.VoidForTicket(context.Background(), 41); err != nil {
		t.Fatalf("VoidForTicket: %v", err)
	}

	if got := fake.execCount("SET superseded_at = NOW(), superseded_reason = 'VOIDED'"); got != 2 {
		t.Fatalf("voided rows = %d, want both current declarations", got)
	}
	restores := 0
	for _, record := range fake.records {
		if !strings.Contains(record.query, "SET superseded_at = NULL, superseded_reason = NULL") {
			continue
		}
		restores++
		if got, _ := record.args[0].(int64); got != 900 {
			t.Errorf("restored declaration id = %v, want 900", record.args[0])
		}
	}
	if restores != 1 {
		t.Fatalf("restored rows = %d, want exactly the one with history", restores)
	}
	// 恢复查询只认 REPLACED：VOIDED 的历史行本身也是一次没落地的发布。
	if got := fake.queryCount("superseded_reason = 'REPLACED'"); got != 2 {
		t.Errorf("restore lookups = %d, want one per voided declaration", got)
	}
	args := fake.recordedQuery("ORDER BY (file_key = $3) DESC")
	if len(args) != 3 || args[0] != int64(7) || args[1] != "role:app" || args[2] != "role-app" {
		t.Errorf("restore lookup args = %v, want account/resource/file", args)
	}
}

// TestVoidForPublicationScopesToPublication 基线 PR 关闭未合并与工单废弃是
// 同一件事，只是定位维度不同：按 publication_id 而不是 ticket_id。
func TestVoidForPublicationScopesToPublication(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	if err := declarations.VoidForPublication(context.Background(), 77); err != nil {
		t.Fatalf("VoidForPublication: %v", err)
	}
	if got := fake.queryCount("WHERE publication_id = $1 AND superseded_at IS NULL"); got != 1 {
		t.Fatalf("publication-scoped void queries = %d, want 1", got)
	}
	if args := fake.recordedQuery("WHERE publication_id = $1 AND superseded_at IS NULL"); len(args) != 1 ||
		args[0] != int64(77) {
		t.Fatalf("void query args = %v, want publication 77", args)
	}
	// 没有生效中的声明：不该有任何写操作。
	if len(fake.records) != 0 {
		t.Fatalf("voiding an empty publication must not write, got %d statements", len(fake.records))
	}
}

// declarationFakeRepo 按文件名返回预置的 blob SHA / 是否存在，记录被问过的
// 路径（断言路径推导与发布器同源）。
type declarationFakeRepo struct {
	files map[string]string
	// missing 是「文件在 main 上不存在」的文件名集合。
	missing map[string]bool
	err     error
	asked   []string
}

func (fake *declarationFakeRepo) TerraformFileMeta(
	_ context.Context, fileName string,
) (string, bool, error) {
	fake.asked = append(fake.asked, fileName)
	if fake.err != nil {
		return "", false, fake.err
	}
	if fake.missing[fileName] {
		return "", false, nil
	}
	sha, exists := fake.files[fileName]
	if !exists {
		return "", false, nil
	}
	return sha, true, nil
}

func newFreshnessFakeDB(fake *publishFakeDB) {
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "GROUP BY file_key, content_blob_sha",
		columns: []string{"file_key", "content_blob_sha", "count", "stale_count"},
		rows: [][]driver.Value{
			// 有人绕过平台改了 main：声明时的 blob 与现在不一致。
			{"role-app", "sha-old", int64(2), int64(0)},
			// 没动过：不写任何标记。
			{"policy-logs", "sha-logs", int64(1), int64(0)},
			// 文件被删/改名。
			{"group-devs", "sha-devs", int64(1), int64(0)},
			// 之前误标过期、现在与 main 一致：要清掉。
			{"user-bot", "sha-bot", int64(1), int64(1)},
		},
	})
}

// TestReconcileFreshnessMarksChangedMissingAndClears 新鲜度核对三种结论：
// 内容变了 / 文件没了 → 打过期标记；一致 → 清标记；只在状态翻转时写。
func TestReconcileFreshnessMarksChangedMissingAndClears(t *testing.T) {
	fake := &publishFakeDB{}
	newFreshnessFakeDB(fake)
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	repo := &declarationFakeRepo{
		files: map[string]string{
			"iam/account-123456789012/role-app.tf":    "sha-new",
			"iam/account-123456789012/policy-logs.tf": "sha-logs",
			"iam/account-123456789012/user-bot.tf":    "sha-bot",
		},
		missing: map[string]bool{
			"iam/account-123456789012/group-devs.tf": true,
		},
	}
	report, err := declarations.ReconcileFreshness(
		context.Background(), 7, "iam/account-123456789012", repo)
	if err != nil {
		t.Fatalf("ReconcileFreshness: %v", err)
	}

	if report.FilesChecked != 4 || report.FilesStale != 2 || report.FilesUnverified != 0 {
		t.Fatalf("report = checked %d / stale %d / unverified %d; want 4 / 2 / 0",
			report.FilesChecked, report.FilesStale, report.FilesUnverified)
	}
	if report.StaleDeclarations != 3 {
		t.Errorf("stale declarations = %d, want 3 (2 role + 1 group)", report.StaleDeclarations)
	}
	reasons := map[string]string{}
	for _, file := range report.Files {
		reasons[file.FileKey] = file.Reason
	}
	if reasons["role-app"] != DeclarationStaleContentChanged {
		t.Errorf("role-app reason = %q, want %q", reasons["role-app"], DeclarationStaleContentChanged)
	}
	if reasons["group-devs"] != DeclarationStaleFileMissing {
		t.Errorf("group-devs reason = %q, want %q", reasons["group-devs"], DeclarationStaleFileMissing)
	}
	if reasons["policy-logs"] != "" || reasons["user-bot"] != "" {
		t.Errorf("fresh files must carry no reason, got %v", reasons)
	}

	if got := fake.execCount("SET stale_at = NOW()"); got != 2 {
		t.Errorf("stale marks = %d, want 2", got)
	}
	if got := fake.execCount("SET stale_at = NULL, stale_reason = NULL"); got != 1 {
		t.Errorf("stale clears = %d, want 1", got)
	}
	// 已经标过过期的文件再核对一次不该重复写：刷新时间戳会让「过期多久」
	// 失真。
	for _, record := range fake.records {
		if !strings.Contains(record.query, "SET stale_at = NOW()") {
			continue
		}
		if got, _ := record.args[1].(string); got != "role-app" && got != "group-devs" {
			t.Errorf("unexpected stale mark for %v", record.args[1])
		}
	}
	for _, asked := range repo.asked {
		if !strings.HasPrefix(asked, "iam/account-123456789012/") || !strings.HasSuffix(asked, ".tf") {
			t.Errorf("checked unexpected path %q", asked)
		}
	}
}

// TestReconcileFreshnessKeepsStateWhenRepoUnreadable 读不到远端时保持原状：
// 一次网络抖动绝不能把整账号声明判成过期——那会静默关掉漂移检测。
func TestReconcileFreshnessKeepsStateWhenRepoUnreadable(t *testing.T) {
	fake := &publishFakeDB{}
	newFreshnessFakeDB(fake)
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	repo := &declarationFakeRepo{err: errors.New("github contents API unavailable")}
	report, err := declarations.ReconcileFreshness(
		context.Background(), 7, "iam/account-123456789012", repo)
	if err != nil {
		t.Fatalf("ReconcileFreshness: %v", err)
	}
	if report.FilesStale != 0 || report.StaleDeclarations != 0 {
		t.Fatalf("unreadable repo must not mark anything stale: %+v", report)
	}
	if report.FilesUnverified != 4 {
		t.Errorf("unverified files = %d, want 4", report.FilesUnverified)
	}
	if len(fake.records) != 0 {
		t.Fatalf("unreadable repo must not write, got %d statements", len(fake.records))
	}
	for _, file := range report.Files {
		if file.Verified {
			t.Errorf("%s must be reported unverified", file.FileKey)
		}
	}
}

// TestReconcileFreshnessWithoutDeclarations 没有声明就没有基准可比：不查
// 仓库、不写库，返回空报告（而不是报错——还没发布过基线的账号是正常的）。
func TestReconcileFreshnessWithoutDeclarations(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	repo := &declarationFakeRepo{}
	report, err := declarations.ReconcileFreshness(
		context.Background(), 7, "iam/account-123456789012", repo)
	if err != nil {
		t.Fatalf("ReconcileFreshness: %v", err)
	}
	if report.FilesChecked != 0 || len(report.Files) != 0 {
		t.Fatalf("empty account report = %+v, want no files", report)
	}
	if len(repo.asked) != 0 || len(fake.records) != 0 {
		t.Fatalf("empty account must not touch repo or table: asked=%v writes=%d",
			repo.asked, len(fake.records))
	}
}

// TestStaleDeclarationFiles 判定侧按文件跳过比对：过期声明不能当基准。
func TestStaleDeclarationFiles(t *testing.T) {
	declarations := []BaselineDeclaration{
		{FileKey: "role-app", ResourceKey: "role:app"},
		{FileKey: "role-app-server", ResourceKey: "role:app-server", StaleReason: "CONTENT_CHANGED"},
	}
	if got := StaleDeclarationFiles(nil); got != nil {
		t.Errorf("no declarations must yield nil, got %v", got)
	}
	now := time.Now()
	declarations[1].StaleAt = &now
	files := StaleDeclarationFiles(declarations)
	if len(files) != 1 || !files["role-app-server"] {
		t.Errorf("stale files = %v, want only role-app-server", files)
	}
	if files["role-app"] {
		t.Error("fresh file must not be listed as stale")
	}
}
