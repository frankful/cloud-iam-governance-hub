package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// publishFakeDB 在 inventoryFakeDB 的「查询匹配」之上补了 ExecContext 记录
// 与 once 语义（同一响应只被消费一次），覆盖发布服务「INSERT/UPDATE ...
// RETURNING 走查询、无返回更新走执行」的两条路径。
type publishFakeDB struct {
	queries []inventoryFakeResponse
	execs   []publishFakeExec

	mu      sync.Mutex
	onces   []*onceResponse
	records []publishFakeExec
	// statements 记录 QueryContext 收到的语句：作废/恢复这类「先查出受影响
	// 行再逐行改」的逻辑，断言对象是查询条件本身。
	statements []publishFakeExec
}

type onceResponse struct {
	inventoryFakeResponse
	consumed bool
}

type publishFakeExec struct {
	query string
	args  []driver.Value
}

// addOnce 注册一条只消费一次的查询响应（按注册顺序匹配 UPDATE ... RETURNING
// 这类「每次调用应返回不同行」的场景）。
func (db *publishFakeDB) addOnce(match string, columns []string, rows [][]driver.Value) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.onces = append(db.onces, &onceResponse{
		inventoryFakeResponse: inventoryFakeResponse{match: match, columns: columns, rows: rows},
	})
}

func (db *publishFakeDB) lookup(query string) inventoryFakeResponse {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, once := range db.onces {
		if !once.consumed && strings.Contains(query, once.match) {
			once.consumed = true
			return once.inventoryFakeResponse
		}
	}
	for _, response := range db.queries {
		if strings.Contains(query, response.match) {
			return response
		}
	}
	return inventoryFakeResponse{}
}

func (db *publishFakeDB) Connect(context.Context) (driver.Conn, error) {
	return &publishFakeConn{state: db}, nil
}
func (db *publishFakeDB) Driver() driver.Driver { return db }
func (db *publishFakeDB) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected direct driver open")
}

func (db *publishFakeDB) record(exec publishFakeExec) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.records = append(db.records, exec)
}

func (db *publishFakeDB) recordQuery(exec publishFakeExec) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.statements = append(db.statements, exec)
}

// queryCount 数 QueryContext 里匹配的语句条数。
func (db *publishFakeDB) queryCount(match string) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	count := 0
	for _, statement := range db.statements {
		if strings.Contains(statement.query, match) {
			count++
		}
	}
	return count
}

// recordedQuery 返回第一条匹配的查询参数，供断言查询条件。
func (db *publishFakeDB) recordedQuery(match string) []driver.Value {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, statement := range db.statements {
		if strings.Contains(statement.query, match) {
			return statement.args
		}
	}
	return nil
}

func (db *publishFakeDB) execCount(match string) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	count := 0
	for _, record := range db.records {
		if strings.Contains(record.query, match) {
			count++
		}
	}
	return count
}

type publishFakeConn struct {
	state *publishFakeDB
}

func (*publishFakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not expected")
}

// CheckNamedValue 声明驱动自己接收未转换的参数：真实驱动（pgx）同样实现
// 这个接口，所以 []string 这类数组参数会原样传给它编码成 text[]。不实现
// 的话 database/sql 会在客户端做默认转换，遇到 []string 直接报错——那是
// 假驱动的限制，不是生产行为。
func (*publishFakeConn) CheckNamedValue(*driver.NamedValue) error { return nil }
func (*publishFakeConn) Close() error { return nil }
func (*publishFakeConn) Begin() (driver.Tx, error) {
	return inventoryFakeTx{}, nil
}

func (connection *publishFakeConn) QueryContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	if strings.Contains(query, "$") && len(args) == 0 {
		return nil, fmt.Errorf("query has placeholders but 0 args passed: %.80s", query)
	}
	values := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	connection.state.recordQuery(publishFakeExec{query: query, args: values})
	response := connection.state.lookup(query)
	return &inventoryFakeRows{response: response}, nil
}

func (connection *publishFakeConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	if strings.Contains(query, "$") && len(args) == 0 {
		return nil, fmt.Errorf("exec has placeholders but 0 args passed: %.80s", query)
	}
	values := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	connection.state.record(publishFakeExec{query: query, args: values})
	return driver.RowsAffected(1), nil
}

// publishFakePublisher 记录 PublishBranch 收到的请求；可注入失败。
type publishFakePublisher struct {
	mu      sync.Mutex
	request []BranchPublishRequest
	result  *TicketPublishResult
	err     error
}

func (fake *publishFakePublisher) PublishBranch(
	_ context.Context, req BranchPublishRequest,
) (*TicketPublishResult, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.request = append(fake.request, req)
	if fake.err != nil {
		return nil, fake.err
	}
	if fake.result == nil {
		fake.result = &TicketPublishResult{
			URL:      "https://github.com/acme/infra/pull/77",
			Provider: "github", Project: "acme/infra", RemoteRequestNumber: "77",
		}
	}
	return fake.result, nil
}

func (fake *publishFakePublisher) last() BranchPublishRequest {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.request[len(fake.request)-1]
}

// publishFakeBuilder 返回预置的 bundle 报告。
type publishFakeBuilder struct {
	report *BaselineBundleReport
	err    error
	built  []string
}

func (fake *publishFakeBuilder) Build(_ context.Context, accountRef string) (*BaselineBundleReport, error) {
	fake.built = append(fake.built, accountRef)
	if fake.err != nil {
		return nil, fake.err
	}
	return fake.report, nil
}

func baselineTestHash() string {
	sum := make([]byte, 32)
	for index := range sum {
		sum[index] = byte(index)
	}
	return hex.EncodeToString(sum)
}

func baselineTestReport() *BaselineBundleReport {
	exists := false
	return &BaselineBundleReport{
		AccountDBID:   7,
		AWSAccountID:  "111122223333",
		RepoDirectory: "iam/account-111122223333",
		Files: []BaselineBundleFile{
			{Key: "role-demo", FileName: "role-demo.tf", Content: "resource \"aws_iam_role\" \"demo\" {}",
				ExistsInRepo: &exists},
			{Key: "attachment-role-demo-policy", FileName: "attachment-role-demo-policy.tf",
				Content: "resource \"aws_iam_role_policy_attachment\" {}"},
		},
		Declarations: []BaselineDeclaration{
			{ResourceKey: "role:demo", FileKey: "role-demo", Kind: "role", Name: "demo",
				Attributes: []byte(`{"path":"/"}`)},
			{ResourceKey: "attachment:role:demo:arn:aws:iam::aws:policy/PowerUserAccess",
				FileKey: "attachment-role-demo-policy", Kind: "attachment", Name: "PowerUserAccess",
				Attributes: []byte(`{"policy_arn":"arn:aws:iam::aws:policy/PowerUserAccess"}`)},
		},
		Counts:        map[string]int{"files": 2, "resources": 1},
		ContentSHA256: baselineTestHash(),
	}
}

const baselinePublicationColumns = "p.id, p.account_id, p.aws_account_id, p.sync_run_id"

var _ = baselinePublicationColumns // 台账查询列序备忘（scanBaselinePublication 顺序对齐）

func baselinePublicationRow(id int64, status string) []driver.Value {
	return []driver.Value{
		id, int64(7), "111122223333", int64(41), status,
		"baseline/111122223333/41", "https://github.com/acme/infra/pull/1", "1",
		"iam/account-111122223333", int64(2), "",
		false, "", "tester",
		time.Unix(0, 0),
		// applied_at / applied_commit_sha / applied_ci_url（0035）：合并与
		// 已应用是两件事，测试行默认「未应用」。
		nil, "", "",
		time.Unix(0, 0), time.Unix(0, 0),
		[]byte("{}"), []byte("[]"), []byte("[]"),
	}
}

func newPublishTestDB() *publishFakeDB {
	fake := &publishFakeDB{}
	// 账号解析（Create 与 job 服务同一条 SQL）。
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "WHERE account_id = $1 OR id::text = $1",
		columns: []string{"id", "account_id"},
		rows:    [][]driver.Value{{int64(7), "111122223333"}},
	})
	// 最新成功快照 run（幂等键的另一半）。
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "SELECT id FROM aws_sync_run",
		columns: []string{"id"},
		rows:    [][]driver.Value{{int64(41)}},
	})
	return fake
}

// TestBaselinePublishCreateHappyPath 新账号发布：落 PUBLISHING 台账，分支名
// = baseline/<AWS账号>/<run>。
func TestBaselinePublishCreateHappyPath(t *testing.T) {
	fake := newPublishTestDB()
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match: "p.account_id = $1 AND p.sync_run_id = $2",
		rows:  nil, // 无既有台账
	})
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "INSERT INTO iam_baseline_publication",
		columns: []string{"id", "created_at", "updated_at"},
		rows:    [][]driver.Value{{int64(9), time.Unix(0, 0), time.Unix(0, 0)}},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{}, &publishFakePublisher{}, false, nil)

	publication, alreadyPublished, err := service.Create(context.Background(), "111122223333", "tester")
	if err != nil || alreadyPublished {
		t.Fatalf("Create: pub=%v already=%v err=%v", publication, alreadyPublished, err)
	}
	if publication.Branch != "baseline/111122223333/41" {
		t.Fatalf("branch = %q, want baseline/111122223333/41", publication.Branch)
	}
	if publication.SyncRunID != 41 {
		t.Fatalf("sync_run_id = %d, want 41", publication.SyncRunID)
	}
}

// TestBaselinePublishCreateIdempotent D4：同账号同 run 已 PUBLISHED 时不重发，
// 直接返回既有记录。
func TestBaselinePublishCreateIdempotent(t *testing.T) {
	fake := newPublishTestDB()
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match: "p.account_id = $1 AND p.sync_run_id = $2",
		rows:  [][]driver.Value{baselinePublicationRow(9, BaselinePublicationStatusPublished)},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	publisher := &publishFakePublisher{}
	service := NewBaselinePublishService(database, &publishFakeBuilder{}, publisher, false, nil)

	publication, alreadyPublished, err := service.Create(context.Background(), "111122223333", "tester")
	if err != nil || !alreadyPublished {
		t.Fatalf("Create: already=%v err=%v", alreadyPublished, err)
	}
	if publication.ID != 9 || publication.Status != BaselinePublicationStatusPublished {
		t.Fatalf("publication = %#v", publication)
	}
}

// TestBaselinePublishCreateRepublishArchivesSuperseded MERGED 行重发时，
// 旧 PR 记录先归档进 superseded，再原地重置为 PUBLISHING（审计不丢）。
func TestBaselinePublishCreateRepublishArchivesSuperseded(t *testing.T) {
	fake := newPublishTestDB()
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match: "p.account_id = $1 AND p.sync_run_id = $2",
		rows:  [][]driver.Value{baselinePublicationRow(9, BaselinePublicationStatusMerged)},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{}, &publishFakePublisher{}, false, nil)

	publication, alreadyPublished, err := service.Create(context.Background(), "111122223333", "tester")
	if err != nil || alreadyPublished {
		t.Fatalf("Create: already=%v err=%v", alreadyPublished, err)
	}
	if publication.Status != BaselinePublicationStatusPublishing {
		t.Fatalf("status = %s, want PUBLISHING", publication.Status)
	}

	var archived string
	found := false
	for _, exec := range fake.records {
		if strings.Contains(exec.query, "superseded = superseded || $5") {
			archived = fmt.Sprint(exec.args[4])
			found = true
		}
	}
	if !found {
		t.Fatalf("republish UPDATE did not archive superseded records; execs=%d", len(fake.records))
	}
	if !strings.Contains(archived, `"remote_request_number":"1"`) ||
		!strings.Contains(archived, `"status":"MERGED"`) {
		t.Fatalf("superseded archive = %s, want the old MERGED PR record", archived)
	}
}

// TestBaselinePublishCreateRequiresSyncRun 没有成功同步就没有幂等键，拒绝发布。
func TestBaselinePublishCreateRequiresSyncRun(t *testing.T) {
	fake := &publishFakeDB{}
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "WHERE account_id = $1 OR id::text = $1",
		columns: []string{"id", "account_id"},
		rows:    [][]driver.Value{{int64(7), "111122223333"}},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{}, &publishFakePublisher{}, false, nil)

	_, _, err := service.Create(context.Background(), "111122223333", "tester")
	if !errors.Is(err, ErrBaselineNoSyncRun) {
		t.Fatalf("err = %v, want ErrBaselineNoSyncRun", err)
	}
}

// TestBaselinePublishRunHappyPath 完整发布回路：构建 → 无冲突 → 提交分支 →
// 台账记 PUBLISHED（PR、文件数、哈希）。
func TestBaselinePublishRunHappyPath(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	builder := &publishFakeBuilder{report: baselineTestReport()}
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, builder, publisher, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(publisher.request) != 1 {
		t.Fatalf("PublishBranch calls = %d, want 1", len(publisher.request))
	}
	req := publisher.last()
	if req.Branch != "baseline/111122223333/41" {
		t.Fatalf("branch = %q", req.Branch)
	}
	if len(req.Files) != 2 || req.Files[0].FileName != "iam/account-111122223333/role-demo.tf" {
		t.Fatalf("files = %#v", req.Files)
	}
	if !strings.Contains(req.Body, "inventory run 41") {
		t.Fatalf("PR body should pin the idempotency key: %s", req.Body)
	}
	// 台账完成更新：哈希按 32 字节二进制落库。
	if fake.execCount("SET status = $2, pull_request_url") != 1 {
		t.Fatalf("publication completion update not executed")
	}
}

// TestBaselinePublishRunRefusesExistingFiles 无风险门禁：目标文件已在 main 上
// 存在、内容不同、且不在基线既往发布清单里（工单/手工归属）时拒绝发布，
// 绝不覆盖别人的文件。
func TestBaselinePublishRunRefusesExistingFiles(t *testing.T) {
	report := baselineTestReport()
	exists := true
	report.Files[0].ExistsInRepo = &exists

	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report}, publisher, false, nil)

	err := service.Run(context.Background(), 9)
	if !errors.Is(err, ErrBaselineFilesExistInRepo) {
		t.Fatalf("err = %v, want ErrBaselineFilesExistInRepo", err)
	}
	if len(publisher.request) != 0 {
		t.Fatalf("publisher must not be called when conflicts exist")
	}
	if fake.execCount("SET status = $2, error = $3") != 1 {
		t.Fatalf("failure must be recorded on the ledger")
	}
}

// TestBaselinePublishBatchAggregate 聚合模式：多账号文件进同一分支、一个 PR，
// 每个账号台账共享分支与 PR。
func TestBaselinePublishBatchAggregate(t *testing.T) {
	report := baselineTestReport()
	fake := &publishFakeDB{}
	fake.addOnce("SET branch = $2, updated_at = NOW()",
		[]string{"account_id", "aws_account_id", "sync_run_id"},
		[][]driver.Value{{int64(7), "111122223333", int64(41)}})
	builder := &publishFakeBuilder{report: report}
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, builder, publisher, false, nil)

	if err := service.RunBatch(context.Background(), []int64{9}, true); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	req := publisher.last()
	if !strings.HasPrefix(req.Branch, "baseline/batch/") {
		t.Fatalf("aggregate branch = %q, want baseline/batch/*", req.Branch)
	}
	if len(req.Files) != 2 {
		t.Fatalf("aggregate files = %d, want 2", len(req.Files))
	}
	if fake.execCount("SET status = $2, pull_request_url") != 1 {
		t.Fatalf("ledger completion not recorded")
	}
	if !strings.Contains(req.Body, "Accounts: 111122223333") {
		t.Fatalf("PR body should list accounts: %s", req.Body)
	}
}

// TestBaselinePublishSweepStaleStuckPUBLISHING SweepStale 把中断发布收尾成 FAILED。
func TestBaselinePublishSweepStaleStuckPUBLISHING(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{}, &publishFakePublisher{}, false, nil)

	count, err := service.SweepStale(context.Background())
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if count != 1 {
		t.Fatalf("swept = %d, want 1 (fake ExecContext reports 1 row)", count)
	}
	if fake.execCount("WHERE status = $3 AND created_at < NOW()") != 1 {
		t.Fatalf("sweep statement not executed")
	}
}

// manifestResponse 造一条既往发布的归属清单响应（归属感知门禁的数据源）。
func manifestResponse(manifest string) inventoryFakeResponse {
	return inventoryFakeResponse{
		match:   "SELECT files FROM iam_baseline_publication",
		columns: []string{"files"},
		rows:    [][]driver.Value{{[]byte(manifest)}},
	}
}

// TestBaselinePublishRunSkipsUnchangedFiles 门禁升级：目标文件在 main 上存在
// 但内容与 bundle 完全一致（blob SHA 相同）时跳过提交，不算冲突。
func TestBaselinePublishRunSkipsUnchangedFiles(t *testing.T) {
	report := baselineTestReport()
	exists := true
	sameContent := report.Files[0].Content
	report.Files[0].ExistsInRepo = &exists
	report.Files[0].RepoBlobSHA = gitBlobSHA(sameContent)

	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report}, publisher, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(publisher.request) != 1 {
		t.Fatalf("PublishBranch calls = %d, want 1", len(publisher.request))
	}
	// 未变化的文件不再出现在 PR 提交集合里。
	req := publisher.last()
	if len(req.Files) != 1 || req.Files[0].FileName != "iam/account-111122223333/attachment-role-demo-policy.tf" {
		t.Fatalf("publish set should exclude the unchanged file, got %#v", req.Files)
	}
}

// TestBaselinePublishRunUpdatesBaselineOwnedFiles 门禁升级：内容不同但文件在
// 既往发布清单里（PR 合并后基线拥有）时允许更新。
func TestBaselinePublishRunUpdatesBaselineOwnedFiles(t *testing.T) {
	report := baselineTestReport()
	exists := true
	report.Files[0].ExistsInRepo = &exists
	report.Files[0].RepoBlobSHA = "stale-blob-sha"

	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	fake.queries = append(fake.queries, manifestResponse(
		`[{"file":"role-demo.tf","sha256":"abc"}]`))
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report}, publisher, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	req := publisher.last()
	if len(req.Files) != 2 {
		t.Fatalf("owned file must be republished, got %#v", req.Files)
	}
}

// TestBaselinePublishRunAllUnchangedSkipsPR 门禁升级：全部文件与 main 一致时
// 不开 PR（GitHub 拒绝空 diff），直接记 PUBLISHED 并保留归属清单。
func TestBaselinePublishRunAllUnchangedSkipsPR(t *testing.T) {
	report := baselineTestReport()
	exists := true
	for i := range report.Files {
		report.Files[i].ExistsInRepo = &exists
		report.Files[i].RepoBlobSHA = gitBlobSHA(report.Files[i].Content)
	}

	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report}, publisher, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(publisher.request) != 0 {
		t.Fatalf("no PR should be opened when everything is unchanged")
	}
	if fake.execCount("SET status = $2, repo_directory") != 1 {
		t.Fatalf("unchanged publication must be recorded as PUBLISHED")
	}
}

// TestBaselinePublishPreviewCounts 预览必须与真实发布同一套判定（C10）：它
// 的价值全在「点确认前说真话」，自己抄一遍分类逻辑迟早与发布走偏。
func TestBaselinePublishPreviewCounts(t *testing.T) {
	report := baselineTestReport()
	exists := true
	// 第一个文件在 main 上且内容一致 -> 无变化；第二个不在 -> 待发布。
	report.Files[0].ExistsInRepo = &exists
	report.Files[0].RepoBlobSHA = gitBlobSHA(report.Files[0].Content)
	absent := false
	report.Files[1].ExistsInRepo = &absent

	fake := &publishFakeDB{}
	fake.addOnce("SELECT id, account_id FROM aws_account",
		[]string{"id", "account_id"},
		[][]driver.Value{{int64(7), "111122223333"}})
	fake.addOnce("SELECT id FROM aws_sync_run",
		[]string{"id"}, [][]driver.Value{{int64(41)}})
	// 没有既往发布清单：owned 为空，不影响本例（无冲突文件）。
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "SELECT files FROM iam_baseline_publication",
		columns: []string{"files"},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report},
		&publishFakePublisher{}, false, nil)

	preview, err := service.Preview(context.Background(), "111122223333")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if preview.Files != 2 || preview.Unchanged != 1 || preview.ToPublish != 1 {
		t.Fatalf("preview = files %d / unchanged %d / to publish %d, want 2/1/1",
			preview.Files, preview.Unchanged, preview.ToPublish)
	}
	if len(preview.Conflicts) != 0 {
		t.Fatalf("conflicts = %v, want none", preview.Conflicts)
	}
	if preview.SyncRunID != 41 || preview.RepoDirectory != report.RepoDirectory {
		t.Fatalf("preview lost its snapshot context: %+v", preview)
	}
	// 只读：预览绝不能落台账——落一条 PUBLISHING 就等于「有人在发布」。
	if fake.execCount("INSERT INTO iam_baseline_publication") != 0 {
		t.Errorf("preview must not write the publication ledger")
	}
}

// TestBaselinePublishPreviewReportsConflicts 内容不同且不在归属清单里的文件
// 必须在预览里就报出来：等到发布才失败，用户白等一轮。
func TestBaselinePublishPreviewReportsConflicts(t *testing.T) {
	report := baselineTestReport()
	exists := true
	report.Files[0].ExistsInRepo = &exists
	report.Files[0].RepoBlobSHA = "blob-owned-by-someone-else"
	absent := false
	report.Files[1].ExistsInRepo = &absent

	fake := &publishFakeDB{}
	fake.addOnce("SELECT id, account_id FROM aws_account",
		[]string{"id", "account_id"},
		[][]driver.Value{{int64(7), "111122223333"}})
	fake.addOnce("SELECT id FROM aws_sync_run",
		[]string{"id"}, [][]driver.Value{{int64(41)}})
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "SELECT files FROM iam_baseline_publication",
		columns: []string{"files"},
	})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report},
		&publishFakePublisher{}, false, nil)

	preview, err := service.Preview(context.Background(), "111122223333")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(preview.Conflicts) != 1 || preview.Conflicts[0] != report.Files[0].FileName {
		t.Fatalf("conflicts = %v, want [%s]", preview.Conflicts, report.Files[0].FileName)
	}
	if preview.ToPublish != 1 {
		t.Fatalf("to publish = %d, want 1 (the absent file)", preview.ToPublish)
	}
}

// TestBaselinePublishPreviewRequiresSyncRun 没有成功同步就没有快照可钉：预览
// 与发布必须给出同一个原因（409），而不是造一份空差异让人以为「没变化」。
func TestBaselinePublishPreviewRequiresSyncRun(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("SELECT id, account_id FROM aws_account",
		[]string{"id", "account_id"},
		[][]driver.Value{{int64(7), "111122223333"}})
	fake.addOnce("SELECT id FROM aws_sync_run", []string{"id"}, [][]driver.Value{})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: baselineTestReport()},
		&publishFakePublisher{}, false, nil)

	_, err := service.Preview(context.Background(), "111122223333")
	if !errors.Is(err, ErrBaselineNoSyncRun) {
		t.Fatalf("Preview error = %v, want ErrBaselineNoSyncRun", err)
	}
}

// TestBaselinePublishRunUnchangedRecordsDeclarations 无变化发布同样要落声明快照
// （台账 C9）：0027 归属台账记了 files 只说明「文件在 main 上」，漂移判定看的是
// 声明数——0 声明会让账号被当成「未纳管」整账号跳过检测，而页面上仍显示
// 已纳管，两边都看不出问题。
func TestBaselinePublishRunUnchangedRecordsDeclarations(t *testing.T) {
	report := baselineTestReport()
	exists := true
	for i := range report.Files {
		report.Files[i].ExistsInRepo = &exists
		report.Files[i].RepoBlobSHA = gitBlobSHA(report.Files[i].Content)
	}

	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})

	database := sql.OpenDB(fake)
	defer database.Close()
	// 声明服务由构造函数按同一个 db 装配，这里不需要手工注入。
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: report},
		&publishFakePublisher{}, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 先作废旧的、再插入新的：同一份内容重发也必须换掉上一版声明（属性可能
	// 在两次之间被别人改过，而 main 上的文件正是这次的版本）。
	if fake.execCount("SET superseded_at = NOW()") != 1 {
		t.Fatalf("unchanged publication must supersede previous declarations")
	}
	if got := fake.execCount("INSERT INTO iam_baseline_declaration"); got != len(report.Declarations) {
		t.Fatalf("declaration inserts = %d, want %d", got, len(report.Declarations))
	}
	for _, record := range fake.records {
		if !strings.Contains(record.query, "INSERT INTO iam_baseline_declaration") {
			continue
		}
		if len(record.args) != 11 {
			t.Fatalf("insert args = %v, want 11 columns", record.args)
		}
		// 声明必须挂在本次 publication 与它领取到的 sync run 上：伪造或留空
		// 会让「这条声明是哪次发布写的」事后无法追溯。
		publication, ok := record.args[2].(*int64)
		if !ok || publication == nil || *publication != 9 {
			t.Errorf("declaration publication_id = %v, want 9", record.args[2])
		}
		if run, ok := record.args[4].(int64); !ok || run != 41 {
			t.Errorf("declaration sync_run_id = %v, want 41", record.args[4])
		}
	}
}

// TestBaselinePublishRunFullyDeferred 全部文件被在途工单占用（phase4 §4.1）：
// 不开 PR（空 diff 会被 GitHub 拒绝），台账记 PUBLISHED、file_count=0，
// deferred 原因进 issues——「为什么没发」必须可见，而不是静默。
func TestBaselinePublishRunFullyDeferred(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	// 预约冲突查询对每个 key 都返回同一个持有者：两张文件全部让路。
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "NOT (channel = $3 AND ref = $4)",
		columns: []string{"channel", "ref"},
		rows:    [][]driver.Value{{"ticket", "IAM-9999"}},
	})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: baselineTestReport()}, publisher, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(publisher.request) != 0 {
		t.Fatalf("PublishBranch calls = %d, want 0 (all files deferred)", len(publisher.request))
	}
	var deferredIssue string
	for _, exec := range fake.records {
		if !strings.Contains(exec.query, "issues = $6::jsonb") {
			continue
		}
		if len(exec.args) > 5 {
			deferredIssue = fmt.Sprint(exec.args[5])
		}
	}
	if !strings.Contains(deferredIssue, `"kind":"deferred"`) ||
		!strings.Contains(deferredIssue, "IAM-9999") {
		t.Fatalf("issues must record the deferred holder: %s", deferredIssue)
	}
}

// TestBaselinePublishRunPartiallyDeferred 让路是文件级的：两个文件只有
// 一个被占用时，另一个照发，PR 描述列出 deferred 清单。
func TestBaselinePublishRunPartiallyDeferred(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	// publishFakeDB 的冲突查询按子串匹配、无法按参数区分 key，这里让
	// 「role-demo.tf 归属检查」命中冲突行、另一文件不命中做不到；退而
	// 求其次用预约服务的参数感知 fake 覆盖部分让路（见
	// TestReserveForPublicationDefersConflicts），本测试锁定「部分让路时
	// 其余文件照发」的服务层行为——通过 first-match 顺序实现：冲突响应
	// 注册在前面，但 lookup 顺序遍历，用 once 语义只消费一次。
	fake.addOnce("NOT (channel = $3 AND ref = $4)",
		[]string{"channel", "ref"},
		[][]driver.Value{{"ticket", "IAM-9999"}})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database, &publishFakeBuilder{report: baselineTestReport()}, publisher, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// once 语义：第一个 key 冲突、第二个 key 无冲突 → 仍有 1 个文件提交。
	if len(publisher.request) != 1 {
		t.Fatalf("PublishBranch calls = %d, want 1", len(publisher.request))
	}
	if got := len(publisher.last().Files); got != 1 {
		t.Fatalf("published files = %d, want 1", got)
	}
	if !strings.Contains(publisher.last().Body, "IAM-9999") {
		t.Fatalf("PR body must list the deferred holder:/n%s", publisher.last().Body)
	}
}

// TestBaselinePublishBatchPartiallyDeferred 聚合发布也要走文件级预约：
// 被在途变更占用的文件从批量 PR 中剔除，占用者在 PR 描述里带账号前缀
// 列出，其余文件照发。
func TestBaselinePublishBatchPartiallyDeferred(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("SET branch = $2, updated_at = NOW()",
		[]string{"account_id", "aws_account_id", "sync_run_id"},
		[][]driver.Value{{int64(7), "111122223333", int64(41)}})
	// once 语义：只有第一个文件的冲突查询命中，第二个文件照发。
	fake.addOnce("NOT (channel = $3 AND ref = $4)",
		[]string{"channel", "ref"},
		[][]driver.Value{{"ticket", "IAM-9999"}})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(
		database, &publishFakeBuilder{report: baselineTestReport()}, publisher, false, nil)

	if err := service.RunBatch(context.Background(), []int64{9}, true); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(publisher.request) != 1 {
		t.Fatalf("PublishBranch calls = %d, want 1", len(publisher.request))
	}
	req := publisher.last()
	if len(req.Files) != 1 {
		t.Fatalf("batch files = %d, want 1 (one deferred)", len(req.Files))
	}
	if !strings.Contains(req.Body, "Deferred files") ||
		!strings.Contains(req.Body, "111122223333/role-demo") {
		t.Fatalf("batch PR body must list deferred files with account prefix:/n%s", req.Body)
	}
}

// TestBaselinePublishBatchFullyDeferred 聚合模式下某账号全部让路：该账号
// 单独记 PUBLISHED + file_count=0，不进批量 PR；「本轮无可发布内容」不是
// 错误，RunBatch 不应把它报成失败。
func TestBaselinePublishBatchFullyDeferred(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("SET branch = $2, updated_at = NOW()",
		[]string{"account_id", "aws_account_id", "sync_run_id"},
		[][]driver.Value{{int64(7), "111122223333", int64(41)}})
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "NOT (channel = $3 AND ref = $4)",
		columns: []string{"channel", "ref"},
		rows:    [][]driver.Value{{"ticket", "IAM-9999"}},
	})
	publisher := &publishFakePublisher{}

	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(
		database, &publishFakeBuilder{report: baselineTestReport()}, publisher, false, nil)

	if err := service.RunBatch(context.Background(), []int64{9}, true); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(publisher.request) != 0 {
		t.Fatalf("PublishBranch calls = %d, want 0 (nothing publishable)", len(publisher.request))
	}
	if fake.execCount("SET status = $2, repo_directory = $3, file_count = 0") != 1 {
		t.Fatalf("fully deferred account must be recorded as PUBLISHED with file_count=0")
	}
}

// TestBaselinePublishRunRecordsDeclarations 发布成功后声明快照必须落库：
// 漂移判定的基准就是这份声明，漏记等于让检测停在上一版。让路的文件
// 不进声明（它们没写进仓库）。
func TestBaselinePublishRunRecordsDeclarations(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("RETURNING account_id, aws_account_id, sync_run_id, branch",
		[]string{"account_id", "aws_account_id", "sync_run_id", "branch"},
		[][]driver.Value{{int64(7), "111122223333", int64(41), "baseline/111122223333/41"}})
	database := sql.OpenDB(fake)
	defer database.Close()
	service := NewBaselinePublishService(database,
		&publishFakeBuilder{report: baselineTestReport()}, &publishFakePublisher{}, false, nil)

	if err := service.Run(context.Background(), 9); err != nil {
		t.Fatalf("Run: %v", err)
	}

	inserts := 0
	resourceKeys := map[string]bool{}
	for _, record := range fake.records {
		if !strings.Contains(record.query, "INSERT INTO iam_baseline_declaration") {
			continue
		}
		inserts++
		if key, ok := record.args[5].(string); ok {
			resourceKeys[key] = true
		}
	}
	if inserts != 2 {
		t.Fatalf("declaration inserts = %d, want 2", inserts)
	}
	if !resourceKeys["role:demo"] {
		t.Errorf("declared resources = %v, want role:demo", resourceKeys)
	}
	if fake.execCount("SET superseded_at = NOW()") != 1 {
		t.Errorf("previous declarations must be superseded before inserting")
	}
}

// 台账钉住的 sync run 与 bundle 实际构建所用快照必须一致：Create → Run 之间
// 又跑了一次同步时，声明/审计键会指向旧快照而内容来自新快照（审计错位）。
func TestEnsureSnapshotPinned(t *testing.T) {
	t.Run("matching run passes", func(t *testing.T) {
		if err := ensureSnapshotPinned(42, &BaselineBundleReport{LatestSyncRunID: 42}); err != nil {
			t.Fatalf("matching run must pass, got %v", err)
		}
	})

	t.Run("moved snapshot fails fast", func(t *testing.T) {
		err := ensureSnapshotPinned(42, &BaselineBundleReport{LatestSyncRunID: 43})
		if !errors.Is(err, ErrBaselineSnapshotMoved) {
			t.Fatalf("expected ErrBaselineSnapshotMoved, got %v", err)
		}
		if !strings.Contains(err.Error(), "pinned run 42") || !strings.Contains(err.Error(), "build used 43") {
			t.Errorf("error must name both runs: %v", err)
		}
	})

	t.Run("unknown run id does not block", func(t *testing.T) {
		if err := ensureSnapshotPinned(42, &BaselineBundleReport{}); err != nil {
			t.Errorf("zero LatestSyncRunID must not block legacy paths, got %v", err)
		}
		if err := ensureSnapshotPinned(0, &BaselineBundleReport{LatestSyncRunID: 43}); err != nil {
			t.Errorf("zero pinned run must not block, got %v", err)
		}
		if err := ensureSnapshotPinned(42, nil); err != nil {
			t.Errorf("nil report must not block, got %v", err)
		}
	})
}
