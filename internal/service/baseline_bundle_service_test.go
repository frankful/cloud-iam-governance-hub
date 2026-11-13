package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

// bundleFakeDB 是 baseline bundle 测试专用的内存 SQL fake：按「子串 → 结果集」
// 顺序匹配（先注册的先赢），未命中返回空结果。候选集 Build + bundle 补充加载
// 一共十几个查询，用这个 fake 可以整链路跑通 Build 而不需要真实 Postgres。
type bundleFakeDB struct {
	mu        sync.Mutex
	responses []bundleFakeResponse
	queries   []string
}

type bundleFakeResponse struct {
	match   string
	columns []string
	rows    [][]driver.Value
}

func (db *bundleFakeDB) add(match string, columns []string, rows [][]driver.Value) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.responses = append(db.responses, bundleFakeResponse{match, columns, rows})
}

func (db *bundleFakeDB) lookup(query string) bundleFakeResponse {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.queries = append(db.queries, query)
	for _, response := range db.responses {
		if strings.Contains(query, response.match) {
			return response
		}
	}
	return bundleFakeResponse{}
}

// recordedQueries returns the SQL text of every query the service issued.
func (db *bundleFakeDB) recordedQueries() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	return append([]string(nil), db.queries...)
}

func (db *bundleFakeDB) Connect(context.Context) (driver.Conn, error) {
	return &bundleFakeConn{state: db}, nil
}

func (db *bundleFakeDB) Driver() driver.Driver { return db }

func (db *bundleFakeDB) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected direct driver open")
}

func (db *bundleFakeDB) ExecContext(
	_ context.Context, _ string, _ []driver.NamedValue,
) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type bundleFakeConn struct {
	state *bundleFakeDB
}

func (*bundleFakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not expected")
}

func (*bundleFakeConn) Close() error { return nil }

func (connection *bundleFakeConn) Begin() (driver.Tx, error) {
	return connection.BeginTx(context.Background(), driver.TxOptions{})
}

type bundleFakeTx struct{}

func (bundleFakeTx) Commit() error   { return nil }
func (bundleFakeTx) Rollback() error { return nil }

func (connection *bundleFakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return bundleFakeTx{}, nil
}

func (connection *bundleFakeConn) QueryContext(
	_ context.Context, query string, _ []driver.NamedValue,
) (driver.Rows, error) {
	response := connection.state.lookup(query)
	return &bundleFakeRows{response: response}, nil
}

type bundleFakeRows struct {
	response bundleFakeResponse
	index    int
}

func (rows *bundleFakeRows) Columns() []string {
	if len(rows.response.columns) > 0 {
		return rows.response.columns
	}
	// 测试数据只关心值：列名省略时按首行长度给占位列名，
	// database/sql 用列数校验 Scan 目标个数。
	if len(rows.response.rows) > 0 {
		names := make([]string, len(rows.response.rows[0]))
		for index := range names {
			names[index] = fmt.Sprintf("col_%d", index)
		}
		return names
	}
	return nil
}
func (rows *bundleFakeRows) Close() error { return nil }

func (rows *bundleFakeRows) Next(dest []driver.Value) error {
	if rows.index >= len(rows.response.rows) {
		return io.EOF
	}
	copy(dest, rows.response.rows[rows.index])
	rows.index++
	return nil
}

// bundleTestInventory 造一个小而全的库存：1 角色（含信任策略、tag、内联策略、
// 客户自管与 AWS 托管挂载）、1 用户（挂 AWS 托管策略）、1 组（含成员）。
func bundleTestInventory(db *bundleFakeDB) {
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	inlineDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:CreateLogGroup","Resource":"*"}]}`

	db.add("FROM aws_account", nil, [][]driver.Value{{int64(1), "123456789012"}})
	db.add("principal_type, principal_name, arn, path, managed_by, tags", nil, [][]driver.Value{
		{"Role", "app-server", "arn:aws:iam::123456789012:role/app-server", "/app/", "platform", []byte(`{"team":"app"}`)},
		{"User", "deploy-bot", "arn:aws:iam::123456789012:user/deploy-bot", "/", "platform", nil},
	})
	db.add("group_name, arn, path, managed_by", nil, [][]driver.Value{
		{"release-managers", "arn:aws:iam::123456789012:group/release-managers", "/", "platform"},
	})
	db.add("OR (policy_arn LIKE 'arn:aws:iam::aws:policy/%'", nil, [][]driver.Value{
		{"app-logs", "arn:aws:iam::123456789012:policy/app-logs", "platform", "App logging policy", []byte(`{"team":"app"}`)},
		{"ReadOnlyAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess", "unknown", "", nil},
	})
	db.add(") inline", nil, [][]driver.Value{
		{"role", "app-server", "s3-access", []byte(inlineDoc), "", "platform", []byte(`{"team":"app"}`)},
	})
	db.add("HAVING COUNT(m.id) > 0", nil, [][]driver.Value{
		{"release-managers", int64(1)},
	})
	db.add("AS aws_managed", nil, [][]driver.Value{
		{"Role", "app-server", int64(1), int64(1)},
		{"User", "deploy-bot", int64(1), int64(0)},
	})
	db.add("COALESCE(trust_policy::text", nil, [][]driver.Value{
		{"app-server", []byte(trust), "application role", int64(3600), "", `{"team":"app"}`},
		{"deploy-bot", []byte(""), "", int64(0), "", ""},
	})
	db.add("SELECT group_name, path FROM iam_group", nil, [][]driver.Value{
		{"release-managers", "/"},
	})
	db.add("pol.policy_document::text AS document", nil, [][]driver.Value{
		{"role", "app-server", "s3-access", []byte(inlineDoc)},
	})
	db.add("|| $1 || ':policy/%'", nil, [][]driver.Value{
		{"app-logs", []byte(policyDoc)},
	})
	db.add("FROM attachments a", nil, [][]driver.Value{
		{"Role", "app-server", "arn:aws:iam::123456789012:policy/app-logs"},
		{"Role", "app-server", "arn:aws:iam::aws:policy/ReadOnlyAccess"},
		{"User", "deploy-bot", "arn:aws:iam::aws:policy/ReadOnlyAccess"},
		// 组挂载来自 iam_group_policy 分支：缺失会导致组挂载永远无法纳管。
		{"Group", "release-managers", "arn:aws:iam::123456789012:policy/app-logs"},
	})
	db.add("FROM iam_group_membership m", nil, [][]driver.Value{
		{"release-managers", "deploy-bot"},
	})
}

func newBundleTestDB(t *testing.T) (*sql.DB, *bundleFakeDB) {
	t.Helper()
	state := &bundleFakeDB{}
	return sql.OpenDB(state), state
}

func TestBaselineBundleBuildGeneratesDeterministicFiles(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)

	candidates := NewBaselineCandidateService(db)
	bundleService := NewBaselineBundleService(db, candidates, nil, "iam")

	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	filesBySlug := map[string]BaselineBundleFile{}
	for _, file := range report.Files {
		filesBySlug[strings.TrimSuffix(file.FileName, ".tf")] = file
	}
	for _, slug := range []string{
		"role-app-server",
		"user-deploy-bot",
		"group-release-managers",
		"policy-app-logs",
		"role-app-server-policy-s3-access",
		"attachment-role-app-server-app-logs",
		"attachment-role-app-server-readonlyaccess",
		"attachment-user-deploy-bot-readonlyaccess",
		"attachment-group-release-managers-app-logs",
		"group-release-managers-membership",
	} {
		if _, ok := filesBySlug[slug]; !ok {
			t.Errorf("bundle is missing file %q; got %v", slug, fileKeys(report))
		}
	}

	// 角色文件：import 块 + 信任策略 + ForceNew 属性 + tag，全部来自库存。
	// 属性对齐宽度取决于块内最长属性名，断言只看属性本身。
	roleFile := filesBySlug["role-app-server"]
	for _, want := range []string{
		`import {`,
		`id = "app-server"`,
		`to = aws_iam_role.role_app-server`,
		`resource "aws_iam_role" "role_app-server" {`,
		`assume_role_policy`,
		`jsonencode(`,
		`"Service" = "ec2.amazonaws.com"`,
		`path`,
		`"/app/"`,
		`max_session_duration`,
		`3600`,
		`tags`,
		`"team" = "app"`,
	} {
		if !strings.Contains(roleFile.Content, want) {
			t.Errorf("role file missing %q:\n%s", want, roleFile.Content)
		}
	}

	// 关系文件：挂载声明 role/user 用名字字符串 + import ID <principal>/<arn>。
	attachment := filesBySlug["attachment-role-app-server-app-logs"]
	if !strings.Contains(attachment.Content, `id = "app-server/arn:aws:iam::123456789012:policy/app-logs"`) {
		t.Errorf("attachment import ID wrong:\n%s", attachment.Content)
	}
	if !attachment.Relationship {
		t.Errorf("attachment file should be flagged as relationship")
	}

	// 策略文件：description 是 aws_iam_policy 的 ForceNew 属性，漏写会让首次
	// apply 销毁重建（实测 8 个 replace 的唯一 FORCE 原因）；tags 漏写会清空
	// 实态 tag。两者必须原样来自库存。
	policyFile := filesBySlug["policy-app-logs"]
	for _, want := range []string{
		`description = "App logging policy"`,
		`tags = {`,
		`"team" = "app"`,
	} {
		if !strings.Contains(policyFile.Content, want) {
			t.Errorf("policy file missing %q:\n%s", want, policyFile.Content)
		}
	}

	// AWS 托管策略本体不得出现在 bundle：它只能被引用。
	for key := range filesBySlug {
		if key == "policy-readonlyaccess" {
			t.Errorf("AWS managed policy must not be declared as a file")
		}
	}

	// 确定性：同库存再跑一次，文件与整体指纹必须逐字节一致。
	second, err := bundleService.Build(context.Background(), "1")
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	if second.ContentSHA256 != report.ContentSHA256 {
		t.Errorf("content hash drifted: %s vs %s",
			report.ContentSHA256, second.ContentSHA256)
	}
	if len(second.Files) != len(report.Files) {
		t.Fatalf("file count drifted: %d vs %d", len(report.Files), len(second.Files))
	}
	for index := range report.Files {
		if report.Files[index].Content != second.Files[index].Content {
			t.Errorf("file %s content drifted", report.Files[index].FileName)
		}
	}
}

func TestBaselineBundleFileExistsConflict(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)

	candidates := NewBaselineCandidateService(db)
	checker := &bundleFakeRepo{existing: map[string]string{
		"iam/account-123456789012/role-app-server.tf": "fake-blob-sha",
	}}
	bundleService := NewBaselineBundleService(db, candidates, checker, "iam")

	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if report.RepoDirectory != "iam/account-123456789012" {
		t.Errorf("repo directory = %q", report.RepoDirectory)
	}
	found := false
	for _, file := range report.Files {
		if file.FileName != "role-app-server.tf" {
			continue
		}
		if file.ExistsInRepo == nil || !*file.ExistsInRepo {
			t.Fatalf("role-app-server.tf should be flagged as existing in repo")
		}
		if file.RepoBlobSHA != "fake-blob-sha" {
			t.Fatalf("RepoBlobSHA = %q, want fake-blob-sha", file.RepoBlobSHA)
		}
		found = true
	}
	if !found {
		t.Fatal("role file missing from bundle")
	}
	if report.Counts["files-exist-in-repo"] != 1 {
		t.Errorf("files-exist-in-repo count = %d, want 1", report.Counts["files-exist-in-repo"])
	}
	var flagged []string
	for _, issue := range report.Issues {
		if issue.Kind == "file-exists" {
			flagged = append(flagged, issue.Value)
			if issue.DetailCode != IssueDetailFileExists {
				t.Errorf("file-exists issue detail code = %q, want %q",
					issue.DetailCode, IssueDetailFileExists)
			}
		}
	}
	if len(flagged) != 1 || !strings.Contains(flagged[0], "role-app-server.tf") {
		t.Errorf("file-exists issue = %v", flagged)
	}
}

// bundleTreeFakeRepo 在逐文件能力之上再实现整树清单：Build 应只问一次
// 整树、不再逐文件查询——逐文件是「338 个文件、无变化也要等两分钟」的来源。
type bundleTreeFakeRepo struct {
	bundleFakeRepo
	tree      map[string]string
	treeErr   error
	treeCalls int
	metaCalls int
}

func (repo *bundleTreeFakeRepo) TerraformFileTree(context.Context) (map[string]string, error) {
	repo.treeCalls++
	if repo.treeErr != nil {
		return nil, repo.treeErr
	}
	return repo.tree, nil
}

func (repo *bundleTreeFakeRepo) TerraformFileMeta(
	ctx context.Context, fileName string,
) (string, bool, error) {
	repo.metaCalls++
	return repo.bundleFakeRepo.TerraformFileMeta(ctx, fileName)
}

// 有整树清单时，存在性与 blob SHA 全部来自那一次查询。
func TestBaselineBundleUsesSingleTreeLookup(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)

	checker := &bundleTreeFakeRepo{tree: map[string]string{
		"iam/account-123456789012/role-app-server.tf": "tree-blob-sha",
	}}
	bundleService := NewBaselineBundleService(db, NewBaselineCandidateService(db), checker, "iam")

	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if checker.treeCalls != 1 {
		t.Errorf("tree lookups = %d, want 1", checker.treeCalls)
	}
	if checker.metaCalls != 0 {
		t.Errorf("per-file lookups = %d, want 0 (tree answer should be enough)", checker.metaCalls)
	}
	found := false
	for _, file := range report.Files {
		if file.FileName != "role-app-server.tf" {
			if file.ExistsInRepo != nil && *file.ExistsInRepo {
				t.Errorf("%s flagged as existing, but the tree does not contain it", file.FileName)
			}
			continue
		}
		found = true
		if file.ExistsInRepo == nil || !*file.ExistsInRepo || file.RepoBlobSHA != "tree-blob-sha" {
			t.Errorf("role-app-server.tf = exists %v / sha %q", file.ExistsInRepo, file.RepoBlobSHA)
		}
	}
	if !found {
		t.Fatal("role file missing from bundle")
	}
}

// 整树清单拿不到（失败/截断）时退回逐文件查询：批量只是加速，不是前提。
func TestBaselineBundleFallsBackToPerFileLookup(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)

	checker := &bundleTreeFakeRepo{treeErr: errors.New("tree truncated")}
	bundleService := NewBaselineBundleService(db, NewBaselineCandidateService(db), checker, "iam")

	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if checker.treeCalls != 1 || checker.metaCalls == 0 {
		t.Errorf("tree/per-file lookups = %d/%d, want 1/>0", checker.treeCalls, checker.metaCalls)
	}
	for _, issue := range report.Issues {
		if issue.Kind == "file-exists" && issue.Detail != "" &&
			strings.Contains(issue.Detail, "tree truncated") {
			t.Fatalf("fallback must not leak the tree error into file-exists issues: %+v", issue)
		}
	}
}

// 已被工单纳管的资源（already-declared）进 issue 清单，不进文件。
func TestBaselineBundleListsAlreadyDeclared(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)
	// 一条 UPDATE_ROLE 工单声明了 deploy-bot 用户之外的角色：让 app-server
	// 变成 already-declared——挂载关系也必须跟着消失（避免同地址双声明）。
	state.add("request_policy", nil, [][]driver.Value{
		{"UPDATE_ROLE", "app-server", []byte(`{"update_role":{"trust_policy":{}}}`)},
	})

	candidates := NewBaselineCandidateService(db)
	bundleService := NewBaselineBundleService(db, candidates, nil, "iam")

	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if _, ok := fileSlugs(report)["role-app-server.tf"]; ok {
		t.Error("already-declared role must not be regenerated")
	}
	if _, ok := fileSlugs(report)["attachment-role-app-server-app-logs.tf"]; ok {
		t.Error("attachments of an already-declared role must not be declared by the baseline")
	}
	if report.Counts["already-declared"] != 1 {
		t.Errorf("already-declared count = %d, want 1", report.Counts["already-declared"])
	}
	for _, issue := range report.Issues {
		if issue.Kind != "already-declared" {
			continue
		}
		if issue.DetailCode != IssueDetailAlreadyDeclared {
			t.Errorf("already-declared detail code = %q, want %q",
				issue.DetailCode, IssueDetailAlreadyDeclared)
		}
	}
}

// 台账里的每条 issue 都必须带 detail_code：界面语言由前端决定，服务端的
// 中文原文只是兜底。缺码的 issue 在英文界面下会直接显示中文（用户就是
// 这么发现「Detail 列切英文还是中文」的）。
func TestBaselineBundleIssuesCarryDetailCodes(t *testing.T) {
	db, state := newBundleTestDB(t)
	defer db.Close()
	bundleTestInventory(state)
	// 同时造出两类 issue：already-declared（工单已声明）与 file-exists（仓库已有同名文件）。
	state.add("request_policy", nil, [][]driver.Value{
		{"UPDATE_ROLE", "app-server", []byte(`{"update_role":{"trust_policy":{}}}`)},
	})
	// 用 deploy-bot 做「仓库已有」：app-server 已被工单纳管，不生成文件，
	// 拿它当夹具会一个 file-exists 都造不出来。
	checker := &bundleFakeRepo{existing: map[string]string{
		"iam/account-123456789012/user-deploy-bot.tf": "fake-blob-sha",
	}}

	bundleService := NewBaselineBundleService(db, NewBaselineCandidateService(db), checker, "iam")
	report, err := bundleService.Build(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(report.Issues) == 0 {
		t.Fatal("fixture produced no issues, nothing to assert")
	}
	for _, issue := range report.Issues {
		if issue.DetailCode == "" {
			t.Errorf("issue %s/%s has no detail code: %+v", issue.Kind, issue.Value, issue)
		}
	}
}

func fileKeys(report *BaselineBundleReport) []string {
	keys := make([]string, 0, len(report.Files))
	for _, file := range report.Files {
		keys = append(keys, file.Key)
	}
	return keys
}

func fileSlugs(report *BaselineBundleReport) map[string]bool {
	slugs := map[string]bool{}
	for _, file := range report.Files {
		slugs[file.FileName] = true
	}
	return slugs
}

// bundleFakeRepo 是 BundleRepoChecker 的内存实现：existing 里记录「存在的
// 文件名 -> 伪 blob SHA」，发布侧据此比对内容是否变化。
type bundleFakeRepo struct {
	mu       sync.Mutex
	existing map[string]string
}

func (repo *bundleFakeRepo) TerraformFileMeta(
	_ context.Context, fileName string,
) (string, bool, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	sha, ok := repo.existing[fileName]
	return sha, ok, nil
}

// AWS ListOpenIDConnectProviders 返回的 Url 不带 https:// 前缀，Terraform
// 的 ForceNew url 属性要求完整 URL：只补协议头，主体不动。
func TestNormalizeOIDCProviderURL(t *testing.T) {
	cases := map[string]string{
		"oidc.eks.ap-southeast-1.amazonaws.com/id/ABC": "https://oidc.eks.ap-southeast-1.amazonaws.com/id/ABC",
		"https://token.actions.githubusercontent.com":  "https://token.actions.githubusercontent.com",
		"https://oidc.example.com/a/b":                 "https://oidc.example.com/a/b",
		"":                                             "",
	}
	for input, want := range cases {
		if got := normalizeOIDCProviderURL(input); got != want {
			t.Errorf("normalizeOIDCProviderURL(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestBaselineBundleDeclarationsMatchFiles 声明快照必须与文件同源：每条
// 声明都落在本次生成的某个文件上，资源 key 唯一，属性是生成器真正写进
// HCL 的那一组（「留空不声明」的字段不出现，否则漂移判定会拿 Terraform
// 没管的默认值去比对）。
func TestBaselineBundleDeclarationsMatchFiles(t *testing.T) {
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

	files := map[string]bool{}
	for _, file := range report.Files {
		files[file.Key] = true
	}
	byResource := map[string]BaselineDeclaration{}
	for _, declaration := range report.Declarations {
		if !files[declaration.FileKey] {
			t.Errorf("declaration %s points at unknown file %s",
				declaration.ResourceKey, declaration.FileKey)
		}
		if _, duplicate := byResource[declaration.ResourceKey]; duplicate {
			t.Errorf("duplicate resource key %s", declaration.ResourceKey)
		}
		byResource[declaration.ResourceKey] = declaration
	}

	roleDeclaration, ok := byResource["role:app-server"]
	if !ok {
		t.Fatalf("missing role declaration; got %v", declarationKeys(report))
	}
	var roleAttributes map[string]any
	if err := json.Unmarshal(roleDeclaration.Attributes, &roleAttributes); err != nil {
		t.Fatalf("role attributes are not JSON: %v", err)
	}
	if roleAttributes["path"] != "/app/" {
		t.Errorf("role path = %v, want /app/", roleAttributes["path"])
	}
	if _, ok := roleAttributes["trust_policy"].(map[string]any); !ok {
		t.Errorf("role declaration must carry the canonical trust policy: %v",
			roleAttributes["trust_policy"])
	}
	if _, ok := roleAttributes["tags"].(map[string]any); !ok {
		t.Errorf("role declaration must carry tags: %v", roleAttributes)
	}

	// 挂载是关系类声明：身份三元组要完整，否则无法判定「这条挂载还在不在」。
	if _, ok := byResource["attachment:role:app-server:arn:aws:iam::123456789012:policy/app-logs"]; !ok {
		t.Errorf("missing attachment declaration; got %v", declarationKeys(report))
	}
	// 内联策略的 key 带上主体：策略名只在主体内唯一。
	if _, ok := byResource["role:app-server:inline:s3-access"]; !ok {
		t.Errorf("missing inline policy declaration; got %v", declarationKeys(report))
	}
	membership, ok := byResource["membership:group:release-managers"]
	if !ok {
		t.Fatalf("missing membership declaration; got %v", declarationKeys(report))
	}
	if !strings.Contains(string(membership.Attributes), "deploy-bot") {
		t.Errorf("membership declaration must list members: %s", membership.Attributes)
	}
}

func declarationKeys(report *BaselineBundleReport) []string {
	keys := make([]string, 0, len(report.Declarations))
	for _, declaration := range report.Declarations {
		keys = append(keys, declaration.ResourceKey)
	}
	sort.Strings(keys)
	return keys
}

// TestCanonicalJSONSortsKeys 声明属性必须键序固定：同一语义不同插入顺序
// 若得到不同字节，漂移判定会把「没变」报成变更。
func TestCanonicalJSONSortsKeys(t *testing.T) {
	first, err := canonicalJSON(map[string]any{"b": 1, "a": map[string]any{"d": 2, "c": 3}})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	second, err := canonicalJSON(map[string]any{"a": map[string]any{"c": 3, "d": 2}, "b": 1})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("canonical JSON depends on insertion order:/n%s/n%s", first, second)
	}
	if string(first) != `{"a":{"c":3,"d":2},"b":1}` {
		t.Errorf("canonical JSON = %s", first)
	}
}

// TestBaselineAttachmentImportID 回归台账 25 方案 1：历史基线已 apply 收编
// 的挂载不再带 import ID；未收编的渲染 <principal>/<arn>；nil map 安全。
func TestBaselineAttachmentImportID(t *testing.T) {
	adopted := map[string]bool{
		"attachment:role:app-server:arn:aws:iam::123456789012:policy/app-logs": true,
	}
	if got := baselineAttachmentImportID(adopted, "role", "app-server",
		"arn:aws:iam::123456789012:policy/app-logs"); got != "" {
		t.Errorf("adopted attachment import = %q, want empty", got)
	}
	if got := baselineAttachmentImportID(adopted, "role", "app-server",
		"arn:aws:iam::123456789012:policy/other"); got != "app-server/arn:aws:iam::123456789012:policy/other" {
		t.Errorf("un-adopted attachment import = %q", got)
	}
	if got := baselineAttachmentImportID(nil, "user", "deploy-bot",
		"arn:aws:iam::123456789012:policy/app-logs"); got != "deploy-bot/arn:aws:iam::123456789012:policy/app-logs" {
		t.Errorf("nil adopted map must behave as empty, got %q", got)
	}
}
