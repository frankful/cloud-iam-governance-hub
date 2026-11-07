package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// inventoryFakeDB 是清单服务回归测试用的内存 SQL fake。它专门防一类真实
// 事故：计数查询传了 args、列表查询漏传（数据库驱动对带 $N 占位符却不带
// 参数的语句直接报错，fake 之前照常返回行，测不出来）。
type inventoryFakeDB struct {
	responses []inventoryFakeResponse
	// queries 记录执行过的 SQL，供断言生成的语句形态（如 COALESCE 包裹）。
	queries []string
}

type inventoryFakeResponse struct {
	match   string
	columns []string
	rows    [][]driver.Value
}

func (db *inventoryFakeDB) add(match string, columns []string, rows [][]driver.Value) {
	db.responses = append(db.responses, inventoryFakeResponse{match, columns, rows})
}

func (db *inventoryFakeDB) lookup(query string) inventoryFakeResponse {
	for _, response := range db.responses {
		if strings.Contains(query, response.match) {
			return response
		}
	}
	return inventoryFakeResponse{}
}

func (db *inventoryFakeDB) Connect(context.Context) (driver.Conn, error) {
	return &inventoryFakeConn{state: db}, nil
}

func (db *inventoryFakeDB) Driver() driver.Driver { return db }
func (db *inventoryFakeDB) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected direct driver open")
}

type inventoryFakeConn struct {
	state *inventoryFakeDB
}

func (*inventoryFakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not expected")
}
func (*inventoryFakeConn) Close() error { return nil }
func (connection *inventoryFakeConn) Begin() (driver.Tx, error) {
	return inventoryFakeTx{}, nil
}

// QueryContext 在查询含 $N 占位符但没传参数时直接报错——这正是
// ListInlinePolicies 曾 经漏传 args 导致线上 500 的形态。
func (connection *inventoryFakeConn) QueryContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	if strings.Contains(query, "$") && len(args) == 0 {
		return nil, fmt.Errorf(
			"query has placeholders but 0 args passed: %.80s", query)
	}
	response := connection.state.lookup(query)
	connection.state.queries = append(connection.state.queries, query)
	return &inventoryFakeRows{response: response}, nil
}

// ExecContext 记录执行过的写语句（AuthenticateToken 会更新 last_used_at），
// 供测试断言 SQL 形态；不实现会让 database/sql 回退到 Prepare 并报错。
func (connection *inventoryFakeConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	if strings.Contains(query, "$") && len(args) == 0 {
		return nil, fmt.Errorf(
			"exec has placeholders but 0 args passed: %.80s", query)
	}
	connection.state.queries = append(connection.state.queries, query)
	return driver.RowsAffected(1), nil
}

type inventoryFakeTx struct{}

func (inventoryFakeTx) Commit() error   { return nil }
func (inventoryFakeTx) Rollback() error { return nil }

type inventoryFakeRows struct {
	response inventoryFakeResponse
	index    int
}

func (rows *inventoryFakeRows) Columns() []string {
	if len(rows.response.columns) > 0 {
		return rows.response.columns
	}
	if len(rows.response.rows) > 0 {
		names := make([]string, len(rows.response.rows[0]))
		for index := range names {
			names[index] = fmt.Sprintf("col_%d", index)
		}
		return names
	}
	return nil
}
func (rows *inventoryFakeRows) Close() error { return nil }
func (rows *inventoryFakeRows) Next(dest []driver.Value) error {
	if rows.index >= len(rows.response.rows) {
		return io.EOF
	}
	copy(dest, rows.response.rows[rows.index])
	rows.index++
	return nil
}

// TestListInlinePoliciesPassesArgsToListQuery 复现「必选账号后内联策略
// 列表为空/500」：带 account_id 过滤时列表查询含 $1 占位符，漏传 args
// 会被 fake driver 拒绝。
func TestListInlinePoliciesPassesArgsToListQuery(t *testing.T) {
	fake := &inventoryFakeDB{}
	fake.add("counted", []string{"count"},
		[][]driver.Value{{int64(1)}})
	fake.add("ORDER BY owner_kind", []string{
		"policy_id", "account_db_id", "aws_account_id", "policy_name",
		"owner_kind", "owner_name", "owner_arn", "aws_managed", "last_seen_at",
	}, [][]driver.Value{{
		int64(233), int64(1), "111122223333", "acm-speech-dev-policy",
		"group", "acm-speech-dev",
		"arn:aws:iam::111122223333:group/acm-speech-dev", false, nil,
	}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewIAMInventoryService(database)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	policies, total, err := service.ListInlinePolicies(
		context.Background(),
		InlinePolicyListFilter{AccountID: 1, Limit: 20},
	)
	if err != nil {
		t.Fatalf("ListInlinePolicies: %v", err)
	}
	if total != 1 || len(policies) != 1 {
		t.Fatalf("want 1 policy (total=1), got len=%d total=%d",
			len(policies), total)
	}
	if policies[0].PolicyName != "acm-speech-dev-policy" {
		t.Fatalf("unexpected policy name %q", policies[0].PolicyName)
	}
}

// TestListPrincipalsCoalescesAWSLifecycle 回归：aws_lifecycle 计算列对
// 「tags 为 NULL 且不匹配任何 AWS 前缀」的角色产生 NULL（三值逻辑
// `true AND NULL` = NULL），真实 pgx 扫描进 bool 直接 500——工单中心
// role 下拉（limit=100 扫全量）必现。修复在 SQL 文本层（COALESCE 包裹），
// fake driver 模拟不了 Postgres 的三值逻辑，所以这里断言生成的查询
// 确实带 COALESCE——有人删掉它就会在此暴露。
func TestListPrincipalsCoalescesAWSLifecycle(t *testing.T) {
	fake := &inventoryFakeDB{}
	fake.add("COUNT(*) FROM iam_principal", []string{"count"},
		[][]driver.Value{{int64(1)}})
	fake.add("ORDER BY p.principal_name", []string{
		"id", "account_db_id", "aws_account_id", "principal_type",
		"principal_name", "arn", "last_seen_at", "updated_at",
		"managed_by", "aws_lifecycle",
	}, [][]driver.Value{{
		int64(6), int64(1), "111122223333", "Role",
		"AmazonEKSPodIdentityAmazonEBSCSIRole",
		"arn:aws:iam::111122223333:role/AmazonEKSPodIdentityAmazonEBSCSIRole",
		time.Now(), time.Now(), "unknown", false,
	}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewIAMInventoryService(database)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	if _, _, err := service.ListPrincipals(
		context.Background(),
		PrincipalListFilter{AccountID: 1, Type: "Role", Limit: 100},
	); err != nil {
		t.Fatalf("ListPrincipals: %v", err)
	}

	listQuery := ""
	for _, query := range fake.queries {
		if strings.Contains(query, "ORDER BY p.principal_name") {
			listQuery = query
		}
	}
	if listQuery == "" {
		t.Fatalf("list query not captured")
	}
	if !strings.Contains(listQuery, "COALESCE(") ||
		!strings.Contains(listQuery, "AS aws_lifecycle") {
		t.Fatalf("aws_lifecycle column must be wrapped in COALESCE to keep\n"+
			"NULL (three-valued logic) from breaking the bool scan, got: %.200s", listQuery)
	}
}

// ---- A3：资产详情三查询的列/Scan 对应回归 ----
//
// managed_by 漏扫曾让详情接口 500 一次；GetRoleAttributes 已有同类锁
// （TestSQLTicketRepositoryRoleAttributesIncludesForceNewColumns），这里把
// GetPrincipal / ListGroups / GetGroup 补齐。fake 按查询特征返回「与真实
// 投影列数一致的行」，任何加列不Scan / 删列不改 Scan 的漂移都会让
// database/sql 的 Scan 直接报错。

// GetPrincipal 的主查询投影 12 列（含 managed_by / description / trust_policy /
// tags），附策略 4 列、所属组 3 列。
func TestGetPrincipalScansAllProjectedColumns(t *testing.T) {
	fake := &inventoryFakeDB{}
	updatedAt := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	fake.add("p.trust_policy, p.tags", []string{
		"id", "account_db_id", "aws_account_id", "principal_type",
		"principal_name", "arn", "last_seen_at", "updated_at",
		"managed_by", "description", "trust_policy", "tags",
	}, [][]driver.Value{{
		int64(9), int64(1), "111122223333", "Role", "billing-reader",
		"arn:aws:iam::111122223333:role/billing-reader", nil, updatedAt,
		"platform", "application role", []byte(`{"Version":"2012-10-17"}`),
		[]byte(`{"team":"otel"}`),
	}})
	fake.add("pol.id = pp.policy_id", []string{
		"policy_id", "policy_name", "policy_type", "policy_arn",
	}, [][]driver.Value{{
		int64(3), "billing-readonly", "managed",
		"arn:aws:iam::aws:policy/billing-readonly",
	}})
	fake.add("gm.user_principal_id = $1", []string{
		"id", "group_name", "arn",
	}, [][]driver.Value{{
		int64(5), "readers", "arn:aws:iam::111122223333:group/readers",
	}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewIAMInventoryService(database)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	detail, err := service.GetPrincipal(context.Background(), 9)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if detail.ManagedBy != "platform" {
		t.Errorf("managed_by = %q, want platform（漏扫即 500 的那列）", detail.ManagedBy)
	}
	if detail.Description == nil || *detail.Description != "application role" {
		t.Errorf("description = %v", detail.Description)
	}
	if detail.LastSeenAt != nil {
		t.Errorf("last_seen_at = %v, want nil（NULL 列不破坏 Scan）", detail.LastSeenAt)
	}
	if detail.Tags["team"] != "otel" {
		t.Errorf("tags = %v", detail.Tags)
	}
	if len(detail.Policies) != 1 || detail.Policies[0].PolicyName == nil ||
		*detail.Policies[0].PolicyName != "billing-readonly" {
		t.Errorf("policies = %#v", detail.Policies)
	}
	if len(detail.Groups) != 1 || detail.Groups[0].GroupName != "readers" {
		t.Errorf("groups = %#v", detail.Groups)
	}
}

// ListGroups 的列表查询投影 9 列（含 managed_by），COUNT 查询 1 列。
func TestListGroupsScansAllProjectedColumns(t *testing.T) {
	fake := &inventoryFakeDB{}
	fake.add("COUNT(*) FROM iam_group", []string{"count"},
		[][]driver.Value{{int64(1)}})
	updatedAt := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	fake.add("ORDER BY g.group_name", []string{
		"id", "account_db_id", "aws_account_id", "group_name", "arn",
		"path", "member_count", "updated_at", "managed_by",
	}, [][]driver.Value{{
		int64(5), int64(1), "111122223333", "readers",
		"arn:aws:iam::111122223333:group/readers", "/", int64(2),
		updatedAt, "platform",
	}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewIAMInventoryService(database)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	groups, total, err := service.ListGroups(context.Background(), GroupListFilter{AccountID: 1, Limit: 20})
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("want 1 group (total=1), got len=%d total=%d", len(groups), total)
	}
	if groups[0].ManagedBy != "platform" {
		t.Errorf("managed_by = %q, want platform（漏扫即 500 的那列）", groups[0].ManagedBy)
	}
	if groups[0].MemberCount != 2 || groups[0].Path != "/" {
		t.Errorf("group summary = %#v", groups[0])
	}
}

// GetGroup 的主查询与 ListGroups 同形（9 列），成员 3 列、挂载策略 4 列。
func TestGetGroupScansAllProjectedColumns(t *testing.T) {
	fake := &inventoryFakeDB{}
	updatedAt := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	fake.add("WHERE g.id = $1", []string{
		"id", "account_db_id", "aws_account_id", "group_name", "arn",
		"path", "updated_at", "member_count", "managed_by",
	}, [][]driver.Value{{
		int64(5), int64(1), "111122223333", "readers",
		"arn:aws:iam::111122223333:group/readers", "/", updatedAt,
		int64(1), "platform",
	}})
	fake.add("gm.group_id = $1", []string{
		"id", "principal_name", "arn",
	}, [][]driver.Value{{
		int64(9), "billing-reader",
		"arn:aws:iam::111122223333:role/billing-reader",
	}})
	fake.add("FROM iam_group_policy gp", []string{
		"policy_id", "policy_name", "policy_type", "policy_arn",
	}, [][]driver.Value{{
		int64(3), "billing-readonly", "managed",
		"arn:aws:iam::aws:policy/billing-readonly",
	}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewIAMInventoryService(database)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	detail, err := service.GetGroup(context.Background(), 5)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if detail.ManagedBy != "platform" {
		t.Errorf("managed_by = %q, want platform（漏扫即 500 的那列）", detail.ManagedBy)
	}
	if len(detail.Members) != 1 || detail.Members[0].PrincipalName != "billing-reader" {
		t.Errorf("members = %#v", detail.Members)
	}
	if len(detail.Policies) != 1 || detail.Policies[0].PolicyName == nil ||
		*detail.Policies[0].PolicyName != "billing-readonly" {
		t.Errorf("policies = %#v", detail.Policies)
	}
}

// TestListManagedPoliciesScopesToAccount 回归：托管策略清单原先不吃
// account_id，工单表单和资产页的策略下拉因此会列出**其他账号**的策略
// （多账号接入后表现为「选了测试账号却能看到真实账号的策略」）。断言
// SQL 里带上 pol.account_id 条件，且占位符与 args 数量匹配。
func TestListManagedPoliciesScopesToAccount(t *testing.T) {
	fake := &inventoryFakeDB{}
	fake.add("COUNT(*) FROM iam_policy", []string{"count"},
		[][]driver.Value{{int64(1)}})
	fake.add("ORDER BY (pol.account_id IS NULL)", []string{
		"id", "policy_name", "policy_arn", "policy_type", "managed_by", "aws_managed",
	}, [][]driver.Value{{
		int64(31), "billing-readonly", "arn:aws:iam::999900001111:policy/billing-readonly",
		"managed", "customer", false,
	}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewIAMInventoryService(database)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	policies, total, err := service.ListManagedPolicies(context.Background(),
		ManagedPolicyFilter{AccountID: 2, Limit: 20})
	if err != nil {
		t.Fatalf("ListManagedPolicies: %v", err)
	}
	if total != 1 || len(policies) != 1 || policies[0].PolicyName != "billing-readonly" {
		t.Fatalf("policies = %#v total = %d", policies, total)
	}
	for _, query := range fake.queries {
		if !strings.Contains(query, "pol.account_id = $1") {
			t.Errorf("query is not account-scoped: %.160s", query)
		}
		// C2：AWS 托管策略没有归属账号，必须与账号过滤取并集，否则
		// 工单下拉里永远看不到 AdministratorAccess 这类官方策略。
		if !strings.Contains(query, "arn:aws:iam::aws:policy/") {
			t.Errorf("query does not union the global AWS-managed catalog: %.160s", query)
		}
	}

	// AccountID=0 保持跨账号清单（基线/审计等管理视角仍需要全量）。
	_, _, err = service.ListManagedPolicies(context.Background(),
		ManagedPolicyFilter{Limit: 20})
	if err != nil {
		t.Fatalf("ListManagedPolicies without account: %v", err)
	}
	for _, query := range fake.queries {
		if strings.Contains(query, "pol.account_id =") &&
			!strings.Contains(query, "pol.account_id = $1") {
			t.Errorf("unexpected account condition: %.160s", query)
		}
	}
}

// TestGetManagedPolicyComputesAWSManaged 回归：详情查询原先没有计算
// aws_managed，官方托管策略（如 AdministratorAccess）在详情抽屉里被判成
// 可编辑，点下去必然被后端拒绝。详情与列表必须用同一口径
// （AWSManagedPolicySQL）判定。
func TestGetManagedPolicyComputesAWSManaged(t *testing.T) {
	cases := []struct {
		name       string
		policyARN  string
		document   driver.Value
		wantDocNil bool
	}{
		{
			name:       "aws managed catalog row",
			policyARN:  "arn:aws:iam::aws:policy/AdministratorAccess",
			document:   nil,
			wantDocNil: true,
		},
		{
			name:       "customer managed policy",
			policyARN:  "arn:aws:iam::999900001111:policy/billing-readonly",
			document:   []byte(`{"Version":"2012-10-17","Statement":[]}`),
			wantDocNil: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// 真实的 aws_managed 由 SQL 从 ARN 前缀算出，这里按同一口径给值。
			wantManaged := strings.HasPrefix(testCase.policyARN,
				"arn:aws:iam::aws:policy/")
			fake := &inventoryFakeDB{}
			fake.add("pol.policy_type,", []string{
				"id", "policy_name", "policy_arn", "policy_type",
				"aws_managed", "policy_document",
			}, [][]driver.Value{{
				int64(77), "some-policy", testCase.policyARN, "managed",
				wantManaged, testCase.document,
			}})
			fake.add("COUNT(DISTINCT ipp.principal_id)", []string{
				"principal_count", "group_count",
			}, [][]driver.Value{{int64(3), int64(1)}})

			database := sql.OpenDB(fake)
			defer database.Close()
			service, err := NewIAMInventoryService(database)
			if err != nil {
				t.Fatalf("new service: %v", err)
			}

			detail, err := service.GetManagedPolicy(context.Background(), 77)
			if err != nil {
				t.Fatalf("GetManagedPolicy: %v", err)
			}
			if detail.AWSManaged != wantManaged {
				t.Errorf("aws_managed = %v, want %v",
					detail.AWSManaged, wantManaged)
			}
			// 详情查询必须自带 aws_managed 计算，与列表同一口径。
			if len(fake.queries) == 0 ||
				!strings.Contains(fake.queries[0], "arn:aws:iam::aws:policy/") {
				t.Errorf("detail query does not compute aws_managed: %#v",
					fake.queries)
			}
			if (detail.PolicyDocument == nil) != testCase.wantDocNil {
				t.Errorf("policy_document nil = %v, want %v",
					detail.PolicyDocument == nil, testCase.wantDocNil)
			}
			if detail.AttachedPrincipals != 3 || detail.AttachedGroups != 1 {
				t.Errorf("attachments = %d/%d, want 3/1",
					detail.AttachedPrincipals, detail.AttachedGroups)
			}
		})
	}
}
