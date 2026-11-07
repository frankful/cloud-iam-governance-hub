package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// liveUsageStub 记录 ResolveUsedProfiles 调用次数，用于断言数据库快照命中时
// 不再实时回源。
type liveUsageStub struct {
	calls  int
	result profileUsageResult
	err    error
}

func (stub *liveUsageStub) ResolveUsedProfiles(
	context.Context, string,
) (profileUsageResult, error) {
	stub.calls++
	if stub.err != nil {
		return profileUsageResult{}, stub.err
	}
	return stub.result, nil
}

// usageEvidenceTable 在 fake 层模拟 iam_profile_usage_evidence 的行为：
// INSERT/UPSERT 覆盖一行，SELECT 按账号返回（缺行时走 ErrNoRows 路径），
// 让 Save→Load 成为真实往返而不只是各自喂假数据。
type usageEvidenceTable struct {
	mu   sync.Mutex
	rows map[string][][]driver.Value
}

func newUsageEvidenceTable() *usageEvidenceTable {
	return &usageEvidenceTable{rows: map[string][][]driver.Value{}}
}

// hook 返回给 usageFakeDB.queryHook；同时拦 INSERT（写）与 SELECT（读）。
func (table *usageEvidenceTable) hook(query string, args []driver.NamedValue) (usageFakeResponse, bool) {
	switch {
	case strings.Contains(query, "INSERT INTO iam_profile_usage_evidence"):
		if len(args) < 5 {
			return usageFakeResponse{}, false
		}
		account, _ := args[0].Value.(string)
		table.mu.Lock()
		defer table.mu.Unlock()
		table.rows[account] = [][]driver.Value{{
			args[1].Value, args[2].Value, args[3].Value, args[4].Value, time.Now(),
		}}
		return usageFakeResponse{}, true
	case strings.Contains(query, "FROM iam_profile_usage_evidence"):
		if len(args) == 0 {
			return usageFakeResponse{}, false
		}
		account, _ := args[0].Value.(string)
		table.mu.Lock()
		defer table.mu.Unlock()
		rows, ok := table.rows[account]
		if !ok {
			return usageFakeResponse{}, false // 无行 → sql.ErrNoRows → NotFound
		}
		return usageFakeResponse{
			columns: []string{"used_profiles", "role_nodegroups", "warnings", "eks_unavailable", "collected_at"},
			rows:    rows,
		}, true
	}
	return usageFakeResponse{}, false
}

func newUsageEvidenceTestDB(t *testing.T) (*sql.DB, *usageEvidenceTable) {
	t.Helper()
	fake := &usageFakeDB{}
	// upsert：ExecContext 不匹配任何响应也返回成功；这里注册只是为了
	// 万一将来 SQL 结构变化时能在 fake 层发现问题。
	fake.responses = append(fake.responses, usageFakeResponse{
		match: "INSERT INTO iam_profile_usage_evidence",
	})
	table := newUsageEvidenceTable()
	fake.queryHook = table.hook
	database := sql.OpenDB(fake)
	t.Cleanup(func() { database.Close() })
	return database, table
}

func usageSampleResult() profileUsageResult {
	return profileUsageResult{
		UsedProfiles: map[string][]string{
			"arn:aws:iam::123456789012:instance-profile/eks-used": {
				"被 launch template eks-template（lt-1）引用",
			},
			"eks-used": {"被 launch template eks-template（lt-1）引用"},
		},
		RoleNodegroups: map[string][]string{
			"arn:aws:iam::123456789012:role/node-role": {"cluster cluster-a / nodegroup ng-a"},
		},
		Warnings:       []string{"部分模板版本读取失败"},
		EKSUnavailable: true,
	}
}

// TestProfileUsageEvidenceSaveLoadRoundTrip 保证快照能完整往返：三个 JSONB
// 列（含空值与 nil map）都要原样恢复，available() 才不会误判。
func TestProfileUsageEvidenceSaveLoadRoundTrip(t *testing.T) {
	database, _ := newUsageEvidenceTestDB(t)
	store, err := NewProfileUsageEvidenceStore(database)
	if err != nil {
		t.Fatalf("NewProfileUsageEvidenceStore: %v", err)
	}

	if err := store.Save(context.Background(), "123456789012", usageSampleResult()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, collectedAt, err := store.Load(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.available() {
		t.Fatalf("loaded evidence should be available")
	}
	if !loaded.isUsed("arn:aws:iam::123456789012:instance-profile/eks-used", "eks-used") {
		t.Fatalf("loaded evidence lost profile references: %#v", loaded.UsedProfiles)
	}
	if !loaded.roleInUse("arn:aws:iam::123456789012:role/node-role") {
		t.Fatalf("loaded evidence lost nodegroup roles: %#v", loaded.RoleNodegroups)
	}
	if len(loaded.Warnings) != 1 {
		t.Fatalf("loaded warnings = %v, want 1 entry", loaded.Warnings)
	}
	if !loaded.EKSUnavailable {
		t.Fatalf("loaded evidence lost EKSUnavailable flag")
	}
	if collectedAt.IsZero() {
		t.Fatalf("collectedAt should be set")
	}

	// 空结果（账号没有任何 launch template 引用）也是有效证据，不许存成
	// 「解析失败」的 nil map。
	empty := profileUsageResult{
		UsedProfiles:   map[string][]string{},
		RoleNodegroups: map[string][]string{},
	}
	if err := store.Save(context.Background(), "999999999999", empty); err != nil {
		t.Fatalf("Save empty: %v", err)
	}
	loadedEmpty, _, err := store.Load(context.Background(), "999999999999")
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if !loadedEmpty.available() {
		t.Fatalf("empty evidence must stay available (nil maps mean failure)")
	}
	if loadedEmpty.EKSUnavailable {
		t.Fatalf("EKSUnavailable must default to false")
	}

	if _, _, err := store.Load(context.Background(), "111111111111"); !errors.Is(err, ErrProfileUsageEvidenceNotFound) {
		t.Fatalf("missing account error = %v, want ErrProfileUsageEvidenceNotFound", err)
	}
}

// TestStoredResolverPrefersDatabaseSnapshot 复现「页面读库」的契约：
// 有快照时完全不实时回源，并带上新鲜度提示。
func TestStoredResolverPrefersDatabaseSnapshot(t *testing.T) {
	database, _ := newUsageEvidenceTestDB(t)
	store, err := NewProfileUsageEvidenceStore(database)
	if err != nil {
		t.Fatalf("NewProfileUsageEvidenceStore: %v", err)
	}
	if err := store.Save(context.Background(), "123456789012", usageSampleResult()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	live := &liveUsageStub{}
	resolver, err := NewStoredProfileUsageResolver(store, live, nil)
	if err != nil {
		t.Fatalf("NewStoredProfileUsageResolver: %v", err)
	}

	result, err := resolver.ResolveUsedProfiles(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("ResolveUsedProfiles: %v", err)
	}
	if live.calls != 0 {
		t.Fatalf("snapshot hit must not call live resolver (calls=%d)", live.calls)
	}
	if !result.isUsed("eks-used", "") {
		t.Fatalf("snapshot result lost profile references")
	}
	if len(result.Warnings) != 2 {
		t.Fatalf("snapshot should append freshness warning, warnings=%v", result.Warnings)
	}
}

// TestStoredResolverFallsBackAndPersists 没有快照时实时回源，并把结果
// 落库，下次命中。
func TestStoredResolverFallsBackAndPersists(t *testing.T) {
	database, _ := newUsageEvidenceTestDB(t)
	store, err := NewProfileUsageEvidenceStore(database)
	if err != nil {
		t.Fatalf("NewProfileUsageEvidenceStore: %v", err)
	}
	live := &liveUsageStub{result: usageSampleResult()}
	resolver, err := NewStoredProfileUsageResolver(store, live, nil)
	if err != nil {
		t.Fatalf("NewStoredProfileUsageResolver: %v", err)
	}

	result, err := resolver.ResolveUsedProfiles(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if live.calls != 1 {
		t.Fatalf("first resolve should hit live resolver (calls=%d)", live.calls)
	}
	if !result.isUsed("eks-used", "") {
		t.Fatalf("live result lost profile references")
	}

	// 第二次：落库成功后不再回源。
	live.calls = 0
	if _, err := resolver.ResolveUsedProfiles(context.Background(), "123456789012"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if live.calls != 0 {
		t.Fatalf("persisted result must serve subsequent reads (calls=%d)", live.calls)
	}
}

// TestStoredResolverLiveErrorNotCachedAsSnapshot 实时回源失败时不落库，
// 后续调用仍会重试（短命的瞬断不该被钉死成永久快照）。
func TestStoredResolverLiveErrorNotCachedAsSnapshot(t *testing.T) {
	database, _ := newUsageEvidenceTestDB(t)
	store, err := NewProfileUsageEvidenceStore(database)
	if err != nil {
		t.Fatalf("NewProfileUsageEvidenceStore: %v", err)
	}
	live := &liveUsageStub{err: errors.New("sts assume failed")}
	resolver, err := NewStoredProfileUsageResolver(store, live, nil)
	if err != nil {
		t.Fatalf("NewStoredProfileUsageResolver: %v", err)
	}
	if _, err := resolver.ResolveUsedProfiles(context.Background(), "123456789012"); err == nil {
		t.Fatalf("expected live error to propagate")
	}
	if _, _, err := store.Load(context.Background(), "123456789012"); !errors.Is(err, ErrProfileUsageEvidenceNotFound) {
		t.Fatalf("failed resolution must not be persisted (err=%v)", err)
	}
}

// TestSyncConfiguredAccountStoresProfileUsageEvidence 同步收尾应把在用性
// 证据 UPSERT 进库：清理页从此直接读库。采集失败不拖垮同步本身。
func TestSyncConfiguredAccountStoresProfileUsageEvidence(t *testing.T) {
	database, _ := newUsageEvidenceTestDB(t)
	store, err := NewProfileUsageEvidenceStore(database)
	if err != nil {
		t.Fatalf("NewProfileUsageEvidenceStore: %v", err)
	}
	eksFake := &usageFakeEKS{}
	ec2Fake := &usageFakeEC2{}

	repository := &fakeAWSAssetRepository{
		configuredAccount: model.AWSAccount{ID: 34, AccountID: "123456789012"},
	}
	collector := newTestAWSCollector(t, &fakeOrganizationsClient{}, &fakeSTSClient{},
		&fakeIAMClient{}, repository)
	if err := collector.EnableProfileUsageCollection(store); err != nil {
		t.Fatalf("EnableProfileUsageCollection: %v", err)
	}
	collector.usageEKSFactory = func(aws.Config) eksUsageAPI { return eksFake }
	collector.usageEC2Factory = func(aws.Config) ec2UsageAPI { return ec2Fake }

	roleARN := "arn:aws:iam::123456789012:role/readonly"
	if _, _, err := collector.SyncConfiguredAccount(context.Background(), model.AWSAccountConfig{
		ID: 5, AWSAccountID: "123456789012", DisplayName: "configured",
		ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncAssumeRole, SyncEnabled: true,
	}); err != nil {
		t.Fatalf("SyncConfiguredAccount: %v", err)
	}
	if eksFake.describeNodegroupCalls == 0 || ec2Fake.versionCalls == 0 {
		t.Fatalf("sync should collect profile usage evidence (eks=%d ec2=%d)",
			eksFake.describeNodegroupCalls, ec2Fake.versionCalls)
	}
	loaded, _, err := store.Load(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("evidence not stored by sync: %v", err)
	}
	if !loaded.isUsed("eks-used", "") {
		t.Fatalf("stored evidence lost profile references: %#v", loaded.UsedProfiles)
	}
}

// TestProfileUsageEvidenceSaveNilWarnings 回归：nil 切片会被 json.Marshal
// 编码成 null，违反 iam_profile_usage_evidence_object_check（要求 array）。
// 这个 bug 曾让回源后的落库全部静默失败。
func TestProfileUsageEvidenceSaveNilWarnings(t *testing.T) {
	database, _ := newUsageEvidenceTestDB(t)
	store, err := NewProfileUsageEvidenceStore(database)
	if err != nil {
		t.Fatalf("NewProfileUsageEvidenceStore: %v", err)
	}
	result := usageSampleResult()
	result.Warnings = nil // 真实回源成功时 warnings 常为 nil
	if err := store.Save(context.Background(), "123456789012", result); err != nil {
		t.Fatalf("Save with nil warnings: %v", err)
	}
}
