package service

import (
	stdcontext "context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
)

// newMergeTestDB 把 fake driver 包成 *sql.DB。
func newMergeTestDB(fake *publishFakeDB) *sql.DB {
	return sql.OpenDB(fake)
}

// mergeFakeHost 按编号返回预置的 PR 状态，可注入错误。
type mergeFakeHost struct {
	statuses map[string]*githost.MergeRequestStatus
	err      error
	fetched  []string
}

func (fake *mergeFakeHost) FetchMergeRequest(
	_ stdcontext.Context, project, number string,
) (*githost.MergeRequestStatus, error) {
	fake.fetched = append(fake.fetched, number)
	if fake.err != nil {
		return nil, fake.err
	}
	return fake.statuses[number], nil
}

// mergeFakeCleaner 记录删除请求，可注入失败。
type mergeFakeCleaner struct {
	deleted []string
	err     error
}

func (fake *mergeFakeCleaner) DeleteBranch(_ stdcontext.Context, branch string) error {
	if fake.err != nil {
		return fake.err
	}
	fake.deleted = append(fake.deleted, branch)
	return nil
}

func newMergeTestService(
	db *publishFakeDB,
	host *mergeFakeHost,
	cleaner *mergeFakeCleaner,
) *BaselinePublicationMergeService {
	return NewBaselinePublicationMergeService(newMergeTestDB(db), host, "acme/infra", cleaner, nil)
}

func TestReconcileMergedMarksAndDeletesBranch(t *testing.T) {
	db := &publishFakeDB{}
	db.addOnce("FROM iam_baseline_publication", []string{"id", "branch", "remote_request_number", "keep_branch"}, [][]driver.Value{
		{int64(3), "baseline/111122223333/27", "38", false},
		{int64(4), "baseline/111122223333/28", "39", true},
	})
	host := &mergeFakeHost{statuses: map[string]*githost.MergeRequestStatus{
		"38": {State: githost.MergeStateMerged, MergeCommit: "abc123"},
		"39": {State: githost.MergeStateMerged},
	}}
	cleaner := &mergeFakeCleaner{}
	mergeService := newMergeTestService(db, host, cleaner)

	merged, deleted, err := mergeService.ReconcileMerged(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	if merged != 2 || deleted != 1 {
		t.Fatalf("merged = %d, deleted = %d; want 2 / 1", merged, deleted)
	}
	if len(cleaner.deleted) != 1 || cleaner.deleted[0] != "baseline/111122223333/27" {
		t.Errorf("deleted branches = %v; want only keep_branch=false one", cleaner.deleted)
	}
	if got := db.execCount("SET status = $2, updated_at = NOW()"); got != 2 {
		t.Errorf("MERGED updates = %d, want 2", got)
	}
	if got := db.execCount("SET status = $2, error = $3"); got != 0 {
		t.Errorf("unexpected CLOSED updates = %d", got)
	}
}

func TestReconcileMergedSkipsOpenAndRecordsClosed(t *testing.T) {
	db := &publishFakeDB{}
	db.addOnce("FROM iam_baseline_publication", []string{"id", "branch", "remote_request_number", "keep_branch"}, [][]driver.Value{
		{int64(5), "baseline/111122223333/30", "40", false},
		{int64(6), "baseline/111122223333/31", "41", false},
	})
	host := &mergeFakeHost{statuses: map[string]*githost.MergeRequestStatus{
		"40": {State: githost.MergeStateOpen},
		"41": {State: githost.MergeStateClosed},
	}}
	cleaner := &mergeFakeCleaner{}
	mergeService := newMergeTestService(db, host, cleaner)

	merged, deleted, err := mergeService.ReconcileMerged(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	if merged != 0 || deleted != 0 {
		t.Fatalf("merged = %d, deleted = %d; want 0 / 0", merged, deleted)
	}
	if got := db.execCount("SET status = $2, error = $3"); got != 1 {
		t.Errorf("CLOSED updates = %d, want 1", got)
	}
	if len(cleaner.deleted) != 0 {
		t.Errorf("closed PR must not delete branch, deleted = %v", cleaner.deleted)
	}
}

func TestReconcileMergedToleratesFetchErrorAndMissingPR(t *testing.T) {
	db := &publishFakeDB{}
	db.addOnce("FROM iam_baseline_publication", []string{"id", "branch", "remote_request_number", "keep_branch"}, [][]driver.Value{
		{int64(7), "baseline/1/1", "50", false},
		{int64(8), "baseline/2/2", "51", false},
	})
	host := &mergeFakeHost{
		err: errors.New("rate limited"),
		statuses: map[string]*githost.MergeRequestStatus{
			// "51" 未命中 map → FetchMergeRequest 返回 nil（远端查不到）。
			"__none__": {State: githost.MergeStateOpen},
		},
	}
	cleaner := &mergeFakeCleaner{}
	mergeService := newMergeTestService(db, host, cleaner)

	merged, deleted, err := mergeService.ReconcileMerged(stdcontext.Background())
	if err != nil {
		t.Fatalf("single fetch failure must not fail the round: %v", err)
	}
	if merged != 0 || deleted != 0 {
		t.Fatalf("merged = %d, deleted = %d; want 0 / 0", merged, deleted)
	}
	if got := db.execCount("SET status = $2, updated_at = NOW()"); got != 0 {
		t.Errorf("unexpected MERGED updates = %d", got)
	}
}

func TestReconcileMergedBranchDeletionFailureKeepsStatusUpdate(t *testing.T) {
	db := &publishFakeDB{}
	db.addOnce("FROM iam_baseline_publication", []string{"id", "branch", "remote_request_number", "keep_branch"}, [][]driver.Value{
		{int64(9), "baseline/3/3", "52", false},
	})
	host := &mergeFakeHost{statuses: map[string]*githost.MergeRequestStatus{
		"52": {State: githost.MergeStateMerged},
	}}
	cleaner := &mergeFakeCleaner{err: errors.New("forbidden")}
	mergeService := newMergeTestService(db, host, cleaner)

	merged, deleted, err := mergeService.ReconcileMerged(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	if merged != 1 || deleted != 0 {
		t.Fatalf("merged = %d, deleted = %d; want 1 / 0 (status first, deletion best effort)", merged, deleted)
	}
	if got := db.execCount("SET status = $2, updated_at = NOW()"); got != 1 {
		t.Errorf("MERGED updates = %d, want 1", got)
	}
}

// TestReconcileClosedVoidsDeclarations 基线 PR 关闭未合并（发布被拒）= 这次
// 发布从未进 main：声明必须撤回，并把被它取代的上一条有效声明恢复回来。
// 不撤，漂移检测会拿一份幽灵意图当基准，把线上正确的资源全报成被改坏。
func TestReconcileClosedVoidsDeclarations(t *testing.T) {
	db := &publishFakeDB{}
	db.addOnce("FROM iam_baseline_publication", []string{
		"id", "branch", "remote_request_number", "keep_branch",
	}, [][]driver.Value{
		{int64(6), "baseline/111122223333/31", "41", false},
	})
	db.queries = append(db.queries, inventoryFakeResponse{
		match:   "WHERE publication_id = $1 AND superseded_at IS NULL",
		columns: []string{"id", "account_id", "resource_key", "file_key"},
		rows: [][]driver.Value{
			{int64(2001), int64(7), "role:app", "role-app"},
		},
	})
	db.addOnce("ORDER BY (file_key = $3) DESC", []string{"id"}, [][]driver.Value{{int64(1900)}})

	host := &mergeFakeHost{statuses: map[string]*githost.MergeRequestStatus{
		"41": {State: githost.MergeStateClosed},
	}}
	mergeService := newMergeTestService(db, host, &mergeFakeCleaner{})

	merged, deleted, err := mergeService.ReconcileMerged(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	if merged != 0 || deleted != 0 {
		t.Fatalf("closed PR must not count as merged: %d / %d", merged, deleted)
	}
	if got := db.queryCount("WHERE publication_id = $1 AND superseded_at IS NULL"); got != 1 {
		t.Fatalf("declaration voids for closed publication = %d, want 1", got)
	}
	if got := db.execCount("superseded_reason = 'VOIDED'"); got != 1 {
		t.Errorf("voided rows = %d, want 1", got)
	}
	if got := db.execCount("SET superseded_at = NULL, superseded_reason = NULL"); got != 1 {
		t.Errorf("restored rows = %d, want 1", got)
	}
}
