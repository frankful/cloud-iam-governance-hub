package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"log/slog"
	"strings"
	"testing"
)

// TestRecordPublishConflictsWritesFindings 归属冲突是「这个文件归谁」这个
// 待办，不是一个 error 字符串。文件名（含 .tf）必须先归一成 file key，否则
// 同一份冲突会按两种键各存一条。
func TestRecordPublishConflictsWritesFindings(t *testing.T) {
	fake := &publishFakeDB{}
	fake.addOnce("SELECT account_id, aws_account_id FROM iam_baseline_publication",
		[]string{"account_id", "aws_account_id"},
		[][]driver.Value{{int64(7), "111122223333"}})
	fake.addOnce("INSERT INTO iam_drift_finding", []string{"id"}, [][]driver.Value{{int64(31)}})
	fake.addOnce("INSERT INTO iam_drift_finding", []string{"id"}, [][]driver.Value{{int64(32)}})

	database := sql.OpenDB(fake)
	defer database.Close()
	service := &DriftService{db: database, logger: slog.Default()}

	err := service.RecordPublishConflicts(context.Background(), 4,
		[]string{"role-app.tf", "role-app", "policy-demo.tf"}, "2 file(s) not owned by baseline")
	if err != nil {
		t.Fatalf("RecordPublishConflicts: %v", err)
	}
	// 三个输入 → 两个 file key（role-app 的两种写法合并）。insertFinding 用
	// QueryRow（RETURNING id），因此断言对象是 statements 而不是 execs。
	if count := fake.queryCount("INSERT INTO iam_drift_finding"); count != 2 {
		t.Fatalf("insert count = %d, want 2", count)
	}
	var keys []string
	for _, statement := range fake.statements {
		if !strings.Contains(statement.query, "INSERT INTO iam_drift_finding") {
			continue
		}
		keys = append(keys, statement.args[3].(string))
	}
	joined := strings.Join(keys, ",")
	if !strings.Contains(joined, "file:policy-demo") || !strings.Contains(joined, "file:role-app") {
		t.Fatalf("resource keys = %v", keys)
	}
}

// TestResolvePublishConflictsClosesAccountFindings 发布成功即证明归属已谈妥：
// 关闭范围必须限定在该 publication 的账号，不能波及别的账号。
func TestResolvePublishConflictsClosesAccountFindings(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	service := &DriftService{db: database, logger: slog.Default()}

	if err := service.ResolvePublishConflicts(context.Background(), 4); err != nil {
		t.Fatalf("ResolvePublishConflicts: %v", err)
	}
	if count := fake.execCount("UPDATE iam_drift_finding"); count != 1 {
		t.Fatalf("update count = %d, want 1", count)
	}
	var args []driver.Value
	for _, record := range fake.records {
		if strings.Contains(record.query, "UPDATE iam_drift_finding") {
			args = record.args
		}
	}
	if len(args) != 2 || args[0].(int64) != 4 || args[1].(string) != DriftSourcePublish {
		t.Fatalf("args = %v", args)
	}
}
