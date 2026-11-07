package service

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestBaselineDeclarationSaveSupersedesThenInserts 声明快照的写入语义：
// 先把该账号的「当前」声明整体作废（保留历史），再插入本次声明。
// 不做 upsert——资源被移除时也必须从基准里消失，否则漂移检测会一直比对
// 一个已经不存在的资源。
func TestBaselineDeclarationSaveSupersedesThenInserts(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, err := NewBaselineDeclarationService(database, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	publication := int64(41)
	err = declarations.Save(context.Background(), DeclarationTarget{
		AccountDBID:   7,
		AWSAccountID:  "123456789012",
		SyncRunID:     88,
		PublicationID: &publication,
		Declarations: []BaselineDeclaration{
			{ResourceKey: "role:app", FileKey: "role-app", Kind: "role", Name: "app",
				Attributes: []byte(`{"path":"/"}`), ContentBlobSHA: "abc"},
			{ResourceKey: "policy:logs", FileKey: "policy-logs", Kind: "policy", Name: "logs",
				Attributes: []byte(`{}`)},
		},
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if fake.execCount("SET superseded_at = NOW()") != 1 {
		t.Errorf("previous declarations must be superseded exactly once")
	}
	// 作废范围必须是「这批文件 + 这批资源」，不是账号级：基线声明与工单
	// 声明共享同一张表，账号级作废会让一次基线发布抹掉所有工单声明。
	for _, record := range fake.records {
		if !strings.Contains(record.query, "SET superseded_at = NOW()") {
			continue
		}
		if len(record.args) != 3 {
			t.Fatalf("supersede args = %v, want account + file keys + resource keys", record.args)
		}
		fileKeys, ok := record.args[1].([]string)
		if !ok || len(fileKeys) != 2 {
			t.Fatalf("superseded file keys = %v, want the two published files", record.args[1])
		}
		resourceKeys, ok := record.args[2].([]string)
		if !ok || len(resourceKeys) != 2 {
			t.Fatalf("superseded resource keys = %v, want the two declared resources", record.args[2])
		}
	}
	inserts := 0
	var firstArgs []string
	for _, record := range fake.records {
		if !strings.Contains(record.query, "INSERT INTO iam_baseline_declaration") {
			continue
		}
		inserts++
		if firstArgs == nil {
			for _, arg := range record.args {
				if text, ok := arg.(string); ok {
					firstArgs = append(firstArgs, text)
				}
			}
		}
	}
	if inserts != 2 {
		t.Fatalf("inserts = %d, want 2", inserts)
	}
	joined := strings.Join(firstArgs, "|")
	for _, want := range []string{"role:app", "role-app", "123456789012", "abc"} {
		if !strings.Contains(joined, want) {
			t.Errorf("insert args missing %q: %s", want, joined)
		}
	}
}

// TestBaselineDeclarationSaveIgnoresEmpty 空声明不覆盖既有基准：本轮没发布
// 任何文件 ≠ 什么都没声明。抹掉基准会让漂移检测失去比对依据。
func TestBaselineDeclarationSaveIgnoresEmpty(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	if err := declarations.Save(context.Background(), DeclarationTarget{AccountDBID: 7}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(fake.records) != 0 {
		t.Fatalf("empty declaration set must not touch the table, got %d statements",
			len(fake.records))
	}
}

// TestRecordDeclarationsVoidsEmptiedFile 「零声明」的发布同样是声明：回滚
// 把文件清空、移除最后一名成员把 membership 文件清空之后，旧声明必须按
// 文件作废——否则漂移检测会一直比对一份 main 上已经不存在的意图。
func TestRecordDeclarationsVoidsEmptiedFile(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	err := declarations.RecordDeclarations(context.Background(), DeclarationTarget{
		AccountDBID:  7,
		AWSAccountID: "123456789012",
		TouchedFiles: []string{"group-devs-membership"},
	}, []BaselineBundleFile{
		{Key: "group-devs-membership", FileName: "group-devs-membership.tf",
			Content: "# GROUP MEMBERSHIP emptied by rollback ticket IAM-1\n"},
	})
	if err != nil {
		t.Fatalf("RecordDeclarations: %v", err)
	}
	if fake.execCount("INSERT INTO iam_baseline_declaration") != 0 {
		t.Error("an emptied file must not insert declarations")
	}
	if fake.execCount("SET superseded_at = NOW()") != 1 {
		t.Fatal("an emptied file must still supersede its previous declarations")
	}
	for _, record := range fake.records {
		if !strings.Contains(record.query, "SET superseded_at = NOW()") {
			continue
		}
		fileKeys, ok := record.args[1].([]string)
		if !ok || len(fileKeys) != 1 || fileKeys[0] != "group-devs-membership" {
			t.Errorf("superseded files = %v, want the emptied file", record.args[1])
		}
	}
}

// TestRecordDeclarationsSkipsFilesNotPublished 让路的文件不能进声明：它们
// 没写进仓库，本轮并没有声明成功；把它们的声明落库会让漂移判定拿一份
// 从未生效的意图当基准。
func TestRecordDeclarationsSkipsFilesNotPublished(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarations, _ := NewBaselineDeclarationService(database, nil)

	publishedContent := "resource \"aws_iam_role\" \"app\" {}\n"
	err := declarations.RecordDeclarations(context.Background(), DeclarationTarget{
		AccountDBID:  7,
		AWSAccountID: "123456789012",
		Declarations: []BaselineDeclaration{
			{ResourceKey: "role:app", FileKey: "role-app", Kind: "role", Name: "app",
				Attributes: []byte(`{}`)},
			{ResourceKey: "role:deferred", FileKey: "role-deferred", Kind: "role", Name: "deferred",
				Attributes: []byte(`{}`)},
		},
	}, []BaselineBundleFile{
		{Key: "role-app", FileName: "role-app.tf", Content: publishedContent},
	})
	if err != nil {
		t.Fatalf("RecordDeclarations: %v", err)
	}

	inserts := 0
	var blobSHA string
	for _, record := range fake.records {
		if !strings.Contains(record.query, "INSERT INTO iam_baseline_declaration") {
			continue
		}
		inserts++
		key, _ := record.args[5].(string)
		if key != "role:app" {
			t.Errorf("unexpected declared resource %q", key)
		}
		blobSHA, _ = record.args[10].(string)
	}
	if inserts != 1 {
		t.Fatalf("inserts = %d, want 1 (deferred file excluded)", inserts)
	}
	if blobSHA != gitBlobSHA(publishedContent) {
		t.Errorf("content_blob_sha = %q, want git blob SHA of the published file", blobSHA)
	}
}
