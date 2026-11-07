package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// TestPublishedTicketRecordsDeclarations 工单发布成功即落声明快照（P2b）：
// 声明集合是「基线 ∪ 成功工单」，工单这一半从发布内容反解。落库时带
// ticket_id（废弃关单据此作废）与文件 blob SHA（baseline_stale 核对）。
func TestPublishedTicketRecordsDeclarations(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarationService, err := NewBaselineDeclarationService(database, nil)
	if err != nil {
		t.Fatalf("new declaration service: %v", err)
	}

	repository := newMemoryTicketRepository()
	publisher := &memoryTicketPublisher{url: "https://gitlab.example/group/iac/-/merge_requests/34"}
	service, err := NewTicketService(repository, publisher, nil,
		WithBaselineDeclarations(declarationService))
	if err != nil {
		t.Fatalf("NewTicketService() error = %v", err)
	}
	ctx := context.Background()

	ticket, err := service.CreateTicket(ctx, "requester", validTicketRequest())
	if err != nil {
		t.Fatalf("CreateTicket() error = %v", err)
	}
	if _, err := service.Decide(ctx, *ticket.TicketNo, "alice", TicketDecision{Result: "APPROVE", Comment: "ok"}); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	published, err := service.Decide(ctx, *ticket.TicketNo, "bob", TicketDecision{Result: "APPROVE", Comment: "ok"})
	if err != nil {
		t.Fatalf("final approval: %v", err)
	}
	if published.GitPRURL == nil {
		t.Fatal("ticket was not published")
	}

	inserts := 0
	var resourceKeys []string
	var ticketIDArg any
	for _, record := range fake.records {
		if !strings.Contains(record.query, "INSERT INTO iam_baseline_declaration") {
			continue
		}
		inserts++
		if key, ok := record.args[5].(string); ok {
			resourceKeys = append(resourceKeys, key)
		}
		ticketIDArg = record.args[3]
	}
	if inserts == 0 {
		t.Fatal("published ticket recorded no declarations")
	}
	if ticketIDArg == nil {
		t.Errorf("ticket declarations must carry the ticket id, got %v", ticketIDArg)
	}
	wantRole := "role:billing-reader"
	found := false
	for _, key := range resourceKeys {
		if key == wantRole {
			found = true
		}
	}
	if !found {
		t.Errorf("declarations = %v, want %s", resourceKeys, wantRole)
	}
	for _, record := range fake.records {
		if !strings.Contains(record.query, "SET superseded_at = NOW()") {
			continue
		}
		if len(record.args) != 3 {
			t.Fatalf("supersede must be scoped by files/resources, got args %v", record.args)
		}
		break
	}
}

// TestCloseAbandonedVoidsTicketDeclarations 废弃 = PR 关闭未合并，这张工单
// 什么都没落地：它的声明必须撤回，否则漂移基准拿一份从未进 main 的意图
// 去比对，会把实态里正确的资源全报成「被改回去了」。
func TestCloseAbandonedVoidsTicketDeclarations(t *testing.T) {
	fake := &publishFakeDB{}
	// 作废先在事务里把这张工单的「当前」声明查出来（FOR UPDATE），再逐行
	// 打 VOIDED 标记。
	fake.queries = append(fake.queries, inventoryFakeResponse{
		match:   "WHERE ticket_id = $1 AND superseded_at IS NULL",
		columns: []string{"id", "account_id", "resource_key", "file_key"},
		rows: [][]driver.Value{
			{int64(1001), int64(7), "role:app", "role-app"},
		},
	})
	database := sql.OpenDB(fake)
	defer database.Close()
	declarationService, _ := NewBaselineDeclarationService(database, nil)

	ticketNo := "IAM-ABANDON"
	status := TicketStatusApproved
	repository := newMemoryTicketRepository()
	repository.tickets[ticketNo] = ticketWithID(41, ticketNo, status)

	service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
		WithBaselineDeclarations(declarationService))
	if err != nil {
		t.Fatalf("NewTicketService() error = %v", err)
	}
	if _, err := service.CloseTicket(context.Background(), ticketNo, "admin",
		ClosureReasonAbandoned, "superseded by another change", false); err != nil {
		t.Fatalf("CloseTicket() error = %v", err)
	}

	if got := fake.queryCount("WHERE ticket_id = $1 AND superseded_at IS NULL"); got != 1 {
		t.Fatalf("declaration void queries = %d, want 1", got)
	}
	if args := fake.recordedQuery("WHERE ticket_id = $1 AND superseded_at IS NULL"); len(args) != 1 ||
		args[0] != int64(41) {
		t.Fatalf("void query args = %v, want the ticket id 41", args)
	}
	voids := 0
	for _, record := range fake.records {
		if !strings.Contains(record.query, "SET superseded_at = NOW(), superseded_reason = 'VOIDED'") {
			continue
		}
		voids++
		if got, _ := record.args[0].(int64); got != 1001 {
			t.Errorf("voided declaration id = %v, want 1001", record.args[0])
		}
	}
	if voids != 1 {
		t.Fatalf("declaration voids = %d, want 1", voids)
	}
}

// TestCloseAppliedKeepsTicketDeclarations APPLIED 关单代表已合并生效：声明
// 保留，只释放预约。
func TestCloseAppliedKeepsTicketDeclarations(t *testing.T) {
	fake := &publishFakeDB{}
	database := sql.OpenDB(fake)
	defer database.Close()
	declarationService, _ := NewBaselineDeclarationService(database, nil)

	ticketNo := "IAM-APPLIED"
	status := TicketStatusApproved
	repository := newMemoryTicketRepository()
	repository.tickets[ticketNo] = ticketWithID(42, ticketNo, status)

	service, err := NewTicketService(repository, &memoryTicketPublisher{}, nil,
		WithBaselineDeclarations(declarationService))
	if err != nil {
		t.Fatalf("NewTicketService() error = %v", err)
	}
	if _, err := service.CloseTicket(context.Background(), ticketNo, "admin",
		ClosureReasonApplied, "", false); err != nil {
		t.Fatalf("CloseTicket() error = %v", err)
	}
	if got := fake.queryCount("WHERE ticket_id = $1 AND superseded_at IS NULL"); got != 0 {
		t.Fatalf("applied close must keep the declarations, got %d void queries", got)
	}
	for _, record := range fake.records {
		if strings.Contains(record.query, "superseded_reason = 'VOIDED'") {
			t.Fatalf("applied close must keep the declarations, got %s", record.query)
		}
	}
}

func ticketWithID(id int64, ticketNo, status string) model.IAMTicket {
	ticket := model.IAMTicket{
		ID:       id,
		TicketNo: stringPointer(ticketNo),
		Status:   stringPointer(status),
	}
	accountID := int64(7)
	ticket.AccountID = &accountID
	return ticket
}
