package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDriftNotifierPostsFindings webhook 是对外契约：字段名必须与 API 一致，
// 使用方不该为了告警再去看一遍文档。
func TestDriftNotifierPostsFindings(t *testing.T) {
	received := make(chan driftWebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		var payload driftWebhookPayload
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		received <- payload
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notifier := NewDriftNotifier(server.URL, nil)
	notifier.Notify("drift.detected", []DriftFinding{{
		ID: 5, AWSAccountID: "111122223333", Source: DriftSourceInventory,
		ResourceKey: "role:foo", ChangeType: DriftChangeAttribute,
		Severity: DriftSeverityHigh, Status: DriftStatusOpen,
		Fields: []DriftFieldDiff{{Field: "trust_policy", Declared: "a", Live: "b"}},
	}})

	select {
	case payload := <-received:
		if payload.Event != "drift.detected" || payload.Total != 1 || len(payload.Findings) != 1 {
			t.Fatalf("payload = %+v", payload)
		}
		if payload.Findings[0].ResourceKey != "role:foo" ||
			payload.Findings[0].Fields[0].Field != "trust_policy" {
			t.Fatalf("finding not preserved: %+v", payload.Findings[0])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not delivered")
	}
}

// TestDriftNotifierTruncatesBulkFindings 一次判定可能冒出上百条：接收方不该被
// 一条消息打爆，但必须知道被截断了。
func TestDriftNotifierTruncatesBulkFindings(t *testing.T) {
	received := make(chan driftWebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload driftWebhookPayload
		_ = json.NewDecoder(request.Body).Decode(&payload)
		received <- payload
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	findings := make([]DriftFinding, driftWebhookMaxFindings+7)
	for index := range findings {
		findings[index] = DriftFinding{ID: int64(index + 1), ResourceKey: "role:x"}
	}
	NewDriftNotifier(server.URL, nil).Notify("drift.detected", findings)

	select {
	case payload := <-received:
		if !payload.Truncated {
			t.Fatal("truncated flag must be set")
		}
		if payload.Total != len(findings) || len(payload.Findings) != driftWebhookMaxFindings {
			t.Fatalf("total = %d, delivered = %d", payload.Total, len(payload.Findings))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not delivered")
	}
}

// TestDriftNotifierDisabledIsNil 未配置时构造出 nil，调用方不需要判断「有没有
// 配 webhook」——空 URL 不是错误。
func TestDriftNotifierDisabledIsNil(t *testing.T) {
	if NewDriftNotifier("  ", nil) != nil {
		t.Fatal("blank url must disable the notifier")
	}
	// nil 接收者调用必须安全：判定路径不该因为没配 webhook 而 panic。
	var notifier *DriftNotifier
	notifier.Notify("drift.detected", []DriftFinding{{ID: 1}})
}
