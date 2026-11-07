package v1

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type memoryAuditWriter struct {
	events []AuditRecord
}

func (writer *memoryAuditWriter) WriteAuditEvent(_ context.Context, event AuditRecord) error {
	writer.events = append(writer.events, event)
	return nil
}

func TestRequestAuditMiddlewareRecordsRouteAndActorWithoutRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	writer := &memoryAuditWriter{}
	router := gin.New()
	router.Use(RequestAuditMiddleware(writer, slog.New(slog.NewTextHandler(httptest.NewRecorder(), nil))))
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Next()
	})
	router.POST("/api/v1/tickets/:ticketNo/decision", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"ok": true})
	})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/tickets/IAM-123/decision", nil)
	request.Header.Set("X-Request-ID", "request-123")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Request-ID"); got != "request-123" {
		t.Errorf("X-Request-ID = %q", got)
	}
	if len(writer.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(writer.events))
	}
	event := writer.events[0]
	if event.ActorID != "admin" || event.Action != "POST /api/v1/tickets/:ticketNo/decision" ||
		event.ResourceID != "IAM-123" || event.Outcome != "SUCCESS" || event.HTTPStatus != http.StatusOK {
		t.Errorf("audit event = %+v", event)
	}
}
