package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakeAuditQueryService struct {
	listEvents []service.AuditEventView
	listTotal  int
	lastFilter service.AuditEventFilter
	exported   []service.AuditEventView
	lastActor  string
	exportErr  error
	listErr    error
}

func (fake *fakeAuditQueryService) ListAuditEvents(
	ctx context.Context,
	filter service.AuditEventFilter,
) ([]service.AuditEventView, int, error) {
	fake.lastFilter = filter
	return fake.listEvents, fake.listTotal, fake.listErr
}

func (fake *fakeAuditQueryService) ExportAuditEvents(
	ctx context.Context,
	filter service.AuditEventFilter,
	exportedBy string,
) ([]service.AuditEventView, error) {
	fake.lastFilter, fake.lastActor = filter, exportedBy
	return fake.exported, fake.exportErr
}

func newTestAuditRouter(t *testing.T, fake *fakeAuditQueryService, user, role string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewAuditHandler(fake)
	if err != nil {
		t.Fatalf("NewAuditHandler() error = %v", err)
	}
	router := gin.New()
	if user != "" {
		router.Use(func(context *gin.Context) {
			context.Set(AuthenticatedUserContextKey, user)
			context.Set(AuthenticatedRolesContextKey, []string{role})
		})
	}
	RegisterAuditRoutes(router, handler)
	return router
}

func TestAuditListPassesFiltersAndEnvelope(t *testing.T) {
	fake := &fakeAuditQueryService{
		listEvents: []service.AuditEventView{
			{ID: 5, Action: "TICKET_CREATED", ResourceType: "iam_ticket", Outcome: "SUCCESS"},
		},
		listTotal: 9,
	}
	router := newTestAuditRouter(t, fake, "example-org", "platform_admin")
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	query := "/audit/events?actor_id=example-org&action=TICKET_CREATED&outcome=SUCCESS" +
		"&from=" + from.Format(time.RFC3339) + "&limit=50&offset=10"
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	filter := fake.lastFilter
	if filter.ActorID != "example-org" || filter.Action != "TICKET_CREATED" ||
		filter.Outcome != "SUCCESS" || filter.Limit != 50 || filter.Offset != 10 ||
		filter.From == nil || !filter.From.Equal(from) {
		t.Fatalf("filter = %+v", filter)
	}
	var payload struct {
		Events []service.AuditEventView `json:"events"`
		Total  int                      `json:"total"`
		Limit  int                      `json:"limit"`
		Offset int                      `json:"offset"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Total != 9 || payload.Limit != 50 || payload.Offset != 10 || len(payload.Events) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestAuditListRejectsInvalidQuery(t *testing.T) {
	fake := &fakeAuditQueryService{listErr: service.ErrInvalidAuditOutcome}
	router := newTestAuditRouter(t, fake, "example-org", "platform_admin")
	for _, test := range []struct {
		query string
	}{
		{query: "outcome=MAYBE"},                                     // service-level rejection
		{query: "from=not-a-time"},                                   // malformed timestamp
		{query: "from=2026-10-02T00:00:00Z&to=2026-10-01T00:00:00Z"}, // from after to
		{query: "limit=0"},
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit/events?"+test.query, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("query %q status = %d, want 400; body=%s", test.query, recorder.Code, recorder.Body)
		}
	}
}

func TestAuditExportRecordsActorAndAttachment(t *testing.T) {
	fake := &fakeAuditQueryService{
		exported: []service.AuditEventView{{ID: 1, Action: "AUDIT_EVENTS_EXPORTED"}},
	}
	router := newTestAuditRouter(t, fake, "example-org", "platform_admin")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit/events/export?outcome=FAILURE", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastActor != "example-org" {
		t.Fatalf("export actor = %q, want example-org", fake.lastActor)
	}
	if fake.lastFilter.Outcome != "FAILURE" {
		t.Fatalf("filter = %+v", fake.lastFilter)
	}
	if disposition := recorder.Header().Get("Content-Disposition"); !strings.Contains(disposition, "audit-events.json") {
		t.Fatalf("Content-Disposition = %q", disposition)
	}
	var payload struct {
		Events []service.AuditEventView `json:"events"`
		Count  int                      `json:"count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Count != 1 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestAuditRoutesRequirePlatformAdmin(t *testing.T) {
	// standard_user passes authentication but lacks the role.
	fake := &fakeAuditQueryService{}
	router := newTestAuditRouter(t, fake, "reader@example.com", "standard_user")
	for _, path := range []string{"/audit/events", "/audit/events/export"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", path, recorder.Code)
		}
	}

	// Unauthenticated.
	router = newTestAuditRouter(t, fake, "", "")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit/events", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", recorder.Code)
	}
}
