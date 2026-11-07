package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakeDashboardService struct {
	summary service.DashboardSummary
	err     error
}

func (fake *fakeDashboardService) Summary(ctx context.Context) (service.DashboardSummary, error) {
	return fake.summary, fake.err
}

func newTestDashboardRouter(t *testing.T, fake *fakeDashboardService, user, role string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewDashboardHandler(fake)
	if err != nil {
		t.Fatalf("NewDashboardHandler() error = %v", err)
	}
	router := gin.New()
	if user != "" {
		router.Use(func(context *gin.Context) {
			context.Set(AuthenticatedUserContextKey, user)
			context.Set(AuthenticatedRolesContextKey, []string{role})
		})
	}
	RegisterDashboardRoutes(router, handler)
	return router
}

func TestDashboardSummaryReturnsAggregates(t *testing.T) {
	fake := &fakeDashboardService{summary: service.DashboardSummary{
		Tickets:     service.DashboardTickets{Total: 5, ByStatus: map[string]int{"CLOSED": 3, "APPROVING": 1}},
		Risks:       service.DashboardRisks{Open: 2, OpenByLevel: map[string]int{"HIGH": 1}},
		Inventory:   service.DashboardInventory{Users: 40, Roles: 98, Groups: 21},
		GeneratedAt: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
		Sync: service.DashboardSync{
			ConfigsTotal: 1, ConfigsEnabled: 1,
			BySyncStatus:        map[string]int{"SUCCEEDED": 1},
			RunsLast24hByStatus: map[string]int{"SUCCEEDED": 2},
		},
	}}
	router := newTestDashboardRouter(t, fake, "example-org", "platform_admin")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/summary", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	var payload struct {
		Summary service.DashboardSummary `json:"summary"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Summary.Tickets.Total != 5 || payload.Summary.Inventory.Groups != 21 ||
		payload.Summary.Risks.Open != 2 || payload.Summary.Sync.ConfigsEnabled != 1 {
		t.Fatalf("summary = %+v", payload.Summary)
	}
	if payload.Summary.GeneratedAt.IsZero() {
		t.Fatal("generated_at is zero")
	}
}

func TestDashboardSummaryErrorMapsToInternalError(t *testing.T) {
	fake := &fakeDashboardService{err: context.DeadlineExceeded}
	router := newTestDashboardRouter(t, fake, "example-org", "platform_admin")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/summary", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", recorder.Code, recorder.Body)
	}
}

func TestDashboardRouteAccessControl(t *testing.T) {
	fake := &fakeDashboardService{}

	// approval_admin may read the dashboard.
	router := newTestDashboardRouter(t, fake, "approver@example.com", "approval_admin")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/summary", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("approval_admin status = %d, want 200", recorder.Code)
	}

	// standard_user is forbidden.
	router = newTestDashboardRouter(t, fake, "reader@example.com", "standard_user")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/summary", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("standard_user status = %d, want 403", recorder.Code)
	}

	// Unauthenticated.
	router = newTestDashboardRouter(t, fake, "", "")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/summary", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", recorder.Code)
	}
}
