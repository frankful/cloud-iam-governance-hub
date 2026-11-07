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

type cleanupHandlerFake struct {
	report  *service.CleanupReport
	err     error
	account string
}

func (fake *cleanupHandlerFake) Build(_ context.Context, ref string) (*service.CleanupReport, error) {
	fake.account = ref
	return fake.report, fake.err
}

func cleanupTestRouter(handler *CleanupHandler, roles []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "tester")
		context.Set(AuthenticatedRolesContextKey, roles)
	})
	RegisterCleanupRoutes(api, handler)
	return router
}

func TestCleanupRouteRequiresPlatformAdmin(t *testing.T) {
	handler, err := NewCleanupHandler(&cleanupHandlerFake{})
	if err != nil {
		t.Fatal(err)
	}
	router := cleanupTestRouter(handler, []string{"standard_user"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/aws/accounts/123/cleanup-suggestions", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestCleanupReturnsReport(t *testing.T) {
	fake := &cleanupHandlerFake{report: &service.CleanupReport{
		AccountDBID:    1,
		AWSAccountID:   "123456789012",
		GeneratedAt:    time.Unix(0, 0).UTC(),
		Items:          []service.CleanupItem{{Category: service.CleanupCategoryAWSResource, Name: "x"}},
		CategoryCounts: map[string]int{"aws-resource": 1},
	}}
	handler, err := NewCleanupHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := cleanupTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/aws/accounts/123456789012/cleanup-suggestions", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.account != "123456789012" {
		t.Errorf("account ref = %q", fake.account)
	}
	var payload struct {
		Cleanup service.CleanupReport `json:"cleanup"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Cleanup.Items) != 1 || payload.Cleanup.AWSAccountID != "123456789012" {
		t.Errorf("payload = %#v", payload.Cleanup)
	}
}

// 账号不存在要能和「服务内部出错」分开：前者是 404，后者是 500。
func TestCleanupAccountNotFound(t *testing.T) {
	handler, err := NewCleanupHandler(&cleanupHandlerFake{err: service.ErrBaselineAccountNotFound})
	if err != nil {
		t.Fatal(err)
	}
	router := cleanupTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/aws/accounts/does-not-exist/cleanup-suggestions", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}
