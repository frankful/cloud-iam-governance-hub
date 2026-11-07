package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

type publishReservationFake struct {
	reservations []service.PublishReservation
	listFilter   service.PublishReservationFilter
	releaseInput struct {
		channel string
		ref     string
	}
	listErr    error
	releaseErr error
	released   int
}

func (fake *publishReservationFake) List(
	_ context.Context, filter service.PublishReservationFilter,
) ([]service.PublishReservation, error) {
	fake.listFilter = filter
	if fake.listErr != nil {
		return nil, fake.listErr
	}
	return fake.reservations, nil
}

func (fake *publishReservationFake) ReleaseExpiredForAdmin(
	_ context.Context, channel, ref string,
) (int, error) {
	fake.releaseInput.channel = channel
	fake.releaseInput.ref = ref
	if fake.releaseErr != nil {
		return 0, fake.releaseErr
	}
	return fake.released, nil
}

func newPublishReservationTestRouter(t *testing.T, fake *publishReservationFake) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewPublishReservationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterPublishReservationRoutes(api, handler)
	return router
}

// TestPublishReservationRoutesRequirePlatformAdmin 预约表是运维面：普通用户
// 既不该看到「谁占着哪个文件」，也不该能手动释放（释放等于放行两个开放
// PR 源同时写同一文件）。
func TestPublishReservationRoutesRequirePlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewPublishReservationHandler(&publishReservationFake{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "regular-user")
		context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
	})
	RegisterPublishReservationRoutes(api, handler)

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/publish-reservations", ""},
		{http.MethodPost, "/api/v1/publish-reservations/release",
			`{"channel":"ticket","ref":"IAM-1"}`},
	}
	for _, testCase := range cases {
		request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(testCase.body))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s: expected forbidden, got %d", testCase.method, testCase.path, response.Code)
		}
	}
}

func TestPublishReservationListParsesFilters(t *testing.T) {
	fake := &publishReservationFake{
		reservations: []service.PublishReservation{{
			ID: 12, AccountDBID: 7, FileKey: "role-demo",
			Channel: "ticket", Ref: "IAM-1", Status: "OPEN",
			CreatedAt: time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC),
		}},
	}
	router := newPublishReservationTestRouter(t, fake)

	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/publish-reservations?account_id=7&channel=ticket&status=OPEN&limit=20", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	want := service.PublishReservationFilter{
		AccountDBID: 7, Channel: "ticket", Status: "OPEN", Limit: 20,
	}
	if fake.listFilter != want {
		t.Errorf("filter = %+v, want %+v", fake.listFilter, want)
	}
	if !strings.Contains(response.Body.String(), `"file_key":"role-demo"`) {
		t.Errorf("body must carry reservations: %s", response.Body.String())
	}
}

func TestPublishReservationListRejectsBadFilters(t *testing.T) {
	router := newPublishReservationTestRouter(t, &publishReservationFake{})
	cases := []string{
		"?account_id=abc",
		"?account_id=0",
		"?limit=-1",
		"?channel=manual",
		"?status=open",
	}
	for _, query := range cases {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/publish-reservations"+query, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", query, response.Code)
		}
	}
}

func TestPublishReservationReleaseParsesChannelAndRef(t *testing.T) {
	fake := &publishReservationFake{released: 3}
	router := newPublishReservationTestRouter(t, fake)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/publish-reservations/release",
		strings.NewReader(`{"channel":" baseline ","ref":" 42 "}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.releaseInput.channel != service.PublishChannelBaseline ||
		fake.releaseInput.ref != "42" {
		t.Errorf("release input = %+v, want baseline/42", fake.releaseInput)
	}
	if !strings.Contains(response.Body.String(), `"released":3`) {
		t.Errorf("body must report released count: %s", response.Body.String())
	}
}

func TestPublishReservationReleaseRejectsBadBody(t *testing.T) {
	router := newPublishReservationTestRouter(t, &publishReservationFake{})
	cases := []string{
		`{"channel":"manual","ref":"1"}`,
		`{"channel":"ticket","ref":"  "}`,
		`not-json`,
	}
	for _, body := range cases {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/publish-reservations/release",
			strings.NewReader(body))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, response.Code)
		}
	}
}

func TestPublishReservationReleaseSurfacesServiceError(t *testing.T) {
	fake := &publishReservationFake{releaseErr: errors.New("db down")}
	router := newPublishReservationTestRouter(t, fake)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/publish-reservations/release",
		strings.NewReader(`{"channel":"ticket","ref":"IAM-1"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	if strings.Contains(response.Body.String(), "db down") {
		t.Errorf("internal error detail must not leak: %s", response.Body.String())
	}
}
