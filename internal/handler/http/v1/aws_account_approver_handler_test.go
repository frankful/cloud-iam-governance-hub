package v1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

type accountApproverServiceFake struct {
	bindings        []service.AccountApproverBinding
	candidates      []service.AccountApproverCandidate
	accountsForUser map[string][]service.ApproverAccountSummary
	setInput        struct {
		accountID int64
		userIDs   []string
	}
	setAccountsInput struct {
		userID     string
		accountIDs []int64
	}
	listErr        error
	candErr        error
	setErr         error
	setAccountsErr error
}

func (fake *accountApproverServiceFake) ListBindings(
	context.Context, int64,
) ([]service.AccountApproverBinding, error) {
	if fake.listErr != nil {
		return nil, fake.listErr
	}
	return fake.bindings, nil
}

func (fake *accountApproverServiceFake) ListCandidates(
	context.Context, int64,
) ([]service.AccountApproverCandidate, error) {
	if fake.candErr != nil {
		return nil, fake.candErr
	}
	return fake.candidates, nil
}

func (fake *accountApproverServiceFake) SetBindings(
	_ context.Context, accountID int64, userIDs []string,
) ([]service.AccountApproverBinding, error) {
	if fake.setErr != nil {
		return nil, fake.setErr
	}
	fake.setInput.accountID = accountID
	fake.setInput.userIDs = append([]string(nil), userIDs...)
	return fake.bindings, nil
}

func (fake *accountApproverServiceFake) ListAccountsForApprover(
	_ context.Context, userID string,
) ([]service.ApproverAccountSummary, error) {
	if fake.accountsForUser == nil {
		return []service.ApproverAccountSummary{}, nil
	}
	return fake.accountsForUser[userID], nil
}

func (fake *accountApproverServiceFake) SetAccountsForApprover(
	_ context.Context, userID string, accountIDs []int64,
) ([]service.ApproverAccountSummary, error) {
	if fake.setAccountsErr != nil {
		return nil, fake.setAccountsErr
	}
	fake.setAccountsInput.userID = userID
	fake.setAccountsInput.accountIDs = append([]int64(nil), accountIDs...)
	return fake.accountsForUser[userID], nil
}

func newAccountApproverTestRouter(t *testing.T, fake *accountApproverServiceFake) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSAccountApproverHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterAWSAccountApproverRoutes(api, handler)
	return router
}

func TestAWSAccountApproverRoutesRequirePlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSAccountApproverHandler(&accountApproverServiceFake{})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "regular-user")
		context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
	})
	RegisterAWSAccountApproverRoutes(api, handler)

	for _, target := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/aws/accounts/7/approvers"},
		{http.MethodPut, "/api/v1/aws/accounts/7/approvers"},
		{http.MethodGet, "/api/v1/aws/approver-bindings/admin"},
		{http.MethodPut, "/api/v1/aws/approver-bindings/admin"},
	} {
		request := httptest.NewRequest(target.method, target.path, strings.NewReader("{}"))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s: expected standard user to be forbidden, got %d",
				target.method, target.path, response.Code)
		}
	}
}

func TestAWSAccountApproverReplaceParsesUserIDs(t *testing.T) {
	fake := &accountApproverServiceFake{
		bindings: []service.AccountApproverBinding{
			{AccountID: 7, UserID: "admin", DisplayName: "平台管理员", IsActive: true,
				Roles: []string{"platform_admin"}, CreatedAt: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)},
		},
	}
	router := newAccountApproverTestRouter(t, fake)

	request := httptest.NewRequest(http.MethodPut, "/api/v1/aws/accounts/7/approvers",
		strings.NewReader(`{"user_ids": [" admin ", "", "admin", "sec-lead"]}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.setInput.accountID != 7 {
		t.Fatalf("accountID = %d, want 7", fake.setInput.accountID)
	}
	// The handler passes the raw list through; trimming/deduping is the
	// service's job (normalizeApprovers, covered by service tests).
	if got, want := strings.Join(fake.setInput.userIDs, ","), " admin ,,admin,sec-lead"; got != want {
		t.Fatalf("userIDs = %q, want %q", got, want)
	}
	if !strings.Contains(response.Body.String(), `"user_id":"admin"`) {
		t.Fatalf("response should echo bindings, got %s", response.Body.String())
	}
}

func TestAWSAccountApproverErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		method   string
		body     string
		wantCode int
	}{
		{
			name:     "unknown account maps to 404",
			err:      service.ErrAccountApproverAccountNotFound,
			method:   http.MethodPut,
			body:     `{"user_ids": ["admin"]}`,
			wantCode: http.StatusNotFound,
		},
		{
			name:     "non-approver user maps to 422",
			err:      fmt.Errorf("%w: rogue-user", service.ErrAccountApproverInvalidUser),
			method:   http.MethodPut,
			body:     `{"user_ids": ["rogue-user"]}`,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "unexpected error maps to 500",
			err:      errors.New("db down"),
			method:   http.MethodGet,
			body:     "",
			wantCode: http.StatusInternalServerError,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fake := &accountApproverServiceFake{setErr: testCase.err, listErr: testCase.err}
			router := newAccountApproverTestRouter(t, fake)
			request := httptest.NewRequest(testCase.method, "/api/v1/aws/accounts/7/approvers",
				strings.NewReader(testCase.body))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != testCase.wantCode {
				t.Fatalf("status = %d, want %d, body = %s",
					response.Code, testCase.wantCode, response.Body.String())
			}
		})
	}
}

func TestAWSAccountApproverRejectsBadAccountID(t *testing.T) {
	fake := &accountApproverServiceFake{}
	router := newAccountApproverTestRouter(t, fake)
	for _, path := range []string{
		"/api/v1/aws/accounts/not-a-number/approvers",
		"/api/v1/aws/accounts/0/approvers",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", path, response.Code)
		}
	}
}

func TestAWSAccountApproverCandidatesEndpoint(t *testing.T) {
	fake := &accountApproverServiceFake{
		candidates: []service.AccountApproverCandidate{
			{UserID: "admin", DisplayName: "平台管理员", Bound: true},
			{UserID: "sec-lead", DisplayName: "安全负责人", Bound: false},
		},
	}
	router := newAccountApproverTestRouter(t, fake)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/aws/accounts/7/approver-candidates", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"bound":true`) ||
		!strings.Contains(response.Body.String(), `"bound":false`) {
		t.Fatalf("candidates should carry bound flags, got %s", response.Body.String())
	}
}

// TestAWSAccountApproverSetAccountsFromUserSide 覆盖用户管理页的反向写路径：
// 「此人审批哪些账号」整体替换。它和账号侧的 PUT 写同一张表，只是视角相反。
func TestAWSAccountApproverSetAccountsFromUserSide(t *testing.T) {
	fake := &accountApproverServiceFake{
		accountsForUser: map[string][]service.ApproverAccountSummary{
			"alice": {
				{AccountDBID: 7, AccountNo: "111122223333", BoundAt: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)},
				{AccountDBID: 9, AccountNo: "444455556666", BoundAt: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)},
			},
		},
	}
	router := newAccountApproverTestRouter(t, fake)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/aws/approver-bindings/alice",
		strings.NewReader(`{"account_ids": [7, 9]}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.setAccountsInput.userID != "alice" {
		t.Fatalf("userID = %q, want alice", fake.setAccountsInput.userID)
	}
	if got, want := len(fake.setAccountsInput.accountIDs), 2; got != want {
		t.Fatalf("accountIDs = %v, want 2 entries", fake.setAccountsInput.accountIDs)
	}
	if !strings.Contains(response.Body.String(), `"account_db_id":9`) {
		t.Fatalf("response should echo bound accounts, got %s", response.Body.String())
	}
}

func TestAWSAccountApproverSetAccountsRejectsBadPayload(t *testing.T) {
	fake := &accountApproverServiceFake{}
	router := newAccountApproverTestRouter(t, fake)
	for _, body := range []string{
		`{"account_ids": [0]}`,
		`{"account_ids": [-3]}`,
		`not-json`,
	} {
		request := httptest.NewRequest(http.MethodPut, "/api/v1/aws/approver-bindings/alice",
			strings.NewReader(body))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, response.Code)
		}
	}
}

func TestAWSAccountApproverSetAccountsErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"unknown account maps to 404", service.ErrAccountApproverAccountNotFound, http.StatusNotFound},
		{"non-approver user maps to 422", fmt.Errorf("%w: rogue-user", service.ErrAccountApproverInvalidUser), http.StatusUnprocessableEntity},
		{"unexpected error maps to 500", errors.New("db down"), http.StatusInternalServerError},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fake := &accountApproverServiceFake{setAccountsErr: testCase.err}
			router := newAccountApproverTestRouter(t, fake)
			request := httptest.NewRequest(http.MethodPut, "/api/v1/aws/approver-bindings/alice",
				strings.NewReader(`{"account_ids": [7]}`))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != testCase.wantCode {
				t.Fatalf("status = %d, want %d, body = %s",
					response.Code, testCase.wantCode, response.Body.String())
			}
		})
	}
}
