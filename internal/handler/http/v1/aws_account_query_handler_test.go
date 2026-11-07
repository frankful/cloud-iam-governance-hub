package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakeAWSAccountQueryService struct {
	accounts []service.AWSAccountRef
	err      error
}

func (fake *fakeAWSAccountQueryService) ListAccounts(ctx context.Context) ([]service.AWSAccountRef, error) {
	return fake.accounts, fake.err
}

func newTestAccountQueryRouter(t *testing.T, fake *fakeAWSAccountQueryService, user string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSAccountQueryHandler(fake)
	if err != nil {
		t.Fatalf("NewAWSAccountQueryHandler() error = %v", err)
	}
	router := gin.New()
	if user != "" {
		router.Use(func(context *gin.Context) {
			context.Set(AuthenticatedUserContextKey, user)
			context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
		})
	}
	RegisterAWSAccountQueryRoutes(router, handler)
	return router
}

func TestListAWSAccountsReturnsReferences(t *testing.T) {
	name := "example-sub-account"
	fake := &fakeAWSAccountQueryService{accounts: []service.AWSAccountRef{
		{ID: 1, AWSAccountID: "111122223333", AccountName: &name},
	}}
	router := newTestAccountQueryRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/accounts", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	var payload struct {
		Accounts []service.AWSAccountRef `json:"accounts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Accounts) != 1 || payload.Accounts[0].ID != 1 ||
		payload.Accounts[0].AWSAccountID != "111122223333" {
		t.Fatalf("accounts = %+v", payload.Accounts)
	}
}

func TestListAWSAccountsRequiresAuthentication(t *testing.T) {
	fake := &fakeAWSAccountQueryService{}
	router := newTestAccountQueryRouter(t, fake, "")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/accounts", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}
