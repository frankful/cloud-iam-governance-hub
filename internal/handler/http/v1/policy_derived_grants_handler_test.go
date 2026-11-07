package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakePolicyDerivedGrantService struct {
	result      service.PolicyDerivedGrants
	err         error
	accountID   int64
	principalID int64
	calls       int
}

func (fake *fakePolicyDerivedGrantService) Get(
	_ context.Context,
	accountID, principalID int64,
) (service.PolicyDerivedGrants, error) {
	fake.calls++
	fake.accountID = accountID
	fake.principalID = principalID
	return fake.result, fake.err
}

func TestPolicyDerivedGrantsHandlerReturnsPolicyAndWarnings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &fakePolicyDerivedGrantService{
		result: service.PolicyDerivedGrants{
			AccountID: 12, PrincipalID: 34, Principal: "report-reader",
			Warnings:    []string{"policy has unsupported fields"},
			Limitations: []string{"not AWS effective permissions"},
		},
	}
	handler, err := NewPolicyDerivedGrantsHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "reader")
		context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
	})
	RegisterPolicyDerivedGrantsRoutes(router, handler)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/aws/accounts/12/principals/34/policy-derived-grants",
		nil,
	))
	if response.Code != http.StatusOK || fake.accountID != 12 || fake.principalID != 34 {
		t.Fatalf("status/IDs = %d/%d/%d: %s", response.Code, fake.accountID, fake.principalID, response.Body)
	}
	if !strings.Contains(response.Body.String(), `"warnings":["policy has unsupported fields"]`) ||
		!strings.Contains(response.Body.String(), `"limitations":["not AWS effective permissions"]`) {
		t.Fatalf("warnings or limitations not returned: %s", response.Body)
	}
}

func TestPolicyDerivedGrantsHandlerMapsCrossAccountMissToNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &fakePolicyDerivedGrantService{err: service.ErrPolicyDerivedPrincipalNotFound}
	handler, err := NewPolicyDerivedGrantsHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "reviewer")
		context.Set(AuthenticatedRolesContextKey, []string{"approval_admin"})
	})
	RegisterPolicyDerivedGrantsRoutes(router, handler)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/aws/accounts/12/principals/999/policy-derived-grants",
		nil,
	))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", response.Code, response.Body)
	}
}

func TestPolicyDerivedGrantsHandlerRejectsInvalidPathID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &fakePolicyDerivedGrantService{}
	handler, err := NewPolicyDerivedGrantsHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterPolicyDerivedGrantsRoutes(router, handler)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/aws/accounts/0/principals/34/policy-derived-grants",
		nil,
	))
	if response.Code != http.StatusBadRequest || fake.calls != 0 {
		t.Fatalf("status/calls = %d/%d: %s", response.Code, fake.calls, response.Body)
	}
}

func TestPolicyDerivedGrantsHandlerHidesInternalErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &fakePolicyDerivedGrantService{err: errors.New("database secret detail")}
	handler, err := NewPolicyDerivedGrantsHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterPolicyDerivedGrantsRoutes(router, handler)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/aws/accounts/12/principals/34/policy-derived-grants",
		nil,
	))
	if response.Code != http.StatusInternalServerError ||
		strings.Contains(response.Body.String(), "database secret detail") {
		t.Fatalf("unexpected status/body: %d %s", response.Code, response.Body)
	}
}
