package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

type iamBaselineHandlerFake struct {
	createdAccount int64
	createdActor   string
	createdPolicy  abstractiam.AbstractPolicy
}

func (fake *iamBaselineHandlerFake) Create(
	_ context.Context,
	accountID int64,
	policy abstractiam.AbstractPolicy,
	_ bool,
	actorID string,
) (model.IAMBaseline, error) {
	fake.createdAccount, fake.createdActor, fake.createdPolicy = accountID, actorID, policy
	policyJSON, _ := json.Marshal(policy)
	return model.IAMBaseline{
		ID: 4, AccountID: accountID, Version: 1, Enabled: true, AbstractPolicy: model.JSONB(policyJSON),
	}, nil
}

func (fake *iamBaselineHandlerFake) List(context.Context, int64) ([]model.IAMBaseline, error) {
	return []model.IAMBaseline{}, nil
}

func (fake *iamBaselineHandlerFake) SetEnabled(
	context.Context, int64, int64, bool, string,
) (model.IAMBaseline, error) {
	return model.IAMBaseline{}, service.ErrIAMBaselineNotFound
}

func TestIAMBaselineRoutesRequirePlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewIAMBaselineHandler(&iamBaselineHandlerFake{})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "standard")
		context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
	})
	RegisterIAMBaselineRoutes(api, handler)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/api/v1/aws/accounts/12/baselines", nil,
	))
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d: %s", response.Code, response.Body.String())
	}
}

func TestIAMBaselineCreateUsesAuthenticatedActorAndCanonicalPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &iamBaselineHandlerFake{}
	handler, err := NewIAMBaselineHandler(fake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterIAMBaselineRoutes(api, handler)
	body := `{"enabled":true,"abstract_policy":{"statements":[{"effect":"Allow","actions":["storage:read"],"resources":["//storage/bucket/prod/*"]}]}}`
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/12/baselines", strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	if fake.createdAccount != 12 || fake.createdActor != "admin" ||
		len(fake.createdPolicy.Statements) != 1 {
		t.Fatalf("handler did not pass parsed values and authenticated actor: %+v", fake)
	}
}

func TestTicketBaselineViolationReturnsStructured422(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/tickets", func(context *gin.Context) {
		writeServiceError(context, &service.IAMBaselineComplianceError{
			Violations: []service.IAMBaselineViolation{{
				Code: "GRANT_OUTSIDE_BASELINE", StatementIndex: 1, Action: "storage:write",
				Description: "request is outside baseline",
			}},
		})
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/tickets", nil))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"GRANT_OUTSIDE_BASELINE"`) ||
		!strings.Contains(response.Body.String(), `"statement_index":1`) {
		t.Fatalf("structured baseline violations missing from response: %s", response.Body.String())
	}
}

func TestTicketCandidateRiskReturnsStructured422(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/tickets", func(context *gin.Context) {
		writeServiceError(context, &service.CandidatePolicyRiskError{
			Findings: []service.CandidatePolicyRiskFinding{{
				RiskType: "phase0_iam_external_trust", RiskLevel: "HIGH",
				Description: "trust policy allows an external principal",
			}},
		})
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/tickets", nil))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"risk_type":"phase0_iam_external_trust"`) ||
		!strings.Contains(response.Body.String(), `"risk_level":"HIGH"`) {
		t.Fatalf("structured candidate risk finding missing: %s", response.Body.String())
	}
}
