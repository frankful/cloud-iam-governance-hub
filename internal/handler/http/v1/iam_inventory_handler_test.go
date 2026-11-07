package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakeIAMInventoryService struct {
	principals      []service.PrincipalSummary
	principalsTotal int
	principalsErr   error
	lastPrincipal   service.PrincipalListFilter
	principal       service.PrincipalDetail
	principalErr    error
	groups          []service.GroupSummary
	groupsTotal     int
	groupsErr       error
	lastGroup       service.GroupListFilter
	group           service.GroupDetail
	groupErr        error
	policies        []service.ManagedPolicySummary
	policiesTotal   int
	policiesErr     error
	lastPolicy      service.ManagedPolicyFilter
	policyDetail    service.ManagedPolicyDetail
	policyDetailErr error
	lastPolicyID    int64
	inlinePolicies      []service.InlinePolicySummary
	inlinePoliciesTotal int
	lastInlineFilter    service.InlinePolicyListFilter
	profiles            []service.InstanceProfileSummary
	profilesTotal       int
	lastProfileFilter   service.InstanceProfileListFilter
	inlineDetail        service.InlinePolicyDetail
	inlineDetailID      int64
	profileDetail       service.InstanceProfileDetail
	profileDetailID     int64
}

func (fake *fakeIAMInventoryService) ListPrincipals(ctx context.Context, filter service.PrincipalListFilter) ([]service.PrincipalSummary, int, error) {
	fake.lastPrincipal = filter
	return fake.principals, fake.principalsTotal, fake.principalsErr
}

func (fake *fakeIAMInventoryService) GetPrincipal(ctx context.Context, principalID int64) (service.PrincipalDetail, error) {
	return fake.principal, fake.principalErr
}

func (fake *fakeIAMInventoryService) ListGroups(ctx context.Context, filter service.GroupListFilter) ([]service.GroupSummary, int, error) {
	fake.lastGroup = filter
	return fake.groups, fake.groupsTotal, fake.groupsErr
}

func (fake *fakeIAMInventoryService) GetGroup(ctx context.Context, groupID int64) (service.GroupDetail, error) {
	return fake.group, fake.groupErr
}

func (fake *fakeIAMInventoryService) ListManagedPolicies(ctx context.Context, filter service.ManagedPolicyFilter) ([]service.ManagedPolicySummary, int, error) {
	fake.lastPolicy = filter
	return fake.policies, fake.policiesTotal, fake.policiesErr
}

func (fake *fakeIAMInventoryService) GetManagedPolicy(ctx context.Context, policyID int64) (service.ManagedPolicyDetail, error) {
	fake.lastPolicyID = policyID
	return fake.policyDetail, fake.policyDetailErr
}

func (fake *fakeIAMInventoryService) ListInlinePolicies(ctx context.Context, filter service.InlinePolicyListFilter) ([]service.InlinePolicySummary, int, error) {
	fake.lastInlineFilter = filter
	return fake.inlinePolicies, fake.inlinePoliciesTotal, nil
}

func (fake *fakeIAMInventoryService) ListInstanceProfiles(ctx context.Context, filter service.InstanceProfileListFilter) ([]service.InstanceProfileSummary, int, error) {
	fake.lastProfileFilter = filter
	return fake.profiles, fake.profilesTotal, nil
}

func (fake *fakeIAMInventoryService) GetInlinePolicy(ctx context.Context, policyID int64) (service.InlinePolicyDetail, error) {
	fake.inlineDetailID = policyID
	if fake.inlineDetail.PolicyName == "" {
		return service.InlinePolicyDetail{}, service.ErrIAMPolicyNotFound
	}
	return fake.inlineDetail, nil
}

func (fake *fakeIAMInventoryService) GetInstanceProfile(ctx context.Context, profileID int64) (service.InstanceProfileDetail, error) {
	fake.profileDetailID = profileID
	if fake.profileDetail.InstanceProfileName == "" {
		return service.InstanceProfileDetail{}, service.ErrIAMInstanceProfileNotFound
	}
	return fake.profileDetail, nil
}

func (fake *fakeIAMInventoryService) GetRoleInlinePolicy(ctx context.Context, accountID int64, roleName, policyName string) (json.RawMessage, bool, error) {
	return nil, false, nil
}

func (fake *fakeIAMInventoryService) GetGroupInlinePolicy(ctx context.Context, accountID int64, groupName, policyName string) (json.RawMessage, bool, error) {
	return nil, false, nil
}

func newTestInventoryRouter(t *testing.T, fake *fakeIAMInventoryService, user string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewIAMInventoryHandler(fake)
	if err != nil {
		t.Fatalf("NewIAMInventoryHandler() error = %v", err)
	}
	router := gin.New()
	if user != "" {
		router.Use(func(context *gin.Context) {
			context.Set(AuthenticatedUserContextKey, user)
			context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
		})
	}
	RegisterIAMInventoryRoutes(router, handler)
	return router
}

func TestListPrincipalsPassesFiltersAndDefaults(t *testing.T) {
	fake := &fakeIAMInventoryService{
		principals: []service.PrincipalSummary{
			{ID: 103, PrincipalName: "iam-readonly", PrincipalType: "User"},
		},
		principalsTotal: 1,
	}
	router := newTestInventoryRouter(t, fake, "reader@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/aws/principals?account_id=1&type=User&q=iam-&limit=5&offset=0", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	filter := fake.lastPrincipal
	if filter.AccountID != 1 || filter.Type != "User" || filter.Q != "iam-" ||
		filter.Limit != 5 || filter.Offset != 0 {
		t.Fatalf("filter = %+v", filter)
	}
	var payload struct {
		Principals []service.PrincipalSummary `json:"principals"`
		Total      int                        `json:"total"`
		Limit      int                        `json:"limit"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Total != 1 || len(payload.Principals) != 1 {
		t.Fatalf("payload = %+v", payload)
	}

	// Defaults: no filters, limit 20.
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals", nil))
	if fake.lastPrincipal.Limit != 20 || fake.lastPrincipal.AccountID != 0 || fake.lastPrincipal.Type != "" {
		t.Fatalf("default filter = %+v", fake.lastPrincipal)
	}
}

func TestListPrincipalsRejectsInvalidQuery(t *testing.T) {
	fake := &fakeIAMInventoryService{principalsErr: service.ErrInvalidPrincipalType}
	router := newTestInventoryRouter(t, fake, "reader@example.com")
	for _, test := range []struct {
		query      string
		wantStatus int
	}{
		{query: "limit=abc", wantStatus: http.StatusBadRequest},
		{query: "limit=0", wantStatus: http.StatusBadRequest},
		{query: "offset=-1", wantStatus: http.StatusBadRequest},
		{query: "account_id=x", wantStatus: http.StatusBadRequest},
		{query: "account_id=0", wantStatus: http.StatusBadRequest},
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals?"+test.query, nil))
		if recorder.Code != test.wantStatus {
			t.Fatalf("query %q status = %d, want %d; body=%s", test.query, recorder.Code, test.wantStatus, recorder.Body)
		}
	}

	// Invalid service-level filter maps to 400 as well.
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals?type=Admin", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid type status = %d, want 400; body=%s", recorder.Code, recorder.Body)
	}
}

func TestGetPrincipalDetailAndNotFound(t *testing.T) {
	fake := &fakeIAMInventoryService{principal: service.PrincipalDetail{
		PrincipalSummary: service.PrincipalSummary{ID: 103, PrincipalName: "iam-readonly"},
		Policies:         []service.AttachedPolicy{},
		Groups:           []service.GroupRef{},
	}}
	router := newTestInventoryRouter(t, fake, "reader@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals/103", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}

	fake.principalErr = service.ErrIAMPrincipalNotFound
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals/999", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", recorder.Code, recorder.Body)
	}
}

func TestListAndGetGroups(t *testing.T) {
	fake := &fakeIAMInventoryService{
		groups:      []service.GroupSummary{{ID: 1, GroupName: "devs", MemberCount: 2}},
		groupsTotal: 1,
		group: service.GroupDetail{
			GroupSummary: service.GroupSummary{ID: 1, GroupName: "devs"},
			Members:      []service.PrincipalRef{},
			Policies:     []service.AttachedPolicy{},
		},
	}
	router := newTestInventoryRouter(t, fake, "reader@example.com")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/groups?account_id=1&q=dev", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastGroup.AccountID != 1 || fake.lastGroup.Q != "dev" {
		t.Fatalf("filter = %+v", fake.lastGroup)
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/groups/1", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status = %d; body=%s", recorder.Code, recorder.Body)
	}

	fake.groupErr = service.ErrIAMGroupNotFound
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/groups/404", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d; body=%s", recorder.Code, recorder.Body)
	}
}

func TestGetManagedPolicyDetail(t *testing.T) {
	document := model.JSONB(`{"Version":"2012-10-17","Statement":[]}`)
	fake := &fakeIAMInventoryService{
		policyDetail: service.ManagedPolicyDetail{
			ManagedPolicySummary: service.ManagedPolicySummary{
				ID: 7, PolicyName: "team-read", PolicyType: strPtr("LOCAL"),
			},
			PolicyDocument:     &document,
			AttachedPrincipals: 2,
			AttachedGroups:     1,
		},
	}
	router := newTestInventoryRouter(t, fake, "reader@example.com")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/policies/7", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastPolicyID != 7 {
		t.Fatalf("lastPolicyID = %d, want 7", fake.lastPolicyID)
	}
	var payload struct {
		Policy service.ManagedPolicyDetail `json:"policy"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Policy.PolicyName != "team-read" ||
		payload.Policy.AttachedPrincipals != 2 || payload.Policy.AttachedGroups != 1 ||
		payload.Policy.PolicyDocument == nil {
		t.Fatalf("payload = %+v", payload.Policy)
	}

	fake.policyDetailErr = service.ErrIAMPolicyNotFound
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/policies/404", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d; body=%s", recorder.Code, recorder.Body)
	}
}

func strPtr(value string) *string { return &value }

func TestInventoryRoutesRequireAuthentication(t *testing.T) {
	fake := &fakeIAMInventoryService{}
	router := newTestInventoryRouter(t, fake, "")
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/aws/principals", nil),
		httptest.NewRequest(http.MethodGet, "/aws/principals/1", nil),
		httptest.NewRequest(http.MethodGet, "/aws/groups", nil),
		httptest.NewRequest(http.MethodGet, "/aws/groups/1", nil),
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want 401", request.URL, recorder.Code)
		}
	}
}

func TestInventoryRoutesRequireRole(t *testing.T) {
	fake := &fakeIAMInventoryService{}
	gin.SetMode(gin.TestMode)
	handler, err := NewIAMInventoryHandler(fake)
	if err != nil {
		t.Fatalf("NewIAMInventoryHandler() error = %v", err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "viewer@example.com")
		context.Set(AuthenticatedRolesContextKey, []string{"viewer"})
	})
	RegisterIAMInventoryRoutes(router, handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body)
	}
}

// aws 过滤参数只在 true/false 里取值；非法值必须在 handler 层被 400 挡住，
// 而不是漏到 SQL 里拼出空结果。
func TestInventoryAWSFilterValidation(t *testing.T) {
	fake := &fakeIAMInventoryService{}
	router := newTestInventoryRouter(t, fake, "reader@example.com")
	for _, route := range []string{"/aws/principals", "/aws/policies", "/aws/inline-policies"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route+"?aws=maybe", nil))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s with aws=maybe status = %d, want 400", route, recorder.Code)
		}
	}
	// 合法值原样透传。
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/principals?aws=true&type=Role", nil))
	if recorder.Code != http.StatusOK || fake.lastPrincipal.AWS != "true" {
		t.Fatalf("aws=true not passed through: status=%d filter=%+v", recorder.Code, fake.lastPrincipal)
	}
}

func TestListInlinePoliciesAndProfilesRoutes(t *testing.T) {
	fake := &fakeIAMInventoryService{
		inlinePolicies: []service.InlinePolicySummary{
			{PolicyID: 9, PolicyName: "s3-list", OwnerKind: "role", OwnerName: "app-server"},
		},
		inlinePoliciesTotal: 1,
		profiles: []service.InstanceProfileSummary{
			{ID: 3, InstanceProfileName: "eks-123e4567-89ab-cdef-0123-456789abcdef", EKSManaged: true},
		},
		profilesTotal: 1,
	}
	router := newTestInventoryRouter(t, fake, "reader@example.com")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/inline-policies?account_id=1&aws=false", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("inline-policies status = %d; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastInlineFilter.AccountID != 1 || fake.lastInlineFilter.AWS != "false" {
		t.Fatalf("inline filter = %+v", fake.lastInlineFilter)
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/instance-profiles?limit=10", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("instance-profiles status = %d; body=%s", recorder.Code, recorder.Body)
	}
	var payload struct {
		Profiles []service.InstanceProfileSummary `json:"profiles"`
		Total    int                              `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Total != 1 || len(payload.Profiles) != 1 || !payload.Profiles[0].EKSManaged {
		t.Fatalf("profiles payload = %+v", payload)
	}
}

// 详情端点对两类资产都开放（官方托管的策略同样只读可看），404 映射保持一致。
func TestInlinePolicyAndProfileDetailRoutes(t *testing.T) {
	fake := &fakeIAMInventoryService{
		inlineDetail: service.InlinePolicyDetail{
			InlinePolicySummary: service.InlinePolicySummary{
				PolicyID: 9, PolicyName: "s3-list", OwnerKind: "role", OwnerName: "app-server",
			},
		},
		profileDetail: service.InstanceProfileDetail{
			InstanceProfileSummary: service.InstanceProfileSummary{
				ID: 3, InstanceProfileName: "app-profile",
			},
		},
	}
	router := newTestInventoryRouter(t, fake, "reader@example.com")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/inline-policies/9", nil))
	if recorder.Code != http.StatusOK || fake.inlineDetailID != 9 {
		t.Fatalf("inline detail status = %d id = %d", recorder.Code, fake.inlineDetailID)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/instance-profiles/3", nil))
	if recorder.Code != http.StatusOK || fake.profileDetailID != 3 {
		t.Fatalf("profile detail status = %d id = %d", recorder.Code, fake.profileDetailID)
	}

	// 不存在的 ID → 404（fake 里详情字段为空即视为缺失）。
	missing := newTestInventoryRouter(t, &fakeIAMInventoryService{}, "reader@example.com")
	recorder = httptest.NewRecorder()
	missing.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/inline-policies/999", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing inline policy status = %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	missing.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/instance-profiles/999", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing profile status = %d", recorder.Code)
	}
}

// TestListPoliciesPassesAccountFilter 回归：策略清单必须把 account_id
// 传进 filter，否则工单表单/资产页会列到其他账号的策略。
func TestListPoliciesPassesAccountFilter(t *testing.T) {
	fake := &fakeIAMInventoryService{
		policies:      []service.ManagedPolicySummary{{ID: 31, PolicyName: "billing-readonly"}},
		policiesTotal: 1,
	}
	router := newTestInventoryRouter(t, fake, "reader@example.com")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/aws/policies?account_id=2&aws=false&limit=20", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastPolicy.AccountID != 2 || fake.lastPolicy.AWS != "false" {
		t.Fatalf("filter = %+v", fake.lastPolicy)
	}

	// 缺省仍是跨账号清单（基线/审计视角）。
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/policies", nil))
	if fake.lastPolicy.AccountID != 0 {
		t.Fatalf("default account filter = %d, want 0", fake.lastPolicy.AccountID)
	}
}

func TestListPoliciesRejectsInvalidAccountFilter(t *testing.T) {
	fake := &fakeIAMInventoryService{}
	router := newTestInventoryRouter(t, fake, "reader@example.com")
	for _, raw := range []string{"0", "-1", "abc"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
			"/aws/policies?account_id="+raw, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("account_id=%q status = %d, want 400", raw, recorder.Code)
		}
	}
}
