package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

type driftFake struct {
	page       service.DriftFindingPage
	filter     service.DriftFilter
	listErr    error
	finding    service.DriftFinding
	getErr     error
	actionID   int64
	actionName string
	actionBy   string
	summary    []service.DriftAccountSummary
	evaluation service.DriftEvaluation
	checkID    int64
	ciReport   service.CIReport
	ciResult   service.CIReportResult
	ciErr      error
}

func (fake *driftFake) List(
	_ context.Context, filter service.DriftFilter,
) (service.DriftFindingPage, error) {
	fake.filter = filter
	return fake.page, fake.listErr
}

func (fake *driftFake) GetFinding(_ context.Context, id int64) (service.DriftFinding, error) {
	if fake.getErr != nil {
		return service.DriftFinding{}, fake.getErr
	}
	finding := fake.finding
	finding.ID = id
	return finding, nil
}

func (fake *driftFake) ApplyAction(
	_ context.Context, id int64, action, actor string,
) (service.DriftFinding, error) {
	fake.actionID = id
	fake.actionName = action
	fake.actionBy = actor
	if fake.getErr != nil {
		return service.DriftFinding{}, fake.getErr
	}
	finding := fake.finding
	finding.ID = id
	finding.Status = service.DriftStatusIgnored
	return finding, nil
}

func (fake *driftFake) SummarizeAccounts(
	_ context.Context, _ string,
) ([]service.DriftAccountSummary, error) {
	return fake.summary, nil
}

func (fake *driftFake) EvaluateAccount(
	_ context.Context, accountDBID int64,
) (service.DriftEvaluation, error) {
	fake.checkID = accountDBID
	return fake.evaluation, nil
}

func (fake *driftFake) IngestCIReport(
	_ context.Context, report service.CIReport,
) (service.CIReportResult, error) {
	fake.ciReport = report
	if fake.ciErr != nil {
		return service.CIReportResult{}, fake.ciErr
	}
	return fake.ciResult, nil
}

func newDriftTestRouter(t *testing.T, fake *driftFake, roles ...string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewDriftHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, roles)
	})
	RegisterDriftRoutes(api, handler)
	return router
}

// TestDriftWriteRoutesRequirePlatformAdmin 漂移明细对所有登录角色可见（它是
// 给人看的），但「忽略」「关闭」「立即检测」改变的是处置判断，限管理员，
// 免得忽略按钮变成绕过审计的静音键。
func TestDriftWriteRoutesRequirePlatformAdmin(t *testing.T) {
	router := newDriftTestRouter(t, &driftFake{}, "standard_user")
	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/drift-findings/1/ignore", ""},
		{http.MethodPost, "/api/v1/drift-findings/1/reopen", ""},
		{http.MethodPost, "/api/v1/drift-findings/1/resolve", ""},
		{http.MethodPost, "/api/v1/drift-findings/check", `{"account_id":3}`},
	}
	for _, testCase := range cases {
		request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(testCase.body))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s: expected forbidden, got %d", testCase.method, testCase.path, response.Code)
		}
	}

	readRequest := httptest.NewRequest(http.MethodGet, "/api/v1/drift-findings", nil)
	readResponse := httptest.NewRecorder()
	router.ServeHTTP(readResponse, readRequest)
	if readResponse.Code != http.StatusOK {
		t.Fatalf("read must stay available to every authenticated role, got %d", readResponse.Code)
	}
}

func TestDriftListParsesFiltersAndRejectsUnknownStatus(t *testing.T) {
	fake := &driftFake{page: service.DriftFindingPage{Total: 0, Items: []service.DriftFinding{}}}
	router := newDriftTestRouter(t, fake, "platform_admin")

	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/drift-findings?account_id=123456789012&status=open&severity=high&page=2&page_size=20", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.filter.AWSAccountID != "123456789012" || fake.filter.Status != "OPEN" ||
		fake.filter.Severity != "HIGH" || fake.filter.Page != 2 || fake.filter.PageSize != 20 {
		t.Fatalf("filters not forwarded: %+v", fake.filter)
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/v1/drift-findings?status=DONE", nil)
	badResponse := httptest.NewRecorder()
	router.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown status must be rejected, got %d", badResponse.Code)
	}
}

func TestDriftIgnoreUsesAuthenticatedActor(t *testing.T) {
	fake := &driftFake{finding: service.DriftFinding{Status: service.DriftStatusOpen}}
	router := newDriftTestRouter(t, fake, "platform_admin")

	request := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/42/ignore", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.actionID != 42 || fake.actionName != service.DriftActionIgnore {
		t.Fatalf("action forwarded as id=%d name=%s", fake.actionID, fake.actionName)
	}
	if fake.actionBy != "admin" {
		t.Fatalf("actor = %q, want the authenticated user", fake.actionBy)
	}
	var finding service.DriftFinding
	if err := json.Unmarshal(response.Body.Bytes(), &finding); err != nil {
		t.Fatal(err)
	}
	if finding.Status != service.DriftStatusIgnored {
		t.Fatalf("returned status = %s", finding.Status)
	}
}

func TestDriftCheckRequiresAccountID(t *testing.T) {
	fake := &driftFake{evaluation: service.DriftEvaluation{AccountDBID: 9, Surfaced: 2}}
	router := newDriftTestRouter(t, fake, "platform_admin")

	missing := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/check", strings.NewReader(`{}`))
	missingResponse := httptest.NewRecorder()
	router.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing account_id must be rejected, got %d", missingResponse.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/check",
		strings.NewReader(`{"account_id":9}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.checkID != 9 {
		t.Fatalf("account id = %d, want 9", fake.checkID)
	}
}

func TestDriftGetReturnsNotFoundForMissingFinding(t *testing.T) {
	fake := &driftFake{getErr: service.ErrDriftFindingNotFound}
	router := newDriftTestRouter(t, fake, "platform_admin")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/drift-findings/77", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

type driftRemediationFake struct {
	route         string
	findingID     int64
	actor         string
	plan          service.DriftRemediation
	err           error
	rollbackCalls int
}

func (fake *driftRemediationFake) Acknowledge(
	_ context.Context, findingID int64, actor string,
) (service.DriftRemediation, error) {
	fake.route = service.DriftRouteAcknowledge
	fake.findingID = findingID
	fake.actor = actor
	return fake.plan, fake.err
}

func (fake *driftRemediationFake) Rollback(
	_ context.Context, findingID int64, actor string,
) (service.DriftRemediation, error) {
	fake.route = service.DriftRouteRollback
	fake.findingID = findingID
	fake.actor = actor
	fake.rollbackCalls++
	return fake.plan, fake.err
}

// driftPublicationFake 记录「接受现状」是否真的把发布跑起来了：Create 只落
// 台账，不 spawn 就等于发了个寂寞。
type driftPublicationFake struct {
	runs chan int64
}

func (fake *driftPublicationFake) Run(_ context.Context, publicationID int64) error {
	if fake.runs != nil {
		fake.runs <- publicationID
	}
	return nil
}

func newDriftRemediationRouter(
	t *testing.T, remediation *driftRemediationFake, publications *driftPublicationFake,
) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewDriftHandler(&driftFake{}, nil,
		WithDriftRemediation(remediation, publications))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterDriftRoutes(api, handler)
	return router
}

// TestDriftRemediationDisabledReturns501 没有发布器时收敛入口必须明说不可用，
// 不能让页面以为「点一下就能重发基线」。
func TestDriftRemediationDisabledReturns501(t *testing.T) {
	router := newDriftTestRouter(t, &driftFake{}, "platform_admin")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/5/remediate",
		strings.NewReader(`{"route":"acknowledge"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", response.Code)
	}
}

func TestDriftRemediationRoutesToService(t *testing.T) {
	remediation := &driftRemediationFake{plan: service.DriftRemediation{
		FindingID: 5, Route: service.DriftRouteRollback,
		TicketNo: "T-1", TicketType: service.TicketTypeUpdateRole,
	}}
	router := newDriftRemediationRouter(t, remediation, &driftPublicationFake{})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/5/remediate",
		strings.NewReader(`{"route":"rollback"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if remediation.route != service.DriftRouteRollback || remediation.findingID != 5 {
		t.Fatalf("not forwarded: %+v", remediation)
	}
	if !strings.Contains(response.Body.String(), `"ticket_no":"T-1"`) {
		t.Fatalf("plan not returned: %s", response.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/5/remediate",
		strings.NewReader(`{"route":"delete"}`))
	badResponse := httptest.NewRecorder()
	router.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown route status = %d, want 400", badResponse.Code)
	}
}

// TestDriftAcknowledgeSpawnsPublicationRun 追认必须真的把发布跑起来；幂等
// 命中则不再重复跑。
func TestDriftAcknowledgeSpawnsPublicationRun(t *testing.T) {
	publications := &driftPublicationFake{runs: make(chan int64, 1)}
	remediation := &driftRemediationFake{plan: service.DriftRemediation{
		FindingID:   5,
		Route:       service.DriftRouteAcknowledge,
		Publication: &service.BaselinePublication{ID: 42},
	}}
	router := newDriftRemediationRouter(t, remediation, publications)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/5/remediate",
		strings.NewReader(`{"route":"acknowledge"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	select {
	case publicationID := <-publications.runs:
		if publicationID != 42 {
			t.Fatalf("publication id = %d, want 42", publicationID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acknowledge must spawn the publication run")
	}

	remediation.plan.AlreadyPublished = true
	again := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/5/remediate",
		strings.NewReader(`{"route":"acknowledge"}`))
	againResponse := httptest.NewRecorder()
	router.ServeHTTP(againResponse, again)
	if againResponse.Code != http.StatusOK {
		t.Fatalf("idempotent status = %d", againResponse.Code)
	}
	select {
	case publicationID := <-publications.runs:
		t.Fatalf("already published must not spawn again, got %d", publicationID)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestDriftAcknowledgeDoesNotDriveInFlightPublication 幂等命中分两种：已发布
// （already_published）与正在发布（in_flight）。后者返回的是别人正在跑的台账，
// 再 spawn 一次会让同一个 PR 被提交两次。
func TestDriftAcknowledgeDoesNotDriveInFlightPublication(t *testing.T) {
	publications := &driftPublicationFake{runs: make(chan int64, 1)}
	remediation := &driftRemediationFake{plan: service.DriftRemediation{
		FindingID: 5,
		Route:     service.DriftRouteAcknowledge,
		Publication: &service.BaselinePublication{
			ID: 42, Status: service.BaselinePublicationStatusPublishing, InFlight: true,
		},
		InFlight: true,
	}}
	router := newDriftRemediationRouter(t, remediation, publications)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/drift-findings/5/remediate",
		strings.NewReader(`{"route":"acknowledge"}`))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"in_flight":true`) {
		t.Fatalf("in-flight must be surfaced: %s", response.Body.String())
	}
	select {
	case publicationID := <-publications.runs:
		t.Fatalf("in-flight publication must not be driven again, got %d", publicationID)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestDriftCIReportRoutes CI 只能「上报」，不能改配置：路由与错误映射都必须
// 让 CI 的 YAML 立刻看出是账号错、内容错还是平台错。
func TestDriftCIReportRoutes(t *testing.T) {
	fake := &driftFake{ciResult: service.CIReportResult{
		AccountDBID: 1, AWSAccountID: "111122223333", Reported: 1, Surfaced: 1,
	}}
	router := newDriftTestRouter(t, fake, "platform_admin")
	body := `{"account_id":"111122223333","commit_sha":"abc123","ci_url":"https://ci.example.com/1",` +
		`"findings":[{"resource_address":"aws_iam_role.foo","change_type":"attribute"}]}`

	request := httptest.NewRequest(http.MethodPost, "/api/v1/aws/drift-reports", strings.NewReader(body))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if fake.ciReport.AWSAccountID != "111122223333" || len(fake.ciReport.Findings) != 1 {
		t.Fatalf("report not forwarded: %+v", fake.ciReport)
	}

	fake.ciErr = service.ErrDriftAccountNotFound
	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodPost,
		"/api/v1/aws/drift-reports", strings.NewReader(body)))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown account status = %d, want 404", missing.Code)
	}

	fake.ciErr = apperr.Validation("findings[0] change_type is not reportable from CI")
	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, httptest.NewRequest(http.MethodPost,
		"/api/v1/aws/drift-reports", strings.NewReader(body)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("validation status = %d, want 400", invalid.Code)
	}

	// 非管理员不能上报：这条链路能写发现表，信任级别与 apply-result 相同。
	nonAdmin := httptest.NewRecorder()
	newDriftTestRouter(t, &driftFake{}, "standard_user").ServeHTTP(nonAdmin,
		httptest.NewRequest(http.MethodPost, "/api/v1/aws/drift-reports", strings.NewReader(body)))
	if nonAdmin.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", nonAdmin.Code)
	}
}
