package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

type fakeTicketAPIService struct {
	ticket      model.IAMTicket
	createErr   error
	getErr      error
	approvalErr error
	approverErr error
	decideErr   error
	publishErr  error
	submitErr   error
	submitter   string
	submitActor string
	submitRoles []string
	approver    string
	decision    service.TicketDecision
	publishCall int
	listCall    int
	submitCall  int
	rearmCall   int
	rearmErr    error

	listErr             error
	listTotal           int64
	lastListFilter      service.TicketListFilter
	validation          service.TicketValidationSnapshot
	validateErr         error
	validateSubmitter   string
	terraformPreview    string
	terraformPreviewErr error
	terraformPreviewNo  string

	lastCIApply service.CIApplyResult
	ciApplyErr  error
}

func (fake *fakeTicketAPIService) PreviewTicketTerraform(
	_ context.Context,
	ticketNo string,
	_ string,
	_ []string,
) (string, error) {
	fake.terraformPreviewNo = ticketNo
	if fake.terraformPreviewErr != nil {
		return "", fake.terraformPreviewErr
	}
	return fake.terraformPreview, nil
}

func (fake *fakeTicketAPIService) GetTicketForActor(
	_ context.Context,
	_ string,
	actorID string,
	roles []string,
) (model.IAMTicket, error) {
	if fake.getErr != nil {
		return model.IAMTicket{}, fake.getErr
	}
	if fake.ticket.Submitter != nil && *fake.ticket.Submitter == actorID {
		return fake.ticket, nil
	}
	for _, role := range roles {
		if role == "platform_admin" || role == "approval_admin" {
			return fake.ticket, nil
		}
	}
	return model.IAMTicket{}, service.ErrTicketAccessDenied
}

func (fake *fakeTicketAPIService) CloseTicket(
	_ context.Context,
	ticketNo, actorID, reason, comment string,
	triggerSync bool,
) (model.IAMTicket, error) {
	if fake.ticket.TicketNo != nil && *fake.ticket.TicketNo == ticketNo {
		fake.ticket.Status = stringPointer(service.TicketStatusClosed)
		closedBy := actorID
		fake.ticket.ClosedBy = &closedBy
		now := time.Now()
		fake.ticket.ClosedAt = &now
		fake.ticket.ClosureReason = stringPointer(reason)
		return fake.ticket, nil
	}
	return model.IAMTicket{}, service.ErrTicketNotFound
}

func (fake *fakeTicketAPIService) RecordCIApplyResult(
	_ context.Context,
	ticketNo, _ string,
	result service.CIApplyResult,
) (model.IAMTicket, bool, error) {
	fake.lastCIApply = result
	if result.Status != service.CIApplyStatusSucceeded && result.Status != service.CIApplyStatusFailed {
		return model.IAMTicket{}, false, apperr.Validation("apply result status must be succeeded or failed")
	}
	if fake.ciApplyErr != nil {
		return model.IAMTicket{}, false, fake.ciApplyErr
	}
	if fake.ticket.TicketNo != nil && *fake.ticket.TicketNo == ticketNo {
		if result.Status == service.CIApplyStatusFailed {
			return fake.ticket, false, nil
		}
		closed, err := fake.CloseTicket(context.Background(), ticketNo, "ci", service.ClosureReasonApplied, result.Note, true)
		if err != nil {
			return model.IAMTicket{}, false, err
		}
		return closed, true, nil
	}
	return model.IAMTicket{}, false, service.ErrTicketNotFound
}

func (fake *fakeTicketAPIService) GetApprovalInfo(
	_ context.Context,
	ticketNo string,
) (model.TicketApprovalInfo, error) {
	return model.TicketApprovalInfo{TicketNo: ticketNo}, fake.approvalErr
}

func (fake *fakeTicketAPIService) ListAvailableApprovers(
	_ context.Context,
	_ *int64,
) ([]model.PlatformUser, error) {
	fake.listCall++
	return []model.PlatformUser{{UserID: "reviewer", DisplayName: "Reviewer", IsActive: true}}, fake.approverErr
}

func (fake *fakeTicketAPIService) ListTickets(
	_ context.Context,
	filter service.TicketListFilter,
) ([]model.IAMTicket, int64, error) {
	fake.lastListFilter = filter
	if fake.listErr != nil {
		return nil, 0, fake.listErr
	}
	if fake.listTotal == 0 {
		return []model.IAMTicket{}, 0, nil
	}
	return []model.IAMTicket{fake.ticket}, fake.listTotal, nil
}

func (fake *fakeTicketAPIService) PreviewValidation(
	_ context.Context,
	submitter string,
	_ service.CreateIAMTicketRequest,
) (service.TicketValidationSnapshot, error) {
	fake.validateSubmitter = submitter
	return fake.validation, fake.validateErr
}

func (fake *fakeTicketAPIService) CreateTicket(
	_ context.Context,
	submitter string,
	_ service.CreateIAMTicketRequest,
) (model.IAMTicket, error) {
	fake.submitter = submitter
	return fake.ticket, fake.createErr
}

func (fake *fakeTicketAPIService) CreateDraft(
	_ context.Context,
	submitter string,
	_ service.CreateIAMTicketRequest,
) (model.IAMTicket, error) {
	fake.submitter = submitter
	return fake.ticket, fake.createErr
}

func (fake *fakeTicketAPIService) SubmitTicket(
	_ context.Context,
	ticketNo, actorID string,
	roles []string,
) (model.IAMTicket, error) {
	fake.submitCall++
	fake.submitActor = actorID
	fake.submitRoles = roles
	return fake.ticket, fake.submitErr
}

func (fake *fakeTicketAPIService) GetTicket(
	_ context.Context,
	_ string,
) (model.IAMTicket, error) {
	return fake.ticket, fake.getErr
}

func (fake *fakeTicketAPIService) Decide(
	_ context.Context,
	_ string,
	approver string,
	decision service.TicketDecision,
) (model.IAMTicket, error) {
	fake.approver = approver
	fake.decision = decision
	return fake.ticket, fake.decideErr
}

func (fake *fakeTicketAPIService) RetryPublication(
	_ context.Context,
	_ string,
) (model.IAMTicket, error) {
	fake.publishCall++
	return fake.ticket, fake.publishErr
}

func (fake *fakeTicketAPIService) RearmPolling(
	_ context.Context,
	_ string,
) error {
	fake.rearmCall++
	return fake.rearmErr
}

func newTestTicketRouter(t *testing.T, ticketService *fakeTicketAPIService, user string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewTicketHandler(ticketService)
	if err != nil {
		t.Fatalf("NewTicketHandler() error = %v", err)
	}
	router := gin.New()
	if user != "" {
		router.Use(func(context *gin.Context) {
			context.Set(AuthenticatedUserContextKey, user)
			context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
		})
	}
	RegisterTicketRoutes(router, handler)
	return router
}

func TestTicketHandlerRequiresAuthenticatedIdentity(t *testing.T) {
	for _, test := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/tickets", body: `{}`},
		{method: http.MethodGet, path: "/tickets"},
		{method: http.MethodPost, path: "/tickets/validate", body: `{}`},
		{method: http.MethodPost, path: "/tickets/IAM-123/submit"},
		{method: http.MethodGet, path: "/tickets/IAM-123"},
		{method: http.MethodGet, path: "/tickets/IAM-123/terraform"},
		{method: http.MethodGet, path: "/tickets/IAM-123/approval"},
		{method: http.MethodPost, path: "/tickets/IAM-123/decision", body: `{"result":"APPROVE"}`},
		{method: http.MethodPost, path: "/tickets/IAM-123/publish"},
		{method: http.MethodGet, path: "/approvers"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			fake := &fakeTicketAPIService{}
			router := newTestTicketRouter(t, fake, "")
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
			if fake.submitter != "" || fake.submitCall != 0 || fake.publishCall != 0 || fake.listCall != 0 {
				t.Errorf("unauthenticated request reached service: submitter=%q submits=%d publish calls=%d approver calls=%d",
					fake.submitter, fake.submitCall, fake.publishCall, fake.listCall)
			}
		})
	}
}

func TestTicketHandlerSubmitUsesAuthenticatedActorAndRoles(t *testing.T) {
	fake := &fakeTicketAPIService{ticket: model.IAMTicket{ID: 7}}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/tickets/IAM-456/submit", nil))
	if recorder.Code != http.StatusOK || fake.submitCall != 1 ||
		fake.submitActor != "requester@example.com" ||
		len(fake.submitRoles) != 1 || fake.submitRoles[0] != "platform_admin" {
		t.Fatalf("submit response/actor/roles = %d/%q/%v; body=%s",
			recorder.Code, fake.submitActor, fake.submitRoles, recorder.Body)
	}
}

func TestTicketHandlerCreateUsesAuthenticatedSubmitter(t *testing.T) {
	fake := &fakeTicketAPIService{ticket: model.IAMTicket{ID: 123}}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	body := `{
		"ticket_type":"CREATE_ROLE",
		"account_id":17,
		"principal_name":"analytics-reader",
		"request_policy":{"principal":{"name":"analytics-reader","type":"ServiceIdentity"},"permissions":[],"description":"read"},
		"role":{"name":"analytics-reader","trust_policy":{"Version":"2012-10-17","Statement":[]}},
		"approval_mode":"MANUAL",
		"approver_ids":["security-reviewer"]
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated || fake.submitter != "requester@example.com" {
		t.Fatalf("status/submitter = %d/%q; body=%s", recorder.Code, fake.submitter, recorder.Body)
	}
}

func TestTicketHandlerListsApproversAndApprovalInfo(t *testing.T) {
	fake := &fakeTicketAPIService{}
	router := newTestTicketRouter(t, fake, "operator@example.com")

	approverRecorder := httptest.NewRecorder()
	router.ServeHTTP(approverRecorder, httptest.NewRequest(http.MethodGet, "/approvers?account_id=12", nil))
	if approverRecorder.Code != http.StatusOK || fake.listCall != 1 {
		t.Fatalf("approver list status/calls = %d/%d", approverRecorder.Code, fake.listCall)
	}

	approvalRecorder := httptest.NewRecorder()
	router.ServeHTTP(approvalRecorder, httptest.NewRequest(http.MethodGet, "/tickets/IAM-123/approval", nil))
	if approvalRecorder.Code != http.StatusOK || !strings.Contains(approvalRecorder.Body.String(), `"ticket_no":"IAM-123"`) {
		t.Fatalf("approval info response = %d %s", approvalRecorder.Code, approvalRecorder.Body)
	}
}

func TestTicketHandlerRejectsInvalidApproverAccountFilter(t *testing.T) {
	fake := &fakeTicketAPIService{}
	router := newTestTicketRouter(t, fake, "operator@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/approvers?account_id=not-a-number", nil))
	if recorder.Code != http.StatusBadRequest || fake.listCall != 0 {
		t.Fatalf("status/calls = %d/%d", recorder.Code, fake.listCall)
	}
}

func TestTicketHandlerDecisionUsesAuthenticatedApprover(t *testing.T) {
	fake := &fakeTicketAPIService{}
	router := newTestTicketRouter(t, fake, "reviewer@example.com")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/IAM-123/decision", strings.NewReader(`{"result":"APPROVE","comment":"ok"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if fake.approver != "reviewer@example.com" || fake.decision.Result != "APPROVE" {
		t.Errorf("approver/decision = %q/%+v", fake.approver, fake.decision)
	}
}

func TestTicketHandlerMapsServiceErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "not found", err: service.ErrTicketNotFound, wantStatus: http.StatusNotFound},
		{name: "not approver", err: service.ErrNotDesignatedApprover, wantStatus: http.StatusForbidden},
		{name: "conflict", err: service.ErrInvalidTicketState, wantStatus: http.StatusConflict},
		{name: "internal", err: errors.New("database down"), wantStatus: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTicketAPIService{getErr: test.err}
			router := newTestTicketRouter(t, fake, "reader@example.com")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets/IAM-123", nil))
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body)
			}
			var response struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil ||
				response.Message == "" || response.Code == "" {
				t.Fatalf("error response = %s, decode error = %v", recorder.Body, err)
			}
		})
	}
}

// Regression: trust_policy 字符串形态与未注册账号必须走 400（此前落入 500 且无日志）。
func TestWriteServiceErrorMapsValidationPrefixes(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "trust_policy string unwrap failure",
			err:        errors.New("role.trust_policy arrived as a JSON string whose contents are not valid JSON; send the trust policy as a JSON object (or a JSON string containing one)"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unregistered account",
			err:        errors.New("account_id 99: AWS account is not registered on this platform; register it and sync assets first"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid initial policy ARN",
			err:        errors.New(`role.policy_arns: invalid IAM policy ARN "alert"`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "initial policy absent from inventory",
			err:        errors.New(`role.policy_arns: policy ARN "arn:aws:iam::123456789012:policy/alert" was not found in the synced IAM inventory; sync assets and try again`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "policy adoption target absent from inventory",
			err:        errors.New("policy arn:aws:iam::111122223333:policy/dev-galaxy-sns-alert-policy does not exist in the account inventory; cannot adopt it (create a new policy instead)"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unrelated error stays 500",
			err:        errors.New("database connection pool exhausted"),
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			context.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tickets/validate", nil)
			writeServiceError(context, test.err)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body)
			}
		})
	}
}

// 结构化校验错误按类型归类 400，与文案前缀无关：以下消息刻意不匹配任何
// legacy 白名单前缀，若分类退化回前缀匹配，前两条会落 500。
func TestWriteServiceErrorMapsStructuredValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "structured message outside whitelist",
			err:        apperr.Validation("该账号已有同步工单在处理中，请先完成或关闭既有工单"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "structured wrapped through %w chain",
			err:        fmt.Errorf("resolve AUTO approvers: %w", apperr.Validation("no active approvers are bound to this AWS account; open Sync Management → Accounts")),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "plain error still 500",
			err:        errors.New("该账号已有同步工单在处理中，请先完成或关闭既有工单"),
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			context.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tickets/validate", nil)
			writeServiceError(context, test.err)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body)
			}
		})
	}
}

func TestTicketHandlerRetryPublication(t *testing.T) {
	fake := &fakeTicketAPIService{}
	router := newTestTicketRouter(t, fake, "operator@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/tickets/IAM-123/publish", nil))
	if recorder.Code != http.StatusOK || fake.publishCall != 1 {
		t.Fatalf("status/calls = %d/%d", recorder.Code, fake.publishCall)
	}
}

func TestTicketHandlerRecordCIApplyResult(t *testing.T) {
	newRequest := func(status string) *http.Request {
		body := fmt.Sprintf(`{"status":%q,"commit_sha":"abc123","ci_url":"https://ci.example.com/run/1"}`, status)
		return httptest.NewRequest(http.MethodPost, "/tickets/IAM-123/apply-result", strings.NewReader(body))
	}

	t.Run("succeeded closes ticket", func(t *testing.T) {
		fake := &fakeTicketAPIService{ticket: model.IAMTicket{TicketNo: stringPointer("IAM-123")}}
		router := newTestTicketRouter(t, fake, "ci-runner@example.com")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, newRequest(service.CIApplyStatusSucceeded))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body)
		}
		if fake.lastCIApply.Status != service.CIApplyStatusSucceeded || fake.lastCIApply.CommitSHA != "abc123" {
			t.Fatalf("service received %+v", fake.lastCIApply)
		}
		if fake.ticket.ClosureReason == nil || *fake.ticket.ClosureReason != service.ClosureReasonApplied {
			t.Fatalf("ticket not closed as APPLIED: %+v", fake.ticket)
		}
	})

	t.Run("failed leaves ticket open", func(t *testing.T) {
		fake := &fakeTicketAPIService{ticket: model.IAMTicket{TicketNo: stringPointer("IAM-123")}}
		router := newTestTicketRouter(t, fake, "ci-runner@example.com")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, newRequest(service.CIApplyStatusFailed))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body)
		}
		if fake.ticket.Status != nil && *fake.ticket.Status == service.TicketStatusClosed {
			t.Fatal("failed apply must not close the ticket")
		}
	})

	t.Run("invalid status maps to 400", func(t *testing.T) {
		fake := &fakeTicketAPIService{}
		router := newTestTicketRouter(t, fake, "ci-runner@example.com")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, newRequest("unknown"))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body)
		}
	})
}

func TestTicketHandlerTerraformPreviewReturnsGeneratedCode(t *testing.T) {
	fake := &fakeTicketAPIService{
		terraformPreview: "resource \"aws_iam_policy\" \"managed_policy\" {}",
	}
	router := newTestTicketRouter(t, fake, "operator@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets/IAM-B656C324E745F81F/terraform", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if fake.terraformPreviewNo != "IAM-B656C324E745F81F" {
		t.Errorf("preview ticket no = %q", fake.terraformPreviewNo)
	}
	var payload struct {
		TerraformPreview string `json:"terraform_preview"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.TerraformPreview != fake.terraformPreview {
		t.Errorf("terraform_preview = %q", payload.TerraformPreview)
	}
}

func TestTicketHandlerTerraformPreviewMapsServiceError(t *testing.T) {
	fake := &fakeTicketAPIService{terraformPreviewErr: service.ErrTicketNotFound}
	router := newTestTicketRouter(t, fake, "operator@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets/IAM-MISSING/terraform", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestTicketHandlerListParsesFiltersAndPaginates(t *testing.T) {
	fake := &fakeTicketAPIService{ticket: model.IAMTicket{ID: 1}, listTotal: 42}
	router := newTestTicketRouter(t, fake, "viewer@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(
		http.MethodGet,
		"/tickets?status=DRAFT,APPROVING&account_id=3&submitter=alice&ticket_type=ROLLBACK&q=readonly&limit=5&offset=10",
		nil,
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body)
	}
	filter := fake.lastListFilter
	if len(filter.Statuses) != 2 || filter.Statuses[0] != "DRAFT" || filter.Statuses[1] != "APPROVING" {
		t.Errorf("statuses = %v, want [DRAFT APPROVING]", filter.Statuses)
	}
	if filter.AccountID == nil || *filter.AccountID != 3 {
		t.Errorf("account_id = %v, want 3", filter.AccountID)
	}
	if filter.Submitter != "alice" || filter.TicketType != "ROLLBACK" || filter.Keyword != "readonly" {
		t.Errorf("submitter/type/keyword = %q/%q/%q", filter.Submitter, filter.TicketType, filter.Keyword)
	}
	if filter.Limit != 5 || filter.Offset != 10 {
		t.Errorf("limit/offset = %d/%d, want 5/10", filter.Limit, filter.Offset)
	}
	var payload struct {
		Total   int64             `json:"total"`
		Limit   int               `json:"limit"`
		Offset  int               `json:"offset"`
		Tickets []model.IAMTicket `json:"tickets"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Total != 42 || payload.Limit != 5 || payload.Offset != 10 || len(payload.Tickets) != 1 {
		t.Errorf("payload total/limit/offset/tickets = %d/%d/%d/%d, want 42/5/10/1",
			payload.Total, payload.Limit, payload.Offset, len(payload.Tickets))
	}
}

func TestTicketHandlerListRejectsInvalidPaging(t *testing.T) {
	for _, query := range []string{"account_id=x", "account_id=0", "limit=abc", "limit=-1", "offset=-2"} {
		fake := &fakeTicketAPIService{}
		router := newTestTicketRouter(t, fake, "viewer@example.com")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets?"+query, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("query %q status = %d, want 400", query, recorder.Code)
		}
	}
}

func TestTicketHandlerListDefaultsLimit(t *testing.T) {
	fake := &fakeTicketAPIService{listTotal: 1}
	router := newTestTicketRouter(t, fake, "viewer@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastListFilter.Limit != 20 || fake.lastListFilter.Offset != 0 {
		t.Errorf("default limit/offset = %d/%d, want 20/0", fake.lastListFilter.Limit, fake.lastListFilter.Offset)
	}
}

func TestTicketHandlerValidateRunsPreviewWithoutPersisting(t *testing.T) {
	fake := &fakeTicketAPIService{
		validation: service.TicketValidationSnapshot{
			RequestSHA256: make([]byte, 32),
			Checks:        json.RawMessage(`[{"code":"STATIC_RISK_SCAN","result":"PASSED"}]`),
		},
	}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	body := `{
		"ticket_type":"CREATE_ROLE",
		"account_id":17,
		"principal_name":"analytics-reader",
		"request_policy":{"principal":{"name":"analytics-reader","type":"ServiceIdentity"},"permissions":[],"description":"read"},
		"role":{"name":"analytics-reader","trust_policy":{"Version":"2012-10-17","Statement":[]}},
		"approval_mode":"MANUAL",
		"approver_ids":["security-reviewer"]
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body)
	}
	if fake.validateSubmitter != "requester@example.com" {
		t.Errorf("validate submitter = %q, want requester@example.com", fake.validateSubmitter)
	}
	if !strings.Contains(recorder.Body.String(), `"validation"`) ||
		!strings.Contains(recorder.Body.String(), "STATIC_RISK_SCAN") {
		t.Errorf("body missing validation checks: %s", recorder.Body)
	}
}

func TestTicketHandlerValidateAcceptsRoleWithoutPermissionPolicy(t *testing.T) {
	fake := &fakeTicketAPIService{
		validation: service.TicketValidationSnapshot{
			RequestSHA256: make([]byte, 32),
			Checks:        json.RawMessage(`[]`),
		},
	}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	body := `{
		"ticket_type":"CREATE_ROLE",
		"account_id":17,
		"principal_name":"analytics-reader",
		"role":{"name":"analytics-reader","trust_policy":{"Version":"2012-10-17","Statement":[]}},
		"approval_mode":"MANUAL",
		"approver_ids":["security-reviewer"]
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body)
	}
	if fake.validateSubmitter != "requester@example.com" {
		t.Errorf("validate submitter = %q, want requester@example.com", fake.validateSubmitter)
	}
}

func TestTicketHandlerValidateAcceptsRoleInlinePolicyBatchWithoutPolicyEnvelope(t *testing.T) {
	fake := &fakeTicketAPIService{
		validation: service.TicketValidationSnapshot{
			RequestSHA256: make([]byte, 32),
			Checks:        json.RawMessage(`[]`),
		},
	}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	body := `{
		"ticket_type":"ADOPT_ROLE_INLINE_POLICIES",
		"account_id":17,
		"principal_name":"workspaces_DefaultRole",
		"principal_type":"Role",
		"approval_mode":"MANUAL",
		"approver_ids":["security-reviewer"]
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body)
	}
	if fake.validateSubmitter != "requester@example.com" {
		t.Errorf("validate submitter = %q, want requester@example.com", fake.validateSubmitter)
	}
}

func TestTicketHandlerValidateAcceptsCreateResourceConfigWithoutPolicyEnvelope(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "managed policy",
			body: `{"ticket_type":"CREATE_MANAGED_POLICY","account_id":17,"principal_name":"team-read","create_managed_policy":{"name":"team-read"}}`,
		},
		{
			name: "user",
			body: `{"ticket_type":"CREATE_USER","account_id":17,"principal_name":"app-user","create_user":{"name":"app-user"}}`,
		},
		{
			name: "group",
			body: `{"ticket_type":"CREATE_GROUP","account_id":17,"principal_name":"app-group","create_group":{"name":"app-group"}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTicketAPIService{
				validation: service.TicketValidationSnapshot{
					RequestSHA256: make([]byte, 32),
					Checks:        json.RawMessage(`[]`),
				},
			}
			router := newTestTicketRouter(t, fake, "requester@example.com")
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(
				http.MethodPost, "/tickets/validate", strings.NewReader(test.body),
			)
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body)
			}
			if fake.validateSubmitter != "requester@example.com" {
				t.Errorf("validate submitter = %q, want requester@example.com", fake.validateSubmitter)
			}
		})
	}
}

func TestTicketHandlerValidateRejectsMissingPolicyAndRolePayload(t *testing.T) {
	fake := &fakeTicketAPIService{}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/validate",
		strings.NewReader(`{"ticket_type":"CREATE_ROLE","account_id":17,"principal_name":"x"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "either request_policy or abstract_policy") {
		t.Errorf("status/body = %d/%s", recorder.Code, recorder.Body)
	}
	if fake.validateSubmitter != "" {
		t.Errorf("service reached despite missing payload: %q", fake.validateSubmitter)
	}
}

func TestTicketHandlerValidateMapsBlockingRiskTo422(t *testing.T) {
	fake := &fakeTicketAPIService{
		validateErr: &service.CandidatePolicyRiskError{
			Findings: []service.CandidatePolicyRiskFinding{
				{RiskType: "ADMIN_ACTION", RiskLevel: "HIGH", Description: "wildcard admin"},
			},
		},
	}
	router := newTestTicketRouter(t, fake, "requester@example.com")
	body := `{
		"ticket_type":"CREATE_ROLE",
		"account_id":17,
		"principal_name":"analytics-reader",
		"request_policy":{"principal":{"name":"analytics-reader","type":"ServiceIdentity"},"permissions":[],"description":"read"},
		"role":{"name":"analytics-reader","trust_policy":{"Version":"2012-10-17","Statement":[]}},
		"approval_mode":"MANUAL",
		"approver_ids":["security-reviewer"]
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(recorder.Body.String(), "findings") ||
		!strings.Contains(recorder.Body.String(), "ADMIN_ACTION") {
		t.Errorf("status/body = %d/%s", recorder.Code, recorder.Body)
	}
}

func TestErrorResponsesUseUnifiedEnvelope(t *testing.T) {
	type envelope struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Details json.RawMessage `json:"details"`
	}
	for _, test := range []struct {
		name            string
		unauthenticated bool
		call            func(router *gin.Engine) *httptest.ResponseRecorder
		wantStatus      int
		wantCode        string
	}{
		{
			name: "bad request",
			call: func(router *gin.Engine) *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets?limit=abc", nil))
				return recorder
			},
			wantStatus: http.StatusBadRequest, wantCode: "INVALID_REQUEST",
		},
		{
			name: "not found",
			call: func(router *gin.Engine) *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets/IAM-MISSING", nil))
				return recorder
			},
			wantStatus: http.StatusNotFound, wantCode: "NOT_FOUND",
		},
		{
			name:            "unauthorized",
			unauthenticated: true,
			call: func(router *gin.Engine) *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tickets/IAM-123", nil))
				return recorder
			},
			wantStatus: http.StatusUnauthorized, wantCode: "UNAUTHORIZED",
		},
		{
			name: "conflict",
			call: func(router *gin.Engine) *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				body := `{"ticket_type":"CREATE_ROLE","account_id":1,"principal_name":"x"}`
				request := httptest.NewRequest(http.MethodPost, "/tickets/validate", strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, request)
				return recorder
			},
			wantStatus: http.StatusBadRequest, wantCode: "INVALID_REQUEST",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTicketAPIService{getErr: service.ErrTicketNotFound}
			user := "reader@example.com"
			if test.unauthenticated {
				user = ""
			}
			router := newTestTicketRouter(t, fake, user)
			recorder := test.call(router)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body)
			}
			var payload envelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode error envelope: %v; body=%s", err, recorder.Body)
			}
			if payload.Code != test.wantCode {
				t.Errorf("code = %q, want %q", payload.Code, test.wantCode)
			}
			if payload.Message == "" {
				t.Error("message must not be empty")
			}
			if string(payload.Details) != "{}" {
				t.Errorf("details = %s, want {}", payload.Details)
			}
		})
	}
}

func TestValidationFailureEnvelopeCarriesStructuredDetails(t *testing.T) {
	fake := &fakeTicketAPIService{
		validateErr: &service.IAMBaselineComplianceError{
			Violations: []service.IAMBaselineViolation{{Code: "GRANT_OUTSIDE_BASELINE"}},
		},
	}
	router := newTestTicketRouter(t, fake, "reader@example.com")
	body := `{
		"ticket_type":"CREATE_ROLE","account_id":1,"principal_name":"x",
		"request_policy":{"principal":{"name":"x","type":"ServiceIdentity"},"permissions":[]},
		"role":{"name":"x","trust_policy":{}},"approval_mode":"MANUAL","approver_ids":["admin"]
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tickets/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", recorder.Code, recorder.Body)
	}
	var payload struct {
		Code    string `json:"code"`
		Details struct {
			Violations []service.IAMBaselineViolation `json:"violations"`
		} `json:"details"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v; body=%s", err, recorder.Body)
	}
	if payload.Code != "BASELINE_VIOLATION" {
		t.Errorf("code = %q, want BASELINE_VIOLATION", payload.Code)
	}
	if len(payload.Details.Violations) != 1 || payload.Details.Violations[0].Code != "GRANT_OUTSIDE_BASELINE" {
		t.Errorf("details.violations = %+v", payload.Details.Violations)
	}
}

// fakePublicationReporter 记录工单回调里「标记基线发布已应用」的动作。
type fakePublicationReporter struct {
	publication *service.BaselinePublication
	getErr      error
	applyErr    error
	appliedID   int64
	applyResult service.BaselineApplyResult
}

func (fake *fakePublicationReporter) Get(
	_ context.Context, _ int64,
) (*service.BaselinePublication, error) {
	if fake.getErr != nil {
		return nil, fake.getErr
	}
	return fake.publication, nil
}

func (fake *fakePublicationReporter) RecordApplyResult(
	_ context.Context, publicationID int64, _ string, result service.BaselineApplyResult,
) (*service.BaselinePublication, error) {
	fake.appliedID = publicationID
	fake.applyResult = result
	if fake.applyErr != nil {
		return nil, fake.applyErr
	}
	return fake.publication, nil
}

func ticketRouterWithReporter(
	t *testing.T, ticketService *fakeTicketAPIService, reporter publicationApplyReporter,
) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewTicketHandler(ticketService, WithTicketPublicationReporter(reporter))
	if err != nil {
		t.Fatalf("NewTicketHandler() error = %v", err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "ci-runner@example.com")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterTicketRoutes(router, handler)
	return router
}

// TestTicketApplyResultLinksPublication 一次 main 提交可能同时应用了工单 PR 与
// 基线 PR。归属校验必须发生在关单之前：先关单再发现「应用的是别的账号」是
// 最难收拾的顺序。
func TestTicketApplyResultLinksPublication(t *testing.T) {
	accountID := int64(3)
	ticketNo := "IAM-123"
	body := `{"status":"succeeded","commit_sha":"abc123","publication_id":42}`

	t.Run("same account marks publication applied", func(t *testing.T) {
		serviceFake := &fakeTicketAPIService{ticket: model.IAMTicket{
			TicketNo: &ticketNo, AccountID: &accountID,
		}}
		reporter := &fakePublicationReporter{publication: &service.BaselinePublication{
			ID: 42, AccountDBID: accountID, Status: service.BaselinePublicationStatusPublished,
		}}
		router := ticketRouterWithReporter(t, serviceFake, reporter)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost,
			"/tickets/IAM-123/apply-result", strings.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
		}
		if reporter.appliedID != 42 || reporter.applyResult.CommitSHA != "abc123" {
			t.Fatalf("publication not marked applied: %+v", reporter)
		}
		if serviceFake.lastCIApply.PublicationID != 42 {
			t.Fatalf("publication id not forwarded to service: %+v", serviceFake.lastCIApply)
		}
	})

	t.Run("other account is rejected before closing", func(t *testing.T) {
		serviceFake := &fakeTicketAPIService{ticket: model.IAMTicket{
			TicketNo: &ticketNo, AccountID: &accountID,
		}}
		reporter := &fakePublicationReporter{publication: &service.BaselinePublication{
			ID: 42, AccountDBID: 999,
		}}
		router := ticketRouterWithReporter(t, serviceFake, reporter)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost,
			"/tickets/IAM-123/apply-result", strings.NewReader(body)))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
		}
		if serviceFake.lastCIApply.Status != "" {
			t.Fatal("ticket callback must not run when the publication belongs elsewhere")
		}
		if reporter.appliedID != 0 {
			t.Fatal("publication must not be marked applied on account mismatch")
		}
	})

	t.Run("unconfigured reporter answers 501", func(t *testing.T) {
		serviceFake := &fakeTicketAPIService{ticket: model.IAMTicket{
			TicketNo: &ticketNo, AccountID: &accountID,
		}}
		router := newTestTicketRouter(t, serviceFake, "ci-runner@example.com")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost,
			"/tickets/IAM-123/apply-result", strings.NewReader(body)))
		if recorder.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", recorder.Code)
		}
	})
}
