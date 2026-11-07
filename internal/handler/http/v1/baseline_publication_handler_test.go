package v1

import (
	stdcontext "context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type baselinePublicationFake struct {
	mu sync.Mutex

	createdRef     string
	createdUser    string
	publication    *service.BaselinePublication
	alreadyPub     bool
	createErr      error
	runIDs         []int64
	runErr         error
	runStarted     chan struct{}
	batchRefs      []string
	batchOutcomes  []service.BaselineBatchOutcome
	batchIDs       []int64
	batchAgg       bool
	runShouldPanic bool
	listRef        string
	publications   []service.BaselinePublication
	getID          int64
	getErr         error
	applyID        int64
	applyResult    service.BaselineApplyResult
	applyErr       error
	previewRef     string
	preview        service.BaselinePublishPreview
	previewErr     error
}

func (fake *baselinePublicationFake) Preview(
	_ stdcontext.Context, accountRef string,
) (service.BaselinePublishPreview, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.previewRef = accountRef
	if fake.previewErr != nil {
		return service.BaselinePublishPreview{}, fake.previewErr
	}
	return fake.preview, nil
}

func (fake *baselinePublicationFake) Create(
	_ stdcontext.Context, ref, requestedBy string,
) (*service.BaselinePublication, bool, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.createdRef = ref
	fake.createdUser = requestedBy
	if fake.createErr != nil {
		return nil, false, fake.createErr
	}
	if fake.publication == nil {
		fake.publication = &service.BaselinePublication{
			ID: 9, AccountDBID: 1, AWSAccountID: "111122223333", SyncRunID: 41,
			Status: service.BaselinePublicationStatusPublishing,
			Branch: "baseline/111122223333/41", RequestedBy: requestedBy,
			CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC(),
		}
	}
	return fake.publication, fake.alreadyPub, nil
}

func (fake *baselinePublicationFake) CreateBatch(
	_ stdcontext.Context, refs []string, requestedBy string,
) ([]service.BaselineBatchOutcome, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.batchRefs = refs
	outcomes := fake.batchOutcomes
	if outcomes == nil {
		outcomes = []service.BaselineBatchOutcome{{
			AccountRef:  refs[0],
			Publication: &service.BaselinePublication{ID: 11, Status: service.BaselinePublicationStatusPublishing},
		}}
	}
	return outcomes, nil
}

func (fake *baselinePublicationFake) RecordApplyResult(
	_ stdcontext.Context, publicationID int64, _ string, result service.BaselineApplyResult,
) (*service.BaselinePublication, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.applyID = publicationID
	fake.applyResult = result
	if fake.applyErr != nil {
		return nil, fake.applyErr
	}
	publication := fake.publication
	if publication == nil {
		publication = &service.BaselinePublication{ID: publicationID}
	}
	applied := *publication
	if result.Status == service.BaselineApplyStatusSucceeded {
		now := time.Unix(0, 0).UTC()
		applied.AppliedAt = &now
		applied.AppliedCommitSHA = result.CommitSHA
	}
	return &applied, nil
}

func (fake *baselinePublicationFake) Run(_ stdcontext.Context, publicationID int64) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.runShouldPanic {
		panic("simulated worker crash")
	}
	fake.runIDs = append(fake.runIDs, publicationID)
	if fake.runStarted != nil {
		fake.runStarted <- struct{}{}
	}
	return fake.runErr
}

func (fake *baselinePublicationFake) RunBatch(
	_ stdcontext.Context, publicationIDs []int64, aggregate bool,
) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.batchIDs = publicationIDs
	fake.batchAgg = aggregate
	if fake.runStarted != nil {
		fake.runStarted <- struct{}{}
	}
	return fake.runErr
}

func (fake *baselinePublicationFake) List(
	_ stdcontext.Context, ref string, _ int,
) ([]service.BaselinePublication, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.listRef = ref
	return fake.publications, nil
}

func (fake *baselinePublicationFake) Get(
	_ stdcontext.Context, publicationID int64,
) (*service.BaselinePublication, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.getID = publicationID
	if fake.getErr != nil {
		return nil, fake.getErr
	}
	return fake.publication, nil
}

func baselinePublicationTestRouter(handler *BaselinePublicationHandler, roles []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "tester")
		context.Set(AuthenticatedRolesContextKey, roles)
	})
	RegisterBaselinePublicationRoutes(api, handler)
	return router
}

func TestBaselinePublicationRouteRequiresPlatformAdmin(t *testing.T) {
	handler, err := NewBaselinePublicationHandler(&baselinePublicationFake{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselinePublicationTestRouter(handler, []string{"standard_user"})
	requests := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/aws/accounts/123/baseline-publications"},
		{http.MethodPost, "/api/v1/aws/baseline-publications/batch"},
		{http.MethodGet, "/api/v1/aws/accounts/123/baseline-publications"},
		{http.MethodGet, "/api/v1/baseline-publications/1"},
		{http.MethodGet, "/api/v1/aws/accounts/123/baseline-preview"},
	}
	for _, item := range requests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(item.method, item.path, nil)
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403", item.method, item.path, response.Code)
		}
	}
}

// Create：新建发布 202 并后台执行；幂等命中（同 run 已发布）200 不再执行。
// Preview：确认框里的差异数（C10）。只读接口，但同样只给平台管理员；
// 没有成功同步时必须 409（和发布同一原因），不能返回「0 个待发布」。
func TestBaselinePublicationPreview(t *testing.T) {
	fake := &baselinePublicationFake{
		preview: service.BaselinePublishPreview{
			AccountDBID: 1, AWSAccountID: "111122223333", SyncRunID: 41,
			RepoDirectory: "iam/account-111122223333",
			Files:         338, Unchanged: 336, ToPublish: 2,
			Conflicts: []string{},
		},
	}
	handler, err := NewBaselinePublicationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselinePublicationTestRouter(handler, []string{"platform_admin"})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/aws/accounts/111122223333/baseline-preview", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("preview status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.previewRef != "111122223333" {
		t.Fatalf("preview ref = %q", fake.previewRef)
	}
	var body service.BaselinePublishPreview
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if body.Files != 338 || body.Unchanged != 336 || body.ToPublish != 2 {
		t.Fatalf("preview body = %+v", body)
	}

	fake.previewErr = service.ErrBaselineNoSyncRun
	response = httptest.NewRecorder()
	request = httptest.NewRequest(
		http.MethodGet, "/api/v1/aws/accounts/111122223333/baseline-preview", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("preview without sync run status = %d, want 409", response.Code)
	}
}

func TestBaselinePublicationCreateAcceptedThenIdempotent(t *testing.T) {
	fake := &baselinePublicationFake{runStarted: make(chan struct{}, 1)}
	handler, err := NewBaselinePublicationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselinePublicationTestRouter(handler, []string{"platform_admin"})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/111122223333/baseline-publications", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("first create status = %d, body = %s", response.Code, response.Body.String())
	}
	select {
	case <-fake.runStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Run was not invoked after create")
	}
	if len(fake.runIDs) != 1 || fake.runIDs[0] != 9 {
		t.Fatalf("run ids = %v, want [9]", fake.runIDs)
	}

	fake.alreadyPub = true
	response = httptest.NewRecorder()
	request = httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/111122223333/baseline-publications", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("idempotent create status = %d, want 200", response.Code)
	}
	var body struct {
		AlreadyPublished bool `json:"already_published"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || !body.AlreadyPublished {
		t.Fatalf("body = %s (err=%v), want already_published=true", response.Body.String(), err)
	}
	if len(fake.runIDs) != 1 {
		t.Fatalf("idempotent create must not spawn another run")
	}
}

// Create：同 run 没有成功同步（无幂等键）→ 409，提示先同步。
func TestBaselinePublicationCreateNoSyncRunConflicts(t *testing.T) {
	fake := &baselinePublicationFake{}
	handler, err := NewBaselinePublicationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 在 Create 的错误路径里直接返回 ErrBaselineNoSyncRun 的包装由服务层做；
	// handler 只按 errors.Is 分流，这里塞一个裸错误验证映射。
	handlerCreateErr := fmtWrap(service.ErrBaselineNoSyncRun)
	fake.createErr = handlerCreateErr
	router := baselinePublicationTestRouter(handler, []string{"platform_admin"})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/111122223333/baseline-publications", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (sync first)", response.Code)
	}
}

// 批量：空 refs 400；正常路径 202 并把可发布行交给 RunBatch（聚合开关透传）。
func TestBaselinePublicationBatch(t *testing.T) {
	fake := &baselinePublicationFake{runStarted: make(chan struct{}, 1)}
	handler, err := NewBaselinePublicationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselinePublicationTestRouter(handler, []string{"platform_admin"})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/aws/baseline-publications/batch",
		strings.NewReader(`{"account_refs":[]}`))
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("empty refs status = %d, want 400", response.Code)
	}

	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/aws/baseline-publications/batch",
		strings.NewReader(`{"account_refs":["111122223333","111122223333","123456789012"],"aggregate":true}`))
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("batch status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(fake.batchRefs) != 2 || fake.batchRefs[1] != "123456789012" {
		t.Fatalf("batch refs = %v (duplicates must be dropped)", fake.batchRefs)
	}
	select {
	case <-fake.runStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("RunBatch was not invoked")
	}
	if !fake.batchAgg || len(fake.batchIDs) != 1 || fake.batchIDs[0] != 11 {
		t.Fatalf("batch run = %v aggregate=%v", fake.batchIDs, fake.batchAgg)
	}
}

func TestBaselinePublicationGetNotFound(t *testing.T) {
	fake := &baselinePublicationFake{getErr: service.ErrBaselinePublicationNotFound}
	handler, err := NewBaselinePublicationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselinePublicationTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/baseline-publications/9", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

// fmtWrap 是 errors.Is 可穿透的简单包装（handler 分流只看 Is）。
type fmtWrapError struct{ cause error }

func (err fmtWrapError) Error() string { return err.cause.Error() }
func (err fmtWrapError) Unwrap() error { return err.cause }

func fmtWrap(cause error) error { return fmtWrapError{cause: cause} }

// TestBaselinePublicationApplyResult 基线没有工单号，只能按 publication 回调
// 「到底 apply 了没有」。状态值、幂等与错误映射都要和工单侧一致。
func TestBaselinePublicationApplyResult(t *testing.T) {
	fake := &baselinePublicationFake{publication: &service.BaselinePublication{
		ID: 7, AccountDBID: 1, Status: service.BaselinePublicationStatusPublished,
	}}
	handler, err := NewBaselinePublicationHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselinePublicationTestRouter(handler, []string{"platform_admin"})
	post := func(path, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return recorder
	}

	response := post("/api/v1/aws/baseline-publications/7/apply-result",
		`{"status":"succeeded","commit_sha":"deadbeef","ci_url":"https://ci.example.com/run/9"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if fake.applyID != 7 || fake.applyResult.Status != service.BaselineApplyStatusSucceeded ||
		fake.applyResult.CommitSHA != "deadbeef" {
		t.Fatalf("apply result not forwarded: id=%d result=%+v", fake.applyID, fake.applyResult)
	}
	if !strings.Contains(response.Body.String(), `"applied_commit_sha":"deadbeef"`) {
		t.Fatalf("applied evidence missing: %s", response.Body.String())
	}

	if bad := post("/api/v1/aws/baseline-publications/0/apply-result",
		`{"status":"succeeded"}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("bad id status = %d, want 400", bad.Code)
	}

	fake.applyErr = apperr.Validation("status must be succeeded or failed")
	if invalid := post("/api/v1/aws/baseline-publications/7/apply-result",
		`{"status":"ok"}`); invalid.Code != http.StatusBadRequest {
		t.Fatalf("validation status = %d, want 400", invalid.Code)
	}

	fake.applyErr = service.ErrBaselinePublicationNotFound
	if missing := post("/api/v1/aws/baseline-publications/7/apply-result",
		`{"status":"failed"}`); missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", missing.Code)
	}
}
