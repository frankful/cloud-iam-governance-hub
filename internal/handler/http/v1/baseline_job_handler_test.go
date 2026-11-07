package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type baselineJobHandlerFake struct {
	mu sync.Mutex

	createdRef     string
	createdUser    string
	createdJob     *service.BaselinePreviewJob
	createErr      error
	runJobID       int64
	runErr         error
	runStarted     chan struct{}
	listRef        string
	listLimit      int
	jobs           []service.BaselinePreviewJob
	getJobID       int64
	getJob         *service.BaselinePreviewJob
	getErr         error
	runShouldPanic bool

	enqueuer      service.BaselinePreviewJobEnqueuer
	enqueuedJobID int64
	enqueueErr    error
	failJobID     int64
	failCause     error
	failCalled    bool
}

func (fake *baselineJobHandlerFake) Enqueuer() service.BaselinePreviewJobEnqueuer {
	return fake.enqueuer
}

func (fake *baselineJobHandlerFake) Fail(_ context.Context, jobID int64, cause error) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.failCalled = true
	fake.failJobID = jobID
	fake.failCause = cause
	return nil
}

func (fake *baselineJobHandlerFake) Create(
	_ context.Context, ref, requestedBy string,
) (*service.BaselinePreviewJob, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.createdRef = ref
	fake.createdUser = requestedBy
	if fake.createErr != nil {
		return nil, fake.createErr
	}
	fake.createdJob = &service.BaselinePreviewJob{
		ID: 7, AccountDBID: 1, AWSAccountID: "123456789012",
		Status: service.BaselineJobStatusPending, RequestedBy: requestedBy,
		CreatedAt: time.Unix(0, 0).UTC(),
	}
	return fake.createdJob, nil
}

func (fake *baselineJobHandlerFake) Run(_ context.Context, jobID int64) error {
	if fake.runShouldPanic {
		panic("simulated worker crash")
	}
	fake.mu.Lock()
	fake.runJobID = jobID
	fake.mu.Unlock()
	if fake.runStarted != nil {
		close(fake.runStarted)
	}
	return fake.runErr
}

func (fake *baselineJobHandlerFake) List(
	_ context.Context, ref string, limit int,
) ([]service.BaselinePreviewJob, error) {
	fake.listRef = ref
	fake.listLimit = limit
	return fake.jobs, nil
}

func (fake *baselineJobHandlerFake) Get(_ context.Context, jobID int64) (*service.BaselinePreviewJob, error) {
	fake.getJobID = jobID
	if fake.getErr != nil {
		return nil, fake.getErr
	}
	return fake.getJob, nil
}

func baselineJobTestRouter(handler *BaselineJobHandler, roles []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "tester")
		context.Set(AuthenticatedRolesContextKey, roles)
	})
	RegisterBaselineJobRoutes(api, handler)
	return router
}

func TestBaselineJobRouteRequiresPlatformAdmin(t *testing.T) {
	handler, err := NewBaselineJobHandler(&baselineJobHandlerFake{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"standard_user"})
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(
			method, "/api/v1/aws/accounts/123/baseline-jobs", nil)
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", method, response.Code)
		}
	}
}

func TestBaselineJobCreateReturnsAcceptedAndRuns(t *testing.T) {
	fake := &baselineJobHandlerFake{runStarted: make(chan struct{})}
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/123456789012/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.createdRef != "123456789012" || fake.createdUser != "tester" {
		t.Errorf("create args = %q / %q", fake.createdRef, fake.createdUser)
	}
	if !strings.Contains(response.Body.String(), `"status":"PENDING"`) {
		t.Errorf("body should carry the pending job: %s", response.Body.String())
	}
	select {
	case <-fake.runStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Run was not invoked after create")
	}
	if fake.runJobID != 7 {
		t.Errorf("run job id = %d, want 7", fake.runJobID)
	}
}

// Run 在后台 goroutine 里执行：panic 不能带崩进程，只允许作为 job 失败处理。
func TestBaselineJobCreateSurvivesRunPanic(t *testing.T) {
	fake := &baselineJobHandlerFake{runShouldPanic: true}
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/123456789012/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.Code)
	}
}

func TestBaselineJobCreateAccountNotFound(t *testing.T) {
	handler, err := NewBaselineJobHandler(
		&baselineJobHandlerFake{createErr: service.ErrBaselineAccountNotFound}, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/missing/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

func TestBaselineJobListDefaultsLimit(t *testing.T) {
	fake := &baselineJobHandlerFake{jobs: []service.BaselinePreviewJob{{
		ID: 7, AWSAccountID: "123456789012",
		Status: service.BaselineJobStatusCompleted, ContentSHA256: "ab",
	}}}
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/aws/accounts/123456789012/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fake.listLimit != 20 {
		t.Errorf("limit = %d, want default 20", fake.listLimit)
	}
	if !strings.Contains(response.Body.String(), `"content_sha256":"ab"`) {
		t.Errorf("body = %s", response.Body.String())
	}
}

func TestBaselineJobGetNotFoundAndBadRequest(t *testing.T) {
	fake := &baselineJobHandlerFake{getErr: service.ErrBaselineJobNotFound}
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/baseline-jobs/9", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}

	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/baseline-jobs/not-a-number", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

// Run 的错误只进日志与 job 行，不冒泡成 HTTP 错误——创建已经成功。
func TestBaselineJobCreateIgnoresRunError(t *testing.T) {
	fake := &baselineJobHandlerFake{runErr: errors.New("boom"), runStarted: make(chan struct{})}
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/123456789012/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.Code)
	}
}

// enqueueFake 模拟队列执行面：记录入队参数，可注入失败。
type enqueueFake struct {
	mu      sync.Mutex
	jobID   int64
	wantErr error
}

func (fake *enqueueFake) EnqueuePreviewJob(_ context.Context, jobID int64) error {
	if fake.wantErr != nil {
		return fake.wantErr
	}
	fake.jobID = jobID
	return nil
}

func TestBaselineJobCreateEnqueuesInsteadOfInProcessRun(t *testing.T) {
	fake := &baselineJobHandlerFake{runStarted: make(chan struct{})}
	enqueuer := &enqueueFake{}
	fake.enqueuer = enqueuer
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/123456789012/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if enqueuer.jobID != 7 {
		t.Errorf("enqueued job id = %d, want 7", enqueuer.jobID)
	}
	select {
	case <-fake.runStarted:
		t.Fatal("Run must not be invoked in-process when an enqueuer is set")
	case <-time.After(200 * time.Millisecond):
	}
	if fake.failCalled {
		t.Error("Fail must not be called when enqueue succeeds")
	}
}

func TestBaselineJobCreateEnqueueFailureMarksJobFailed(t *testing.T) {
	fake := &baselineJobHandlerFake{runStarted: make(chan struct{})}
	fake.enqueuer = &enqueueFake{wantErr: errors.New("redis down")}
	handler, err := NewBaselineJobHandler(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := baselineJobTestRouter(handler, []string{"platform_admin"})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/aws/accounts/123456789012/baseline-jobs", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	if !fake.failCalled || fake.failJobID != 7 {
		t.Errorf("Fail called = %v (job %d), want job 7", fake.failCalled, fake.failJobID)
	}
	if fake.failCause == nil || !strings.Contains(fake.failCause.Error(), "redis down") {
		t.Errorf("fail cause should carry enqueue error, got %v", fake.failCause)
	}
}
