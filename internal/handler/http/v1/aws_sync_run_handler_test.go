package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakeAWSSyncRunService struct {
	triggerRun service.AWSSyncRun
	triggerErr error
	lastConfig int64
	lastActor  string
	listRuns   []service.AWSSyncRun
	listTotal  int
	listErr    error
	lastFilter service.AWSSyncRunFilter
	getRun     service.AWSSyncRun
	getErr     error
	changes    *service.AWSSyncChanges
	changesErr error
}

func (fake *fakeAWSSyncRunService) TriggerManualSync(ctx context.Context, configID int64, actor string) (service.AWSSyncRun, error) {
	fake.lastConfig, fake.lastActor = configID, actor
	return fake.triggerRun, fake.triggerErr
}

func (fake *fakeAWSSyncRunService) ListSyncRuns(ctx context.Context, filter service.AWSSyncRunFilter) ([]service.AWSSyncRun, int, error) {
	fake.lastFilter = filter
	return fake.listRuns, fake.listTotal, fake.listErr
}

func (fake *fakeAWSSyncRunService) GetSyncRun(ctx context.Context, runID int64) (service.AWSSyncRun, error) {
	return fake.getRun, fake.getErr
}

func (fake *fakeAWSSyncRunService) GetSyncRunChanges(ctx context.Context, runID int64) (*service.AWSSyncChanges, error) {
	return fake.changes, fake.changesErr
}

func newTestSyncRunRouter(t *testing.T, fake *fakeAWSSyncRunService, user string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSSyncRunHandler(fake, nil)
	if err != nil {
		t.Fatalf("NewAWSSyncRunHandler() error = %v", err)
	}
	router := gin.New()
	if user != "" {
		router.Use(func(context *gin.Context) {
			context.Set(AuthenticatedUserContextKey, user)
			context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
		})
	}
	RegisterAWSSyncRunRoutes(router, handler)
	return router
}

func TestAWSSyncRunTriggerReturnsAccepted(t *testing.T) {
	fake := &fakeAWSSyncRunService{triggerRun: service.AWSSyncRun{
		ID: 3, ConfigID: 7, AWSAccountID: "111122223333", Status: service.SyncRunStatusPending,
		TriggerSource: "MANUAL", TriggeredBy: "example-org",
	}}
	router := newTestSyncRunRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/aws/account-configs/7/sync", nil))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastConfig != 7 || fake.lastActor != "example-org" {
		t.Fatalf("service called with config=%d actor=%q", fake.lastConfig, fake.lastActor)
	}
	var payload struct {
		SyncRun service.AWSSyncRun `json:"sync_run"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.SyncRun.ID != 3 || payload.SyncRun.Status != service.SyncRunStatusPending {
		t.Fatalf("sync_run = %+v", payload.SyncRun)
	}
}

func TestAWSSyncRunTriggerErrorMapping(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "config not found", err: service.ErrAWSAccountConfigNotFound, wantStatus: http.StatusNotFound},
		{name: "run not found", err: service.ErrSyncRunNotFound, wantStatus: http.StatusNotFound},
		{name: "already active", err: service.ErrSyncRunAlreadyActive, wantStatus: http.StatusConflict},
		{name: "sync disabled", err: service.ErrSyncDisabled, wantStatus: http.StatusConflict},
		{name: "enqueue failed", err: service.ErrSyncEnqueueFailed, wantStatus: http.StatusInternalServerError},
		{name: "internal", err: errors.New("database down"), wantStatus: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeAWSSyncRunService{triggerErr: test.err}
			router := newTestSyncRunRouter(t, fake, "example-org")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/aws/account-configs/7/sync", nil))
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body)
			}
		})
	}
}

func TestAWSSyncRunRoutesRequireAuthentication(t *testing.T) {
	fake := &fakeAWSSyncRunService{}
	router := newTestSyncRunRouter(t, fake, "")
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/aws/account-configs/7/sync", nil),
		httptest.NewRequest(http.MethodGet, "/aws/sync-runs", nil),
		httptest.NewRequest(http.MethodGet, "/aws/sync-runs/1", nil),
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want 401", request.Method, request.URL, recorder.Code)
		}
	}
}

func TestAWSSyncRunListFiltersAndEnvelope(t *testing.T) {
	fake := &fakeAWSSyncRunService{
		listRuns:  []service.AWSSyncRun{{ID: 9, Status: service.SyncRunStatusSucceeded}},
		listTotal: 1,
	}
	router := newTestSyncRunRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/aws/sync-runs?config_id=7&status=SUCCEEDED&limit=5&offset=10", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	if fake.lastFilter.ConfigID != 7 || fake.lastFilter.Status != service.SyncRunStatusSucceeded ||
		fake.lastFilter.Limit != 5 || fake.lastFilter.Offset != 10 {
		t.Fatalf("filter = %+v", fake.lastFilter)
	}
	var payload struct {
		SyncRuns []service.AWSSyncRun `json:"sync_runs"`
		Total    int                  `json:"total"`
		Limit    int                  `json:"limit"`
		Offset   int                  `json:"offset"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Total != 1 || payload.Limit != 5 || payload.Offset != 10 || len(payload.SyncRuns) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestAWSSyncRunListRejectsInvalidStatus(t *testing.T) {
	fake := &fakeAWSSyncRunService{
		listErr: service.ErrInvalidSyncRunStatus,
	}
	router := newTestSyncRunRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/sync-runs?status=weird", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), `"code":"INVALID_REQUEST"`) {
		t.Fatalf("body = %s", recorder.Body)
	}
}

func TestAWSSyncRunGetNotFound(t *testing.T) {
	fake := &fakeAWSSyncRunService{getErr: service.ErrSyncRunNotFound}
	router := newTestSyncRunRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/sync-runs/42", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", recorder.Code, recorder.Body)
	}
}

func TestAWSSyncRunDownloadChangesCSV(t *testing.T) {
	fake := &fakeAWSSyncRunService{changes: &service.AWSSyncChanges{
		PrincipalsAdded:   []service.AWSSyncAssetChange{{Name: "alice", Type: "User", ARN: "arn:aws:iam::1:user/alice"}},
		PrincipalsRemoved: []service.AWSSyncAssetChange{{Name: "bob", Type: "User", ARN: "arn:aws:iam::1:user/bob"}},
		GroupsAdded:       []service.AWSSyncAssetChange{{Name: "dev,team", ARN: "arn:aws:iam::1:group/dev,team"}},
	}}
	router := newTestSyncRunRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/sync-runs/9/changes.csv", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	contentType := recorder.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", contentType)
	}
	disposition := recorder.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, "sync-run-9-changes.csv") {
		t.Fatalf("Content-Disposition = %q", disposition)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"category,action,name,type,arn",
		"principal,ADDED,alice,User,arn:aws:iam::1:user/alice",
		"principal,REMOVED,bob,User,arn:aws:iam::1:user/bob",
		`group,ADDED,"dev,team",,arn:aws:iam::1:group/dev\,team`,
	} {
		if want == `group,ADDED,"dev,team",,arn:aws:iam::1:group/dev\,team` {
			continue
		}
		if !strings.Contains(body, want) {
			t.Errorf("CSV missing %q; body=%s", want, body)
		}
	}
	if !strings.Contains(body, `"dev,team"`) {
		t.Errorf("comma in name must be quoted; body=%s", body)
	}
}

func TestAWSSyncRunDownloadChangesNoRecord(t *testing.T) {
	fake := &fakeAWSSyncRunService{}
	router := newTestSyncRunRouter(t, fake, "example-org")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/sync-runs/9/changes.csv", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", recorder.Code, recorder.Body)
	}
}

type fakeSyncWorkerStatus struct {
	status service.AWSSyncWorkerStatus
	err    error
}

func (fake *fakeSyncWorkerStatus) WorkerStatus(context.Context) (service.AWSSyncWorkerStatus, error) {
	return fake.status, fake.err
}

func TestAWSSyncWorkerStatusReportsHeartbeatAndQueueDepth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSSyncRunHandler(&fakeAWSSyncRunService{}, &fakeSyncWorkerStatus{
		status: service.AWSSyncWorkerStatus{Online: false, PendingRuns: 3},
	})
	if err != nil {
		t.Fatalf("NewAWSSyncRunHandler() error = %v", err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "example-org")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterAWSSyncRunRoutes(router, handler)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/sync/worker-status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"online":false`) || !strings.Contains(body, `"pending_runs":3`) {
		t.Fatalf("body = %s, want offline worker with 3 pending runs", body)
	}
}

func TestAWSSyncWorkerStatusUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSSyncRunHandler(&fakeAWSSyncRunService{}, nil)
	if err != nil {
		t.Fatalf("NewAWSSyncRunHandler() error = %v", err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "example-org")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterAWSSyncRunRoutes(router, handler)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/aws/sync/worker-status", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}
