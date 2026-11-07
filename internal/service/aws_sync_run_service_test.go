package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/hibiken/asynq"
)

type memorySyncRunRepository struct {
	runs      map[int64]AWSSyncRun
	changes   map[int64]*AWSSyncChanges
	nextID    int64
	createErr error
}

func newMemorySyncRunRepository() *memorySyncRunRepository {
	return &memorySyncRunRepository{
		runs:    map[int64]AWSSyncRun{},
		changes: map[int64]*AWSSyncChanges{},
		nextID:  1,
	}
}

func (repository *memorySyncRunRepository) Create(ctx context.Context, run AWSSyncRun) (AWSSyncRun, error) {
	if repository.createErr != nil {
		return AWSSyncRun{}, repository.createErr
	}
	// Mirrors SQLAWSSyncRunRepository.Create: RUNNING is never preempted;
	// a higher-priority trigger supersedes a lower-priority PENDING run.
	for _, existing := range repository.runs {
		if existing.ConfigID != run.ConfigID ||
			(existing.Status != SyncRunStatusPending && existing.Status != SyncRunStatusRunning) {
			continue
		}
		if existing.Status == SyncRunStatusRunning ||
			syncTriggerPriority(existing.TriggerSource) <= syncTriggerPriority(run.TriggerSource) {
			return AWSSyncRun{}, ErrSyncRunAlreadyActive
		}
		superseded := existing
		now := time.Now()
		superseded.Status = SyncRunStatusSuperseded
		superseded.FinishedAt = &now
		message := fmt.Sprintf("superseded by a higher-priority %s sync trigger", run.TriggerSource)
		superseded.LastError = &message
		repository.runs[superseded.ID] = superseded
	}
	run.ID = repository.nextID
	repository.nextID++
	run.CreatedAt = time.Now()
	run.UpdatedAt = run.CreatedAt
	repository.runs[run.ID] = run
	return run, nil
}

func (repository *memorySyncRunRepository) Claim(ctx context.Context, runID int64) (AWSSyncRun, bool, error) {
	run, ok := repository.runs[runID]
	if !ok || run.Status != SyncRunStatusPending {
		return AWSSyncRun{}, false, nil
	}
	now := time.Now()
	run.Status = SyncRunStatusRunning
	run.StartedAt = &now
	repository.runs[runID] = run
	return run, true, nil
}

func (repository *memorySyncRunRepository) Finish(ctx context.Context, runID int64, syncErr error, changes *AWSSyncChanges) error {
	run, ok := repository.runs[runID]
	if !ok || (run.Status != SyncRunStatusPending && run.Status != SyncRunStatusRunning) {
		return ErrSyncRunNotFound
	}
	now := time.Now()
	run.FinishedAt = &now
	if syncErr != nil {
		run.Status = SyncRunStatusFailed
		message := syncErr.Error()
		run.LastError = &message
	} else {
		run.Status = SyncRunStatusSucceeded
		run.HasChanges = changes != nil
	}
	repository.runs[runID] = run
	if changes != nil {
		repository.changes[runID] = changes
	}
	return nil
}

func (repository *memorySyncRunRepository) GetChanges(ctx context.Context, runID int64) (*AWSSyncChanges, error) {
	if _, ok := repository.runs[runID]; !ok {
		return nil, ErrSyncRunNotFound
	}
	return repository.changes[runID], nil
}

func (repository *memorySyncRunRepository) Get(ctx context.Context, runID int64) (AWSSyncRun, error) {
	run, ok := repository.runs[runID]
	if !ok {
		return AWSSyncRun{}, ErrSyncRunNotFound
	}
	return run, nil
}

func (repository *memorySyncRunRepository) List(
	ctx context.Context,
	filter AWSSyncRunFilter,
) ([]AWSSyncRun, int, error) {
	runs := make([]AWSSyncRun, 0, len(repository.runs))
	for _, run := range repository.runs {
		runs = append(runs, run)
	}
	return runs, len(runs), nil
}

type fakeSyncConfigRepository struct {
	config       model.AWSAccountConfig
	getErr       error
	accountErr   error
	accountCalls []int64
	beginClaim AWSConfigSyncClaim
	beginErr     error
	finishErrs   []error
}

func (repository *fakeSyncConfigRepository) Get(ctx context.Context, id int64) (model.AWSAccountConfig, error) {
	if repository.getErr != nil {
		return model.AWSAccountConfig{}, repository.getErr
	}
	return repository.config, nil
}

func (repository *fakeSyncConfigRepository) GetByAccountDBID(ctx context.Context, accountDBID int64) (model.AWSAccountConfig, error) {
	repository.accountCalls = append(repository.accountCalls, accountDBID)
	if repository.accountErr != nil {
		return model.AWSAccountConfig{}, repository.accountErr
	}
	return repository.config, nil
}

func (repository *fakeSyncConfigRepository) BeginSync(ctx context.Context, id int64) (AWSConfigSyncClaim, error) {
	return repository.beginClaim, repository.beginErr
}

func (repository *fakeSyncConfigRepository) FinishSync(ctx context.Context, id int64, syncErr error) error {
	repository.finishErrs = append(repository.finishErrs, syncErr)
	return nil
}

type fakeSyncEnqueuer struct {
	tasks  []AWSSyncRunTask
	delays []time.Duration
	err    error
}

func (enqueuer *fakeSyncEnqueuer) EnqueueSyncRun(ctx context.Context, task AWSSyncRunTask, delay time.Duration) error {
	if enqueuer.err != nil {
		return enqueuer.err
	}
	enqueuer.tasks = append(enqueuer.tasks, task)
	enqueuer.delays = append(enqueuer.delays, delay)
	return nil
}

type fakeSyncCollector struct {
	calls    int
	account  model.AWSAccount
	changes  *AWSSyncChanges
	err      error
	panicMsg string
}

func (collector *fakeSyncCollector) SyncConfiguredAccount(
	ctx context.Context,
	config model.AWSAccountConfig,
) (model.AWSAccount, *AWSSyncChanges, error) {
	collector.calls++
	if collector.panicMsg != "" {
		panic(collector.panicMsg)
	}
	return collector.account, collector.changes, collector.err
}

func testAWSSyncRunService(
	t *testing.T,
	runs AWSSyncRunRepository,
	configs AWSSyncConfigRepository,
	enqueuer AWSSyncRunPollEnqueuer,
	collector AWSAccountSyncRunner,
) *AWSSyncRunService {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := NewAWSSyncRunService(runs, configs, enqueuer, collector, logger)
	if err != nil {
		t.Fatalf("NewAWSSyncRunService() error = %v", err)
	}
	return service
}

func TestTriggerSyncForClosedTicketEnqueuesSystemRun(t *testing.T) {
	runs := newMemorySyncRunRepository()
	accountDBID := int64(3)
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{
		ID: 7, AWSAccountID: "111122223333", AWSAccountDBID: &accountDBID, SyncEnabled: true,
	}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	if err := service.TriggerSyncForClosedTicket(context.Background(), accountDBID, "IAM-CLOSED-1"); err != nil {
		t.Fatalf("TriggerSyncForClosedTicket() error = %v", err)
	}
	if len(configs.accountCalls) != 1 || configs.accountCalls[0] != accountDBID {
		t.Fatalf("config lookup by account database id = %v, want [%d]", configs.accountCalls, accountDBID)
	}
	if len(enqueuer.tasks) != 1 {
		t.Fatalf("enqueued tasks = %+v, want exactly one", enqueuer.tasks)
	}
	run := runs.runs[enqueuer.tasks[0].SyncRunID]
	if run.TriggerSource != SyncTriggerSourceTicketClosed || run.TriggeredBy != "system" {
		t.Fatalf("run = %+v, want TICKET_CLOSED by system", run)
	}
	if len(enqueuer.delays) != 1 || enqueuer.delays[0] != TicketClosedSyncDelay {
		t.Fatalf("scheduled delays = %v, want [%s]", enqueuer.delays, TicketClosedSyncDelay)
	}
}

// 已有 PENDING/RUNNING run 说明同步已在路上：关单联动视为已达标，不报错。
func TestTriggerSyncForClosedTicketTreatsActiveRunAsSatisfied(t *testing.T) {
	runs := newMemorySyncRunRepository()
	accountDBID := int64(3)
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, AWSAccountDBID: &accountDBID, SyncEnabled: true}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	first, err := service.TriggerManualSync(context.Background(), 7, "example-org")
	if err != nil {
		t.Fatalf("TriggerManualSync() error = %v", err)
	}
	if err := service.TriggerSyncForClosedTicket(context.Background(), accountDBID, "IAM-CLOSED-2"); err != nil {
		t.Fatalf("already-active run must satisfy the closure trigger, got %v", err)
	}
	if len(enqueuer.tasks) != 1 || first.ID != runs.runs[enqueuer.tasks[0].SyncRunID].ID {
		t.Fatalf("closure trigger must not enqueue a second run, tasks = %+v", enqueuer.tasks)
	}
	if len(enqueuer.delays) != 1 || enqueuer.delays[0] != 0 {
		t.Fatalf("manual sync delay = %v, want immediate", enqueuer.delays)
	}
}

// 同步优先级（2026-11-05）：MANUAL > TICKET_CLOSED。手工触发抢占在途的
// 低优先级 PENDING run：旧 run 标 SUPERSEDED 留痕，新 run 立即入队。
func TestManualTriggerSupersedesPendingTicketClosedSync(t *testing.T) {
	runs := newMemorySyncRunRepository()
	accountDBID := int64(3)
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, AWSAccountDBID: &accountDBID, SyncEnabled: true}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	if err := service.TriggerSyncForClosedTicket(context.Background(), accountDBID, "IAM-CLOSED-5"); err != nil {
		t.Fatalf("TriggerSyncForClosedTicket() error = %v", err)
	}
	var pendingTicketRun AWSSyncRun
	for _, run := range runs.runs {
		if run.TriggerSource == SyncTriggerSourceTicketClosed {
			pendingTicketRun = run
		}
	}
	manual, err := service.TriggerManualSync(context.Background(), 7, "example-org")
	if err != nil {
		t.Fatalf("TriggerManualSync() must preempt the pending ticket-closed run, got %v", err)
	}
	superseded := runs.runs[pendingTicketRun.ID]
	if superseded.Status != SyncRunStatusSuperseded || superseded.LastError == nil {
		t.Fatalf("pending ticket-closed run = %+v, want SUPERSEDED with a reason", superseded)
	}
	if enqueuer.delays[len(enqueuer.delays)-1] != 0 {
		t.Fatalf("manual preempt delay = %v, want immediate", enqueuer.delays[len(enqueuer.delays)-1])
	}
	if len(enqueuer.tasks) != 2 || enqueuer.tasks[1].SyncRunID != manual.ID {
		t.Fatalf("enqueued tasks = %+v, want the manual run enqueued after the ticket run", enqueuer.tasks)
	}
}

// 反方向不抢占：手工 PENDING 在途时，关单触发视为已满足（新快照会一并
// 覆盖关单变更），不排队、不改状态。
func TestTicketClosedTriggerDoesNotSupersedePendingManualSync(t *testing.T) {
	runs := newMemorySyncRunRepository()
	accountDBID := int64(3)
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, AWSAccountDBID: &accountDBID, SyncEnabled: true}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	first, err := service.TriggerManualSync(context.Background(), 7, "example-org")
	if err != nil {
		t.Fatalf("TriggerManualSync() error = %v", err)
	}
	if err := service.TriggerSyncForClosedTicket(context.Background(), accountDBID, "IAM-CLOSED-6"); err != nil {
		t.Fatalf("closure trigger must stay satisfied by the pending manual run, got %v", err)
	}
	if len(enqueuer.tasks) != 1 {
		t.Fatalf("enqueued tasks = %+v, want only the manual run", enqueuer.tasks)
	}
	if got := runs.runs[first.ID]; got.Status != SyncRunStatusPending {
		t.Fatalf("pending manual run = %+v, want untouched PENDING", got)
	}
}

// RUNNING 永不抢占：手工触发撞上正在执行的 run 只能拒绝（409），
// 不能杀掉一个已经在写库存的 run。
func TestManualTriggerRejectedWhileSyncRunning(t *testing.T) {
	runs := newMemorySyncRunRepository()
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, SyncEnabled: true}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	if err := service.TriggerSyncForClosedTicket(context.Background(), 3, "IAM-CLOSED-7"); err != nil {
		t.Fatalf("TriggerSyncForClosedTicket() error = %v", err)
	}
	// 直接把 PENDING 抬成 RUNNING，模拟 worker 已领取。
	claimed, ok, err := runs.Claim(context.Background(), enqueuer.tasks[0].SyncRunID)
	if err != nil || !ok {
		t.Fatalf("Claim() = (%+v, %v, %v), want claimed", claimed, ok, err)
	}
	if _, err := service.TriggerManualSync(context.Background(), 7, "example-org"); !errors.Is(err, ErrSyncRunAlreadyActive) {
		t.Fatalf("TriggerManualSync() error = %v, want ErrSyncRunAlreadyActive", err)
	}
	if len(enqueuer.tasks) != 1 {
		t.Fatalf("enqueued tasks = %+v, want no second task", enqueuer.tasks)
	}
	if got := runs.runs[enqueuer.tasks[0].SyncRunID]; got.Status != SyncRunStatusRunning {
		t.Fatalf("running run = %+v, want untouched RUNNING", got)
	}
}

func TestTriggerSyncForClosedTicketSkipsDisabledSync(t *testing.T) {
	accountDBID := int64(3)
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, AWSAccountDBID: &accountDBID, SyncEnabled: false}}
	service := testAWSSyncRunService(t, newMemorySyncRunRepository(), configs, &fakeSyncEnqueuer{}, nil)

	if err := service.TriggerSyncForClosedTicket(context.Background(), accountDBID, "IAM-CLOSED-3"); !errors.Is(err, ErrSyncDisabled) {
		t.Fatalf("error = %v, want ErrSyncDisabled", err)
	}
}

func TestTriggerSyncForClosedTicketPropagatesUnknownAccount(t *testing.T) {
	configs := &fakeSyncConfigRepository{accountErr: ErrAWSAccountConfigNotFound}
	service := testAWSSyncRunService(t, newMemorySyncRunRepository(), configs, &fakeSyncEnqueuer{}, nil)

	if err := service.TriggerSyncForClosedTicket(context.Background(), 99, "IAM-CLOSED-4"); !errors.Is(err, ErrAWSAccountConfigNotFound) {
		t.Fatalf("error = %v, want ErrAWSAccountConfigNotFound", err)
	}
}

func TestTriggerManualSyncEnqueuesRun(t *testing.T) {
	runs := newMemorySyncRunRepository()
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{
		ID: 7, AWSAccountID: "111122223333", SyncEnabled: true,
	}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	run, err := service.TriggerManualSync(context.Background(), 7, "example-org")
	if err != nil {
		t.Fatalf("TriggerManualSync() error = %v", err)
	}
	if run.Status != SyncRunStatusPending || run.TriggerSource != "MANUAL" || run.TriggeredBy != "example-org" {
		t.Fatalf("run = %+v", run)
	}
	if len(enqueuer.tasks) != 1 || enqueuer.tasks[0].SyncRunID != run.ID || enqueuer.tasks[0].ConfigID != 7 {
		t.Fatalf("enqueued tasks = %+v", enqueuer.tasks)
	}
}

func TestTriggerManualSyncRejectsDisabledConfig(t *testing.T) {
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, SyncEnabled: false}}
	service := testAWSSyncRunService(t, newMemorySyncRunRepository(), configs, &fakeSyncEnqueuer{}, nil)

	if _, err := service.TriggerManualSync(context.Background(), 7, "example-org"); !errors.Is(err, ErrSyncDisabled) {
		t.Fatalf("error = %v, want ErrSyncDisabled", err)
	}
}

func TestTriggerManualSyncPropagatesConfigNotFound(t *testing.T) {
	configs := &fakeSyncConfigRepository{getErr: ErrAWSAccountConfigNotFound}
	service := testAWSSyncRunService(t, newMemorySyncRunRepository(), configs, &fakeSyncEnqueuer{}, nil)

	if _, err := service.TriggerManualSync(context.Background(), 9, "example-org"); !errors.Is(err, ErrAWSAccountConfigNotFound) {
		t.Fatalf("error = %v, want ErrAWSAccountConfigNotFound", err)
	}
}

func TestTriggerManualSyncRejectsDuplicateActiveRun(t *testing.T) {
	runs := newMemorySyncRunRepository()
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, SyncEnabled: true}}
	enqueuer := &fakeSyncEnqueuer{}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	if _, err := service.TriggerManualSync(context.Background(), 7, "example-org"); err != nil {
		t.Fatalf("first TriggerManualSync() error = %v", err)
	}
	if _, err := service.TriggerManualSync(context.Background(), 7, "example-org"); !errors.Is(err, ErrSyncRunAlreadyActive) {
		t.Fatalf("second TriggerManualSync() error = %v, want ErrSyncRunAlreadyActive", err)
	}
}

func TestTriggerManualSyncRecordsEnqueueFailure(t *testing.T) {
	runs := newMemorySyncRunRepository()
	configs := &fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, SyncEnabled: true}}
	enqueuer := &fakeSyncEnqueuer{err: errors.New("redis down")}
	service := testAWSSyncRunService(t, runs, configs, enqueuer, nil)

	if _, err := service.TriggerManualSync(context.Background(), 7, "example-org"); !errors.Is(err, ErrSyncEnqueueFailed) {
		t.Fatalf("error = %v, want ErrSyncEnqueueFailed", err)
	}
	run, err := runs.Get(context.Background(), 1)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if run.Status != SyncRunStatusFailed || run.LastError == nil {
		t.Fatalf("run after enqueue failure = %+v", run)
	}
}

func newSyncRunTask(t *testing.T, runID, configID int64) *asynq.Task {
	t.Helper()
	payload, err := json.Marshal(AWSSyncRunTask{SyncRunID: runID, ConfigID: configID})
	if err != nil {
		t.Fatalf("marshal task payload: %v", err)
	}
	return asynq.NewTask(AWSAccountSyncTaskType, payload)
}

func TestHandleAWSAccountSyncTaskSuccess(t *testing.T) {
	runs := newMemorySyncRunRepository()
	run, err := runs.Create(context.Background(), AWSSyncRun{
		ConfigID: 7, AWSAccountID: "111122223333", TriggerSource: "MANUAL", TriggeredBy: "example-org",
		Status: SyncRunStatusPending,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	configs := &fakeSyncConfigRepository{
		config:       model.AWSAccountConfig{ID: 7, AWSAccountID: "111122223333", SyncEnabled: true},
		beginClaim: SyncClaimed,
	}
	collector := &fakeSyncCollector{account: model.AWSAccount{ID: 1}}
	service := testAWSSyncRunService(t, runs, configs, &fakeSyncEnqueuer{}, collector)

	if err := service.HandleAWSAccountSyncTask(context.Background(), newSyncRunTask(t, run.ID, 7)); err != nil {
		t.Fatalf("HandleAWSAccountSyncTask() error = %v", err)
	}
	if collector.calls != 1 {
		t.Fatalf("collector calls = %d, want 1", collector.calls)
	}
	if len(configs.finishErrs) != 1 || configs.finishErrs[0] != nil {
		t.Fatalf("FinishSync errors = %v, want one nil", configs.finishErrs)
	}
	finished, err := runs.Get(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if finished.Status != SyncRunStatusSucceeded || finished.StartedAt == nil || finished.FinishedAt == nil {
		t.Fatalf("run = %+v", finished)
	}
}

func TestHandleAWSAccountSyncTaskSkipsClaimedRun(t *testing.T) {
	runs := newMemorySyncRunRepository()
	run, _ := runs.Create(context.Background(), AWSSyncRun{
		ConfigID: 7, AWSAccountID: "111122223333", TriggerSource: "MANUAL", TriggeredBy: "example-org",
		Status: SyncRunStatusPending,
	})
	if _, claimed, err := runs.Claim(context.Background(), run.ID); err != nil || !claimed {
		t.Fatalf("pre-claim run: claimed=%v err=%v", claimed, err)
	}
	collector := &fakeSyncCollector{}
	service := testAWSSyncRunService(t, runs,
		&fakeSyncConfigRepository{config: model.AWSAccountConfig{ID: 7, SyncEnabled: true}, beginClaim: SyncClaimed},
		&fakeSyncEnqueuer{}, collector)

	// Second delivery of an already-running run must be a no-op.
	if err := service.HandleAWSAccountSyncTask(context.Background(), newSyncRunTask(t, run.ID, 7)); err != nil {
		t.Fatalf("HandleAWSAccountSyncTask() error = %v", err)
	}
	if collector.calls != 0 {
		t.Fatalf("collector calls = %d, want 0", collector.calls)
	}
}

func TestHandleAWSAccountSyncTaskFailsWhenConfigLocked(t *testing.T) {
	runs := newMemorySyncRunRepository()
	run, _ := runs.Create(context.Background(), AWSSyncRun{
		ConfigID: 7, AWSAccountID: "111122223333", TriggerSource: "MANUAL", TriggeredBy: "example-org",
		Status: SyncRunStatusPending,
	})
	configs := &fakeSyncConfigRepository{
		config:       model.AWSAccountConfig{ID: 7, AWSAccountID: "111122223333", SyncEnabled: true},
		beginClaim: SyncClaimAlreadyRunning,
	}
	collector := &fakeSyncCollector{}
	service := testAWSSyncRunService(t, runs, configs, &fakeSyncEnqueuer{}, collector)

	err := service.HandleAWSAccountSyncTask(context.Background(), newSyncRunTask(t, run.ID, 7))
	if err == nil {
		t.Fatal("HandleAWSAccountSyncTask() expected config-locked error")
	}
	if collector.calls != 0 {
		t.Fatalf("collector calls = %d, want 0", collector.calls)
	}
	finished, _ := runs.Get(context.Background(), run.ID)
	if finished.Status != SyncRunStatusFailed || finished.LastError == nil {
		t.Fatalf("run = %+v", finished)
	}
}

func TestHandleAWSAccountSyncTaskFailsWhenConfigDisabled(t *testing.T) {
	runs := newMemorySyncRunRepository()
	run, _ := runs.Create(context.Background(), AWSSyncRun{
		ConfigID: 7, AWSAccountID: "111122223333", TriggerSource: "MANUAL", TriggeredBy: "example-org",
		Status: SyncRunStatusPending,
	})
	// 手动触发被禁用账号时，失败原因必须是「禁用」而不是误导性的「已在同步」。
	configs := &fakeSyncConfigRepository{
		config:     model.AWSAccountConfig{ID: 7, AWSAccountID: "111122223333", SyncEnabled: false},
		beginClaim: SyncClaimDisabled,
	}
	collector := &fakeSyncCollector{}
	service := testAWSSyncRunService(t, runs, configs, &fakeSyncEnqueuer{}, collector)

	err := service.HandleAWSAccountSyncTask(context.Background(), newSyncRunTask(t, run.ID, 7))
	if err == nil || !strings.Contains(err.Error(), "sync is disabled") {
		t.Fatalf("error = %v, want disabled-account failure", err)
	}
	if collector.calls != 0 {
		t.Fatalf("collector calls = %d, want 0", collector.calls)
	}
	finished, _ := runs.Get(context.Background(), run.ID)
	if finished.Status != SyncRunStatusFailed || finished.LastError == nil ||
		!strings.Contains(*finished.LastError, "sync is disabled") {
		t.Fatalf("run = %+v", finished)
	}
}

func TestHandleAWSAccountSyncTaskRecordsCollectorFailure(t *testing.T) {
	runs := newMemorySyncRunRepository()
	run, _ := runs.Create(context.Background(), AWSSyncRun{
		ConfigID: 7, AWSAccountID: "111122223333", TriggerSource: "MANUAL", TriggeredBy: "example-org",
		Status: SyncRunStatusPending,
	})
	configs := &fakeSyncConfigRepository{
		config:       model.AWSAccountConfig{ID: 7, AWSAccountID: "111122223333", SyncEnabled: true},
		beginClaim: SyncClaimed,
	}
	collector := &fakeSyncCollector{err: errors.New("assume role denied")}
	service := testAWSSyncRunService(t, runs, configs, &fakeSyncEnqueuer{}, collector)

	err := service.HandleAWSAccountSyncTask(context.Background(), newSyncRunTask(t, run.ID, 7))
	if err == nil || !strings.Contains(err.Error(), "assume role denied") {
		t.Fatalf("error = %v, want collector failure", err)
	}
	if len(configs.finishErrs) != 1 || configs.finishErrs[0] == nil {
		t.Fatalf("FinishSync errors = %v, want the collector error", configs.finishErrs)
	}
	finished, _ := runs.Get(context.Background(), run.ID)
	if finished.Status != SyncRunStatusFailed || finished.LastError == nil ||
		!strings.Contains(*finished.LastError, "assume role denied") {
		t.Fatalf("run = %+v", finished)
	}
}

// TestHandleAWSAccountSyncTaskFailsRunOnPanic is a regression test for a
// real incident: the collector panicked mid-flight (nil diff dereference in
// logging), asynq recovered but knew nothing about our DB state, and the run
// row stayed RUNNING forever while holding the per-account sync lock — the
// exhausted task was archived so no worker would ever reclaim it.
func TestHandleAWSAccountSyncTaskFailsRunOnPanic(t *testing.T) {
	runs := newMemorySyncRunRepository()
	run, err := runs.Create(context.Background(), AWSSyncRun{
		ConfigID: 7, AWSAccountID: "111122223333", TriggerSource: "MANUAL", TriggeredBy: "example-org",
		Status: SyncRunStatusPending,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	configs := &fakeSyncConfigRepository{
		config:       model.AWSAccountConfig{ID: 7, AWSAccountID: "111122223333", SyncEnabled: true},
		beginClaim: SyncClaimed,
	}
	collector := &fakeSyncCollector{panicMsg: "collector exploded"}
	service := testAWSSyncRunService(t, runs, configs, &fakeSyncEnqueuer{}, collector)

	err = service.HandleAWSAccountSyncTask(context.Background(), newSyncRunTask(t, run.ID, 7))
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("error = %v, want panic-derived error", err)
	}
	finished, getErr := runs.Get(context.Background(), run.ID)
	if getErr != nil {
		t.Fatalf("Get() error = %v", getErr)
	}
	if finished.Status != SyncRunStatusFailed || finished.LastError == nil ||
		!strings.Contains(*finished.LastError, "panicked") {
		t.Fatalf("run after panic = %+v, want FAILED with panic error", finished)
	}
	if finished.FinishedAt == nil {
		t.Fatal("run after panic must have FinishedAt set")
	}
	// The per-account sync lock must be released too, otherwise the config
	// stays un-synchronizable for 30 minutes.
	if len(configs.finishErrs) != 1 || configs.finishErrs[0] == nil {
		t.Fatalf("FinishSync errors = %v, want exactly one non-nil entry", configs.finishErrs)
	}
}
