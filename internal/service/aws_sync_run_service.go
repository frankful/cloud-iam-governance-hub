package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
	"github.com/hibiken/asynq"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// AWSAccountSyncTaskType is the Asynq task type for one account sync run.
const AWSAccountSyncTaskType = "aws:sync:account"

// AWSSyncQueueName isolates sync tasks so workers of other task types never
// claim (and fail) them.
const AWSSyncQueueName = "sync"

// Sync run lifecycle states (aws_sync_run.status).
const (
	SyncRunStatusPending    = "PENDING"
	SyncRunStatusRunning    = "RUNNING"
	SyncRunStatusSucceeded  = "SUCCEEDED"
	SyncRunStatusFailed     = "FAILED"
	SyncRunStatusSuperseded = "SUPERSEDED"
)

// Sync run trigger sources (aws_sync_run.trigger_source). TICKET_CLOSED is
// written by the gitstatus worker after it auto-closes a ticket whose merge
// request is merged and whose CI succeeded — the only point where the
// platform knows the apply actually ran (migration 0018 widens the CHECK).
const (
	SyncTriggerSourceManual       = "MANUAL"
	SyncTriggerSourceTicketClosed = "TICKET_CLOSED"
)

// Sentinel errors for sync-run operations.
var (
	ErrSyncRunNotFound      = errors.New("AWS sync run not found")
	ErrSyncRunAlreadyActive = errors.New("an AWS sync run is already pending or running for this account")
	ErrSyncDisabled         = errors.New("AWS account sync is disabled; enable it before triggering a sync")
	ErrSyncEnqueueFailed    = errors.New("failed to enqueue AWS sync run")
)

// Sentinel errors for list-filter validation.
var (
	ErrInvalidPrincipalType = errors.New("principal type must be User or Role")
	ErrInvalidSyncRunStatus = errors.New("invalid sync run status")
)

// syncTriggerPriority ranks sync triggers for PENDING preemption
// (sync-priority design, 2026-11-05): lower number = higher priority.
// MANUAL beats ticket-closure beats future scheduled syncs. A
// higher-priority trigger supersedes a PENDING run of lower priority;
// RUNNING runs are never preempted (a sync is a full-account inventory
// pull — cancelling one mid-flight would leave partial writes, and the
// preempting run re-captures the superseded trigger's changes anyway).
func syncTriggerPriority(source string) int {
	switch source {
	case SyncTriggerSourceManual:
		return 0
	case SyncTriggerSourceTicketClosed:
		return 1
	default:
		return 2
	}
}

// stale RUNNING runs (worker crash) are reclaimed after 30 minutes, mirroring
// the 30-minute per-account config sync lock (see BeginSync).

// AWSSyncRun is one recorded AWS account synchronization run.
type AWSSyncRun struct {
	ID            int64      `json:"id"`
	ConfigID      int64      `json:"aws_account_config_id"`
	AWSAccountID  string     `json:"aws_account_id"`
	TriggerSource string     `json:"trigger_source"`
	TriggeredBy   string     `json:"triggered_by"`
	Status        string     `json:"status"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"`
	HasChanges    bool       `json:"has_changes"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// AWSSyncAssetChange describes one principal or group that appeared in or
// disappeared from the AWS account relative to the platform inventory.
type AWSSyncAssetChange struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // principal type (USER/ROLE) when applicable
	ARN  string `json:"arn"`
}

// AWSSyncChanges is the inventory diff of one sync run: what AWS has that the
// platform did not, and what the platform had that AWS no longer returns. It
// is computed before SaveAccountIAM overwrites the previous inventory.
type AWSSyncChanges struct {
	PrincipalsAdded   []AWSSyncAssetChange `json:"principals_added"`
	PrincipalsRemoved []AWSSyncAssetChange `json:"principals_removed"`
	GroupsAdded       []AWSSyncAssetChange `json:"groups_added"`
	GroupsRemoved     []AWSSyncAssetChange `json:"groups_removed"`
}

// AWSSyncRunFilter filters the sync-run history listing.
type AWSSyncRunFilter struct {
	ConfigID     int64
	AWSAccountID string
	Status       string
	Limit        int
	Offset       int
}

// AWSSyncRunTask is the Asynq payload for one sync run. Traceparent keeps
// the trigger request and the worker execution in one trace.
type AWSSyncRunTask struct {
	SyncRunID   int64  `json:"sync_run_id"`
	ConfigID    int64  `json:"config_id"`
	Traceparent string `json:"traceparent,omitempty"`
}

// AWSSyncRunRepository persists sync-run records.
type AWSSyncRunRepository interface {
	Create(ctx context.Context, run AWSSyncRun) (AWSSyncRun, error)
	Claim(ctx context.Context, runID int64) (AWSSyncRun, bool, error)
	Finish(ctx context.Context, runID int64, syncErr error, changes *AWSSyncChanges) error
	Get(ctx context.Context, runID int64) (AWSSyncRun, error)
	GetChanges(ctx context.Context, runID int64) (*AWSSyncChanges, error)
	List(ctx context.Context, filter AWSSyncRunFilter) ([]AWSSyncRun, int, error)
}

// AWSAccountSyncRunner executes one configured-account synchronization. It
// returns the inventory diff computed before the previous inventory was
// overwritten (nil when nothing changed).
type AWSAccountSyncRunner interface {
	SyncConfiguredAccount(ctx context.Context, config model.AWSAccountConfig) (model.AWSAccount, *AWSSyncChanges, error)
}

// AWSSyncConfigRepository is the account-config surface needed to run syncs.
// *SQLAWSAccountConfigRepository implements it.
type AWSSyncConfigRepository interface {
	Get(ctx context.Context, id int64) (model.AWSAccountConfig, error)
	// GetByAccountDBID resolves the config of one aws_account row; ticket
	// closure carries that database id, not the config id.
	GetByAccountDBID(ctx context.Context, accountDBID int64) (model.AWSAccountConfig, error)
	BeginSync(ctx context.Context, id int64) (AWSConfigSyncClaim, error)
	FinishSync(ctx context.Context, id int64, syncErr error) error
}

// TicketClosureSyncTrigger refreshes the inventory of the account a ticket
// just changed. *AWSSyncRunService implements it; the gitstatus worker calls
// it after an auto-close. Best-effort: the caller logs and never blocks or
// reverts the closure.
type TicketClosureSyncTrigger interface {
	TriggerSyncForClosedTicket(ctx context.Context, accountDBID int64, ticketNo string) error
}

// AWSSyncRunPollEnqueuer enqueues sync-run tasks. Implemented by Asynq.
type AWSSyncRunPollEnqueuer interface {
	EnqueueSyncRun(ctx context.Context, task AWSSyncRunTask, delay time.Duration) error
}

// AWSSyncRunService triggers manual sync runs, exposes run history and
// executes queued runs (worker side).
type AWSSyncRunService struct {
	runs      AWSSyncRunRepository
	configs   AWSSyncConfigRepository
	enqueuer  AWSSyncRunPollEnqueuer
	collector AWSAccountSyncRunner // nil in the API process; required by the worker
	// drift 在同步成功后执行一次漂移判定（phase4 §3）：库存刚刚确认，
	// 这一刻的实态才是可信的比对对象。nil 安全，未装配时跳过。
	drift  AWSSyncDriftEvaluator
	logger *slog.Logger
}

// AWSSyncDriftEvaluator 是同步结束点的漂移判定入口。抽成接口而不是直接
// 依赖 *DriftService，是因为判定失败绝不能反过来让同步失败——调用方只
// 记日志，接口让这个契约在类型上就成立。
type AWSSyncDriftEvaluator interface {
	EvaluateAccount(ctx context.Context, accountDBID int64) (DriftEvaluation, error)
}

// WithSyncDriftEvaluator 装配漂移判定。只有 worker 进程需要：API 进程不
// 执行同步，也就没有「同步结束后」这个时点。
func WithSyncDriftEvaluator(evaluator AWSSyncDriftEvaluator) AWSSyncRunServiceOption {
	return func(service *AWSSyncRunService) error {
		if evaluator == nil {
			return errors.New("drift evaluator must not be nil")
		}
		service.drift = evaluator
		return nil
	}
}

// AWSSyncRunServiceOption 让构造保持向后兼容：已有调用点不需要为了新能力
// 改签名。
type AWSSyncRunServiceOption func(*AWSSyncRunService) error

// NewAWSSyncRunService creates an AWSSyncRunService. The collector may be nil
// when the process only triggers and lists runs (API); the worker must supply
// one before registering HandleAWSAccountSyncTask.
func NewAWSSyncRunService(
	runs AWSSyncRunRepository,
	configs AWSSyncConfigRepository,
	enqueuer AWSSyncRunPollEnqueuer,
	collector AWSAccountSyncRunner,
	logger *slog.Logger,
	options ...AWSSyncRunServiceOption,
) (*AWSSyncRunService, error) {
	if runs == nil {
		return nil, errors.New("sync run repository must not be nil")
	}
	if configs == nil {
		return nil, errors.New("AWS account config repository must not be nil")
	}
	if enqueuer == nil {
		return nil, errors.New("sync run enqueuer must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	service := &AWSSyncRunService{
		runs: runs, configs: configs, enqueuer: enqueuer, collector: collector, logger: logger,
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// TriggerManualSync records a PENDING run and enqueues it. The actual AWS
// call happens in the sync worker, never on the HTTP thread.
func (service *AWSSyncRunService) TriggerManualSync(
	ctx context.Context,
	configID int64,
	actor string,
) (AWSSyncRun, error) {
	config, err := service.configs.Get(ctx, configID)
	if err != nil {
		return AWSSyncRun{}, err
	}
	return service.triggerForConfig(ctx, config, actor, SyncTriggerSourceManual, 0)
}

// TriggerSyncForClosedTicket refreshes the inventory of the account whose
// ticket was just auto-closed, after a short delay for Terraform apply to settle.
//
// An already pending/running run counts as satisfied (closure triggers must
// not pile up); a disabled sync is reported as ErrSyncDisabled so the caller
// can log it as configuration rather than failure.
const TicketClosedSyncDelay = 5 * time.Minute

func (service *AWSSyncRunService) TriggerSyncForClosedTicket(
	ctx context.Context,
	accountDBID int64,
	ticketNo string,
) error {
	return service.triggerForClosedAccount(ctx, accountDBID, ticketNo, TicketClosedSyncDelay)
}

// TriggerSyncForManuallyClosedTicket refreshes the inventory immediately
// (no settle delay): the operator explicitly confirmed the change was
// applied before closing the ticket, so there is nothing to wait for.
// Dedup and ErrSyncDisabled semantics match TriggerSyncForClosedTicket.
func (service *AWSSyncRunService) TriggerSyncForManuallyClosedTicket(
	ctx context.Context,
	accountDBID int64,
	ticketNo string,
) error {
	return service.triggerForClosedAccount(ctx, accountDBID, ticketNo, 0)
}

func (service *AWSSyncRunService) triggerForClosedAccount(
	ctx context.Context,
	accountDBID int64,
	ticketNo string,
	delay time.Duration,
) error {
	if accountDBID <= 0 {
		return fmt.Errorf("closed ticket %s has no AWS account database ID", ticketNo)
	}
	// The closure is already committed: the enqueue must survive the request
	// or asynq task being cancelled.
	enqueueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	config, err := service.configs.GetByAccountDBID(enqueueCtx, accountDBID)
	if err != nil {
		return fmt.Errorf("resolve AWS account config for closed ticket %s: %w", ticketNo, err)
	}
	if !config.SyncEnabled {
		return fmt.Errorf("closed ticket %s: %w", ticketNo, ErrSyncDisabled)
	}
	run, err := service.triggerForConfig(
		enqueueCtx,
		config,
		"system",
		SyncTriggerSourceTicketClosed,
		delay,
	)
	if errors.Is(err, ErrSyncRunAlreadyActive) {
		service.logger.Info("AWS sync already pending for the closed ticket's account",
			"ticket_no", ticketNo, "config_id", config.ID, "account_id", config.AWSAccountID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("trigger AWS sync for closed ticket %s: %w", ticketNo, err)
	}
	service.logger.Info("AWS sync run enqueued after ticket closure",
		"ticket_no", ticketNo, "sync_run_id", run.ID,
		"config_id", config.ID, "account_id", config.AWSAccountID,
		"delay", delay)
	return nil
}

// triggerForConfig records a PENDING run and enqueues it.
func (service *AWSSyncRunService) triggerForConfig(
	ctx context.Context,
	config model.AWSAccountConfig,
	actor, triggerSource string,
	delay time.Duration,
) (AWSSyncRun, error) {
	configID := config.ID
	if !config.SyncEnabled {
		return AWSSyncRun{}, ErrSyncDisabled
	}
	run, err := service.runs.Create(ctx, AWSSyncRun{
		ConfigID:      configID,
		AWSAccountID:  config.AWSAccountID,
		TriggerSource: triggerSource,
		TriggeredBy:   strings.TrimSpace(actor),
		Status:        SyncRunStatusPending,
	})
	if err != nil {
		return AWSSyncRun{}, err
	}
	task := AWSSyncRunTask{
		SyncRunID:   run.ID,
		ConfigID:    configID,
		Traceparent: oteltrace.TraceParentFromContext(ctx),
	}
	if err := service.enqueuer.EnqueueSyncRun(ctx, task, delay); err != nil {
		enqueueErr := fmt.Errorf("enqueue AWS sync run %d: %w", run.ID, err)
		if finishErr := service.runs.Finish(ctx, run.ID, enqueueErr, nil); finishErr != nil {
			return AWSSyncRun{}, errors.Join(enqueueErr, finishErr)
		}
		return AWSSyncRun{}, fmt.Errorf("%w: %v", ErrSyncEnqueueFailed, err)
	}
	service.logger.Info("AWS sync run enqueued",
		"sync_run_id", run.ID, "config_id", configID,
		"account_id", config.AWSAccountID, "trigger_source", triggerSource,
		"triggered_by", actor)
	return run, nil
}

// ListSyncRuns lists recorded runs with total count.
func (service *AWSSyncRunService) ListSyncRuns(
	ctx context.Context,
	filter AWSSyncRunFilter,
) ([]AWSSyncRun, int, error) {
	return service.runs.List(ctx, filter)
}

// GetSyncRun returns one recorded run.
func (service *AWSSyncRunService) GetSyncRun(ctx context.Context, runID int64) (AWSSyncRun, error) {
	return service.runs.Get(ctx, runID)
}

// GetSyncRunChanges returns the inventory diff of one run, or nil when the
// run recorded no changes.
func (service *AWSSyncRunService) GetSyncRunChanges(ctx context.Context, runID int64) (*AWSSyncChanges, error) {
	return service.runs.GetChanges(ctx, runID)
}

// HandleAWSAccountSyncTask executes one queued sync run: claim the run,
// claim the per-account sync lock, collect from AWS, record both results.
func (service *AWSSyncRunService) HandleAWSAccountSyncTask(
	ctx context.Context,
	task *asynq.Task,
) (err error) {
	if service.collector == nil {
		return errors.New("AWS collector is not configured for sync execution")
	}
	var payload AWSSyncRunTask
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal AWS sync task: %w", err)
	}

	ctx = oteltrace.ContextWithTraceParent(ctx, payload.Traceparent)
	ctx, span := otel.Tracer("finops/aws-sync").Start(ctx, "aws.sync.account",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(attribute.Int64("config_id", payload.ConfigID)))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	// A panic mid-flight (e.g. a nil dereference in the collector) previously
	// left the run row stuck in RUNNING forever and held the per-account sync
	// lock: asynq recovered the panic but knew nothing about our DB state, and
	// the exhausted task was archived so no worker would ever reclaim it.
	// Convert the panic into the same terminal state a normal failure produces.
	var claimedConfigID int64
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		panicErr := fmt.Errorf("AWS sync task panicked: %v", recovered)
		if claimedConfigID != 0 {
			if finishErr := service.configs.FinishSync(ctx, claimedConfigID, panicErr); finishErr != nil {
				service.logger.Error("release AWS account sync lock after panic",
					"config_id", claimedConfigID, "error", finishErr)
			}
		}
		if finishErr := service.runs.Finish(ctx, payload.SyncRunID, panicErr, nil); finishErr != nil &&
			!errors.Is(finishErr, ErrSyncRunNotFound) {
			service.logger.Error("fail AWS sync run after panic",
				"sync_run_id", payload.SyncRunID, "error", finishErr)
		}
		service.logger.Error("AWS sync task panicked; run marked failed",
			"sync_run_id", payload.SyncRunID, "config_id", payload.ConfigID,
			"panic", recovered, "stack", string(debug.Stack()))
		err = panicErr
	}()

	run, claimed, err := service.runs.Claim(ctx, payload.SyncRunID)
	if err != nil {
		return fmt.Errorf("claim AWS sync run %d: %w", payload.SyncRunID, err)
	}
	if !claimed {
		service.logger.Info("skipping AWS sync run already claimed or finished",
			"sync_run_id", payload.SyncRunID)
		return nil
	}
	span.SetAttributes(attribute.String("aws_account_id", run.AWSAccountID))

	config, err := service.configs.Get(ctx, payload.ConfigID)
	if err != nil {
		return service.failRun(ctx, span, run.ID, fmt.Errorf("load AWS account config %d: %w", payload.ConfigID, err))
	}
	configClaimed, err := service.configs.BeginSync(ctx, config.ID)
	if err != nil {
		return service.failRun(ctx, span, run.ID, fmt.Errorf("claim AWS account config %d: %w", config.ID, err))
	}
	if configClaimed != SyncClaimed {
		if configClaimed == SyncClaimDisabled {
			return service.failRun(ctx, span, run.ID,
				fmt.Errorf("AWS account %s sync is disabled; re-enable the account under account admin before triggering a sync", config.AWSAccountID))
		}
		return service.failRun(ctx, span, run.ID,
			fmt.Errorf("AWS account %s is already syncing", config.AWSAccountID))
	}
	claimedConfigID = config.ID

	_, changes, syncErr := service.collector.SyncConfiguredAccount(ctx, config)
	if finishErr := service.configs.FinishSync(ctx, config.ID, syncErr); finishErr != nil {
		syncErr = errors.Join(syncErr, fmt.Errorf("record sync result: %w", finishErr))
	}
	if syncErr != nil {
		return service.failRun(ctx, span, run.ID, syncErr)
	}
	if err := service.runs.Finish(ctx, run.ID, nil, changes); err != nil {
		return fmt.Errorf("finish AWS sync run %d: %w", run.ID, err)
	}
	service.logger.Info("AWS sync run completed",
		"sync_run_id", run.ID, "config_id", config.ID, "account_id", config.AWSAccountID,
		"has_changes", changes != nil)
	// 判定必须跑在同步成功之后：库存此刻才反映合并后的状态。失败只记
	// 日志——同步已经成功，把同步报成失败会让运维重跑一次昂贵的采集，
	// 而漂移检测下一轮还会再来。
	if service.drift != nil && config.AWSAccountDBID != nil && *config.AWSAccountDBID > 0 {
		if _, err := service.drift.EvaluateAccount(ctx, *config.AWSAccountDBID); err != nil {
			service.logger.Warn("drift evaluation after sync failed",
				"sync_run_id", run.ID, "account_id", config.AWSAccountID, "error", err)
		}
	}
	return nil
}

func (service *AWSSyncRunService) failRun(ctx context.Context, span trace.Span, runID int64, syncErr error) error {
	span.RecordError(syncErr)
	if err := service.runs.Finish(ctx, runID, syncErr, nil); err != nil {
		return errors.Join(syncErr, fmt.Errorf("fail AWS sync run %d: %w", runID, err))
	}
	service.logger.Error("AWS sync run failed", "sync_run_id", runID, "error", syncErr)
	return syncErr
}

// SyncRunStaleAfter is how long a RUNNING sync run may survive without a live
// worker. It matches the reclaim windows of Claim/Create/BeginSync: past this
// point the run can no longer be picked up, so leaving it RUNNING only
// corrupts the history view.
const SyncRunStaleAfter = 30 * time.Minute

// SweepStaleSyncRuns fails the artifacts a crashed sync-worker leaves behind:
// a panic is recovered in-process (HandleAWSAccountSyncTask), but a process
// kill (OOM, node loss) has nobody to write the terminal state. With
// MaxRetry(0) asynq also archives the dead worker's task instead of
// redelivering it, so nothing else ever transitions these rows.
//
// Both updates are idempotent no-ops on a healthy system: the 30-minute
// threshold is the same one Claim/Create/BeginSync use, so a sweep never
// races a legitimately long collection — that one is still inside its window.
// Sweeping on the API process (always up) rather than the worker: the crashed
// process cannot clean up after itself.
func SweepStaleSyncRuns(ctx context.Context, db *sql.DB, logger *slog.Logger) (int64, error) {
	if db == nil {
		return 0, errors.New("stale sync-run sweep requires a database handle")
	}
	if logger == nil {
		logger = slog.Default()
	}
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin stale sync-run sweep: %w", err)
	}
	defer transaction.Rollback()

	result, err := transaction.ExecContext(ctx, `UPDATE aws_sync_run
		SET status = 'FAILED',
			last_error = 'sync worker stopped mid-run; reclaimed by stale-run sweep',
			finished_at = NOW(),
			updated_at = NOW()
		WHERE status = 'RUNNING'
			AND started_at < NOW() - $1::interval`, SyncRunStaleAfter)
	if err != nil {
		return 0, fmt.Errorf("fail stale RUNNING sync runs: %w", err)
	}
	failedRuns, _ := result.RowsAffected()

	// Mirror FinishSync's terminal-state semantics for the per-account lock.
	if _, err := transaction.ExecContext(ctx, `UPDATE aws_account_config
		SET sync_status = CASE WHEN sync_enabled THEN 'FAILED' ELSE 'DISABLED' END,
			last_sync_error = CASE WHEN sync_enabled
				THEN 'sync worker stopped mid-run; reclaimed by stale-run sweep'
				ELSE NULL END,
			updated_at = NOW()
		WHERE sync_status = 'RUNNING'
			AND updated_at < NOW() - $1::interval`, SyncRunStaleAfter); err != nil {
		return 0, fmt.Errorf("release stale AWS account sync locks: %w", err)
	}

	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit stale sync-run sweep: %w", err)
	}
	if failedRuns > 0 {
		logger.Warn("stale sync-run sweep reclaimed crashed runs",
			"failed_runs", failedRuns)
	}
	return failedRuns, nil
}

// StartStaleSyncRunSweeper sweeps immediately and then on a fixed interval
// until ctx is cancelled. The first sweep cleans leftovers from a crash that
// happened while the API was down, without waiting a full interval.
func StartStaleSyncRunSweeper(
	ctx context.Context,
	db *sql.DB,
	interval time.Duration,
	logger *slog.Logger,
) {
	if logger == nil {
		logger = slog.Default()
	}
	sweep := func() {
		sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := SweepStaleSyncRuns(sweepCtx, db, logger); err != nil {
			logger.Error("stale sync-run sweep failed", "error", err)
		}
	}
	sweep()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
}

// AsynqAWSSyncRunEnqueuer implements AWSSyncRunPollEnqueuer using Asynq.
type AsynqAWSSyncRunEnqueuer struct {
	client *asynq.Client
}

// NewAsynqAWSSyncRunEnqueuer creates an Asynq-backed enqueuer.
func NewAsynqAWSSyncRunEnqueuer(client *asynq.Client) (*AsynqAWSSyncRunEnqueuer, error) {
	if client == nil {
		return nil, errors.New("asynq client must not be nil")
	}
	return &AsynqAWSSyncRunEnqueuer{client: client}, nil
}

// EnqueueSyncRun enqueues a sync-run task without asynq retries: a failed run
// is recorded as FAILED and re-triggered manually, matching run history
// semantics (every row is one real attempt).
func (e *AsynqAWSSyncRunEnqueuer) EnqueueSyncRun(
	ctx context.Context,
	task AWSSyncRunTask,
	delay time.Duration,
) error {
	if delay < 0 {
		return errors.New("AWS sync run delay must not be negative")
	}
	payloadJSON, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal AWS sync run payload: %w", err)
	}
	options := []asynq.Option{asynq.Queue(AWSSyncQueueName), asynq.MaxRetry(0)}
	if delay > 0 {
		options = append(options, asynq.ProcessIn(delay))
	}
	_, err = e.client.EnqueueContext(ctx, asynq.NewTask(AWSAccountSyncTaskType, payloadJSON), options...)
	if err != nil {
		return fmt.Errorf("enqueue AWS sync run task: %w", err)
	}
	return nil
}

// SQLAWSSyncRunRepository persists sync runs in PostgreSQL.
type SQLAWSSyncRunRepository struct {
	db *sql.DB
}

// NewSQLAWSSyncRunRepository creates a SQLAWSSyncRunRepository.
func NewSQLAWSSyncRunRepository(database *sql.DB) (*SQLAWSSyncRunRepository, error) {
	if database == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLAWSSyncRunRepository{db: database}, nil
}

const awsSyncRunColumns = `id, aws_account_config_id, aws_account_id, trigger_source,
	triggered_by, status, started_at, finished_at, last_error, changes IS NOT NULL,
	created_at, updated_at`

var _ AWSSyncRunRepository = (*SQLAWSSyncRunRepository)(nil)

func scanAWSSyncRun(scanner interface {
	Scan(...any) error
}) (AWSSyncRun, error) {
	var run AWSSyncRun
	err := scanner.Scan(&run.ID, &run.ConfigID, &run.AWSAccountID, &run.TriggerSource,
		&run.TriggeredBy, &run.Status, &run.StartedAt, &run.FinishedAt,
		&run.LastError, &run.HasChanges, &run.CreatedAt, &run.UpdatedAt)
	return run, err
}

// Create inserts a PENDING run with priority-aware dedup (sync-priority
// design, 2026-11-05). "Active" means PENDING or RUNNING within the last 30
// minutes: a stale row left behind by a crashed worker (whose asynq task was
// exhausted and archived) must not block re-triggering forever — it can
// still be reclaimed by Claim, which uses the same 30-minute window.
//
// When an active run exists:
//   - RUNNING → reject. Never preempt a run that is already pulling
//     inventory; the caller surfaces a 409.
//   - PENDING with a LOWER priority than the new trigger (MANUAL 0 >
//     TICKET_CLOSED 1 > future scheduled 2) → the pending row is marked
//     SUPERSEDED (kept for history; its asynq task is skipped at Claim
//     time because the row is no longer PENDING) and the new run inserts.
//   - Anything else → reject (same-priority dedup; lower-priority trigger
//     arriving over a higher-priority pending run just waits).
func (repository *SQLAWSSyncRunRepository) Create(ctx context.Context, run AWSSyncRun) (AWSSyncRun, error) {
	created, err := scanAWSSyncRun(repository.db.QueryRowContext(ctx, `
		WITH active AS (
			SELECT id, status, trigger_source FROM aws_sync_run
			WHERE aws_account_config_id = $1
				AND status IN ('PENDING', 'RUNNING')
				AND created_at >= NOW() - INTERVAL '30 minutes'
			FOR UPDATE
		),
		decision AS (
			SELECT CASE
				WHEN NOT EXISTS (SELECT 1 FROM active) THEN 'INSERT'
				WHEN EXISTS (SELECT 1 FROM active WHERE status = 'RUNNING') THEN 'REJECT'
				WHEN EXISTS (
					SELECT 1 FROM active
					WHERE status = 'PENDING'
						AND (CASE trigger_source WHEN 'MANUAL' THEN 0 WHEN 'TICKET_CLOSED' THEN 1 ELSE 2 END)
							> (CASE $3::text WHEN 'MANUAL' THEN 0 WHEN 'TICKET_CLOSED' THEN 1 ELSE 2 END)
				) THEN 'PREEMPT'
				ELSE 'REJECT'
			END AS action
		),
		supersede AS (
			UPDATE aws_sync_run
			SET status = 'SUPERSEDED', finished_at = NOW(),
				last_error = $6, updated_at = NOW()
			WHERE (SELECT action FROM decision) = 'PREEMPT'
				AND id IN (SELECT id FROM active WHERE status = 'PENDING')
			RETURNING id
		)
		INSERT INTO aws_sync_run (aws_account_config_id, aws_account_id, trigger_source, triggered_by, status)
		SELECT $1, $2, $3, $4, $5
		WHERE (SELECT action FROM decision) IN ('INSERT', 'PREEMPT')
		RETURNING `+awsSyncRunColumns,
		run.ConfigID, run.AWSAccountID, run.TriggerSource, run.TriggeredBy, run.Status,
		fmt.Sprintf("superseded by a higher-priority %s sync trigger", run.TriggerSource)))
	if errors.Is(err, sql.ErrNoRows) {
		return AWSSyncRun{}, ErrSyncRunAlreadyActive
	}
	if err != nil {
		return AWSSyncRun{}, fmt.Errorf("create AWS sync run: %w", err)
	}
	return created, nil
}

// Claim transitions a run to RUNNING. Only PENDING runs, or stale RUNNING
// runs (worker crash), can be claimed.
func (repository *SQLAWSSyncRunRepository) Claim(ctx context.Context, runID int64) (AWSSyncRun, bool, error) {
	claimed, err := scanAWSSyncRun(repository.db.QueryRowContext(ctx,
		`UPDATE aws_sync_run
		SET status = 'RUNNING', started_at = NOW(), updated_at = NOW()
		WHERE id = $1
			AND (status = 'PENDING'
				OR (status = 'RUNNING' AND started_at < NOW() - INTERVAL '30 minutes'))
		RETURNING `+awsSyncRunColumns, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return AWSSyncRun{}, false, nil
	}
	if err != nil {
		return AWSSyncRun{}, false, fmt.Errorf("claim AWS sync run: %w", err)
	}
	return claimed, true, nil
}

// Finish records the terminal state of a run. On success the inventory diff
// computed by the collector is persisted so operators can download it.
func (repository *SQLAWSSyncRunRepository) Finish(
	ctx context.Context,
	runID int64,
	syncErr error,
	changes *AWSSyncChanges,
) error {
	var lastError *string
	status := SyncRunStatusSucceeded
	if syncErr != nil {
		status = SyncRunStatusFailed
		message := syncErr.Error()
		lastError = &message
		changes = nil // failed runs have no trustworthy diff
	}
	var changesJSON []byte
	if changes != nil {
		encoded, err := json.Marshal(changes)
		if err != nil {
			return fmt.Errorf("marshal AWS sync changes: %w", err)
		}
		changesJSON = encoded
	}
	result, err := repository.db.ExecContext(ctx,
		`UPDATE aws_sync_run
		SET status = $2, finished_at = NOW(), last_error = $3, changes = $4, updated_at = NOW()
		WHERE id = $1 AND status IN ('PENDING', 'RUNNING')`, runID, status, lastError, changesJSON)
	if err != nil {
		return fmt.Errorf("finish AWS sync run: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ErrSyncRunNotFound
	}
	// 同步成功 = 清单已确认反映合并后的状态（phase4 §4.2）：释放该账号
	// 处于 MERGED 态的发布预约，merge→apply→同步的窗口在此关闭。失败的
	// 同步不释放——清单还是旧状态，预约继续挡住对同一文件的新发布。
	if status == SyncRunStatusSucceeded {
		if _, err := repository.db.ExecContext(ctx, `
			UPDATE publish_reservation
			SET status = 'RELEASED', released_at = NOW()
			WHERE account_id = (SELECT aws_account_config_id FROM aws_sync_run WHERE id = $1)
			  AND status = 'MERGED'`, runID); err != nil {
			// 释放失败只影响下次发布时间，不推翻同步结果；下次成功同步会重试。
			return fmt.Errorf("release merged publish reservations after sync: %w", err)
		}
	}
	return nil
}

// GetChanges returns the persisted inventory diff of one run. It returns nil
// (no error) when the run finished without recording a diff.
func (repository *SQLAWSSyncRunRepository) GetChanges(ctx context.Context, runID int64) (*AWSSyncChanges, error) {
	var raw []byte
	err := repository.db.QueryRowContext(ctx,
		`SELECT changes FROM aws_sync_run WHERE id = $1`, runID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSyncRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get AWS sync run changes: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var changes AWSSyncChanges
	if err := json.Unmarshal(raw, &changes); err != nil {
		return nil, fmt.Errorf("decode AWS sync run changes: %w", err)
	}
	return &changes, nil
}

// Get returns one run by ID.
func (repository *SQLAWSSyncRunRepository) Get(ctx context.Context, runID int64) (AWSSyncRun, error) {
	run, err := scanAWSSyncRun(repository.db.QueryRowContext(ctx,
		`SELECT `+awsSyncRunColumns+` FROM aws_sync_run WHERE id = $1`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return AWSSyncRun{}, ErrSyncRunNotFound
	}
	if err != nil {
		return AWSSyncRun{}, fmt.Errorf("get AWS sync run: %w", err)
	}
	return run, nil
}

// List lists runs with total count.
func (repository *SQLAWSSyncRunRepository) List(
	ctx context.Context,
	filter AWSSyncRunFilter,
) ([]AWSSyncRun, int, error) {
	conditions := []string{"TRUE"}
	args := make([]any, 0, 4)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if filter.ConfigID > 0 {
		conditions = append(conditions, "aws_account_config_id = "+addArg(filter.ConfigID))
	}
	if accountID := strings.TrimSpace(filter.AWSAccountID); accountID != "" {
		conditions = append(conditions, "aws_account_id = "+addArg(accountID))
	}
	switch filter.Status {
	case "":
	case SyncRunStatusPending, SyncRunStatusRunning, SyncRunStatusSucceeded,
		SyncRunStatusFailed, SyncRunStatusSuperseded:
		conditions = append(conditions, "status = "+addArg(filter.Status))
	default:
		return nil, 0, fmt.Errorf("%w: %q", ErrInvalidSyncRunStatus, filter.Status)
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := repository.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM aws_sync_run"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count AWS sync runs: %w", err)
	}
	if total == 0 || filter.Offset >= total {
		return []AWSSyncRun{}, total, nil
	}

	query := "SELECT " + awsSyncRunColumns + " FROM aws_sync_run" + where +
		fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
			addArg(filter.Limit), addArg(filter.Offset))
	rows, err := repository.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list AWS sync runs: %w", err)
	}
	defer rows.Close()
	runs := make([]AWSSyncRun, 0, filter.Limit)
	for rows.Next() {
		run, err := scanAWSSyncRun(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan AWS sync run: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate AWS sync runs: %w", err)
	}
	return runs, total, nil
}
