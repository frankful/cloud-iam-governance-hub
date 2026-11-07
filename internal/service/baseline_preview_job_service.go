package service

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// 基线预览 job：把一次 bundle 构建变成可追溯的状态机。PENDING 由 API 写入，
// 执行体领取（RUNNING）后构建 bundle，终态写回结果与内容指纹。结果整体
// 落 JSONB，前端只读渲染——预览不是发布（B3 才接仓库），失败可重跑。
const (
	BaselineJobStatusPending   = "PENDING"
	BaselineJobStatusRunning   = "RUNNING"
	BaselineJobStatusCompleted = "COMPLETED"
	BaselineJobStatusFailed    = "FAILED"

	// BaselineJobRunTimeout 单次构建的上限。构建是纯 DB 读 + HCL 渲染，
	// 只有文件存在性检查走 GitHub API；十分钟足够几百个文件。
	BaselineJobRunTimeout = 10 * time.Minute

	// BaselineJobStaleAfter 超过该时长仍处于 PENDING/RUNNING 的 job 视为被
	// 中断（进程重启、panic），由 SweepStale 收尾成 FAILED，避免永远转圈。
	BaselineJobStaleAfter = time.Hour
)

// ErrBaselineJobNotFound 表示 job 不存在，handler 据此返回 404。
var ErrBaselineJobNotFound = errors.New("baseline preview job not found")

// ErrBaselineJobNotPending 表示 job 已被领取或已完成，不能重复执行。
var ErrBaselineJobNotPending = errors.New("baseline preview job is not pending")

// BaselinePreviewJob 是 iam_baseline_job 的一行。Result 与 ContentSHA256
// 只在 COMPLETED 出现；hash 以 hex 字符串返回给前端。
type BaselinePreviewJob struct {
	ID            int64           `json:"id"`
	AccountDBID   int64           `json:"account_db_id"`
	AWSAccountID  string          `json:"aws_account_id"`
	Status        string          `json:"status"`
	RequestedBy   string          `json:"requested_by,omitempty"`
	Error         string          `json:"error,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	ContentSHA256 string          `json:"content_sha256,omitempty"`
	StartedAt     *time.Time      `json:"started_at,omitempty"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// BaselinePreviewJobService 管理预览 job 的生命周期。
type BaselinePreviewJobService struct {
	db      *sql.DB
	bundles *BaselineBundleService
	logger  *slog.Logger
	// enqueuer 非空时（生产装配）Create 后入队交给 sync-worker 执行；
	// 为空时由调用方（handler / 测试）用 Run 进程内驱动。
	enqueuer BaselinePreviewJobEnqueuer
}

func NewBaselinePreviewJobService(
	db *sql.DB,
	bundles *BaselineBundleService,
	logger *slog.Logger,
) *BaselinePreviewJobService {
	if logger == nil {
		logger = slog.Default()
	}
	return &BaselinePreviewJobService{db: db, bundles: bundles, logger: logger}
}

// Create 落一条 PENDING job。执行由调用方（handler）用 Run 驱动；创建与
// 执行分离让重跑与审计都有落点。
func (service *BaselinePreviewJobService) Create(
	ctx context.Context,
	accountRef string,
	requestedBy string,
) (*BaselinePreviewJob, error) {
	ref := strings.TrimSpace(accountRef)
	if ref == "" {
		return nil, errors.New("account reference must not be empty")
	}
	var accountDBID int64
	var awsAccountID string
	if err := service.db.QueryRowContext(ctx, `
		SELECT id, account_id FROM aws_account
		WHERE account_id = $1 OR id::text = $1
		LIMIT 1`, ref,
	).Scan(&accountDBID, &awsAccountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q", ErrBaselineAccountNotFound, ref)
		}
		return nil, fmt.Errorf("load AWS account %q: %w", ref, err)
	}
	job := &BaselinePreviewJob{
		AccountDBID:  accountDBID,
		AWSAccountID: awsAccountID,
		Status:       BaselineJobStatusPending,
		RequestedBy:  strings.TrimSpace(requestedBy),
	}
	err := service.db.QueryRowContext(ctx, `
		INSERT INTO iam_baseline_job (account_id, status, requested_by)
		VALUES ($1, $2, NULLIF($3, ''))
		RETURNING id, created_at`,
		accountDBID, BaselineJobStatusPending, job.RequestedBy,
	).Scan(&job.ID, &job.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create baseline preview job: %w", err)
	}
	return job, nil
}

// Fail 把 job 落成 FAILED 并记录原因。入队失败时由 handler 调用，避免 job
// 永远停在 PENDING。
func (service *BaselinePreviewJobService) Fail(
	ctx context.Context,
	jobID int64,
	cause error,
) error {
	return service.finishFailed(ctx, jobID, cause)
}

// Run 领取并执行一个 PENDING job。执行上下文与调用方解耦（后台 goroutine
// 传入 context.Background()），所以这里自带超时。
func (service *BaselinePreviewJobService) Run(ctx context.Context, jobID int64) error {
	runCtx, cancel := context.WithTimeout(context.Background(), BaselineJobRunTimeout)
	defer cancel()

	var accountDBID int64
	err := service.db.QueryRowContext(runCtx, `
		UPDATE iam_baseline_job
		SET status = $2, started_at = NOW()
		WHERE id = $1 AND status = $3
		RETURNING account_id`,
		jobID, BaselineJobStatusRunning, BaselineJobStatusPending,
	).Scan(&accountDBID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBaselineJobNotPending
	}
	if err != nil {
		return fmt.Errorf("claim baseline preview job %d: %w", jobID, err)
	}

	report, err := service.bundles.Build(runCtx, fmt.Sprintf("%d", accountDBID))
	if err != nil {
		return service.finishFailed(runCtx, jobID, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return service.finishFailed(runCtx, jobID, fmt.Errorf("encode bundle result: %w", err))
	}
	hash, err := hex.DecodeString(report.ContentSHA256)
	if err != nil || len(hash) != 32 {
		return service.finishFailed(runCtx, jobID,
			fmt.Errorf("bundle content hash %q is not a 32-byte hex digest", report.ContentSHA256))
	}
	if _, err := service.db.ExecContext(runCtx, `
		UPDATE iam_baseline_job
		SET status = $2, result = $3, content_sha256 = $4, finished_at = NOW()
		WHERE id = $1`,
		jobID, BaselineJobStatusCompleted, encoded, hash,
	); err != nil {
		return fmt.Errorf("complete baseline preview job %d: %w", jobID, err)
	}
	service.logger.Info("baseline preview job completed",
		"job_id", jobID,
		"account", report.AWSAccountID,
		"files", report.Counts["files"],
		"issues", len(report.Issues),
		"content_sha256", report.ContentSHA256,
	)
	return nil
}

func (service *BaselinePreviewJobService) finishFailed(
	ctx context.Context,
	jobID int64,
	cause error,
) error {
	message := sanitizeErrorMessage(cause.Error())
	if _, execErr := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_job
		SET status = $2, error = $3, finished_at = NOW()
		WHERE id = $1`,
		jobID, BaselineJobStatusFailed, message,
	); execErr != nil {
		service.logger.Error("failed to record baseline preview job failure",
			"job_id", jobID, "cause", cause, "record_error", execErr)
	}
	return fmt.Errorf("baseline preview job %d failed: %w", jobID, cause)
}

// SweepStale 把被中断的 job 收尾成 FAILED。API 启动时调用一次。
func (service *BaselinePreviewJobService) SweepStale(ctx context.Context) (int, error) {
	result, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_job
		SET status = $1, error = $2, finished_at = NOW()
		WHERE status IN ($3, $4) AND created_at < NOW() - $5::interval`,
		BaselineJobStatusFailed,
		"interrupted: job never reached a terminal state (restart or crash)",
		BaselineJobStatusPending, BaselineJobStatusRunning,
		fmt.Sprintf("%d seconds", int(BaselineJobStaleAfter.Seconds())),
	)
	if err != nil {
		return 0, fmt.Errorf("sweep stale baseline preview jobs: %w", err)
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// List 返回账号最近的预览 job（新在前）。limit <= 0 取默认 20。
func (service *BaselinePreviewJobService) List(
	ctx context.Context,
	accountRef string,
	limit int,
) ([]BaselinePreviewJob, error) {
	ref := strings.TrimSpace(accountRef)
	if ref == "" {
		return nil, errors.New("account reference must not be empty")
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := service.db.QueryContext(ctx, `
		SELECT j.id, j.account_id, a.account_id, j.status,
		       COALESCE(j.requested_by, ''), j.error, j.result,
		       COALESCE(ENCODE(j.content_sha256, 'hex'), ''),
		       j.started_at, j.finished_at, j.created_at
		FROM iam_baseline_job j
		JOIN aws_account a ON a.id = j.account_id
		WHERE a.account_id = $1 OR a.id::text = $1
		ORDER BY j.id DESC
		LIMIT $2`, ref, limit)
	if err != nil {
		return nil, fmt.Errorf("list baseline preview jobs: %w", err)
	}
	defer rows.Close()
	jobs := []BaselinePreviewJob{}
	for rows.Next() {
		job, scanErr := scanBaselineJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

// Get 返回单个 job（含完整 bundle 结果）。
func (service *BaselinePreviewJobService) Get(
	ctx context.Context,
	jobID int64,
) (*BaselinePreviewJob, error) {
	row := service.db.QueryRowContext(ctx, `
		SELECT j.id, j.account_id, a.account_id, j.status,
		       COALESCE(j.requested_by, ''), j.error, j.result,
		       COALESCE(ENCODE(j.content_sha256, 'hex'), ''),
		       j.started_at, j.finished_at, j.created_at
		FROM iam_baseline_job j
		JOIN aws_account a ON a.id = j.account_id
		WHERE j.id = $1`, jobID)
	job, err := scanBaselineJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBaselineJobNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load baseline preview job %d: %w", jobID, err)
	}
	return job, nil
}

func scanBaselineJob(row interface {
	Scan(dest ...interface{}) error
}) (*BaselinePreviewJob, error) {
	var job BaselinePreviewJob
	var result []byte
	var startedAt, finishedAt sql.NullTime
	if err := row.Scan(
		&job.ID, &job.AccountDBID, &job.AWSAccountID, &job.Status,
		&job.RequestedBy, &job.Error, &result, &job.ContentSHA256,
		&startedAt, &finishedAt, &job.CreatedAt,
	); err != nil {
		return nil, err
	}
	if len(result) > 0 {
		job.Result = json.RawMessage(result)
	}
	if startedAt.Valid {
		value := startedAt.Time
		job.StartedAt = &value
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		job.FinishedAt = &value
	}
	return &job, nil
}
