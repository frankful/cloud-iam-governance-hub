package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
)

// 预览 job 的队列化：API 只落 PENDING 行并入队，构建（数百文件 HCL 渲染 +
// 逐文件远端存在性检查）在 sync-worker 执行——与 AWS 采集同生命周期，API
// 进程重启/发布不再中断进行中的预览。job 的领取（PENDING→RUNNING）、超时
// 与 SweepStale 语义不变；MaxRetry(0)：失败已落 job 行（FAILED + 原因），
// 重跑走 API 重新创建，队列重试只会制造重复执行。

const (
	// BaselinePreviewJobTaskType 是 asynq 任务类型。
	BaselinePreviewJobTaskType = "baseline:preview:job"

	// BaselineQueueName 是基线任务专用队列，与采集队列（sync）隔离——
	// 互为背压，互不阻塞。
	BaselineQueueName = "baseline"
)

// BaselinePreviewJobPayload 是队列消息体。
type BaselinePreviewJobPayload struct {
	JobID int64 `json:"job_id"`
}

// BaselinePreviewJobEnqueuer 把待执行的 job 推给 worker。测试与无 Redis 场景
// 用 fake / 不设置。
type BaselinePreviewJobEnqueuer interface {
	EnqueuePreviewJob(ctx context.Context, jobID int64) error
}

// AsynqBaselinePreviewJobEnqueuer 基于 asynq 的实现。
type AsynqBaselinePreviewJobEnqueuer struct {
	client *asynq.Client
}

func NewAsynqBaselinePreviewJobEnqueuer(client *asynq.Client) (*AsynqBaselinePreviewJobEnqueuer, error) {
	if client == nil {
		return nil, fmt.Errorf("asynq client must not be nil")
	}
	return &AsynqBaselinePreviewJobEnqueuer{client: client}, nil
}

func (enqueuer *AsynqBaselinePreviewJobEnqueuer) EnqueuePreviewJob(ctx context.Context, jobID int64) error {
	encoded, err := json.Marshal(BaselinePreviewJobPayload{JobID: jobID})
	if err != nil {
		return fmt.Errorf("encode baseline preview job payload: %w", err)
	}
	task := asynq.NewTask(BaselinePreviewJobTaskType, encoded)
	_, err = enqueuer.client.EnqueueContext(ctx, task,
		asynq.Queue(BaselineQueueName),
		asynq.MaxRetry(0),
		asynq.Timeout(BaselineJobRunTimeout),
	)
	if err != nil {
		return fmt.Errorf("enqueue baseline preview job %d: %w", jobID, err)
	}
	return nil
}

// SetEnqueuer 注入队列执行面。设置后 handler.Create 不再进程内 goroutine 执行，
// 而是入队交给 sync-worker；未设置（测试、单进程模式）保留原行为。
func (service *BaselinePreviewJobService) SetEnqueuer(enqueuer BaselinePreviewJobEnqueuer) {
	service.enqueuer = enqueuer
}

// Enqueuer 返回当前执行面（handler 判断是否入队）。
func (service *BaselinePreviewJobService) Enqueuer() BaselinePreviewJobEnqueuer {
	return service.enqueuer
}

// HandleBaselinePreviewJobTask 是 asynq 处理入口：解码 → 领取 → 构建。
func (service *BaselinePreviewJobService) HandleBaselinePreviewJobTask(ctx context.Context, task *asynq.Task) error {
	var payload BaselinePreviewJobPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("decode baseline preview job payload: %w: %w", ErrBaselineJobNotPending, err)
	}
	if payload.JobID <= 0 {
		return fmt.Errorf("invalid baseline preview job id %d", payload.JobID)
	}
	return service.Run(ctx, payload.JobID)
}
