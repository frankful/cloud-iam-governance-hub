package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// SyncWorkerHeartbeatKey is written by cmd/sync-worker every 15s with a
	// 30s TTL. A missing key means no worker is consuming the sync queue, so
	// triggered runs would stay PENDING forever.
	SyncWorkerHeartbeatKey = "worker:heartbeat:sync"
	// SyncQueuePendingKey is the asynq pending list for the sync queue
	// (LLEN works with or without an asynq Inspector).
	SyncQueuePendingKey = "asynq:{sync}:pending"

	workerHeartbeatInterval = 15 * time.Second
	workerHeartbeatTTL      = 30 * time.Second
)

// AWSSyncWorkerStatus reports whether a sync worker is consuming the queue.
type AWSSyncWorkerStatus struct {
	Online        bool       `json:"online"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	PendingRuns   int        `json:"pending_runs"`
}

// AWSSyncWorkerStatusService reads the sync worker heartbeat and queue depth.
// It is read-only and used by the UI/ops to explain stuck PENDING runs.
type AWSSyncWorkerStatusService struct {
	redis *redis.Client
}

// NewAWSSyncWorkerStatusService creates the status reader.
func NewAWSSyncWorkerStatusService(client *redis.Client) (*AWSSyncWorkerStatusService, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client must not be nil")
	}
	return &AWSSyncWorkerStatusService{redis: client}, nil
}

// WorkerStatus returns the heartbeat state plus the pending queue depth.
func (service *AWSSyncWorkerStatusService) WorkerStatus(ctx context.Context) (AWSSyncWorkerStatus, error) {
	status := AWSSyncWorkerStatus{}
	value, err := service.redis.Get(ctx, SyncWorkerHeartbeatKey).Result()
	switch {
	case err == redis.Nil:
		// No heartbeat: worker down or never started.
	case err != nil:
		return AWSSyncWorkerStatus{}, fmt.Errorf("read sync worker heartbeat: %w", err)
	default:
		status.Online = true
		if heartbeat, parseErr := time.Parse(time.RFC3339, value); parseErr == nil {
			status.LastHeartbeat = &heartbeat
		}
	}
	pending, err := service.redis.LLen(ctx, SyncQueuePendingKey).Result()
	if err != nil {
		return AWSSyncWorkerStatus{}, fmt.Errorf("read sync queue depth: %w", err)
	}
	status.PendingRuns = int(pending)
	return status, nil
}

// StartWorkerHeartbeat writes the worker heartbeat until ctx is cancelled and
// returns a stop function. Written immediately so a freshly started worker is
// visible before the first interval elapses.
func StartWorkerHeartbeat(
	ctx context.Context,
	client *redis.Client,
	key string,
	logger *slog.Logger,
) func() {
	if client == nil {
		return func() {}
	}
	if logger == nil {
		logger = slog.Default()
	}
	heartbeatCtx, cancel := context.WithCancel(ctx)
	write := func() {
		if err := client.Set(heartbeatCtx, key, time.Now().UTC().Format(time.RFC3339), workerHeartbeatTTL).Err(); err != nil {
			logger.Warn("failed to write worker heartbeat", "key", key, "error", err)
		}
	}
	write()
	go func() {
		ticker := time.NewTicker(workerHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				write()
			}
		}
	}()
	return cancel
}
