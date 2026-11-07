package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
)

// AsynqGitStatusPollEnqueuer implements GitStatusPollEnqueuer using Asynq.
type AsynqGitStatusPollEnqueuer struct {
	client *asynq.Client
}

// NewAsynqGitStatusPollEnqueuer creates a new AsynqGitStatusPollEnqueuer.
func NewAsynqGitStatusPollEnqueuer(client *asynq.Client) (*AsynqGitStatusPollEnqueuer, error) {
	if client == nil {
		return nil, fmt.Errorf("asynq client must not be nil")
	}
	return &AsynqGitStatusPollEnqueuer{client: client}, nil
}

// EnqueueGitStatusPoll enqueues a Git status poll task.
func (e *AsynqGitStatusPollEnqueuer) EnqueueGitStatusPoll(ctx context.Context, payload GitStatusPollTask) error {
	if payload.Traceparent == "" {
		payload.Traceparent = oteltrace.TraceParentFromContext(ctx)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal git status poll payload: %w", err)
	}

	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)
	_, err = e.client.EnqueueContext(ctx, task, asynq.ProcessIn(InitialPollInterval), asynq.Queue(GitStatusQueueName))
	if err != nil {
		return fmt.Errorf("enqueue git status poll task: %w", err)
	}

	return nil
}
