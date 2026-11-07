package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// GitStatusPollTaskType is the Asynq task type for Git status polling.
	GitStatusPollTaskType = "gitstatus:poll"

	// GitStatusQueueName isolates poll tasks so workers of other task types
	// never claim (and fail) them. All workers must serve their own queue.
	GitStatusQueueName = "gitstatus"

	// InitialPollInterval is the wait before the first poll attempt.
	// Subsequent attempts use linear backoff: nextPollDelay adds five
	// minutes per completed attempt (10m, 15m, 20m, ...).
	InitialPollInterval = 5 * time.Minute

	// MaxPollAttempts is the maximum number of poll attempts. With linear
	// backoff (5 minutes per step) the nth attempt runs 5·n(n+1)/2 minutes
	// after publication, so 63 attempts span exactly 7 days — a merged PR
	// is still observed within the first week of review.
	MaxPollAttempts = 63

	// MaxPollAge is the maximum age of a poll task before it is considered stale.
	MaxPollAge = 2 * time.Hour

	// MergedCIWaitPollInterval 是 CI apply 回调开启后、PR 已合并但 CI 尚未
	// 出结果时的短轮询间隔。CI apply 全程约 5-10 分钟，2 分钟一轮足够密，
	// 轮询预算仍受 MaxPollAttempts 约束（63 次 ≈ 2 小时等待窗口）。
	MergedCIWaitPollInterval = 2 * time.Minute
)

// GitStatusPollTask represents a task to poll Git merge request status.
// Traceparent carries the W3C trace context across asynq (no task headers)
// so API requests, publications and every poll attempt stay one trace.
type GitStatusPollTask struct {
	TicketNo            string `json:"ticket_no"`
	Provider            string `json:"provider"`
	Project             string `json:"project"`
	RemoteRequestNumber string `json:"remote_request_number"`
	CommitSHA           string `json:"commit_sha,omitempty"`
	Attempt             int    `json:"attempt"`
	Traceparent         string `json:"traceparent,omitempty"`
}

// GitStatusPoller handles Git status polling tasks.
type GitStatusPoller struct {
	gitHost     githost.GitHost
	repository  GitStatusRepository
	client      *asynq.Client
	logger      *slog.Logger
	closureSync TicketClosureSyncTrigger
	// reservations 是文件级发布预约（phase4 §4.2）：PR 合并时把工单的
	// 开放预约转 MERGED 态，等该账号下一次成功同步后再释放。nil 安全。
	reservations *PublishReservationService
	// ciApplyCallback 开启后（部署接入了 CI apply 回调，A12⑤）：merged 不再
	// 立即关单，CI 绿（finops/terraform-apply status success）才关单；CI 红或
	// 一直无 status 挂起留人工。默认 false 保持「merge 即关单」旧语义
	// （GitLab/无 CI 部署唯一可行语义）。
	ciApplyCallback bool
}

// GitStatusPollerOption configures optional poller collaborators.
type GitStatusPollerOption func(*GitStatusPoller) error

// WithGitStatusClosureSync wires the inventory refresh that runs after an
// auto-close. nil keeps the poller self-contained.
func WithGitStatusClosureSync(trigger TicketClosureSyncTrigger) GitStatusPollerOption {
	return func(poller *GitStatusPoller) error {
		poller.closureSync = trigger
		return nil
	}
}

// WithGitStatusReservations wires the publish reservation service so that a
// merged ticket PR moves its file reservations to the MERGED state (released
// by the next successful account sync). nil keeps the poller self-contained.
func WithGitStatusReservations(reservations *PublishReservationService) GitStatusPollerOption {
	return func(poller *GitStatusPoller) error {
		poller.reservations = reservations
		return nil
	}
}

// WithCIApplyCallback toggles the CI-gated close semantics (A12⑤). Enabled:
// a merged ticket PR only auto-closes once the CI reports
// finops/terraform-apply success; failures and missing statuses leave the
// ticket open for manual handling. Disabled (default): merge alone closes.
func WithCIApplyCallback(enabled bool) GitStatusPollerOption {
	return func(poller *GitStatusPoller) error {
		poller.ciApplyCallback = enabled
		return nil
	}
}

// GitStatusRepository defines the interface for Git status persistence.
type GitStatusRepository interface {
	SaveExecutionRecord(ctx context.Context, ticketNo string, record model.IACExecutionRecord) error
	UpdateTicketGitStatus(ctx context.Context, ticketNo string, status GitTicketStatus) error
	GetTicket(ctx context.Context, ticketNo string) (model.IAMTicket, error)
	CloseTicket(ctx context.Context, ticketNo, actorID, reason string) (model.IAMTicket, error)
	MarkTicketPublishFailed(ctx context.Context, ticketNo, errorMessage string) error
	RestoreTicketStatus(ctx context.Context, ticketNo string) error
	ListPollableTickets(ctx context.Context) ([]PollableTicket, error)
}

// PollableTicket identifies a ticket whose remote request still needs
// status polling.
type PollableTicket struct {
	TicketNo            string
	Provider            string
	Project             string
	RemoteRequestNumber string
}

// GitTicketStatus represents the Git-related status of a ticket.
type GitTicketStatus struct {
	MergeState       string
	CIState          string
	ApplyResult      string
	PollAttemptCount int
	NextPollAt       *time.Time
	LastStatusPollAt *time.Time
}

// NewGitStatusPoller creates a new GitStatusPoller.
func NewGitStatusPoller(gitHost githost.GitHost, repository GitStatusRepository, client *asynq.Client, logger *slog.Logger, options ...GitStatusPollerOption) (*GitStatusPoller, error) {
	if gitHost == nil {
		return nil, fmt.Errorf("git host must not be nil")
	}
	if repository == nil {
		return nil, fmt.Errorf("repository must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	poller := &GitStatusPoller{
		gitHost:    gitHost,
		repository: repository,
		client:     client,
		logger:     logger,
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(poller); err != nil {
			return nil, fmt.Errorf("configure git status poller: %w", err)
		}
	}
	return poller, nil
}

// HandleGitStatusPollTask processes a Git status poll task.
func (p *GitStatusPoller) HandleGitStatusPollTask(ctx context.Context, task *asynq.Task) (err error) {
	var payload GitStatusPollTask
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal git status poll task: %w", err)
	}

	// Continue the producer's trace: asynq has no task headers, so the
	// traceparent travels inside the payload.
	ctx = oteltrace.ContextWithTraceParent(ctx, payload.Traceparent)
	ctx, span := otel.Tracer("finops/gitstatus").Start(ctx, "gitstatus.poll",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("ticket_no", payload.TicketNo),
			attribute.String("provider", payload.Provider),
			attribute.String("project", payload.Project),
			attribute.Int("attempt", payload.Attempt),
		))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if payload.TicketNo == "" {
		return fmt.Errorf("git status poll task missing ticket number")
	}
	if payload.Provider == "" {
		return fmt.Errorf("git status poll task missing provider")
	}
	if payload.Project == "" {
		return fmt.Errorf("git status poll task missing project")
	}
	if payload.RemoteRequestNumber == "" {
		return fmt.Errorf("git status poll task missing remote request number")
	}

	p.logger.Info("polling Git status",
		"ticket_no", payload.TicketNo,
		"provider", payload.Provider,
		"remote_request", payload.RemoteRequestNumber,
		"attempt", payload.Attempt,
	)

	// Check if ticket is still active (not closed/rejected)
	ticket, err := p.repository.GetTicket(ctx, payload.TicketNo)
	if err != nil {
		return fmt.Errorf("get ticket for polling: %w", err)
	}
	if ticket.Status == nil {
		return fmt.Errorf("ticket %s has no status", payload.TicketNo)
	}
	if !isPollableStatus(*ticket.Status) {
		p.logger.Info("ticket not in pollable state, skipping",
			"ticket_no", payload.TicketNo,
			"status", *ticket.Status,
		)
		return nil
	}

	// Fetch merge request status
	mrStatus, err := p.gitHost.FetchMergeRequest(ctx, payload.Project, payload.RemoteRequestNumber)
	if err != nil {
		// Record error and mark ticket as PUBLISH_FAILED
		p.handlePollError(ctx, payload, fmt.Sprintf("fetch merge request status: %v", err))
		return fmt.Errorf("fetch merge request status: %w", err)
	}

	if mrStatus == nil {
		err := fmt.Errorf("merge request %s not found in %s", payload.RemoteRequestNumber, payload.Project)
		p.handlePollError(ctx, payload, err.Error())
		return err
	}

	// Fetch CI status if commit SHA is available
	var ciState githost.CIState = githost.CIStateUnknown
	var pipelineStatuses []githost.PipelineStatus
	explicitCISucceeded := false
	commitSHA := payload.CommitSHA
	batchAdoption := ticket.TicketType != nil && *ticket.TicketType == TicketTypeAdoptRoleInlinePolicies
	if batchAdoption {
		commitSHA = mrStatus.HeadSHA
	}
	if commitSHA == "" && mrStatus.HeadSHA != "" {
		commitSHA = mrStatus.HeadSHA
	}
	if commitSHA != "" {
		pipelineStatuses, err = p.gitHost.FetchCommitStatuses(ctx, payload.Project, commitSHA)
		if err != nil {
			p.logger.Warn("failed to fetch commit statuses", "error", err)
		} else if len(pipelineStatuses) > 0 {
			ciState = summarizeCIStatuses(pipelineStatuses)
			explicitCISucceeded = ciState == githost.CIStateSucceeded &&
				(!batchAdoption || (mrStatus.HeadSHA != "" && commitSHA == mrStatus.HeadSHA))
		} else {
			// No check runs configured for this repository/commit.
			// 默认部署没有 CI 门禁，无 status 视为成功，merged PR 才能关单。
			// CI apply 回调开启后，CI 被预期会写 finops/terraform-apply
			// status——缺 status 意味着「还没观察到」而不是成功。
			ciState = githost.CIStateSucceeded
			if p.ciApplyCallback {
				ciState = githost.CIStateUnknown
			}
		}
	}
	if batchAdoption && len(pipelineStatuses) == 0 {
		ciState = githost.CIStateUnknown
	}

	// Determine apply result based on merge and CI state
	applyResult := determineApplyResult(mrStatus.State, ciState)
	if mrStatus.State == githost.MergeStateMerged && !p.ciApplyCallback {
		// 「merge 即成功」是无 CI 门禁部署的语义；CI 回调开启后由
		// determineApplyResult 按 CI 状态决定（A12⑤）。
		applyResult = githost.ApplyResultSucceeded
	}

	// Save execution record
	record := model.IACExecutionRecord{
		Provider:            payload.Provider,
		Repository:          payload.Project,
		RemoteRequestNumber: &payload.RemoteRequestNumber,
		RemoteURL:           &mrStatus.URL,
		CommitSHA:           stringPointer(commitSHA),
		MergeState:          string(mrStatus.State),
		CIState:             string(ciState),
		ApplyResult:         string(applyResult),
		Attempt:             payload.Attempt,
		IdempotencyKey:      fmt.Sprintf("%s:%s:%s:%d", payload.Provider, payload.Project, payload.RemoteRequestNumber, payload.Attempt),
		Metadata:            model.JSONB(fmt.Sprintf(`{"title":%q,"head_sha":%q,"base_branch":%q}`, mrStatus.Title, mrStatus.HeadSHA, mrStatus.BaseBranch)),
		ObservedAt:          time.Now(),
	}

	if err := p.repository.SaveExecutionRecord(ctx, payload.TicketNo, record); err != nil {
		return fmt.Errorf("save execution record: %w", err)
	}

	// Update ticket Git status
	shouldPollAgain := shouldScheduleNextPoll(mrStatus.State, payload.Attempt)
	// CI apply 回调开启时 merged 不再是轮询终点：CI 可能在合并后才写
	// finops/terraform-apply status，短间隔继续轮询直到出现终态或预算耗尽。
	waitingForCI := false
	if p.ciApplyCallback && mrStatus.State == githost.MergeStateMerged &&
		(ciState == githost.CIStatePending || ciState == githost.CIStateRunning ||
			ciState == githost.CIStateUnknown) {
		waitingForCI = true
		shouldPollAgain = payload.Attempt < MaxPollAttempts
	}
	var nextPollAt *time.Time
	if shouldPollAgain {
		delay := nextPollDelay(payload.Attempt)
		if waitingForCI {
			delay = MergedCIWaitPollInterval
		}
		nextPollAt = timePointer(time.Now().Add(delay))
	}
	ticketStatus := GitTicketStatus{
		MergeState:       string(mrStatus.State),
		CIState:          string(ciState),
		ApplyResult:      string(applyResult),
		PollAttemptCount: payload.Attempt,
		NextPollAt:       nextPollAt,
		LastStatusPollAt: timePointer(time.Now()),
	}

	if err := p.repository.UpdateTicketGitStatus(ctx, payload.TicketNo, ticketStatus); err != nil {
		return fmt.Errorf("update ticket git status: %w", err)
	}

	// A successful poll proves the remote request exists, so a ticket that an
	// earlier poll error left in PUBLISH_FAILED is healthy again. Restoring
	// APPROVED avoids asking an operator to retry the publication, which would
	// open a duplicate request for the same change.
	if mrStatus.State != githost.MergeStateMerged &&
		ticket.Status != nil && *ticket.Status == TicketStatusPublishFailed {
		if err := p.repository.RestoreTicketStatus(ctx, payload.TicketNo); err != nil {
			p.logger.Warn("failed to restore ticket status after a successful poll",
				"ticket_no", payload.TicketNo, "error", err)
		}
	}

	if batchAdoption && mrStatus.State == githost.MergeStateOpen && explicitCISucceeded {
		merger, ok := p.gitHost.(githost.MergeRequestMerger)
		if !ok {
			p.logger.Error("Git host does not support protected merge API",
				"ticket_no", payload.TicketNo, "provider", payload.Provider)
		} else if err := merger.MergeMergeRequest(ctx, payload.Project, payload.RemoteRequestNumber); err != nil {
			p.logger.Warn("automatic merge was rejected; ticket will be retried by polling",
				"ticket_no", payload.TicketNo, "error", err)
		}
	}

	p.logger.Info("Git status poll completed",
		"ticket_no", payload.TicketNo,
		"merge_state", mrStatus.State,
		"ci_state", ciState,
		"apply_result", applyResult,
	)

	// 下一次轮询由本函数的调度决定（含 merged 后等 CI 的 2 分钟短间隔）；
	// 关单语义见下方两档分支。
	if shouldPollAgain {
		if err := p.ScheduleNextPoll(ctx, payload); err != nil {
			p.logger.Warn("failed to schedule next poll",
				"ticket_no", payload.TicketNo, "attempt", payload.Attempt, "error", err)
		}
	}

	// 合并后的关单语义分两档（A12⑤）：
	//   - 默认（无 CI apply 门禁）：merge 即关单——GitLab/无 CI 部署唯一可行语义；
	//   - CI apply 回调开启：CI 绿（finops/terraform-apply success）才关单，
	//     此时 apply 真的成功；CI 红或一直无 status 挂起留人工，不做超时兜底
	//     （超时关单可能把失败 apply 关成 APPLIED）。
	if mrStatus.State == githost.MergeStateMerged {
		switch {
		case !p.ciApplyCallback, ciState == githost.CIStateSucceeded:
			if err := p.autoCloseTicket(ctx, payload.TicketNo); err != nil {
				p.logger.Warn("failed to auto-close ticket", "ticket_no", payload.TicketNo, "error", err)
			}
		default:
			if !shouldPollAgain {
				p.logger.Warn("merged ticket left open for manual handling: CI apply status is not successful",
					"ticket_no", payload.TicketNo,
					"ci_state", ciState,
					"apply_result", applyResult,
				)
			} else {
				p.logger.Info("merged ticket waits for CI apply result before closing",
					"ticket_no", payload.TicketNo,
					"ci_state", ciState,
				)
			}
		}
	}

	return nil
}

func summarizeCIStatuses(statuses []githost.PipelineStatus) githost.CIState {
	if len(statuses) == 0 {
		return githost.CIStateUnknown
	}
	result := githost.CIStateSucceeded
	for _, status := range statuses {
		switch status.State {
		case githost.CIStateFailed:
			return githost.CIStateFailed
		case githost.CIStateCanceled:
			result = githost.CIStateCanceled
		case githost.CIStatePending:
			if result != githost.CIStateCanceled {
				result = githost.CIStatePending
			}
		case githost.CIStateRunning:
			if result != githost.CIStateCanceled && result != githost.CIStatePending {
				result = githost.CIStateRunning
			}
		case githost.CIStateUnknown:
			if result == githost.CIStateSucceeded {
				result = githost.CIStateUnknown
			}
		}
	}
	return result
}

// handlePollError records the poll error. Transient failures (network
// timeouts, TLS handshakes, code-host 5xx) are recorded as execution
// records and left to Asynq's task retry: the ticket stays in its
// current state and the next attempt recovers. Only definitive failures
// (e.g. the remote request vanished) mark the ticket PUBLISH_FAILED.
func (p *GitStatusPoller) handlePollError(ctx context.Context, payload GitStatusPollTask, errorMessage string) {
	sanitizedError := sanitizeErrorMessage(errorMessage)

	// Save error record
	errorRecord := model.IACExecutionRecord{
		Provider:            payload.Provider,
		Repository:          payload.Project,
		RemoteRequestNumber: &payload.RemoteRequestNumber,
		MergeState:          "UNKNOWN",
		CIState:             "UNKNOWN",
		ApplyResult:         "FAILED",
		Attempt:             payload.Attempt,
		IdempotencyKey:      fmt.Sprintf("%s:%s:%s:%d:error", payload.Provider, payload.Project, payload.RemoteRequestNumber, payload.Attempt),
		SanitizedError:      &sanitizedError,
		Metadata:            model.JSONB(fmt.Sprintf(`{"error":%q}`, sanitizedError)),
		ObservedAt:          time.Now(),
	}

	if err := p.repository.SaveExecutionRecord(ctx, payload.TicketNo, errorRecord); err != nil {
		p.logger.Error("failed to save error execution record",
			"ticket_no", payload.TicketNo,
			"error", err,
		)
	}

	if isTransientPollError(errorMessage) {
		p.logger.Warn("transient Git poll error, ticket left for retry",
			"ticket_no", payload.TicketNo,
			"error", sanitizedError,
		)
		return
	}

	// Mark ticket as PUBLISH_FAILED
	if err := p.repository.MarkTicketPublishFailed(ctx, payload.TicketNo, sanitizedError); err != nil {
		p.logger.Error("failed to mark ticket as PUBLISH_FAILED",
			"ticket_no", payload.TicketNo,
			"error", err,
		)
	}

	p.logger.Warn("Git poll error recorded, ticket marked as PUBLISH_FAILED",
		"ticket_no", payload.TicketNo,
		"error", sanitizedError,
	)
}

// isTransientPollError reports whether a poll failure is likely
// temporary (network timeout, TLS handshake, connection reset, or
// code-host 5xx) and therefore should be retried rather than
// failing the ticket.
func isTransientPollError(errorMessage string) bool {
	lower := strings.ToLower(errorMessage)
	transientMarkers := []string{
		"timeout",
		"deadline exceeded",
		"tls handshake",
		"connection reset",
		"connection refused",
		"connection aborted",
		"connection closed",
		"broken pipe",
		"unexpected eof",
		"eof", // bare io.EOF from a dropped HTTP/2 stream or closed socket
		"no such host",
		"temporarily unavailable",
		"unreachable",
		"too many requests",
		"service unavailable",
		"internal server error",
		"bad gateway",
		"gateway time-out",
	}
	for _, marker := range transientMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isPollableStatus returns true if the ticket status allows polling.
func isPollableStatus(status string) bool {
	switch status {
	case TicketStatusApproved, TicketStatusPublishing, TicketStatusPublishFailed:
		return true
	default:
		return false
	}
}

// autoCloseTicket automatically closes a ticket with reason APPLIED after
// its merge request is merged.
func (p *GitStatusPoller) autoCloseTicket(ctx context.Context, ticketNo string) error {
	// Check if ticket is still in a closable state
	ticket, err := p.repository.GetTicket(ctx, ticketNo)
	if err != nil {
		return fmt.Errorf("get ticket for auto-close: %w", err)
	}

	if ticket.Status == nil {
		return fmt.Errorf("ticket %s has no status", ticketNo)
	}

	// Only allow closing from states a merged request makes terminal
	if *ticket.Status != TicketStatusApproved &&
		*ticket.Status != TicketStatusPublishing &&
		*ticket.Status != TicketStatusPublishFailed {
		p.logger.Info("ticket not in a closable state, skipping auto-close",
			"ticket_no", ticketNo,
			"status", *ticket.Status,
		)
		return nil
	}

	// Close the ticket
	closed, err := p.repository.CloseTicket(ctx, ticketNo, "system", ClosureReasonApplied)
	if err != nil {
		return fmt.Errorf("auto-close ticket: %w", err)
	}

	// 文件级预约转 MERGED 态（phase4 §4.2）：PR 已合并但 apply 可能尚未
	// 确认，预约不立即释放——等该账号下一次成功同步确认清单已反映变更
	// 后由 ReleaseMergedForAccount 释放。失败只记日志，不影响关单。
	if p.reservations != nil {
		if err := p.reservations.MarkTicketMerged(ctx, ticketNo); err != nil {
			p.logger.Warn("failed to mark publish reservations merged",
				"ticket_no", ticketNo, "error", err)
		}
	}

	p.logger.Info("ticket auto-closed after merge",
		"ticket_no", ticketNo,
		"closed_at", closed.ClosedAt,
	)

	// 关单联动：只有走到这里才确认变更已经合并，
	// 触发一次该账号的资产同步，让清单立即反映变更。人工关单不触发
	//（无法确认是否真的应用）。失败只记日志，不影响关单结果。
	if p.closureSync != nil && ticket.AccountID != nil {
		if err := p.closureSync.TriggerSyncForClosedTicket(ctx, *ticket.AccountID, ticketNo); err != nil {
			if errors.Is(err, ErrSyncDisabled) {
				p.logger.Info("AWS sync disabled for the closed ticket's account; inventory refresh skipped",
					"ticket_no", ticketNo)
			} else {
				p.logger.Warn("failed to trigger AWS sync after auto-close",
					"ticket_no", ticketNo, "error", err)
			}
		}
	}
	return nil
}

// SweepActivePolls re-arms polling for every ticket whose remote request
// is still open. Called at worker startup (and available on demand) so
// tickets recover after restarts or exhausted poll schedules: the first
// poll after a merge flips them into the auto-close path.
func (p *GitStatusPoller) SweepActivePolls(ctx context.Context) error {
	tickets, err := p.repository.ListPollableTickets(ctx)
	if err != nil {
		return fmt.Errorf("list pollable tickets: %w", err)
	}
	if len(tickets) == 0 {
		return nil
	}
	if p.client == nil {
		return fmt.Errorf("asynq client not configured")
	}
	rearmed := 0
	for _, ticket := range tickets {
		payload := GitStatusPollTask{
			TicketNo:            ticket.TicketNo,
			Provider:            ticket.Provider,
			Project:             ticket.Project,
			RemoteRequestNumber: ticket.RemoteRequestNumber,
			Attempt:             1,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			p.logger.Error("marshal sweep poll payload",
				"ticket_no", ticket.TicketNo, "error", err)
			continue
		}
		task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)
		if _, err := p.client.EnqueueContext(ctx, task,
			asynq.ProcessIn(time.Duration(rearmed)*3*time.Second),
			asynq.Queue(GitStatusQueueName),
		); err != nil {
			p.logger.Error("enqueue sweep poll task",
				"ticket_no", ticket.TicketNo, "error", err)
			continue
		}
		rearmed++
	}
	p.logger.Info("Git poll sweep re-armed", "candidates", len(tickets), "rearmed", rearmed)
	return nil
}

// ScheduleNextPoll schedules the next poll attempt.
func (p *GitStatusPoller) ScheduleNextPoll(ctx context.Context, payload GitStatusPollTask) error {
	nextPayload := GitStatusPollTask{
		TicketNo:            payload.TicketNo,
		Provider:            payload.Provider,
		Project:             payload.Project,
		RemoteRequestNumber: payload.RemoteRequestNumber,
		CommitSHA:           payload.CommitSHA,
		Attempt:             payload.Attempt + 1,
		// Chain attempts into one trace: prefer the caller's active span
		// (the worker handler), falling back to the task's own traceparent.
		Traceparent: oteltrace.TraceParentFromContext(ctx),
	}
	if nextPayload.Traceparent == "" {
		nextPayload.Traceparent = payload.Traceparent
	}

	payloadJSON, err := json.Marshal(nextPayload)
	if err != nil {
		return fmt.Errorf("marshal next poll payload: %w", err)
	}

	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)
	if p.client == nil {
		return fmt.Errorf("asynq client not configured")
	}
	_, err = p.client.EnqueueContext(ctx, task, asynq.ProcessIn(nextPollDelay(payload.Attempt)), asynq.Queue(GitStatusQueueName))
	if err != nil {
		return fmt.Errorf("enqueue next poll task: %w", err)
	}

	return nil
}

// nextPollDelay returns how long to wait after a completed attempt
// before scheduling the next one: linear backoff adding five minutes
// per step (10m after attempt 1, 15m after attempt 2, ...). Linear
// growth keeps fresh PRs tracked closely while still covering a full
// week of review time within MaxPollAttempts.
func nextPollDelay(attempt int) time.Duration {
	return time.Duration(attempt+1) * 5 * time.Minute
}

// determineApplyResult determines the apply result based on merge and CI state.
func determineApplyResult(mergeState githost.MergeState, ciState githost.CIState) githost.ApplyResult {
	if mergeState != githost.MergeStateMerged {
		return githost.ApplyResultPending
	}

	switch ciState {
	case githost.CIStateSucceeded:
		return githost.ApplyResultSucceeded
	case githost.CIStateFailed:
		return githost.ApplyResultFailed
	case githost.CIStateCanceled:
		return githost.ApplyResultCanceled
	default:
		return githost.ApplyResultPending
	}
}

// isTerminalMergeState returns true if the merge state is terminal.
func isTerminalMergeState(state githost.MergeState) bool {
	return state == githost.MergeStateMerged || state == githost.MergeStateClosed
}

func shouldScheduleNextPoll(mergeState githost.MergeState, attempt int) bool {
	return attempt < MaxPollAttempts && !isTerminalMergeState(mergeState)
}

func timePointer(t time.Time) *time.Time {
	return &t
}

// GitStatusWorkerConfig holds configuration for the embedded gitstatus worker.
type GitStatusWorkerConfig struct {
	DB               *sql.DB
	RedisAddr        string
	RedisPassword    string
	RedisDB          int
	GitProvider      string
	GitBaseURL       string
	GitToken         string
	GitProjectID     string
	GitTargetBranch  string
	GitTerraformPath string
	Concurrency      int
	Logger           *slog.Logger
	// ClosureSync refreshes the account inventory after an auto-close.
	// nil disables the link (tests, deployments without a sync service).
	ClosureSync TicketClosureSyncTrigger
	// Reservations moves file-level publish reservations to MERGED when a
	// ticket PR is merged (phase4 §4.2). nil disables the link.
	Reservations *PublishReservationService
	// CIApplyCallback enables CI-gated ticket closing (A12⑤): merged ticket
	// PRs auto-close only after CI reports finops/terraform-apply success.
	// Default false keeps the legacy merge-alone semantics.
	CIApplyCallback bool
}

// GitStatusWorker manages the embedded git status polling worker.
type GitStatusWorker struct {
	server          *asynq.Server
	heartbeatCancel context.CancelFunc
	logger          *slog.Logger
}

// RunGitStatusWorker starts the git status polling worker as a background goroutine.
// It returns a stop function that gracefully shuts down the worker.
// The worker will:
//   - Create the Git host client, SQL repository, and Asynq client/server
//   - Re-arm any active polls at startup (SweepActivePolls)
//   - Serve the "gitstatus" queue with the poll task handler
//   - Write a heartbeat to Redis every 15 seconds
//
// Call the returned stop function on application shutdown.
func RunGitStatusWorker(ctx context.Context, cfg GitStatusWorkerConfig) (*GitStatusWorker, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("database connection must not be nil")
	}
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("redis address must not be empty")
	}
	if cfg.GitToken == "" {
		return nil, fmt.Errorf("git token must not be empty")
	}
	if cfg.GitProjectID == "" {
		return nil, fmt.Errorf("git project ID must not be empty")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Create Git host client
	gitHost, err := githost.NewGitHost(githost.GitHostConfig{
		Provider:      cfg.GitProvider,
		BaseURL:       cfg.GitBaseURL,
		Token:         cfg.GitToken,
		ProjectID:     cfg.GitProjectID,
		TargetBranch:  cfg.GitTargetBranch,
		TerraformPath: cfg.GitTerraformPath,
	})
	if err != nil {
		return nil, fmt.Errorf("create git host: %w", err)
	}

	// Create Git status repository
	gitRepo, err := NewSQLGitStatusRepository(cfg.DB)
	if err != nil {
		return nil, fmt.Errorf("create git status repository: %w", err)
	}

	// Create Asynq client
	redisOpt := asynq.RedisClientOpt{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}
	asynqClient := asynq.NewClient(redisOpt)

	// Create Git status poller
	poller, err := NewGitStatusPoller(gitHost, gitRepo, asynqClient, cfg.Logger,
		WithGitStatusClosureSync(cfg.ClosureSync),
		WithGitStatusReservations(cfg.Reservations),
		WithCIApplyCallback(cfg.CIApplyCallback))
	if err != nil {
		asynqClient.Close()
		return nil, fmt.Errorf("create git status poller: %w", err)
	}

	// Create Asynq server
	server := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: cfg.Concurrency,
		Queues:      map[string]int{GitStatusQueueName: 1},
	})

	// Register task handlers
	mux := asynq.NewServeMux()
	mux.HandleFunc(GitStatusPollTaskType, poller.HandleGitStatusPollTask)

	// Re-arm polling for tickets whose remote requests are still open
	go func() {
		sweepCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := poller.SweepActivePolls(sweepCtx); err != nil {
			cfg.Logger.Error("failed to sweep active polls at startup", "error", err)
		}
	}()

	// Create Redis client for heartbeat
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Start heartbeat goroutine
	heartbeatCtx, heartbeatCancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				heartbeatKey := "worker:heartbeat:gitstatus"
				if err := redisClient.Set(heartbeatCtx, heartbeatKey, time.Now().Format(time.RFC3339), 30*time.Second).Err(); err != nil {
					cfg.Logger.Warn("failed to write heartbeat", "error", err)
				}
			}
		}
	}()

	// Start server in background
	go func() {
		if err := server.Start(mux); err != nil {
			cfg.Logger.Error("gitstatus worker server failed", "error", err)
		}
	}()

	cfg.Logger.Info("gitstatus worker started",
		"provider", cfg.GitProvider,
		"project", cfg.GitProjectID,
		"concurrency", cfg.Concurrency,
	)

	return &GitStatusWorker{
		server:          server,
		heartbeatCancel: heartbeatCancel,
		logger:          cfg.Logger,
	}, nil
}

// Stop gracefully shuts down the git status worker.
func (w *GitStatusWorker) Stop() {
	if w == nil {
		return
	}
	w.logger.Info("shutting down gitstatus worker...")
	w.heartbeatCancel()
	w.server.Shutdown()
	w.logger.Info("gitstatus worker stopped")
}
