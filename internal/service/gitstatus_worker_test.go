package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/hibiken/asynq"
)

// mockGitHost implements githost.GitHost for testing.
type mockGitHost struct {
	mrStatus        *githost.MergeRequestStatus
	mrStatusErr     error
	commitStatuses  []githost.PipelineStatus
	commitStatusErr error
	mergeCalls      int
	mergeErr        error
}

func (m *mockGitHost) FetchMergeRequest(_ context.Context, _, _ string) (*githost.MergeRequestStatus, error) {
	return m.mrStatus, m.mrStatusErr
}

func (m *mockGitHost) FetchPipelineStatus(_ context.Context, _, _ string) (*githost.PipelineStatus, error) {
	return nil, nil
}

func (m *mockGitHost) FetchCommitStatuses(_ context.Context, _, _ string) ([]githost.PipelineStatus, error) {
	return m.commitStatuses, m.commitStatusErr
}

func (m *mockGitHost) MergeMergeRequest(_ context.Context, _, _ string) error {
	m.mergeCalls++
	return m.mergeErr
}

// mockGitStatusRepository implements GitStatusRepository for testing.
type mockGitStatusRepository struct {
	ticket           model.IAMTicket
	ticketErr        error
	savedRecords     []model.IACExecutionRecord
	saveErr          error
	updatedStatus    GitTicketStatus
	updateErr        error
	closedTicket     model.IAMTicket
	closeErr         error
	markFailedErr    error
	markFailedCalled bool
	restoreCalled    bool
	restoreErr       error
	pollableTickets  []PollableTicket
	pollableErr      error
}

func (m *mockGitStatusRepository) SaveExecutionRecord(_ context.Context, _ string, record model.IACExecutionRecord) error {
	m.savedRecords = append(m.savedRecords, record)
	return m.saveErr
}

func (m *mockGitStatusRepository) UpdateTicketGitStatus(_ context.Context, _ string, status GitTicketStatus) error {
	m.updatedStatus = status
	return m.updateErr
}

func (m *mockGitStatusRepository) GetTicket(_ context.Context, _ string) (model.IAMTicket, error) {
	return m.ticket, m.ticketErr
}

func (m *mockGitStatusRepository) CloseTicket(_ context.Context, ticketNo, actorID, reason string) (model.IAMTicket, error) {
	m.closedTicket = m.ticket
	m.closedTicket.Status = stringPointer(TicketStatusClosed)
	closedBy := actorID
	m.closedTicket.ClosedBy = &closedBy
	now := time.Now()
	m.closedTicket.ClosedAt = &now
	m.closedTicket.ClosureReason = stringPointer(reason)
	return m.closedTicket, m.closeErr
}

func (m *mockGitStatusRepository) MarkTicketPublishFailed(_ context.Context, _ string, _ string) error {
	m.markFailedCalled = true
	return m.markFailedErr
}

func (m *mockGitStatusRepository) RestoreTicketStatus(_ context.Context, _ string) error {
	m.restoreCalled = true
	return m.restoreErr
}

func (m *mockGitStatusRepository) ListPollableTickets(_ context.Context) ([]PollableTicket, error) {
	return m.pollableTickets, m.pollableErr
}

func TestNextPollDelay(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 10 * time.Minute},   // linear +5m per step
		{2, 15 * time.Minute},   //
		{62, 315 * time.Minute}, // largest scheduled gap
	}

	for _, tc := range cases {
		if got := nextPollDelay(tc.attempt); got != tc.want {
			t.Errorf("nextPollDelay(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}

	// The full schedule must span exactly 7 days: the first attempt runs
	// InitialPollInterval after publication and attempt n lands at
	// InitialPollInterval + Σ nextPollDelay(k), k<n.
	total := InitialPollInterval
	for attempt := 1; attempt < MaxPollAttempts; attempt++ {
		total += nextPollDelay(attempt)
	}
	if want := 7 * 24 * time.Hour; total != want {
		t.Errorf("schedule spans %v, want exactly %v", total, want)
	}
}

func TestShouldScheduleNextPoll(t *testing.T) {
	tests := []struct {
		name       string
		mergeState githost.MergeState
		attempt    int
		want       bool
	}{
		{"open request", githost.MergeStateOpen, 1, true},
		{"merged request", githost.MergeStateMerged, 1, false},
		{"closed request", githost.MergeStateClosed, 1, false},
		{"attempt limit reached", githost.MergeStateOpen, MaxPollAttempts, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldScheduleNextPoll(test.mergeState, test.attempt); got != test.want {
				t.Errorf("shouldScheduleNextPoll(%q, %d) = %t, want %t",
					test.mergeState, test.attempt, got, test.want)
			}
		})
	}
}

func TestRolePolicyBatchAutoMergeRequiresExplicitSuccessfulCI(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		statuses      []githost.PipelineStatus
		wantMergeCall int
		wantCIState   string
	}{
		{name: "no checks", wantCIState: string(githost.CIStateUnknown)},
		{
			name: "all checks passed",
			statuses: []githost.PipelineStatus{
				{State: githost.CIStateSucceeded},
				{State: githost.CIStateSucceeded},
			},
			wantMergeCall: 1,
			wantCIState:   string(githost.CIStateSucceeded),
		},
		{
			name: "one check failed",
			statuses: []githost.PipelineStatus{
				{State: githost.CIStateSucceeded},
				{State: githost.CIStateFailed},
			},
			wantCIState: string(githost.CIStateFailed),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ticketType := TicketTypeAdoptRoleInlinePolicies
			repo := &mockGitStatusRepository{
				ticket: model.IAMTicket{
					TicketNo:   stringPointer("IAM-BATCH-001"),
					TicketType: &ticketType,
					Status:     stringPointer(TicketStatusApproved),
				},
			}
			gitHost := &mockGitHost{
				mrStatus: &githost.MergeRequestStatus{
					Number: "123", State: githost.MergeStateOpen, HeadSHA: "head-sha",
				},
				commitStatuses: testCase.statuses,
			}
			poller := newTestGitStatusPoller(gitHost, repo)
			payload, _ := json.Marshal(GitStatusPollTask{
				TicketNo: "IAM-BATCH-001", Provider: "github", Project: "owner/repo",
				RemoteRequestNumber: "123", CommitSHA: "outdated-sha", Attempt: 1,
			})
			if err := poller.HandleGitStatusPollTask(context.Background(), asynq.NewTask(GitStatusPollTaskType, payload)); err != nil {
				t.Fatalf("HandleGitStatusPollTask() error = %v", err)
			}
			if gitHost.mergeCalls != testCase.wantMergeCall {
				t.Errorf("merge API calls = %d, want %d", gitHost.mergeCalls, testCase.wantMergeCall)
			}
			if repo.updatedStatus.CIState != testCase.wantCIState {
				t.Errorf("recorded CI state = %q, want %q", repo.updatedStatus.CIState, testCase.wantCIState)
			}
		})
	}
}

func newTestGitStatusPoller(gitHost githost.GitHost, repo GitStatusRepository) *GitStatusPoller {
	// Use a nil asynq client in tests so ScheduleNextPoll never enqueues
	// real tasks into a local Redis instance (test isolation).
	poller, _ := NewGitStatusPoller(gitHost, repo, nil, slog.Default())
	return poller
}

func TestGitStatusPoller_SkipsClosedTicket(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-CLOSED-001"),
			Status:   stringPointer(TicketStatusClosed),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			State:  githost.MergeStateOpen,
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-CLOSED-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	// Should not have saved any records or updated status
	if len(repo.savedRecords) != 0 {
		t.Errorf("saved %d records for closed ticket, want 0", len(repo.savedRecords))
	}
}

func TestGitStatusPoller_SkipsRejectedTicket(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-REJECTED-001"),
			Status:   stringPointer(TicketStatusRejected),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			State:  githost.MergeStateOpen,
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-REJECTED-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if len(repo.savedRecords) != 0 {
		t.Errorf("saved %d records for rejected ticket, want 0", len(repo.savedRecords))
	}
}

func TestGitStatusPoller_RecordsErrorAndMarksFailed(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-ERROR-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatusErr: errors.New("GitLab API unavailable"),
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-ERROR-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err == nil {
		t.Fatal("HandleGitStatusPollTask() should return error")
	}

	// Should have saved error record
	if len(repo.savedRecords) != 1 {
		t.Fatalf("saved %d records, want 1", len(repo.savedRecords))
	}
	record := repo.savedRecords[0]
	if record.ApplyResult != "FAILED" {
		t.Errorf("ApplyResult = %s, want FAILED", record.ApplyResult)
	}
	if record.SanitizedError == nil || *record.SanitizedError == "" {
		t.Error("SanitizedError should be populated")
	}

	// Should have marked ticket as PUBLISH_FAILED
	if !repo.markFailedCalled {
		t.Error("MarkTicketPublishFailed was not called")
	}
}

func TestGitStatusPoller_TransientEOFLeavesTicketForRetry(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-EOF-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		// Shape of the GitHub error seen when the connection drops mid-poll.
		mrStatusErr: errors.New(`fetch merge request status: fetch GitHub pull request: execute request: Get "https://api.github.com/repos/acme/tfr/pulls/33": EOF`),
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-EOF-001",
		Provider:            "github",
		Project:             "acme/tfr",
		RemoteRequestNumber: "33",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err == nil {
		t.Fatal("HandleGitStatusPollTask() should return error so Asynq retries")
	}

	if len(repo.savedRecords) != 1 {
		t.Fatalf("saved %d records, want 1", len(repo.savedRecords))
	}
	if repo.markFailedCalled {
		t.Error("a dropped connection must not mark the ticket PUBLISH_FAILED")
	}
}

func TestGitStatusPoller_AutoClosesMergedTicketFromPublishFailed(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-RECOVER-001"),
			Status:   stringPointer(TicketStatusPublishFailed),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "33",
			URL:    "https://github.com/acme/tfr/pull/33",
			State:  githost.MergeStateMerged,
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-RECOVER-001",
		Provider:            "github",
		Project:             "acme/tfr",
		RemoteRequestNumber: "33",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if repo.closedTicket.Status == nil || *repo.closedTicket.Status != TicketStatusClosed {
		t.Errorf("ticket status = %v, want CLOSED (merge is terminal even after a poll error)", repo.closedTicket.Status)
	}
	if repo.updatedStatus.ApplyResult != string(githost.ApplyResultSucceeded) {
		t.Errorf("apply result = %q, want %q", repo.updatedStatus.ApplyResult, githost.ApplyResultSucceeded)
	}
}

func TestGitStatusPoller_RestoresApprovedAfterSuccessfulOpenPoll(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-RESTORE-001"),
			Status:   stringPointer(TicketStatusPublishFailed),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "33",
			URL:    "https://github.com/acme/tfr/pull/33",
			State:  githost.MergeStateOpen,
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-RESTORE-001",
		Provider:            "github",
		Project:             "acme/tfr",
		RemoteRequestNumber: "33",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if !repo.restoreCalled {
		t.Error("a successful poll must clear a stale PUBLISH_FAILED status")
	}
	if repo.markFailedCalled {
		t.Error("a successful poll must not mark the ticket PUBLISH_FAILED")
	}
}

func TestGitStatusPoller_AutoClosesOnMergeWithoutCI(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-AUTOCLOSE-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			URL:    "https://gitlab.example/mr/123",
			State:  githost.MergeStateMerged,
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-AUTOCLOSE-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		CommitSHA:           "abc123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	// Should have auto-closed the ticket
	if repo.closedTicket.Status == nil || *repo.closedTicket.Status != TicketStatusClosed {
		t.Errorf("ticket status = %v, want CLOSED", repo.closedTicket.Status)
	}
	if repo.closedTicket.ClosureReason == nil || *repo.closedTicket.ClosureReason != ClosureReasonApplied {
		t.Errorf("closure reason = %v, want %s", repo.closedTicket.ClosureReason, ClosureReasonApplied)
	}
	if repo.updatedStatus.ApplyResult != string(githost.ApplyResultSucceeded) {
		t.Errorf("apply result = %q, want %q", repo.updatedStatus.ApplyResult, githost.ApplyResultSucceeded)
	}
	if repo.updatedStatus.NextPollAt != nil {
		t.Errorf("next poll = %v, want nil after merge", repo.updatedStatus.NextPollAt)
	}
}

func TestGitStatusPoller_AutoClosesOnMergeRegardlessOfCIState(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-NOCLOSE-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			URL:    "https://gitlab.example/mr/123",
			State:  githost.MergeStateMerged,
		},
		commitStatuses: []githost.PipelineStatus{
			{
				ID:    "pipeline-1",
				State: githost.CIStateFailed,
			},
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-NOCLOSE-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		CommitSHA:           "abc123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if repo.closedTicket.Status == nil || *repo.closedTicket.Status != TicketStatusClosed {
		t.Errorf("ticket status = %v, want CLOSED", repo.closedTicket.Status)
	}
}

func TestGitStatusPoller_ValidatesPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload GitStatusPollTask
		wantErr string
	}{
		{
			name:    "missing ticket number",
			payload: GitStatusPollTask{Provider: "gitlab", Project: "test", RemoteRequestNumber: "123"},
			wantErr: "missing ticket number",
		},
		{
			name:    "missing provider",
			payload: GitStatusPollTask{TicketNo: "IAM-001", Project: "test", RemoteRequestNumber: "123"},
			wantErr: "missing provider",
		},
		{
			name:    "missing project",
			payload: GitStatusPollTask{TicketNo: "IAM-001", Provider: "gitlab", RemoteRequestNumber: "123"},
			wantErr: "missing project",
		},
		{
			name:    "missing remote request number",
			payload: GitStatusPollTask{TicketNo: "IAM-001", Provider: "gitlab", Project: "test"},
			wantErr: "missing remote request number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			poller := newTestGitStatusPoller(&mockGitHost{}, &mockGitStatusRepository{})
			payloadJSON, _ := json.Marshal(tt.payload)
			task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

			err := poller.HandleGitStatusPollTask(context.Background(), task)
			if err == nil || !contains(err.Error(), tt.wantErr) {
				t.Errorf("HandleGitStatusPollTask() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestGitStatusPoller_RecordsSuccessfulPoll(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-SUCCESS-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			URL:    "https://gitlab.example/mr/123",
			State:  githost.MergeStateOpen,
		},
		commitStatuses: []githost.PipelineStatus{
			{
				ID:    "pipeline-1",
				State: githost.CIStateRunning,
			},
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-SUCCESS-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		CommitSHA:           "abc123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	// Should have saved execution record
	if len(repo.savedRecords) != 1 {
		t.Fatalf("saved %d records, want 1", len(repo.savedRecords))
	}
	record := repo.savedRecords[0]
	if record.MergeState != string(githost.MergeStateOpen) {
		t.Errorf("MergeState = %s, want %s", record.MergeState, githost.MergeStateOpen)
	}
	if record.CIState != string(githost.CIStateRunning) {
		t.Errorf("CIState = %s, want %s", record.CIState, githost.CIStateRunning)
	}
	if record.ApplyResult != string(githost.ApplyResultPending) {
		t.Errorf("ApplyResult = %s, want %s", record.ApplyResult, githost.ApplyResultPending)
	}

	// Should have updated ticket status
	if repo.updatedStatus.MergeState != string(githost.MergeStateOpen) {
		t.Errorf("updated MergeState = %s, want %s", repo.updatedStatus.MergeState, githost.MergeStateOpen)
	}
	if repo.updatedStatus.PollAttemptCount != 1 {
		t.Errorf("PollAttemptCount = %d, want 1", repo.updatedStatus.PollAttemptCount)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
	}{
		{"short error", "short error", 1000},
		{"long error", string(make([]byte, 2000)), 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeErrorMessage(tt.input)
			if len(got) > tt.maxLen {
				t.Errorf("sanitizeErrorMessage() returned %d chars, want <= %d", len(got), tt.maxLen)
			}
		})
	}
}

func TestScheduleNextPoll(t *testing.T) {
	repo := &mockGitStatusRepository{}
	gitHost := &mockGitHost{}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             1,
	}

	// Poller has a nil asynq client in tests, so scheduling must fail fast
	// without touching a real Redis instance.
	err := poller.ScheduleNextPoll(context.Background(), payload)
	if err == nil {
		t.Fatal("ScheduleNextPoll with nil client should return an error")
	}
	t.Logf("ScheduleNextPoll rejected nil client as expected: %v", err)
}

func TestNewGitStatusPoller_Validation(t *testing.T) {
	tests := []struct {
		name       string
		gitHost    githost.GitHost
		repository GitStatusRepository
		client     *asynq.Client
		wantErr    bool
	}{
		{"nil git host", nil, &mockGitStatusRepository{}, nil, true},
		{"nil repository", &mockGitHost{}, nil, nil, true},
		{"nil client", &mockGitHost{}, &mockGitStatusRepository{}, nil, false},
		{"valid", &mockGitHost{}, &mockGitStatusRepository{}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGitStatusPoller(tt.gitHost, tt.repository, tt.client, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGitStatusPoller() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandlePollError(t *testing.T) {
	repo := &mockGitStatusRepository{}
	gitHost := &mockGitHost{}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-ERROR-002",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             1,
	}

	poller.handlePollError(context.Background(), payload, "test error message")

	// Should have saved error record
	if len(repo.savedRecords) != 1 {
		t.Fatalf("saved %d records, want 1", len(repo.savedRecords))
	}
	record := repo.savedRecords[0]
	if record.ApplyResult != "FAILED" {
		t.Errorf("ApplyResult = %s, want FAILED", record.ApplyResult)
	}
	if record.SanitizedError == nil || *record.SanitizedError != "test error message" {
		t.Errorf("SanitizedError = %v, want 'test error message'", record.SanitizedError)
	}

	// Should have marked ticket as PUBLISH_FAILED
	if !repo.markFailedCalled {
		t.Error("MarkTicketPublishFailed was not called")
	}
}

func TestAutoCloseTicket_NotApprovedState(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-DRAFT-001"),
			Status:   stringPointer(TicketStatusDraft),
		},
	}
	gitHost := &mockGitHost{}
	poller := newTestGitStatusPoller(gitHost, repo)

	err := poller.autoCloseTicket(context.Background(), "IAM-DRAFT-001")
	if err != nil {
		t.Fatalf("autoCloseTicket() error = %v", err)
	}

	// Should NOT have closed the ticket
	if repo.closedTicket.Status != nil {
		t.Errorf("ticket should not be closed from DRAFT state, got %v", *repo.closedTicket.Status)
	}
}

func TestAutoCloseTicket_AlreadyClosed(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-CLOSED-002"),
			Status:   stringPointer(TicketStatusClosed),
		},
	}
	gitHost := &mockGitHost{}
	poller := newTestGitStatusPoller(gitHost, repo)

	err := poller.autoCloseTicket(context.Background(), "IAM-CLOSED-002")
	if err != nil {
		t.Fatalf("autoCloseTicket() error = %v", err)
	}

	// Should NOT have closed the ticket again
	if repo.closedTicket.Status != nil {
		t.Errorf("ticket should not be re-closed, got %v", *repo.closedTicket.Status)
	}
}

func TestAutoCloseTicket_Success(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-APPROVED-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{}
	poller := newTestGitStatusPoller(gitHost, repo)

	err := poller.autoCloseTicket(context.Background(), "IAM-APPROVED-001")
	if err != nil {
		t.Fatalf("autoCloseTicket() error = %v", err)
	}

	// Should have closed the ticket
	if repo.closedTicket.Status == nil || *repo.closedTicket.Status != TicketStatusClosed {
		t.Errorf("ticket status = %v, want CLOSED", repo.closedTicket.Status)
	}
	if repo.closedTicket.ClosureReason == nil || *repo.closedTicket.ClosureReason != ClosureReasonApplied {
		t.Errorf("closure reason = %v, want %s", repo.closedTicket.ClosureReason, ClosureReasonApplied)
	}
	if repo.closedTicket.ClosedBy == nil || *repo.closedTicket.ClosedBy != "system" {
		t.Errorf("closed by = %v, want 'system'", repo.closedTicket.ClosedBy)
	}
}

// fakeClosureSyncTrigger records the auto-close → inventory-refresh link.
type fakeClosureSyncTrigger struct {
	calls       int
	accountDBID int64
	ticketNo    string
	err         error
}

func (trigger *fakeClosureSyncTrigger) TriggerSyncForClosedTicket(_ context.Context, accountDBID int64, ticketNo string) error {
	trigger.calls++
	trigger.accountDBID = accountDBID
	trigger.ticketNo = ticketNo
	return trigger.err
}

func TestAutoCloseTicketTriggersAccountSync(t *testing.T) {
	accountID := int64(3)
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo:  stringPointer("IAM-APPROVED-002"),
			Status:    stringPointer(TicketStatusApproved),
			AccountID: &accountID,
		},
	}
	trigger := &fakeClosureSyncTrigger{}
	poller, err := NewGitStatusPoller(&mockGitHost{}, repo, nil, slog.Default(),
		WithGitStatusClosureSync(trigger))
	if err != nil {
		t.Fatalf("NewGitStatusPoller() error = %v", err)
	}

	if err := poller.autoCloseTicket(context.Background(), "IAM-APPROVED-002"); err != nil {
		t.Fatalf("autoCloseTicket() error = %v", err)
	}
	if trigger.calls != 1 || trigger.accountDBID != accountID || trigger.ticketNo != "IAM-APPROVED-002" {
		t.Fatalf("closure sync trigger = %+v, want one call for account %d", trigger, accountID)
	}
}

// 同步触发失败（例如 config 缺失、Redis 抖动）绝不能让关单失败或回滚。
func TestAutoCloseTicketSurvivesSyncTriggerFailure(t *testing.T) {
	accountID := int64(3)
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo:  stringPointer("IAM-APPROVED-003"),
			Status:    stringPointer(TicketStatusApproved),
			AccountID: &accountID,
		},
	}
	trigger := &fakeClosureSyncTrigger{err: errors.New("redis unavailable")}
	poller, err := NewGitStatusPoller(&mockGitHost{}, repo, nil, slog.Default(),
		WithGitStatusClosureSync(trigger))
	if err != nil {
		t.Fatalf("NewGitStatusPoller() error = %v", err)
	}

	if err := poller.autoCloseTicket(context.Background(), "IAM-APPROVED-003"); err != nil {
		t.Fatalf("autoCloseTicket() must not fail on sync trigger errors, got %v", err)
	}
	if repo.closedTicket.Status == nil || *repo.closedTicket.Status != TicketStatusClosed {
		t.Fatalf("ticket must stay closed, got %v", repo.closedTicket.Status)
	}
	if trigger.calls != 1 {
		t.Fatalf("closure sync trigger calls = %d, want 1", trigger.calls)
	}
}

func TestGitStatusPoller_MissingMergeRequest(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-MISSING-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: nil, // MR not found
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-MISSING-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "999",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err == nil {
		t.Fatal("HandleGitStatusPollTask() should return error for missing MR")
	}

	// Should have recorded error and marked as failed
	if !repo.markFailedCalled {
		t.Error("MarkTicketPublishFailed was not called for missing MR")
	}
}

func TestGitStatusPoller_CommitStatusError(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-CI-ERROR-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			URL:    "https://gitlab.example/mr/123",
			State:  githost.MergeStateOpen,
		},
		commitStatusErr: errors.New("CI API unavailable"),
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-CI-ERROR-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		CommitSHA:           "abc123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	// Should not fail, just log warning and continue with CIStateUnknown
	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	// Should have saved record with CIStateUnknown
	if len(repo.savedRecords) != 1 {
		t.Fatalf("saved %d records, want 1", len(repo.savedRecords))
	}
	record := repo.savedRecords[0]
	if record.CIState != string(githost.CIStateUnknown) {
		t.Errorf("CIState = %s, want %s", record.CIState, githost.CIStateUnknown)
	}
}

func TestGitStatusPoller_MaxAttemptsReached(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-MAX-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			URL:    "https://gitlab.example/mr/123",
			State:  githost.MergeStateOpen,
		},
	}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-MAX-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             MaxPollAttempts, // Max attempts reached
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	// Should have saved record but not scheduled next poll
	if len(repo.savedRecords) != 1 {
		t.Fatalf("saved %d records, want 1", len(repo.savedRecords))
	}
}

func TestGitStatusPoller_TicketNotFound(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticketErr: fmt.Errorf("ticket not found"),
	}
	gitHost := &mockGitHost{}
	poller := newTestGitStatusPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-NOTFOUND-001",
		Provider:            "gitlab",
		Project:             "test-project",
		RemoteRequestNumber: "123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	err := poller.HandleGitStatusPollTask(context.Background(), task)
	if err == nil {
		t.Fatal("HandleGitStatusPollTask() should return error for missing ticket")
	}
}

// newCIGatedTestPoller 构造开启 CI 门禁关单（A12⑤）的 poller。
func newCIGatedTestPoller(gitHost githost.GitHost, repo GitStatusRepository) *GitStatusPoller {
	poller, _ := NewGitStatusPoller(gitHost, repo, nil, slog.Default(), WithCIApplyCallback(true))
	return poller
}

// CI 门禁开启：PR 已合并但 CI status 尚未出现时不得关单，改为短间隔继续轮询。
func TestGitStatusPoller_CIGatedWaitsForCIStatusBeforeClosing(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-CIGATE-001"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "123",
			URL:    "https://github.com/acme/tfr/pull/123",
			State:  githost.MergeStateMerged,
		},
	}
	poller := newCIGatedTestPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-CIGATE-001",
		Provider:            "github",
		Project:             "acme/tfr",
		RemoteRequestNumber: "123",
		CommitSHA:           "abc123",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if repo.closedTicket.Status != nil {
		t.Errorf("ticket closed before CI reported a status: %v", repo.closedTicket.Status)
	}
	if repo.updatedStatus.ApplyResult != string(githost.ApplyResultPending) {
		t.Errorf("apply result = %q, want %q (missing CI status must not count as success)",
			repo.updatedStatus.ApplyResult, githost.ApplyResultPending)
	}
	if repo.updatedStatus.CIState != string(githost.CIStateUnknown) {
		t.Errorf("ci state = %q, want %q", repo.updatedStatus.CIState, githost.CIStateUnknown)
	}
	if repo.updatedStatus.NextPollAt == nil {
		t.Error("poll must be re-armed while waiting for the CI apply result")
	}
}

// CI 门禁开启：CI 绿（finops/terraform-apply success）才关单。
func TestGitStatusPoller_CIGatedClosesOnCISuccess(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-CIGATE-002"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "124",
			URL:    "https://github.com/acme/tfr/pull/124",
			State:  githost.MergeStateMerged,
		},
		commitStatuses: []githost.PipelineStatus{
			{Name: "finops/terraform-apply", State: githost.CIStateSucceeded},
		},
	}
	poller := newCIGatedTestPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-CIGATE-002",
		Provider:            "github",
		Project:             "acme/tfr",
		RemoteRequestNumber: "124",
		CommitSHA:           "abc124",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if repo.closedTicket.Status == nil || *repo.closedTicket.Status != TicketStatusClosed {
		t.Errorf("ticket status = %v, want CLOSED after CI success", repo.closedTicket.Status)
	}
	if repo.closedTicket.ClosureReason == nil || *repo.closedTicket.ClosureReason != ClosureReasonApplied {
		t.Errorf("closure reason = %v, want %s", repo.closedTicket.ClosureReason, ClosureReasonApplied)
	}
	if repo.updatedStatus.ApplyResult != string(githost.ApplyResultSucceeded) {
		t.Errorf("apply result = %q, want %q", repo.updatedStatus.ApplyResult, githost.ApplyResultSucceeded)
	}
}

// CI 门禁开启：CI 红不关单、停止轮询，工单挂起留人工处理。
func TestGitStatusPoller_CIGatedLeavesFailedCIForManualHandling(t *testing.T) {
	repo := &mockGitStatusRepository{
		ticket: model.IAMTicket{
			TicketNo: stringPointer("IAM-CIGATE-003"),
			Status:   stringPointer(TicketStatusApproved),
		},
	}
	gitHost := &mockGitHost{
		mrStatus: &githost.MergeRequestStatus{
			Number: "125",
			URL:    "https://github.com/acme/tfr/pull/125",
			State:  githost.MergeStateMerged,
		},
		commitStatuses: []githost.PipelineStatus{
			{Name: "finops/terraform-apply", State: githost.CIStateFailed},
		},
	}
	poller := newCIGatedTestPoller(gitHost, repo)

	payload := GitStatusPollTask{
		TicketNo:            "IAM-CIGATE-003",
		Provider:            "github",
		Project:             "acme/tfr",
		RemoteRequestNumber: "125",
		CommitSHA:           "abc125",
		Attempt:             1,
	}
	payloadJSON, _ := json.Marshal(payload)
	task := asynq.NewTask(GitStatusPollTaskType, payloadJSON)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err != nil {
		t.Fatalf("HandleGitStatusPollTask() error = %v", err)
	}

	if repo.closedTicket.Status != nil {
		t.Errorf("ticket closed although CI apply failed: %v", repo.closedTicket.Status)
	}
	if repo.updatedStatus.ApplyResult != string(githost.ApplyResultFailed) {
		t.Errorf("apply result = %q, want %q", repo.updatedStatus.ApplyResult, githost.ApplyResultFailed)
	}
	if repo.updatedStatus.NextPollAt != nil {
		t.Error("poll must stop once CI is failed: the ticket is left for manual handling")
	}
}
