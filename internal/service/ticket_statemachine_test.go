package service

import (
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
)

func TestTicketStateMachine_CanTransition(t *testing.T) {
	sm := NewTicketStateMachine()

	tests := []struct {
		from   string
		to     string
		expect bool
	}{
		// Valid transitions
		{TicketStatusDraft, TicketStatusApproving, true},
		{TicketStatusDraft, TicketStatusClosed, true},
		{TicketStatusApproving, TicketStatusApproved, true},
		{TicketStatusApproving, TicketStatusRejected, true},
		{TicketStatusApproving, TicketStatusClosed, true},
		{TicketStatusApproved, TicketStatusPublishing, true},
		{TicketStatusApproved, TicketStatusPublishFailed, true},
		{TicketStatusApproved, TicketStatusClosed, true},
		{TicketStatusPublishing, TicketStatusApproved, true},
		{TicketStatusPublishing, TicketStatusPublishFailed, true},
		{TicketStatusPublishing, TicketStatusClosed, true},
		{TicketStatusPublishFailed, TicketStatusPublishing, true},
		{TicketStatusPublishFailed, TicketStatusApproved, true},
		{TicketStatusPublishFailed, TicketStatusClosed, true},
		{TicketStatusRejected, TicketStatusClosed, true},
		{TicketStatusMerged, TicketStatusClosed, true},

		// Invalid transitions
		{TicketStatusDraft, TicketStatusApproved, false},
		{TicketStatusDraft, TicketStatusPublishing, false},
		{TicketStatusApproving, TicketStatusPublishing, false},
		{TicketStatusApproved, TicketStatusApproving, false},
		{TicketStatusPublishing, TicketStatusApproving, false},
		{TicketStatusPublishFailed, TicketStatusApproving, false},
		{TicketStatusRejected, TicketStatusApproved, false},
		{TicketStatusMerged, TicketStatusApproved, false},
		{TicketStatusClosed, TicketStatusApproved, false},
		{TicketStatusClosed, TicketStatusPublishing, false},
		{TicketStatusClosed, TicketStatusApproving, false},
		{TicketStatusClosed, TicketStatusDraft, false},
		{TicketStatusClosed, TicketStatusRejected, false},
		{TicketStatusClosed, TicketStatusMerged, false},
		{TicketStatusClosed, TicketStatusClosed, false},
	}

	for _, tt := range tests {
		t.Run(tt.from+"_to_"+tt.to, func(t *testing.T) {
			got := sm.CanTransition(tt.from, tt.to)
			if got != tt.expect {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", tt.from, tt.to, got, tt.expect)
			}
		})
	}
}

func TestTicketStateMachine_ValidateTransition(t *testing.T) {
	sm := NewTicketStateMachine()

	// Valid transition should not return error
	if err := sm.ValidateTransition(TicketStatusDraft, TicketStatusApproving); err != nil {
		t.Errorf("ValidateTransition(DRAFT, APPROVING) returned error: %v", err)
	}

	// Invalid transition should return error
	if err := sm.ValidateTransition(TicketStatusClosed, TicketStatusApproved); err == nil {
		t.Error("ValidateTransition(CLOSED, APPROVED) should return error")
	}
}

func TestTicketStateMachine_GetValidTransitions(t *testing.T) {
	sm := NewTicketStateMachine()

	tests := []struct {
		from   string
		expect int
	}{
		{TicketStatusDraft, 2},
		{TicketStatusApproving, 3},
		{TicketStatusApproved, 3},
		{TicketStatusPublishing, 3},
		{TicketStatusPublishFailed, 3},
		{TicketStatusRejected, 1},
		{TicketStatusMerged, 1},
		{TicketStatusClosed, 0},
	}

	for _, tt := range tests {
		t.Run(tt.from, func(t *testing.T) {
			got := sm.GetValidTransitions(tt.from)
			if len(got) != tt.expect {
				t.Errorf("GetValidTransitions(%s) returned %d transitions, want %d", tt.from, len(got), tt.expect)
			}
		})
	}
}

func TestTicketStateMachine_IsTerminalState(t *testing.T) {
	sm := NewTicketStateMachine()

	tests := []struct {
		status string
		expect bool
	}{
		{TicketStatusClosed, true},
		{TicketStatusRejected, true},
		{TicketStatusMerged, true},
		{TicketStatusDraft, false},
		{TicketStatusApproving, false},
		{TicketStatusApproved, false},
		{TicketStatusPublishing, false},
		{TicketStatusPublishFailed, false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := sm.IsTerminalState(tt.status)
			if got != tt.expect {
				t.Errorf("IsTerminalState(%s) = %v, want %v", tt.status, got, tt.expect)
			}
		})
	}
}

func TestIsPollableStatus(t *testing.T) {
	tests := []struct {
		status string
		expect bool
	}{
		{TicketStatusApproved, true},
		{TicketStatusPublishing, true},
		{TicketStatusPublishFailed, true},
		{TicketStatusDraft, false},
		{TicketStatusApproving, false},
		{TicketStatusRejected, false},
		{TicketStatusMerged, false},
		{TicketStatusClosed, false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := isPollableStatus(tt.status)
			if got != tt.expect {
				t.Errorf("isPollableStatus(%s) = %v, want %v", tt.status, got, tt.expect)
			}
		})
	}
}

func TestDetermineApplyResult(t *testing.T) {
	tests := []struct {
		mergeState githost.MergeState
		ciState    githost.CIState
		expect     githost.ApplyResult
	}{
		{githost.MergeStateMerged, githost.CIStateSucceeded, githost.ApplyResultSucceeded},
		{githost.MergeStateMerged, githost.CIStateFailed, githost.ApplyResultFailed},
		{githost.MergeStateMerged, githost.CIStateCanceled, githost.ApplyResultCanceled},
		{githost.MergeStateMerged, githost.CIStatePending, githost.ApplyResultPending},
		{githost.MergeStateMerged, githost.CIStateRunning, githost.ApplyResultPending},
		{githost.MergeStateMerged, githost.CIStateUnknown, githost.ApplyResultPending},
		{githost.MergeStateOpen, githost.CIStateSucceeded, githost.ApplyResultPending},
		{githost.MergeStateOpen, githost.CIStateFailed, githost.ApplyResultPending},
		{githost.MergeStateClosed, githost.CIStateSucceeded, githost.ApplyResultPending},
		{githost.MergeStateUnknown, githost.CIStateSucceeded, githost.ApplyResultPending},
	}

	for _, tt := range tests {
		t.Run(string(tt.mergeState)+"_"+string(tt.ciState), func(t *testing.T) {
			got := determineApplyResult(tt.mergeState, tt.ciState)
			if got != tt.expect {
				t.Errorf("determineApplyResult(%s, %s) = %s, want %s", tt.mergeState, tt.ciState, got, tt.expect)
			}
		})
	}
}

func TestIsTerminalMergeState(t *testing.T) {
	tests := []struct {
		state  githost.MergeState
		expect bool
	}{
		{githost.MergeStateMerged, true},
		{githost.MergeStateClosed, true},
		{githost.MergeStateOpen, false},
		{githost.MergeStateUnknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			got := isTerminalMergeState(tt.state)
			if got != tt.expect {
				t.Errorf("isTerminalMergeState(%s) = %v, want %v", tt.state, got, tt.expect)
			}
		})
	}
}
