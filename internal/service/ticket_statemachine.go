package service

import "fmt"

// TicketStateMachine defines valid state transitions for IAM tickets.
// All transitions must be explicitly defined; undefined transitions are rejected.
type TicketStateMachine struct {
	transitions map[string]map[string]bool
}

// NewTicketStateMachine creates a new ticket state machine with all valid transitions.
func NewTicketStateMachine() *TicketStateMachine {
	transitions := map[string]map[string]bool{
		// DRAFT can only transition to APPROVING (via submit) or CLOSED (via admin close)
		TicketStatusDraft: {
			TicketStatusApproving: true,
			TicketStatusClosed:    true,
		},
		// APPROVING can transition to APPROVED (all approved), REJECTED (any reject), or CLOSED
		TicketStatusApproving: {
			TicketStatusApproved: true,
			TicketStatusRejected: true,
			TicketStatusClosed:   true,
		},
		// APPROVED can transition to PUBLISHING (claim), PUBLISH_FAILED (publish error), or CLOSED
		TicketStatusApproved: {
			TicketStatusPublishing:    true,
			TicketStatusPublishFailed: true,
			TicketStatusClosed:        true,
		},
		// PUBLISHING can transition to APPROVED (release claim), PUBLISH_FAILED (error), or CLOSED
		TicketStatusPublishing: {
			TicketStatusApproved:      true,
			TicketStatusPublishFailed: true,
			TicketStatusClosed:        true,
		},
		// PUBLISH_FAILED can transition to PUBLISHING (retry), APPROVED (retry success), or CLOSED
		TicketStatusPublishFailed: {
			TicketStatusPublishing: true,
			TicketStatusApproved:   true,
			TicketStatusClosed:     true,
		},
		// REJECTED is terminal - only CLOSED is allowed (admin cleanup)
		TicketStatusRejected: {
			TicketStatusClosed: true,
		},
		// MERGED is terminal - only CLOSED is allowed (admin cleanup)
		TicketStatusMerged: {
			TicketStatusClosed: true,
		},
		// CLOSED is terminal - no transitions allowed
		TicketStatusClosed: {},
	}

	return &TicketStateMachine{transitions: transitions}
}

// CanTransition checks if a state transition is valid.
func (sm *TicketStateMachine) CanTransition(from, to string) bool {
	if fromStates, exists := sm.transitions[from]; exists {
		return fromStates[to]
	}
	return false
}

// ValidateTransition returns an error if the transition is not valid.
func (sm *TicketStateMachine) ValidateTransition(from, to string) error {
	if !sm.CanTransition(from, to) {
		return fmt.Errorf("invalid ticket state transition: %s -> %s", from, to)
	}
	return nil
}

// GetValidTransitions returns all valid target states for a given source state.
func (sm *TicketStateMachine) GetValidTransitions(from string) []string {
	targets := make([]string, 0)
	if fromStates, exists := sm.transitions[from]; exists {
		for to := range fromStates {
			targets = append(targets, to)
		}
	}
	return targets
}

// IsTerminalState returns true if the state is terminal (no outgoing transitions except CLOSED).
func (sm *TicketStateMachine) IsTerminalState(state string) bool {
	if state == TicketStatusClosed {
		return true
	}
	// REJECTED and MERGED are also terminal (only CLOSED allowed)
	if state == TicketStatusRejected || state == TicketStatusMerged {
		return true
	}
	return false
}

// defaultStateMachine is the package-level state machine instance.
var defaultStateMachine = NewTicketStateMachine()

// CanTransition checks if a state transition is valid using the default state machine.
func CanTransition(from, to string) bool {
	return defaultStateMachine.CanTransition(from, to)
}

// ValidateTransition returns an error if the transition is not valid using the default state machine.
func ValidateTransition(from, to string) error {
	return defaultStateMachine.ValidateTransition(from, to)
}
