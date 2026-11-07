package service

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestBuildAuditEventConditionsRejectsUnknownOutcome(t *testing.T) {
	filter := AuditEventFilter{Outcome: "MAYBE"}
	_, err := buildAuditEventConditions(filter, func(any) string { return "$1" })
	if !errors.Is(err, ErrInvalidAuditOutcome) {
		t.Fatalf("error = %v, want ErrInvalidAuditOutcome", err)
	}
}

func TestBuildAuditEventConditionsIncludesAllFilters(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	filter := AuditEventFilter{
		ActorID: "example-org", Action: "TICKET_CREATED", ResourceType: "iam_ticket",
		ResourceID: "IAM-1", Outcome: "SUCCESS", From: &from, To: &to,
	}
	args := make([]any, 0, 7)
	addArg := func(value any) string {
		args = append(args, value)
		return "$" + strconv.Itoa(len(args))
	}
	conditions, err := buildAuditEventConditions(filter, addArg)
	if err != nil {
		t.Fatalf("buildAuditEventConditions() error = %v", err)
	}
	if len(conditions) != 8 { // TRUE + 7 filters
		t.Fatalf("conditions = %v", conditions)
	}
	if len(args) != 7 {
		t.Fatalf("args = %v", args)
	}
}

func TestBuildAuditEventConditionsEmptyFilterIsUnrestricted(t *testing.T) {
	conditions, err := buildAuditEventConditions(AuditEventFilter{}, func(any) string {
		t.Fatal("no arg should be added for an empty filter")
		return ""
	})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(conditions) != 1 || conditions[0] != "TRUE" {
		t.Fatalf("conditions = %v", conditions)
	}
}

func TestFilterSummaryForAudit(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	summary := filterSummaryForAudit(AuditEventFilter{ActorID: "example-org", From: &from})
	if summary["actor_id"] != "example-org" {
		t.Fatalf("summary = %v", summary)
	}
	if summary["from"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("from = %v", summary["from"])
	}
	if _, ok := summary["action"]; ok {
		t.Fatalf("empty action should be omitted: %v", summary)
	}
}
