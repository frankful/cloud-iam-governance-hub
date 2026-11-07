package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hibiken/asynq"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

func TestPMapperTaskMuxRegistersGraphHandler(t *testing.T) {
	runner := &fakePMapperRunner{graphJSON: []byte(`[{
		"principal_arn": "arn:aws:iam::123456789012:role/reports-reader",
		"action": "s3:GetObject",
		"resource": "arn:aws:s3:::reports/*"
	}]`)}
	repository := &fakeIAMRelationshipRepository{}
	graphService := testPMapperService(t, runner, repository, time.Second)

	mux := asynq.NewServeMux()
	if err := RegisterPMapperGraphTaskHandler(mux, graphService); err != nil {
		t.Fatalf("RegisterPMapperGraphTaskHandler() error = %v", err)
	}
	task, err := NewPMapperGraphTask(testPrincipals())
	if err != nil {
		t.Fatalf("NewPMapperGraphTask() error = %v", err)
	}
	handler, pattern := mux.Handler(task)
	if handler == nil || pattern != PMapperGraphTaskType {
		t.Fatalf("registered handler = %v, pattern = %q", handler, pattern)
	}
	if err := mux.ProcessTask(context.Background(), task); err != nil {
		t.Fatalf("ProcessTask() error = %v", err)
	}
	if len(repository.relationships) != 1 ||
		repository.relationships[0].PrincipalID == nil ||
		*repository.relationships[0].PrincipalID != 41 {
		t.Fatalf("relationship was not mapped to persisted principal ID: %#v", repository.relationships)
	}
}

func TestPMapperTaskPreservesPersistedPrincipalIdentity(t *testing.T) {
	principals := testPrincipals()
	principals[0].AccountID = int64Pointer(7)
	task, err := NewPMapperGraphTask(principals)
	if err != nil {
		t.Fatalf("NewPMapperGraphTask() error = %v", err)
	}
	var payload pMapperGraphTaskPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		t.Fatalf("decode task payload: %v", err)
	}
	if len(payload.Principals) != 1 || payload.Principals[0].ID != principals[0].ID ||
		payload.Principals[0].ARN != principals[0].ARN || payload.Principals[0].AccountID == nil ||
		*payload.Principals[0].AccountID != *principals[0].AccountID {
		t.Fatalf("task payload lost persisted principal identity: %#v", payload)
	}
}

func TestNewPMapperTaskRequiresPersistedPrincipalIdentity(t *testing.T) {
	_, err := NewPMapperGraphTask([]model.IAMPrincipal{{ARN: testPrincipals()[0].ARN}})
	if err == nil || !strings.Contains(err.Error(), "positive persisted ID") {
		t.Fatalf("NewPMapperGraphTask() error = %v, want persisted ID validation", err)
	}
}

func TestRegisterPMapperGraphTaskHandlerValidation(t *testing.T) {
	if err := RegisterPMapperGraphTaskHandler(nil, nil); err == nil {
		t.Fatal("RegisterPMapperGraphTaskHandler(nil, nil) expected mux error")
	}
	if err := RegisterPMapperGraphTaskHandler(asynq.NewServeMux(), nil); err == nil {
		t.Fatal("RegisterPMapperGraphTaskHandler() expected service error")
	}
}
