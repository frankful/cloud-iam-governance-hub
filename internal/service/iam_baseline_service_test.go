package service

import (
	"context"
	"errors"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

type baselineRepositoryFake struct {
	createdAccount int64
	createdPolicy  abstractiam.AbstractPolicy
	createdEnabled bool
	createdActor   string
	enabledID      int64
}

func (repository *baselineRepositoryFake) CreateVersion(
	_ context.Context,
	accountID int64,
	policy abstractiam.AbstractPolicy,
	enabled bool,
	actorID string,
) (model.IAMBaseline, error) {
	repository.createdAccount = accountID
	repository.createdPolicy = policy
	repository.createdEnabled = enabled
	repository.createdActor = actorID
	return model.IAMBaseline{ID: 11, AccountID: accountID, Version: 1, Enabled: enabled}, nil
}

func (repository *baselineRepositoryFake) List(context.Context, int64) ([]model.IAMBaseline, error) {
	return []model.IAMBaseline{{ID: 11}}, nil
}

func (repository *baselineRepositoryFake) SetEnabled(
	_ context.Context,
	accountID, baselineID int64,
	enabled bool,
	actorID string,
) (model.IAMBaseline, error) {
	repository.createdAccount = accountID
	repository.enabledID = baselineID
	repository.createdEnabled = enabled
	repository.createdActor = actorID
	return model.IAMBaseline{ID: baselineID, AccountID: accountID, Enabled: enabled}, nil
}

func TestValidateIAMBaselineRejectsUnsupportedSemantics(t *testing.T) {
	tests := []struct {
		name   string
		policy abstractiam.AbstractPolicy
	}{
		{
			name:   "empty statements",
			policy: abstractiam.AbstractPolicy{},
		},
		{
			name: "deny effect",
			policy: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Deny", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/*"},
			}}},
		},
		{
			name: "negated selector",
			policy: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/*"},
				NotActions: []string{"storage:write"},
			}}},
		},
		{
			name: "unsupported condition operator",
			policy: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/*"},
				Conditions: []abstractiam.AbstractCondition{{
					Key: "environment", Operator: "StringNotEquals", Values: []interface{}{"prod"},
				}},
			}}},
		},
		{
			name: "non-string condition",
			policy: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/*"},
				Conditions: []abstractiam.AbstractCondition{{
					Key: "environment", Operator: "StringEquals", Values: []interface{}{1},
				}},
			}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateIAMBaseline(test.policy); err == nil {
				t.Fatal("expected baseline validation error")
			}
		})
	}
}

func TestBaselineComplianceAllowsCoveredRequestAndRequiredConditions(t *testing.T) {
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect:    "Allow",
		Actions:   []string{"storage:read"},
		Resources: []string{"//storage/bucket/prod/*"},
		Conditions: []abstractiam.AbstractCondition{{
			Key: "environment", Operator: "StringEquals", Values: []interface{}{"prod"},
		}},
	}}}
	request := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect:    "Allow",
		Actions:   []string{"storage:read"},
		Resources: []string{"//storage/bucket/prod/data.json"},
		Conditions: []abstractiam.AbstractCondition{{
			Key: "environment", Operator: "StringEquals", Values: []interface{}{"prod"},
		}},
	}}}
	if violations := CheckAbstractPolicyAgainstBaseline(request, baseline); len(violations) != 0 {
		t.Fatalf("expected compliant request, got violations: %+v", violations)
	}
}

func TestBaselineComplianceBlocksOutOfScopeAndAmbiguousWildcards(t *testing.T) {
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"},
		Resources: []string{"//storage/bucket/prod/*"},
	}}}
	tests := []struct {
		name     string
		request  abstractiam.AbstractPolicy
		wantCode string
	}{
		{
			name: "different action",
			request: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Allow", Actions: []string{"storage:write"},
				Resources: []string{"//storage/bucket/prod/file"},
			}}},
			wantCode: "GRANT_OUTSIDE_BASELINE",
		},
		{
			name: "different resource prefix",
			request: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Allow", Actions: []string{"storage:read"},
				Resources: []string{"//storage/bucket/dev/file"},
			}}},
			wantCode: "GRANT_OUTSIDE_BASELINE",
		},
		{
			name: "broader wildcard",
			request: abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
				Effect: "Allow", Actions: []string{"storage:read"},
				Resources: []string{"//storage/bucket/*"},
			}}},
			wantCode: "GRANT_OUTSIDE_BASELINE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			violations := CheckAbstractPolicyAgainstBaseline(test.request, baseline)
			if len(violations) == 0 || violations[0].Code != test.wantCode {
				t.Fatalf("violations = %+v, want code %s", violations, test.wantCode)
			}
			if violations[0].StatementIndex != 0 {
				t.Fatalf("statement index = %d, want 0", violations[0].StatementIndex)
			}
		})
	}
}

func TestBaselineComplianceRequiresAllRequiredConditions(t *testing.T) {
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/*"},
		Conditions: []abstractiam.AbstractCondition{{
			Key: "environment", Operator: "StringEquals", Values: []interface{}{"prod"},
		}},
	}}}
	request := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/file"},
	}}}
	violations := CheckAbstractPolicyAgainstBaseline(request, baseline)
	if len(violations) != 1 || violations[0].Code != "GRANT_OUTSIDE_BASELINE" {
		t.Fatalf("missing required condition was not blocked: %+v", violations)
	}
}

func TestBaselineStringLikeRejectsBroaderRequestedConditionPattern(t *testing.T) {
	baseline := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/*"},
		Conditions: []abstractiam.AbstractCondition{{
			Key: "environment", Operator: "StringLike", Values: []interface{}{"prod*"},
		}},
	}}}
	request := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/file"},
		Conditions: []abstractiam.AbstractCondition{{
			Key: "environment", Operator: "StringLike", Values: []interface{}{"pro*"},
		}},
	}}}
	violations := CheckAbstractPolicyAgainstBaseline(request, baseline)
	if len(violations) != 1 || violations[0].Code != "GRANT_OUTSIDE_BASELINE" {
		t.Fatalf("broader condition pattern should be blocked: %+v", violations)
	}
}

func TestAbstractPolicyFromLegacyPermissionConvertsStorageAndConditions(t *testing.T) {
	policy, err := AbstractPolicyFromLegacyPermission(model.AbstractPermission{
		Principal: model.PermissionPrincipal{Name: "reader", Type: "ServiceIdentity"},
		Permissions: []model.PermissionGrant{{
			Action: "storage:read", Resource: "storage://billing/reports/*",
			Conditions: map[string]interface{}{
				"StringEquals": map[string]interface{}{"environment": "production"},
			},
		}},
	})
	if err != nil {
		t.Fatalf("convert legacy permission: %v", err)
	}
	statement := policy.Statements[0]
	if statement.Resources[0] != "//storage/bucket/billing/reports/*" {
		t.Fatalf("canonical resource = %q", statement.Resources[0])
	}
	if len(statement.Conditions) != 1 ||
		statement.Conditions[0].Key != "environment" ||
		statement.Conditions[0].Operator != "StringEquals" ||
		statement.Conditions[0].Values[0] != "production" {
		t.Fatalf("request conditions were not preserved: %+v", statement.Conditions)
	}
}

func TestIAMBaselineServiceValidatesAndPersistsImmutableVersion(t *testing.T) {
	repository := &baselineRepositoryFake{}
	service, err := NewIAMBaselineService(repository)
	if err != nil {
		t.Fatal(err)
	}
	policy := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Allow", Actions: []string{"storage:read"}, Resources: []string{"//storage/bucket/prod/*"},
	}}}
	baseline, err := service.Create(context.Background(), 6, policy, true, " admin ")
	if err != nil {
		t.Fatalf("create baseline: %v", err)
	}
	if baseline.Version != 1 || !repository.createdEnabled ||
		repository.createdAccount != 6 || repository.createdActor != "admin" {
		t.Fatalf("baseline was not persisted with expected values: baseline=%+v repository=%+v", baseline, repository)
	}
	invalid := abstractiam.AbstractPolicy{Statements: []abstractiam.AbstractStatement{{
		Effect: "Deny", Actions: []string{"storage:read"}, Resources: []string{"*"},
	}}}
	if _, err := service.Create(context.Background(), 6, invalid, false, "admin"); err == nil {
		t.Fatal("invalid policy should not be persisted")
	}
	if repository.createdPolicy.Statements[0].Effect != "Allow" {
		t.Fatal("invalid create must not replace last accepted policy")
	}
}

func TestIAMBaselineServicePropagatesRepositoryErrors(t *testing.T) {
	expected := errors.New("database unavailable")
	repository := &baselineRepositoryFailure{err: expected}
	service, err := NewIAMBaselineService(repository)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.List(context.Background(), 1)
	if !errors.Is(err, expected) {
		t.Fatalf("expected repository error propagation, got %v", err)
	}
}

type baselineRepositoryFailure struct {
	err error
}

func (repository *baselineRepositoryFailure) CreateVersion(
	context.Context, int64, abstractiam.AbstractPolicy, bool, string,
) (model.IAMBaseline, error) {
	return model.IAMBaseline{}, repository.err
}

func (repository *baselineRepositoryFailure) List(context.Context, int64) ([]model.IAMBaseline, error) {
	return nil, repository.err
}

func (repository *baselineRepositoryFailure) SetEnabled(
	context.Context, int64, int64, bool, string,
) (model.IAMBaseline, error) {
	return model.IAMBaseline{}, repository.err
}
