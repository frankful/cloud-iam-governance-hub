package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

func TestFromCloudPolicyAllowS3Wildcard(t *testing.T) {
	raw := json.RawMessage(`{
		"Version":"2012-10-17",
		"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::example/*"}
	}`)
	policy, status, message, err := (*AwsAdapter)(nil).FromCloudPolicy(raw)
	if err != nil {
		t.Fatalf("FromCloudPolicy() error = %v", err)
	}
	if status != ParseStatusSuccess || message != "" {
		t.Fatalf("status/message = %q/%q", status, message)
	}
	if len(policy.Statements) != 1 || policy.Statements[0].Effect != "Allow" ||
		len(policy.Statements[0].Actions) != 1 || policy.Statements[0].Actions[0] != "s3:*" ||
		len(policy.Statements[0].Resources) != 1 || policy.Statements[0].Resources[0] != "arn:aws:s3:::example/*" {
		t.Fatalf("abstract policy = %#v", policy)
	}
}

func TestToCloudPolicyProducesValidAWSJSON(t *testing.T) {
	policy := &abstractiam.AbstractPolicy{
		ID: "policy-42",
		Statements: []abstractiam.AbstractStatement{{
			Effect:    "Allow",
			Actions:   []string{"s3:GetObject"},
			Resources: []string{"arn:aws:s3:::example/*"},
			Conditions: []abstractiam.AbstractCondition{{
				Key: "aws:PrincipalOrgID", Operator: "StringEquals", Values: []interface{}{"o-abc123"},
			}},
		}},
	}
	raw, err := (*AwsAdapter)(nil).ToCloudPolicy(policy)
	if err != nil {
		t.Fatalf("ToCloudPolicy() error = %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("ToCloudPolicy() produced invalid JSON: %s", raw)
	}
	var document struct {
		Version   string `json:"Version"`
		ID        string `json:"Id"`
		Statement []struct {
			Effect    string                 `json:"Effect"`
			Action    string                 `json:"Action"`
			Resource  string                 `json:"Resource"`
			Condition map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode policy JSON: %v", err)
	}
	if document.Version != "2012-10-17" || document.ID != "policy-42" || len(document.Statement) != 1 ||
		document.Statement[0].Action != "s3:GetObject" ||
		document.Statement[0].Resource != "arn:aws:s3:::example/*" {
		t.Fatalf("AWS policy = %#v", document)
	}
}

func TestFromCloudPolicyUnsupportedConditionIsPartial(t *testing.T) {
	raw := json.RawMessage(`{
		"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
		"Condition":{"CustomOperator":{"custom:key":"value"}}}
	}`)
	policy, status, message, err := (*AwsAdapter)(nil).FromCloudPolicy(raw)
	if err != nil {
		t.Fatalf("FromCloudPolicy() error = %v", err)
	}
	if policy == nil || status != ParseStatusPartial || !strings.Contains(message, "CustomOperator") {
		t.Fatalf("policy/status/message = %#v/%q/%q", policy, status, message)
	}
}

func TestFromCloudPolicyInvalidJSONFails(t *testing.T) {
	policy, status, message, err := (*AwsAdapter)(nil).FromCloudPolicy(json.RawMessage(`{"Statement":`))
	if err == nil || policy != nil || status != ParseStatusFailed || message == "" {
		t.Fatalf("policy/status/message/error = %#v/%q/%q/%v", policy, status, message, err)
	}
}

func TestFromCloudTrustPolicyMarksPrincipalPartial(t *testing.T) {
	raw := json.RawMessage(`{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`)
	policy, status, message, err := (*AwsAdapter)(nil).FromCloudPolicy(raw)
	if err != nil {
		t.Fatalf("FromCloudPolicy() error = %v", err)
	}
	if policy == nil || status != ParseStatusPartial || !strings.Contains(message, "Principal") {
		t.Fatalf("policy/status/message = %#v/%q/%q", policy, status, message)
	}
}

func TestToCloudPolicyRejectsUnsupportedCondition(t *testing.T) {
	_, err := (*AwsAdapter)(nil).ToCloudPolicy(&abstractiam.AbstractPolicy{
		Statements: []abstractiam.AbstractStatement{{
			Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"*"},
			Conditions: []abstractiam.AbstractCondition{{Key: "x", Operator: "Unknown", Values: []interface{}{"v"}}},
		}},
	})
	if err == nil {
		t.Fatal("ToCloudPolicy() expected unsupported condition error")
	}
}

func TestAdapterRequiresInjectedSnapshotFetcher(t *testing.T) {
	adapter := NewAwsAdapter(func(context.Context) error { return nil }, nil)
	if err := adapter.TestConnect(context.Background()); err != nil {
		t.Fatalf("TestConnect() error = %v", err)
	}
	if _, err := adapter.FetchIAMSnapshot(context.Background()); err == nil {
		t.Fatal("FetchIAMSnapshot() expected missing fetcher error")
	}
}
