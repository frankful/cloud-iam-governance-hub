package service

import (
	"encoding/json"
	"testing"
)

func TestDetectPermissionOverlapsMatchesAWSPatterns(t *testing.T) {
	candidate := json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::billing/reports"]}]}`)
	existing := []ExistingIAMPolicy{{
		Name:     "bucket-reader",
		Document: json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::billing/*"}]}`),
	}}
	findings, err := DetectPermissionOverlaps(candidate, existing)
	if err != nil {
		t.Fatalf("DetectPermissionOverlaps() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("overlap findings = %+v, want one per candidate action", findings)
	}
	if findings[0].ExistingPolicy != "bucket-reader" ||
		findings[0].MatchedAction != "s3:*" ||
		findings[0].MatchedResource != "arn:aws:s3:::billing/*" {
		t.Fatalf("overlap details = %+v", findings[0])
	}
}

func TestDetectPermissionOverlapsSkipsConditionsAndDeny(t *testing.T) {
	candidate := json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::billing/reports"}]}`)
	existing := []ExistingIAMPolicy{{
		Name: "scoped-policy",
		Document: json.RawMessage(`{"Statement":[
			{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::billing/reports","Condition":{"StringEquals":{"aws:PrincipalTag/team":"finance"}}},
			{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::billing/reports"}
		]}`),
	}}
	findings, err := DetectPermissionOverlaps(candidate, existing)
	if err != nil {
		t.Fatalf("DetectPermissionOverlaps() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("conditional or deny grants reported as overlap: %+v", findings)
	}
}

func TestDetectPermissionOverlapsReportsMalformedInventoryPolicy(t *testing.T) {
	_, err := DetectPermissionOverlaps(
		json.RawMessage(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::billing/reports"}}`),
		[]ExistingIAMPolicy{{Name: "broken", Document: json.RawMessage(`{invalid`)}},
	)
	if err == nil {
		t.Fatal("expected malformed inventory policy error")
	}
}
