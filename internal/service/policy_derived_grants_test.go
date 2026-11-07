package service

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/pkg/adapter/aws"
)

func TestNormalizePolicyGrantRowsDeduplicatesAndPreservesOrigins(t *testing.T) {
	rows := []policyGrantRow{
		{
			policyID: 1, policyName: sqlString("direct-policy"), policyType: sqlString("managed"),
			source:   "DIRECT",
			document: []byte(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}}`),
		},
		{
			policyID: 2, policyName: sqlString("group-policy"), policyType: sqlString("inline"),
			source: "GROUP", groupID: sqlInt64(9), groupName: sqlString("analysts"),
			document: []byte(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"]}]}`),
		},
	}
	statements, warnings, err := normalizePolicyGrantRows(&aws.AwsAdapter{}, "report-reader", rows)
	if err != nil {
		t.Fatalf("normalizePolicyGrantRows() error = %v", err)
	}
	if len(statements) != 1 || len(warnings) != 0 {
		t.Fatalf("normalized statements/warnings = %d/%v", len(statements), warnings)
	}
	if len(statements[0].Origins) != 2 {
		t.Fatalf("deduplicated statement origins = %+v", statements[0].Origins)
	}
	if statements[0].Origins[0].Source != "DIRECT" || statements[0].Origins[1].Source != "GROUP" ||
		statements[0].Origins[1].GroupName == nil || *statements[0].Origins[1].GroupName != "analysts" {
		t.Fatalf("statement origins lost provenance: %+v", statements[0].Origins)
	}
}

func TestNormalizePolicyGrantRowsReportsPartialParseWarnings(t *testing.T) {
	rows := []policyGrantRow{{
		policyID: 8, policyName: sqlString("resource-policy"),
		document: []byte(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":"*"}}`),
	}}
	statements, warnings, err := normalizePolicyGrantRows(&aws.AwsAdapter{}, "report-reader", rows)
	if err != nil {
		t.Fatalf("normalizePolicyGrantRows() error = %v", err)
	}
	if len(statements) != 1 || len(warnings) != 1 ||
		!strings.Contains(warnings[0], "Principal field is not included") {
		t.Fatalf("partial parse result = statements:%+v warnings:%v", statements, warnings)
	}
}

func TestNormalizePolicyGrantRowsRejectsMalformedPolicy(t *testing.T) {
	_, _, err := normalizePolicyGrantRows(&aws.AwsAdapter{}, "report-reader", []policyGrantRow{{
		policyID: 10, document: json.RawMessage(`{invalid`),
	}})
	if err == nil {
		t.Fatal("expected malformed policy to return an error")
	}
}

func sqlString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: true}
}

func sqlInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: true}
}
