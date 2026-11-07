package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
)

// TestNormalizeCIReportFindings CI 的 YAML 出错时必须在入库前报错：写进一条
// 谁也定位不了的发现，比直接 400 糟得多。
func TestNormalizeCIReportFindings(t *testing.T) {
	t.Run("address-only finding gets a stable key", func(t *testing.T) {
		findings, err := normalizeCIReportFindings([]CIReportFinding{{
			ResourceAddress: "aws_iam_role.foo",
		}})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if findings[0].ResourceKey != "address:aws_iam_role.foo" {
			t.Fatalf("resource key = %q", findings[0].ResourceKey)
		}
		if findings[0].ChangeType != DriftChangeAttribute {
			t.Fatalf("default change type = %q", findings[0].ChangeType)
		}
		if findings[0].Severity != DriftSeverityLow {
			t.Fatalf("severity = %q, want LOW for a plain attribute change", findings[0].Severity)
		}
		if findings[0].Status != DriftStatusOpen {
			t.Fatalf("status = %q, want OPEN", findings[0].Status)
		}
	})

	t.Run("missing identity is rejected", func(t *testing.T) {
		_, err := normalizeCIReportFindings([]CIReportFinding{{ChangeType: DriftChangeAttribute}})
		if err == nil || !strings.Contains(err.Error(), "findings[0]") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("inventory-only change types are rejected", func(t *testing.T) {
		_, err := normalizeCIReportFindings([]CIReportFinding{{
			ResourceAddress: "aws_iam_role.foo",
			ChangeType:      DriftChangeBaselineStale,
		}})
		if err == nil {
			t.Fatal("baseline_stale must not be reportable from CI")
		}
		var validation *apperr.ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("err = %T, want validation error", err)
		}
	})

	t.Run("policy document differences stay high", func(t *testing.T) {
		findings, err := normalizeCIReportFindings([]CIReportFinding{{
			ResourceKey: "role:foo",
			Kind:        BaselineKindRole,
			Fields:      []DriftFieldDiff{{Field: "trust_policy"}},
		}})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if findings[0].Severity != DriftSeverityHigh {
			t.Fatalf("severity = %q, want HIGH for a trust policy change", findings[0].Severity)
		}
	})

	t.Run("duplicates collapse into one key", func(t *testing.T) {
		findings, err := normalizeCIReportFindings([]CIReportFinding{
			{ResourceAddress: "aws_iam_role.a"},
			{ResourceAddress: "aws_iam_role.a"},
		})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if findings[0].driftKey() != findings[1].driftKey() {
			t.Fatal("duplicate addresses must share a key so the upsert dedupes them")
		}
	})
}
