package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
)

func TestAddPolicyFindingsDetectsWildcardsAndAdminAccess(t *testing.T) {
	principal := iamRiskScanPrincipal{
		policyID:   sql.NullInt64{Int64: 42, Valid: true},
		policyName: sql.NullString{String: "AdministratorAccess", Valid: true},
		policyDoc: []byte(`{
			"Version":"2012-10-17",
			"Statement":[
				{"Effect":"Allow","Action":["s3:GetObject","iam:AttachUserPolicy"],"Resource":"*"},
				{"Effect":"Deny","Action":"*","Resource":"*"}
			]
		}`),
	}
	findings := make(map[string]*iamRiskFinding)
	if err := addPolicyFindings(findings, principal); err != nil {
		t.Fatalf("addPolicyFindings() error = %v", err)
	}

	for _, riskType := range []string{iamRiskAdminPolicy, iamRiskAdminPermission, iamRiskWildcardResource} {
		if findings[riskType] == nil {
			t.Errorf("missing %q finding", riskType)
		}
	}
	if findings[iamRiskWildcardAction] != nil {
		t.Error("Deny statement incorrectly generated a wildcard-action finding")
	}
	if got := findings[iamRiskAdminPermission].level; got != "HIGH" {
		t.Errorf("admin permission level = %q, want HIGH", got)
	}
}

func TestAddPolicyFindingsDetectsWildcardActionsAndMultiplePolicies(t *testing.T) {
	findings := make(map[string]*iamRiskFinding)
	for _, policy := range []iamRiskScanPrincipal{
		{
			policyID:   sql.NullInt64{Int64: 1, Valid: true},
			policyName: sql.NullString{String: "ReadMostly", Valid: true},
			policyDoc:  []byte(`{"Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"arn:aws:ec2:::instance/*"}}`),
		},
		{
			policyID:   sql.NullInt64{Int64: 2, Valid: true},
			policyName: sql.NullString{String: "Extra", Valid: true},
			policyDoc:  []byte(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket"}}`),
		},
	} {
		if err := addPolicyFindings(findings, policy); err != nil {
			t.Fatalf("addPolicyFindings() error = %v", err)
		}
	}
	if findings[iamRiskWildcardAction] == nil || findings[iamRiskWildcardResource] == nil {
		t.Fatalf("findings = %#v, want wildcard action and resource", findings)
	}
	if got := len(findings[iamRiskWildcardAction].descriptions); got != 2 {
		t.Errorf("wildcard action source count = %d, want 2", got)
	}
}

func TestScanCandidateIAMPolicyUsesPersistedPolicyAndTrustRules(t *testing.T) {
	policy := json.RawMessage(`{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:s3:::reports/*"}}`)
	trust := json.RawMessage(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::210987654321:root"},"Action":"sts:AssumeRole"}}`)
	findings, err := ScanCandidateIAMPolicy(policy, trust, "admin-reader", "123456789012")
	if err != nil {
		t.Fatalf("scan candidate policy: %v", err)
	}
	riskTypes := make(map[string]string, len(findings))
	for _, finding := range findings {
		riskTypes[finding.RiskType] = finding.RiskLevel
	}
	if riskTypes[iamRiskWildcardAction] != "HIGH" ||
		riskTypes[iamRiskAdminPermission] != "HIGH" ||
		riskTypes[iamRiskAdminPolicy] != "HIGH" ||
		riskTypes[iamRiskWildcardResource] != "MEDIUM" ||
		riskTypes[iamRiskExternalTrust] != "HIGH" {
		t.Fatalf("candidate risk findings = %+v", findings)
	}
}

func TestAddTrustPolicyFindingsDetectsExternalPrincipals(t *testing.T) {
	tests := []struct {
		name        string
		document    string
		accountID   string
		wantFinding bool
	}{
		{
			name:        "wildcard",
			document:    `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`,
			accountID:   "123456789012",
			wantFinding: true,
		},
		{
			name:        "external AWS account",
			document:    `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::210987654321:root"},"Action":"sts:AssumeRole"}}`,
			accountID:   "123456789012",
			wantFinding: true,
		},
		{
			name:        "same AWS account",
			document:    `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`,
			accountID:   "123456789012",
			wantFinding: false,
		},
		{
			name:        "deny is not an allowed trust",
			document:    `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}}`,
			accountID:   "123456789012",
			wantFinding: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := make(map[string]*iamRiskFinding)
			principal := iamRiskScanPrincipal{
				accountID:   test.accountID,
				trustPolicy: []byte(test.document),
			}
			if err := addTrustPolicyFindings(findings, principal); err != nil {
				t.Fatalf("addTrustPolicyFindings() error = %v", err)
			}
			if got := findings[iamRiskExternalTrust] != nil; got != test.wantFinding {
				t.Errorf("external trust finding = %v, want %v", got, test.wantFinding)
			}
			if test.wantFinding {
				if !strings.Contains(findings[iamRiskExternalTrust].descriptions[0], "trust policy allows") {
					t.Error("finding does not describe the trust policy rule")
				}
			}
		})
	}
}

func TestTrustPolicyDetectsFederatedIdentity(t *testing.T) {
	findings := make(map[string]*iamRiskFinding)
	principal := iamRiskScanPrincipal{
		trustPolicy: []byte(`{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/example"},"Action":"sts:AssumeRoleWithSAML"}}`),
	}
	if err := addTrustPolicyFindings(findings, principal); err != nil {
		t.Fatalf("addTrustPolicyFindings() error = %v", err)
	}
	if findings[iamRiskExternalTrust] == nil {
		t.Fatal("expected federated trust finding")
	}
}

func TestScanCandidateIAMPolicyDoesNotFlagScopedEKSOIDCTrust(t *testing.T) {
	const accountID = "111122223333"
	const issuer = "oidc.eks.ap-southeast-1.amazonaws.com/id/C4734F6B2A7D9F9A61C2DA6ED365B021"
	policy := json.RawMessage(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/alarm.json"}}`)
	trust := json.RawMessage(`{
		"Version":"2012-10-17",
		"Statement":[{
			"Sid":"AllowEksSaAssumeWebIdentity",
			"Effect":"Allow",
			"Action":"sts:AssumeRoleWithWebIdentity",
			"Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/oidc.eks.ap-southeast-1.amazonaws.com/id/C4734F6B2A7D9F9A61C2DA6ED365B021"},
			"Condition":{"StringEquals":{
				"` + issuer + `:aud":"sts.amazonaws.com",
				"` + issuer + `:sub":"system:serviceaccount:galaxy:alarm-receiver-service"
			}}
		}]
	}`)

	findings, err := ScanCandidateIAMPolicy(policy, trust, "alarm-receiver", accountID)
	if err != nil {
		t.Fatalf("scan candidate policy: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("safe candidate policy unexpectedly reported: %+v", findings)
	}
}

func TestTrustPolicyStillDetectsUnscopedOrBroadFederatedTrust(t *testing.T) {
	const issuer = "oidc.eks.ap-southeast-1.amazonaws.com/id/C4734F6B2A7D9F9A61C2DA6ED365B021"
	tests := []struct {
		name      string
		action    string
		condition string
	}{
		{
			name:   "missing audience",
			action: `"sts:AssumeRoleWithWebIdentity"`,
			condition: `{"StringEquals":{
				"` + issuer + `:sub":"system:serviceaccount:galaxy:alarm-receiver-service"
			}}`,
		},
		{
			name:   "wildcard service account",
			action: `"sts:AssumeRoleWithWebIdentity"`,
			condition: `{"StringEquals":{
				"` + issuer + `:aud":"sts.amazonaws.com",
				"` + issuer + `:sub":"system:serviceaccount:galaxy:*"
			}}`,
		},
		{
			name:      "additional assume role action",
			action:    `["sts:AssumeRoleWithWebIdentity","sts:AssumeRole"]`,
			condition: `{"StringEquals":{"` + issuer + `:aud":"sts.amazonaws.com","` + issuer + `:sub":"system:serviceaccount:galaxy:alarm-receiver-service"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := `{"Statement":{"Effect":"Allow","Action":` + test.action + `,"Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/` + issuer + `"},"Condition":` + test.condition + `}}`
			findings := make(map[string]*iamRiskFinding)
			principal := iamRiskScanPrincipal{
				accountID:   "123456789012",
				trustPolicy: []byte(document),
			}
			if err := addTrustPolicyFindings(findings, principal); err != nil {
				t.Fatalf("addTrustPolicyFindings() error = %v", err)
			}
			if findings[iamRiskExternalTrust] == nil {
				t.Fatal("expected unscoped or broad federated trust finding")
			}
		})
	}
}

func TestMalformedPolicyReturnsError(t *testing.T) {
	principal := iamRiskScanPrincipal{
		policyID:  sql.NullInt64{Int64: 9, Valid: true},
		policyDoc: []byte(`{"Statement":[{"Effect":`),
	}
	if err := addPolicyFindings(make(map[string]*iamRiskFinding), principal); err == nil {
		t.Fatal("expected malformed policy error")
	}
}

func TestIAMRiskScannerRequiresDatabase(t *testing.T) {
	if _, err := NewIAMRiskScanner(nil); err == nil {
		t.Fatal("NewIAMRiskScanner(nil) unexpectedly succeeded")
	}
	var scanner *IAMRiskScanner
	if _, err := scanner.Scan(context.Background()); err == nil {
		t.Fatal("nil scanner unexpectedly succeeded")
	}
}

func TestDecodePolicyStatementsAcceptsSingleStatementAndStringActions(t *testing.T) {
	statements, err := decodePolicyStatements(json.RawMessage(`{"Effect":"Allow","Action":"iam:*","Resource":"*"}`))
	if err != nil {
		t.Fatalf("decodePolicyStatements() error = %v", err)
	}
	if len(statements) != 1 || len(statements[0].Action) != 1 || statements[0].Action[0] != "iam:*" {
		t.Fatalf("decoded statements = %#v", statements)
	}
}
