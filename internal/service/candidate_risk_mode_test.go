package service

import "testing"

func TestParseCandidateRiskMode(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    CandidateRiskMode
		wantErr bool
	}{
		{name: "default is blocking", want: CandidateRiskModeBlock},
		{name: "block is case insensitive", value: " block ", want: CandidateRiskModeBlock},
		{name: "warn is case insensitive", value: "warn", want: CandidateRiskModeWarn},
		{name: "invalid mode", value: "ignore", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseCandidateRiskMode(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseCandidateRiskMode() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && got != test.want {
				t.Errorf("ParseCandidateRiskMode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBlockingCandidateRiskFindingsSeverityThreshold(t *testing.T) {
	findings := []CandidatePolicyRiskFinding{
		{RiskType: iamRiskAdminPolicy, RiskLevel: "HIGH"},
		{RiskType: iamRiskWildcardResource, RiskLevel: "MEDIUM"},
		{RiskType: iamRiskAdminPermission, RiskLevel: "HIGH"},
		{RiskType: iamRiskExternalTrust, RiskLevel: "HIGH"},
	}

	// BLOCK 模式：仅 HIGH 阻断。MEDIUM（wildcard resource）只告警——
	// 大量 AWS 服务不支持资源级 ARN，"*" 是合法且必要的资源模式。
	blocking := blockingCandidateRiskFindings(findings, CandidateRiskModeBlock)
	if len(blocking) != 3 {
		t.Fatalf("BLOCK mode blocking findings = %+v, want 3 HIGH findings", blocking)
	}
	for _, finding := range blocking {
		if finding.RiskLevel != "HIGH" {
			t.Errorf("BLOCK mode retained a non-HIGH finding: %+v", finding)
		}
	}

	// WARN 模式：admin_policy 策略名启发式降级为告警，其余 HIGH 仍阻断；
	// MEDIUM 同样只告警。→ admin_permission + external_trust = 2
	warnBlocking := blockingCandidateRiskFindings(findings, CandidateRiskModeWarn)
	if len(warnBlocking) != 2 {
		t.Fatalf("WARN mode blocking findings = %+v, want 2 HIGH findings excluding admin policy name", warnBlocking)
	}
	for _, finding := range warnBlocking {
		if finding.RiskType == iamRiskAdminPolicy {
			t.Errorf("WARN mode blocked the admin policy name heuristic: %+v", finding)
		}
	}
}
