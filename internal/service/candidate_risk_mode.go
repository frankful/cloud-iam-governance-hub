package service

import (
	"errors"
	"strings"
)

type CandidateRiskMode string

const (
	CandidateRiskModeBlock CandidateRiskMode = "BLOCK"
	CandidateRiskModeWarn  CandidateRiskMode = "WARN"
)

func ParseCandidateRiskMode(value string) (CandidateRiskMode, error) {
	switch CandidateRiskMode(strings.ToUpper(strings.TrimSpace(value))) {
	case "", CandidateRiskModeBlock:
		return CandidateRiskModeBlock, nil
	case CandidateRiskModeWarn:
		return CandidateRiskModeWarn, nil
	default:
		return "", errors.New("IAM_CANDIDATE_RISK_MODE must be BLOCK or WARN")
	}
}

// blockingCandidateRiskFindings returns the findings that block ticket creation.
// MEDIUM/LOW findings never block: wildcard resources like "*" are mandatory on
// AWS services without resource-level ARNs, so they surface as warnings instead.
// HIGH findings block in BLOCK mode; in WARN mode only the admin-policy name
// heuristic is downgraded to a warning while other HIGH findings still block.
func blockingCandidateRiskFindings(
	findings []CandidatePolicyRiskFinding,
	mode CandidateRiskMode,
) []CandidatePolicyRiskFinding {
	blocking := make([]CandidatePolicyRiskFinding, 0, len(findings))
	for _, finding := range findings {
		// MEDIUM/LOW 一律只告警：通配资源 "*" 在大量 AWS 服务中是
		// 合法且必要的（这些服务不支持资源级 ARN），不阻断工单创建。
		if finding.RiskLevel != "HIGH" {
			continue
		}
		// WARN 模式下仅策略名启发式（admin_policy）降级为告警；
		// 其余 HIGH（外部信任、管理员权限、通配动作）仍阻断。
		if mode == CandidateRiskModeWarn && finding.RiskType == iamRiskAdminPolicy {
			continue
		}
		blocking = append(blocking, finding)
	}
	return blocking
}
