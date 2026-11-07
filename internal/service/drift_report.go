package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
)

// CI plan-only 上报（phase4-drift-design.md §8）。
//
// 平台不跑 terraform，真正的 plan 在 CI 里跑：`terraform plan -detailed-exitcode`
// 返回 0 干净、2 有差异、1 出错。CI 只把「哪些资源计划里要改」报上来，平台
// 负责存证与去重。与 inventory 判定同一张表，用 source 区分——两条路径看到
// 的是同一个现实的两个切面，混在一起会互相覆盖。
//
// 语义上是**替换**而不是追加：一次 plan 覆盖该仓库的完整规划范围，本轮没
// 报的资源 = plan 里没有差异 = 已恢复。因此未被上报的 ci 发现会被自动关闭；
// 空上报是合法且重要的（= 干净）。

// ErrDriftAccountNotFound 表示上报里的 AWS 账号没有纳管，handler 回 404。
var ErrDriftAccountNotFound = errors.New("aws account not found")

// 允许 CI 上报的差异类型。baseline_stale 是平台侧的基准新鲜度结论，CI 无从
// 得知；attribute/declared_missing/undeclared_extra/file_conflict 则是 plan
// 里真实可见的三类差异（改、删、未纳管与归属冲突）。
var ciReportChangeTypes = map[string]bool{
	DriftChangeAttribute:       true,
	DriftChangeDeclaredMissing: true,
	DriftChangeUndeclaredExtra: true,
	DriftChangeFileConflict:    true,
}

// CIReportFinding 是 CI 上报的一条差异。ResourceAddress（Terraform 地址）是
// 首选标识：仓库里的 `aws_iam_role.foo` 比平台内部的 resource_key 更容易从
// plan 输出里直接拿到。
type CIReportFinding struct {
	ResourceKey     string           `json:"resource_key"`
	ResourceAddress string           `json:"resource_address"`
	Kind            string           `json:"kind"`
	FileKey         string           `json:"file_key"`
	ChangeType      string           `json:"change_type"`
	Severity        string           `json:"severity"`
	Summary         string           `json:"summary"`
	Fields          []DriftFieldDiff `json:"fields"`
}

// CIReport 是一次 plan-only 上报。
type CIReport struct {
	AWSAccountID string            `json:"account_id"`
	CommitSHA    string            `json:"commit_sha"`
	CIURL        string            `json:"ci_url"`
	Findings     []CIReportFinding `json:"findings"`
}

// CIReportResult 是落库结果。Clean 表示这次 plan 没有任何差异——它是「确定
// 干净」而不是「没检测」，页面/告警要能区分。
type CIReportResult struct {
	AccountDBID  int64     `json:"account_id"`
	AWSAccountID string    `json:"aws_account_id"`
	Reported     int       `json:"reported"`
	Surfaced     int       `json:"surfaced"`
	Refreshed    int       `json:"refreshed"`
	Resolved     int       `json:"resolved"`
	OpenFindings int       `json:"open_findings"`
	Clean        bool      `json:"clean"`
	CheckedAt    time.Time `json:"checked_at"`
}

// IngestCIReport 把一次 CI plan 结果落成漂移发现。
//
// 与 inventory 判定不同，这里不做稳定窗口：plan 已经对着真实 state 跑过一遍，
// 不存在「apply 后库存还没同步」的抖动，首轮即 OPEN。人工忽略仍然不被翻回
// ——那是明确决定，只有 plan 恢复干净才自动关闭。
func (service *DriftService) IngestCIReport(
	ctx context.Context, report CIReport,
) (CIReportResult, error) {
	result := CIReportResult{}
	awsAccountID := strings.TrimSpace(report.AWSAccountID)
	if awsAccountID == "" {
		return result, apperr.Validation("account_id must not be empty")
	}
	err := service.db.QueryRowContext(ctx,
		`SELECT id FROM aws_account WHERE account_id = $1`, awsAccountID).Scan(&result.AccountDBID)
	if errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("%w: %s", ErrDriftAccountNotFound, awsAccountID)
	}
	if err != nil {
		return result, fmt.Errorf("resolve account %s: %w", awsAccountID, err)
	}
	result.AWSAccountID = awsAccountID

	findings, err := normalizeCIReportFindings(report.Findings)
	if err != nil {
		return result, err
	}
	result.Reported = len(findings)

	existing, err := service.loadOpenFindings(ctx, result.AccountDBID, DriftSourceCI)
	if err != nil {
		return result, err
	}

	seen := make(map[string]bool, len(findings))
	surfaced := make([]DriftFinding, 0, len(findings))
	for _, finding := range findings {
		finding.AccountDBID = result.AccountDBID
		finding.AWSAccountID = awsAccountID
		finding.Source = DriftSourceCI
		finding.CIURL = strings.TrimSpace(report.CIURL)
		finding.CommitSHA = strings.TrimSpace(report.CommitSHA)
		key := finding.driftKey()
		if seen[key] {
			// 同一份上报里重复的资源（多模块共用地址）只留第一条，
			// 否则唯一索引会在第二条 insert 上撞车。
			continue
		}
		seen[key] = true
		if previous, ok := existing[key]; ok {
			status := DriftStatusOpen
			if previous.Status == DriftStatusIgnored {
				status = DriftStatusIgnored
			}
			if err := service.updateFinding(ctx, previous.ID, finding, status); err != nil {
				return result, err
			}
			result.Refreshed++
			continue
		}
		id, err := service.insertFinding(ctx, finding, DriftStatusOpen)
		if err != nil {
			return result, err
		}
		finding.ID = id
		result.Surfaced++
		surfaced = append(surfaced, finding)
	}

	// 替换式语义：本轮 plan 没报 = 计划里没有差异 = 已恢复。
	for key, previous := range existing {
		if seen[key] {
			continue
		}
		if err := service.resolveFinding(ctx, previous.ID); err != nil {
			return result, err
		}
		result.Resolved++
	}

	openCount, err := service.countOpenFindings(ctx, result.AccountDBID)
	if err != nil {
		return result, err
	}
	result.OpenFindings = openCount
	result.Clean = result.Reported == 0 && openCount == 0
	result.CheckedAt = time.Now().UTC()
	// CI 上报算不出「跳过了多少文件 / 基准过期几个」——那两个是库存判定
	// 的概念，传 nil 保留上一轮的值，别用 0 假装统计过。
	if err := service.recordHeartbeat(ctx, result.AccountDBID, openCount == 0, nil, nil); err != nil {
		return result, err
	}
	service.logger.Info("ci drift report ingested",
		"account_id", result.AccountDBID, "aws_account_id", awsAccountID,
		"reported", result.Reported, "surfaced", result.Surfaced,
		"refreshed", result.Refreshed, "resolved", result.Resolved,
		"open", openCount)
	if len(surfaced) > 0 {
		service.notify("drift.ci_report", surfaced)
	}
	return result, nil
}

// normalizeCIReportFindings 校验并补齐上报内容。缺标识、类型越界一律按调用
// 方输入错误处理：让 CI 的 YAML 立刻报错，好过写进一条没人能定位的发现。
func normalizeCIReportFindings(
	findings []CIReportFinding,
) ([]DriftFinding, error) {
	normalized := make([]DriftFinding, 0, len(findings))
	for index, finding := range findings {
		resourceKey := strings.TrimSpace(finding.ResourceKey)
		resourceAddress := strings.TrimSpace(finding.ResourceAddress)
		if resourceKey == "" && resourceAddress == "" {
			return nil, apperr.Validationf(
				"findings[%d] must carry resource_key or resource_address", index)
		}
		changeType := strings.TrimSpace(finding.ChangeType)
		if changeType == "" {
			changeType = DriftChangeAttribute
		}
		if !ciReportChangeTypes[changeType] {
			return nil, apperr.Validationf(
				"findings[%d].change_type %q is not reportable from CI (allowed: attribute, declared_missing, undeclared_extra, file_conflict)",
				index, changeType)
		}
		if resourceKey == "" {
			// 没有平台内部键时用地址兜底：唯一索引与页面都只需要一个稳定
			// 标识，地址在仓库里同样唯一。
			resourceKey = "address:" + resourceAddress
		}
		severity := strings.ToUpper(strings.TrimSpace(finding.Severity))
		if severity == "" {
			severity = driftSeverity(changeType, finding.Kind, finding.Fields)
		}
		entry := DriftFinding{
			ResourceKey:     resourceKey,
			ResourceAddress: resourceAddress,
			Kind:            strings.TrimSpace(finding.Kind),
			FileKey:         strings.TrimSpace(finding.FileKey),
			ChangeType:      changeType,
			Severity:        severity,
			Status:          DriftStatusOpen,
			Fields:          finding.Fields,
			Summary:         strings.TrimSpace(finding.Summary),
		}
		// CI 自己给了摘要就原样保留（那是外部系统的文本，翻译它没有意义）；
		// 没给才用平台的措辞生成，顺带带上语义码（C16）。
		if entry.Summary == "" {
			applyDriftSummary(&entry)
		}
		normalized = append(normalized, entry)
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		return normalized[i].driftKey() < normalized[j].driftKey()
	})
	return normalized, nil
}
