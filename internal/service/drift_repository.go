package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DriftFilter 是漂移列表的查询条件。默认只列未解决的：已解决的历史要看
// 得显式要，否则页面上「当前有几处不一致」永远算不清。
type DriftFilter struct {
	AWSAccountID    string
	Status          string
	Severity        string
	ChangeType      string
	IncludeResolved bool
	Page            int
	PageSize        int
}

func (filter DriftFilter) normalized() DriftFilter {
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 || filter.PageSize > 200 {
		filter.PageSize = 50
	}
	filter.AWSAccountID = strings.TrimSpace(filter.AWSAccountID)
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	filter.Severity = strings.ToUpper(strings.TrimSpace(filter.Severity))
	filter.ChangeType = strings.TrimSpace(filter.ChangeType)
	return filter
}

// DriftFindingPage 是一页发现 + 总数。
type DriftFindingPage struct {
	Items    []DriftFinding `json:"items"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// ErrDriftFindingNotFound 让 handler 能区分 404 与内部错误。
var ErrDriftFindingNotFound = errors.New("drift finding not found")

const driftFindingColumns = `id, account_id, aws_account_id, source,
	COALESCE(resource_key, ''), COALESCE(resource_address, ''), COALESCE(kind, ''),
	COALESCE(file_key, ''), change_type, fields::text, severity, status,
	baseline_publication_id, COALESCE(summary, ''), COALESCE(summary_code, ''),
	COALESCE(summary_params::text, '{}'), COALESCE(ci_url, ''),
	COALESCE(commit_sha, ''), first_seen_at, last_seen_at, occurrences,
	resolved_at, COALESCE(resolved_by, '')`

// List 返回一页漂移发现。
func (service *DriftService) List(
	ctx context.Context, filter DriftFilter,
) (DriftFindingPage, error) {
	filter = filter.normalized()
	conditions := []string{"TRUE"}
	args := make([]any, 0, 6)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if filter.AWSAccountID != "" {
		conditions = append(conditions, "aws_account_id = "+addArg(filter.AWSAccountID))
	}
	if filter.Status != "" {
		conditions = append(conditions, "status = "+addArg(filter.Status))
	}
	if filter.Severity != "" {
		conditions = append(conditions, "severity = "+addArg(filter.Severity))
	}
	if filter.ChangeType != "" {
		conditions = append(conditions, "change_type = "+addArg(filter.ChangeType))
	}
	if !filter.IncludeResolved {
		conditions = append(conditions, "resolved_at IS NULL")
	}
	where := strings.Join(conditions, " AND ")

	page := DriftFindingPage{Items: []DriftFinding{}, Page: filter.Page, PageSize: filter.PageSize}
	if err := service.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM iam_drift_finding WHERE `+where, args...).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("count drift findings: %w", err)
	}
	query := `SELECT ` + driftFindingColumns + ` FROM iam_drift_finding WHERE ` + where +
		` ORDER BY (resolved_at IS NOT NULL), CASE severity
		     WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
		   first_seen_at DESC, id DESC` +
		` LIMIT ` + addArg(filter.PageSize) + ` OFFSET ` + addArg((filter.Page-1)*filter.PageSize)
	rows, err := service.db.QueryContext(ctx, query, args...)
	if err != nil {
		return page, fmt.Errorf("list drift findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		finding, err := scanDriftFinding(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, finding)
	}
	return page, rows.Err()
}

// GetFinding 读取一条发现，供详情与操作前校验使用。
func (service *DriftService) GetFinding(
	ctx context.Context, id int64,
) (DriftFinding, error) {
	row := service.db.QueryRowContext(ctx,
		`SELECT `+driftFindingColumns+` FROM iam_drift_finding WHERE id = $1`, id)
	finding, err := scanDriftFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DriftFinding{}, ErrDriftFindingNotFound
	}
	return finding, err
}

// DriftFindingAction 是对一条发现的人工处置。
const (
	DriftActionIgnore  = "ignore"
	DriftActionReopen  = "reopen"
	DriftActionResolve = "resolve"
)

// ApplyAction 记录人工处置。忽略不关闭记录（资源仍然不一致，只是人决定
// 不处理），人工关闭则写 resolved_at——两者语义不同，不能合并成一个
// 「已读」按钮。
func (service *DriftService) ApplyAction(
	ctx context.Context, id int64, action, actor string,
) (DriftFinding, error) {
	var err error
	switch action {
	case DriftActionIgnore:
		_, err = service.db.ExecContext(ctx, `
			UPDATE iam_drift_finding
			SET status = $2, updated_at = NOW()
			WHERE id = $1 AND resolved_at IS NULL`, id, DriftStatusIgnored)
	case DriftActionReopen:
		_, err = service.db.ExecContext(ctx, `
			UPDATE iam_drift_finding
			SET status = $2, resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
			WHERE id = $1`, id, DriftStatusOpen)
	case DriftActionResolve:
		_, err = service.db.ExecContext(ctx, `
			UPDATE iam_drift_finding
			SET resolved_at = NOW(), resolved_by = $2, updated_at = NOW()
			WHERE id = $1 AND resolved_at IS NULL`, id, actor)
	default:
		return DriftFinding{}, fmt.Errorf("unsupported drift action %q", action)
	}
	if err != nil {
		return DriftFinding{}, fmt.Errorf("apply drift action %s: %w", action, err)
	}
	return service.GetFinding(ctx, id)
}

// DriftAccountSummary 是账号维度的覆盖率与心跳：页面要能区分「干净」、
// 「有漂移」和「根本没检测」三种状态。
type DriftAccountSummary struct {
	AccountDBID       int64      `json:"account_id"`
	AWSAccountID      string     `json:"aws_account_id"`
	DisplayName       string     `json:"display_name"`
	Declarations      int        `json:"declarations"`
	StaleDeclarations int        `json:"stale_declarations"`
	Open              int        `json:"open"`
	Suspect           int        `json:"suspect"`
	Pending           int        `json:"pending"`
	PendingRebaseline int        `json:"pending_rebaseline"`
	LastCheckAt       *time.Time `json:"last_check_at,omitempty"`
	LastCleanAt       *time.Time `json:"last_clean_at,omitempty"`
	// LastSkippedFiles/LastStaleFiles 是上一轮判定的覆盖缺口：跳过 = 文件被
	// 在途变更占用（层 4 门禁），过期 = 基准与 main 不一致。两个计数存在的
	// 意义是让页面能说「这轮跳过了 N 个」——否则在途 PR 期间看起来就是
	// 干干净净的 0 发现（台账 C13）。
	LastSkippedFiles int `json:"last_skipped_files"`
	LastStaleFiles   int `json:"last_stale_files"`
}

// SummarizeAccounts 返回全部已纳管账号的覆盖率与计数。未发布过基线的账号
// Declarations=0：页面据此显示「未纳管，不检测」，而不是 0 条漂移。
func (service *DriftService) SummarizeAccounts(
	ctx context.Context, awsAccountID string,
) ([]DriftAccountSummary, error) {
	args := []any{}
	condition := ""
	if trimmed := strings.TrimSpace(awsAccountID); trimmed != "" {
		args = append(args, trimmed)
		condition = "WHERE c.aws_account_id = $1"
	}
	rows, err := service.db.QueryContext(ctx, `
		SELECT c.aws_account_db_id, c.aws_account_id, c.display_name,
		       COALESCE(d.total, 0), COALESCE(d.stale, 0),
		       COALESCE(f.open, 0), COALESCE(f.suspect, 0),
		       COALESCE(f.pending, 0), COALESCE(f.rebaseline, 0),
		       c.last_drift_check_at, c.last_drift_clean_at,
		       c.last_drift_skipped_files, c.last_drift_stale_files
		FROM aws_account_config c
		LEFT JOIN (
			SELECT account_id, COUNT(*) AS total,
			       COUNT(*) FILTER (WHERE stale_at IS NOT NULL) AS stale
			FROM iam_baseline_declaration
			WHERE superseded_at IS NULL
			GROUP BY account_id
		) d ON d.account_id = c.aws_account_db_id
		LEFT JOIN (
			SELECT account_id,
			       COUNT(*) FILTER (WHERE status <> 'IGNORED') AS open,
			       COUNT(*) FILTER (WHERE status = 'SUSPECT') AS suspect,
			       COUNT(*) FILTER (WHERE status = 'PENDING') AS pending,
			       COUNT(*) FILTER (WHERE status = 'PENDING_REBASELINE') AS rebaseline
			FROM iam_drift_finding
			WHERE resolved_at IS NULL
			GROUP BY account_id
		) f ON f.account_id = c.aws_account_db_id
		`+condition+`
		ORDER BY c.aws_account_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("summarize drift accounts: %w", err)
	}
	defer rows.Close()
	summaries := make([]DriftAccountSummary, 0, 16)
	for rows.Next() {
		var summary DriftAccountSummary
		var accountDBID sql.NullInt64
		var lastCheck, lastClean sql.NullTime
		if err := rows.Scan(&accountDBID, &summary.AWSAccountID, &summary.DisplayName,
			&summary.Declarations, &summary.StaleDeclarations,
			&summary.Open, &summary.Suspect, &summary.Pending, &summary.PendingRebaseline,
			&lastCheck, &lastClean,
			&summary.LastSkippedFiles, &summary.LastStaleFiles); err != nil {
			return nil, fmt.Errorf("scan drift account summary: %w", err)
		}
		summary.AccountDBID = accountDBID.Int64
		if lastCheck.Valid {
			at := lastCheck.Time
			summary.LastCheckAt = &at
		}
		if lastClean.Valid {
			at := lastClean.Time
			summary.LastCleanAt = &at
		}
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

// CountUnresolved 给 Dashboard 用：不拉明细，只要一个数。
func (service *DriftService) CountUnresolved(ctx context.Context) (int, error) {
	var count int
	if err := service.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_drift_finding
		WHERE resolved_at IS NULL AND status <> 'IGNORED'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count unresolved drift findings: %w", err)
	}
	return count, nil
}

func scanDriftFinding(scanner interface {
	Scan(dest ...any) error
}) (DriftFinding, error) {
	var finding DriftFinding
	var fields string
	var summaryParams string
	var publicationID sql.NullInt64
	var resolvedAt sql.NullTime
	if err := scanner.Scan(&finding.ID, &finding.AccountDBID, &finding.AWSAccountID,
		&finding.Source, &finding.ResourceKey, &finding.ResourceAddress, &finding.Kind,
		&finding.FileKey, &finding.ChangeType, &fields, &finding.Severity,
		&finding.Status, &publicationID, &finding.Summary, &finding.SummaryCode,
		&summaryParams, &finding.CIURL,
		&finding.CommitSHA, &finding.FirstSeenAt, &finding.LastSeenAt,
		&finding.Occurrences, &resolvedAt, &finding.ResolvedBy); err != nil {
		return DriftFinding{}, err
	}
	if strings.TrimSpace(summaryParams) != "" {
		if err := json.Unmarshal([]byte(summaryParams), &finding.SummaryParams); err != nil {
			return DriftFinding{}, fmt.Errorf("decode drift summary params: %w", err)
		}
	}
	if len(finding.SummaryParams) == 0 {
		finding.SummaryParams = nil
	}
	if strings.TrimSpace(fields) != "" {
		if err := json.Unmarshal([]byte(fields), &finding.Fields); err != nil {
			return DriftFinding{}, fmt.Errorf("decode drift fields: %w", err)
		}
	}
	if finding.Fields == nil {
		finding.Fields = []DriftFieldDiff{}
	}
	if publicationID.Valid {
		id := publicationID.Int64
		finding.BaselinePublicationID = &id
	}
	if resolvedAt.Valid {
		at := resolvedAt.Time
		finding.ResolvedAt = &at
	}
	return finding, nil
}
