package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DashboardSummary is the aggregated overview behind GET /dashboard/summary.
// Counts are grouped by the live status columns rather than hardcoded values,
// so new states appear without a backend change.
type DashboardSummary struct {
	Tickets     DashboardTickets   `json:"tickets"`
	Risks       DashboardRisks     `json:"risks"`
	Inventory   DashboardInventory `json:"inventory"`
	Sync        DashboardSync      `json:"sync"`
	Drift       DashboardDrift     `json:"drift"`
	GeneratedAt time.Time          `json:"generated_at"`
}

// DashboardTickets aggregates the ticket lifecycle.
type DashboardTickets struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// DashboardRisks aggregates unresolved IAM risks.
type DashboardRisks struct {
	Open        int            `json:"open"`
	OpenByLevel map[string]int `json:"open_by_level"`
}

// DashboardInventory counts inventoried principals and groups.
type DashboardInventory struct {
	Users  int `json:"users"`
	Roles  int `json:"roles"`
	Groups int `json:"groups"`
}

// DashboardSync aggregates account sync configuration and recent runs.
type DashboardSync struct {
	ConfigsTotal        int            `json:"configs_total"`
	ConfigsEnabled      int            `json:"configs_enabled"`
	BySyncStatus        map[string]int `json:"by_sync_status"`
	RunsLast24hByStatus map[string]int `json:"runs_last_24h_by_status"`
}

// DashboardDrift aggregates unresolved drift findings (phase4 §8). 页面要能
// 一眼看出「有漂移」与「根本没检测」：Unresolved 只统计未解决的发现，
// 覆盖缺口由 drift 页显式呈现。
type DashboardDrift struct {
	Unresolved int            `json:"unresolved"`
	ByStatus   map[string]int `json:"by_status"`
	BySeverity map[string]int `json:"by_severity"`
}

// DashboardService computes dashboard aggregates in a handful of COUNT queries.
type DashboardService struct {
	db *sql.DB
}

// NewDashboardService creates a DashboardService.
func NewDashboardService(database *sql.DB) (*DashboardService, error) {
	if database == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &DashboardService{db: database}, nil
}

// Summary returns the aggregated dashboard payload.
func (service *DashboardService) Summary(ctx context.Context) (DashboardSummary, error) {
	summary := DashboardSummary{
		Tickets: DashboardTickets{ByStatus: map[string]int{}},
		Risks:   DashboardRisks{OpenByLevel: map[string]int{}},
		Sync: DashboardSync{
			BySyncStatus:        map[string]int{},
			RunsLast24hByStatus: map[string]int{},
		},
		Drift: DashboardDrift{
			ByStatus:   map[string]int{},
			BySeverity: map[string]int{},
		},
		GeneratedAt: time.Now().UTC(),
	}

	if err := service.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM iam_ticket`).Scan(&summary.Tickets.Total); err != nil {
		return DashboardSummary{}, fmt.Errorf("count tickets: %w", err)
	}
	ticketRows, err := service.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM iam_ticket GROUP BY status`)
	if err != nil {
		return DashboardSummary{}, fmt.Errorf("count tickets by status: %w", err)
	}
	summary.Tickets.ByStatus, err = readCountGroups(ticketRows)
	if err != nil {
		return DashboardSummary{}, err
	}

	if err := service.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM iam_risk WHERE is_resolved = FALSE`).
		Scan(&summary.Risks.Open); err != nil {
		return DashboardSummary{}, fmt.Errorf("count open risks: %w", err)
	}
	riskRows, err := service.db.QueryContext(ctx,
		`SELECT COALESCE(risk_level, 'UNKNOWN'), COUNT(*) FROM iam_risk
		WHERE is_resolved = FALSE GROUP BY COALESCE(risk_level, 'UNKNOWN')`)
	if err != nil {
		return DashboardSummary{}, fmt.Errorf("count open risks by level: %w", err)
	}
	summary.Risks.OpenByLevel, err = readCountGroups(riskRows)
	if err != nil {
		return DashboardSummary{}, err
	}

	if err := service.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FILTER (WHERE principal_type = 'User'),
				COUNT(*) FILTER (WHERE principal_type = 'Role')
		FROM iam_principal WHERE is_deleted = FALSE`).
		Scan(&summary.Inventory.Users, &summary.Inventory.Roles); err != nil {
		return DashboardSummary{}, fmt.Errorf("count principals: %w", err)
	}
	if err := service.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM iam_group`).Scan(&summary.Inventory.Groups); err != nil {
		return DashboardSummary{}, fmt.Errorf("count groups: %w", err)
	}

	if err := service.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE sync_enabled)
		FROM aws_account_config`).
		Scan(&summary.Sync.ConfigsTotal, &summary.Sync.ConfigsEnabled); err != nil {
		return DashboardSummary{}, fmt.Errorf("count account configs: %w", err)
	}
	configRows, err := service.db.QueryContext(ctx,
		`SELECT sync_status, COUNT(*) FROM aws_account_config GROUP BY sync_status`)
	if err != nil {
		return DashboardSummary{}, fmt.Errorf("count configs by sync status: %w", err)
	}
	summary.Sync.BySyncStatus, err = readCountGroups(configRows)
	if err != nil {
		return DashboardSummary{}, err
	}

	runRows, err := service.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM aws_sync_run
		WHERE created_at >= NOW() - INTERVAL '24 hours' GROUP BY status`)
	if err != nil {
		return DashboardSummary{}, fmt.Errorf("count sync runs by status: %w", err)
	}
	summary.Sync.RunsLast24hByStatus, err = readCountGroups(runRows)
	if err != nil {
		return DashboardSummary{}, err
	}

	// 漂移：一条查询拿 (status, severity) 再在内存里分组，避免两条几乎
	// 相同的扫描。IGNORED 不计入 unresolved：人已经决定不处理。
	driftRows, err := service.db.QueryContext(ctx,
		`SELECT status, severity FROM iam_drift_finding
		WHERE resolved_at IS NULL AND status <> 'IGNORED'`)
	if err != nil {
		return DashboardSummary{}, fmt.Errorf("count drift findings: %w", err)
	}
	for driftRows.Next() {
		var status, severity string
		if err := driftRows.Scan(&status, &severity); err != nil {
			driftRows.Close()
			return DashboardSummary{}, fmt.Errorf("scan drift finding: %w", err)
		}
		summary.Drift.Unresolved++
		summary.Drift.ByStatus[status]++
		summary.Drift.BySeverity[severity]++
	}
	if err := driftRows.Err(); err != nil {
		driftRows.Close()
		return DashboardSummary{}, fmt.Errorf("iterate drift findings: %w", err)
	}
	driftRows.Close()

	return summary, nil
}

// readCountGroups drains a two-column (key, count) result set.
func readCountGroups(rows *sql.Rows) (map[string]int, error) {
	defer rows.Close()
	groups := map[string]int{}
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return nil, fmt.Errorf("scan count group: %w", err)
		}
		groups[key] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate count groups: %w", err)
	}
	return groups, nil
}
