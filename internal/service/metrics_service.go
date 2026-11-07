package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// MetricsService provides Prometheus-compatible metrics for the platform.
type MetricsService struct {
	db          *sql.DB
	redisClient *redis.Client
}

// NewMetricsService creates a new MetricsService.
func NewMetricsService(db *sql.DB, redisClient *redis.Client) (*MetricsService, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection must not be nil")
	}
	if redisClient == nil {
		return nil, fmt.Errorf("redis client must not be nil")
	}
	return &MetricsService{
		db:          db,
		redisClient: redisClient,
	}, nil
}

// RenderMetrics returns all metrics in Prometheus text format.
func (s *MetricsService) RenderMetrics(ctx context.Context) (string, error) {
	var sb strings.Builder

	// Ticket metrics
	ticketMetrics, err := s.collectTicketMetrics(ctx)
	if err != nil {
		return "", fmt.Errorf("collect ticket metrics: %w", err)
	}
	sb.WriteString(ticketMetrics)

	// Sync metrics
	syncMetrics, err := s.collectSyncMetrics(ctx)
	if err != nil {
		return "", fmt.Errorf("collect sync metrics: %w", err)
	}
	sb.WriteString(syncMetrics)

	// Queue metrics
	queueMetrics, err := s.collectQueueMetrics(ctx)
	if err != nil {
		return "", fmt.Errorf("collect queue metrics: %w", err)
	}
	sb.WriteString(queueMetrics)

	return sb.String(), nil
}

func (s *MetricsService) collectTicketMetrics(ctx context.Context) (string, error) {
	var sb strings.Builder

	// Ticket count by status
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM iam_ticket GROUP BY status`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	sb.WriteString("# HELP finops_tickets_total Total tickets by status\n")
	sb.WriteString("# TYPE finops_tickets_total gauge\n")
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("finops_tickets_total{status=%q} %d\n", status, count))
	}

	// Total tickets
	var totalTickets int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM iam_ticket`).Scan(&totalTickets)
	if err != nil {
		return "", err
	}
	sb.WriteString("# HELP finops_tickets_total_count Total tickets count\n")
	sb.WriteString("# TYPE finops_tickets_total_count gauge\n")
	sb.WriteString(fmt.Sprintf("finops_tickets_total_count %d\n", totalTickets))

	// Execution records count
	var executionRecords int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM iac_execution_record`).Scan(&executionRecords)
	if err != nil {
		return "", err
	}
	sb.WriteString("# HELP finops_execution_records_total Total execution records\n")
	sb.WriteString("# TYPE finops_execution_records_total gauge\n")
	sb.WriteString(fmt.Sprintf("finops_execution_records_total %d\n", executionRecords))

	// Failed execution records
	var failedRecords int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM iac_execution_record WHERE apply_result = 'FAILED'`).Scan(&failedRecords)
	if err != nil {
		return "", err
	}
	sb.WriteString("# HELP finops_execution_records_failed_total Total failed execution records\n")
	sb.WriteString("# TYPE finops_execution_records_failed_total gauge\n")
	sb.WriteString(fmt.Sprintf("finops_execution_records_failed_total %d\n", failedRecords))

	return sb.String(), nil
}

func (s *MetricsService) collectSyncMetrics(ctx context.Context) (string, error) {
	var sb strings.Builder

	// Account config sync status
	rows, err := s.db.QueryContext(ctx, `SELECT sync_status, COUNT(*) FROM aws_account_config GROUP BY sync_status`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	sb.WriteString("# HELP finops_sync_status_total Accounts by sync status\n")
	sb.WriteString("# TYPE finops_sync_status_total gauge\n")
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("finops_sync_status_total{status=%q} %d\n", status, count))
	}

	// Total accounts
	var totalAccounts int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM aws_account_config`).Scan(&totalAccounts)
	if err != nil {
		return "", err
	}
	sb.WriteString("# HELP finops_accounts_total Total accounts\n")
	sb.WriteString("# TYPE finops_accounts_total gauge\n")
	sb.WriteString(fmt.Sprintf("finops_accounts_total %d\n", totalAccounts))

	return sb.String(), nil
}

func (s *MetricsService) collectQueueMetrics(ctx context.Context) (string, error) {
	var sb strings.Builder

	// Worker heartbeat status
	heartbeatKey := "worker:heartbeat:gitstatus"
	heartbeatVal, err := s.redisClient.Get(ctx, heartbeatKey).Result()
	if err == redis.Nil {
		sb.WriteString("# HELP finops_worker_heartbeat_last Last worker heartbeat timestamp\n")
		sb.WriteString("# TYPE finops_worker_heartbeat_last Gauge\n")
		sb.WriteString("finops_worker_heartbeat_last 0\n")
	} else if err != nil {
		return "", err
	} else {
		// Parse heartbeat time
		heartbeatTime, parseErr := time.Parse(time.RFC3339, heartbeatVal)
		if parseErr != nil {
			return "", parseErr
		}
		sb.WriteString("# HELP finops_worker_heartbeat_last Last worker heartbeat timestamp\n")
		sb.WriteString("# TYPE finops_worker_heartbeat_last Gauge\n")
		sb.WriteString(fmt.Sprintf("finops_worker_heartbeat_last %d\n", heartbeatTime.Unix()))
	}

	// Queue depth (approximate via Redis list length)
	queueDepth, err := s.redisClient.LLen(ctx, "asynq:{gitstatus:poll}").Result()
	if err != nil {
		// Queue may not exist yet, that's OK
		queueDepth = 0
	}
	sb.WriteString("# HELP finops_queue_depth Current queue depth\n")
	sb.WriteString("# TYPE finops_queue_depth Gauge\n")
	sb.WriteString(fmt.Sprintf("finops_queue_depth %d\n", queueDepth))

	return sb.String(), nil
}
