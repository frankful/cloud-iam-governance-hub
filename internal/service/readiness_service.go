package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ReadinessService provides comprehensive health checks for Kubernetes readiness probes.
type ReadinessService struct {
	db          *sql.DB
	redisClient *redis.Client
}

// NewReadinessService creates a new ReadinessService.
func NewReadinessService(db *sql.DB, redisClient *redis.Client) (*ReadinessService, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection must not be nil")
	}
	if redisClient == nil {
		return nil, fmt.Errorf("redis client must not be nil")
	}
	return &ReadinessService{
		db:          db,
		redisClient: redisClient,
	}, nil
}

// ReadinessStatus represents the overall readiness status.
type ReadinessStatus struct {
	Status     string            `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Components []ComponentStatus `json:"components"`
}

// ComponentStatus represents the status of an individual component.
type ComponentStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// CheckReadiness performs comprehensive health checks for all components.
func (s *ReadinessService) CheckReadiness(ctx context.Context) ReadinessStatus {
	status := ReadinessStatus{
		Status:     "ready",
		Timestamp:  time.Now(),
		Components: make([]ComponentStatus, 0, 3),
	}

	// Check PostgreSQL
	pgStatus := s.checkPostgreSQL(ctx)
	status.Components = append(status.Components, pgStatus)
	if pgStatus.Status != "ready" {
		status.Status = "not_ready"
	}

	// Check Redis
	redisStatus := s.checkRedis(ctx)
	status.Components = append(status.Components, redisStatus)
	if redisStatus.Status != "ready" {
		status.Status = "not_ready"
	}

	// Check Worker heartbeat
	workerStatus := s.checkWorkerHeartbeat(ctx)
	status.Components = append(status.Components, workerStatus)
	if workerStatus.Status != "ready" {
		status.Status = "not_ready"
	}

	return status
}

func (s *ReadinessService) checkPostgreSQL(ctx context.Context) ComponentStatus {
	start := time.Now()
	err := s.db.PingContext(ctx)
	latency := time.Since(start)

	if err != nil {
		return ComponentStatus{
			Name:    "postgres",
			Status:  "not_ready",
			Message: err.Error(),
			Latency: latency.String(),
		}
	}
	return ComponentStatus{
		Name:    "postgres",
		Status:  "ready",
		Latency: latency.String(),
	}
}

func (s *ReadinessService) checkRedis(ctx context.Context) ComponentStatus {
	start := time.Now()
	err := s.redisClient.Ping(ctx).Err()
	latency := time.Since(start)

	if err != nil {
		return ComponentStatus{
			Name:    "redis",
			Status:  "not_ready",
			Message: err.Error(),
			Latency: latency.String(),
		}
	}
	return ComponentStatus{
		Name:    "redis",
		Status:  "ready",
		Latency: latency.String(),
	}
}

func (s *ReadinessService) checkWorkerHeartbeat(ctx context.Context) ComponentStatus {
	start := time.Now()

	// Check if worker heartbeat exists in Redis
	// Workers should write a heartbeat key with TTL
	heartbeatKey := "worker:heartbeat:gitstatus"
	val, err := s.redisClient.Get(ctx, heartbeatKey).Result()
	latency := time.Since(start)

	if err == redis.Nil {
		return ComponentStatus{
			Name:    "worker",
			Status:  "not_ready",
			Message: "no worker heartbeat found",
			Latency: latency.String(),
		}
	}
	if err != nil {
		return ComponentStatus{
			Name:    "worker",
			Status:  "not_ready",
			Message: err.Error(),
			Latency: latency.String(),
		}
	}

	return ComponentStatus{
		Name:    "worker",
		Status:  "ready",
		Message: fmt.Sprintf("last heartbeat: %s", val),
		Latency: latency.String(),
	}
}
