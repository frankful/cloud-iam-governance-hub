package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/pkg/oteltrace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	PMapperGraphTaskType = "pmapper:graph:build"

	// PMapperQueueName isolates graph-build tasks from other workers.
	PMapperQueueName = "pmapper"

	inputPathPlaceholder  = "{input}"
	outputPathPlaceholder = "{output}"
)

// PMapperConfig defines the CLI command contract for the installed PMapper
// version. ImportArgs and ExportArgs must each contain the corresponding path
// placeholder.
type PMapperConfig struct {
	Binary     string
	ImportArgs []string
	ExportArgs []string
	Timeout    time.Duration
	TempDir    string
}

// PMapperCommandRunner makes command execution replaceable in unit tests.
type PMapperCommandRunner interface {
	Run(ctx context.Context, binary string, args ...string) ([]byte, error)
}

type execPMapperCommandRunner struct{}

func (execPMapperCommandRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}

// IAMRelationshipRepository stores the exported PMapper relationship records.
type IAMRelationshipRepository interface {
	CreateRelationships(ctx context.Context, relationships []model.IAMRelationship) error
}

// SQLIAMRelationshipRepository inserts relationships using parameterized SQL.
type SQLIAMRelationshipRepository struct {
	db *sql.DB
}

func NewSQLIAMRelationshipRepository(db *sql.DB) (*SQLIAMRelationshipRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLIAMRelationshipRepository{db: db}, nil
}

func (repository *SQLIAMRelationshipRepository) CreateRelationships(
	ctx context.Context,
	relationships []model.IAMRelationship,
) error {
	if len(relationships) == 0 {
		return nil
	}

	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin relationship transaction: %w", err)
	}
	defer transaction.Rollback()

	const query = `INSERT INTO iam_relationship
		(principal_id, action, resource, source_json, sync_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	for index, relationship := range relationships {
		if _, err := transaction.ExecContext(ctx, query,
			relationship.PrincipalID,
			relationship.Action,
			relationship.Resource,
			relationship.SourceJSON,
			relationship.SyncVersion,
			relationship.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert IAM relationship %d: %w", index, err)
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit IAM relationship transaction: %w", err)
	}
	return nil
}

// PMapperGraphService imports IAM principal data, exports the graph, and stores
// its normalized relationship records.
type PMapperGraphService struct {
	config PMapperConfig
	runner PMapperCommandRunner
	repo   IAMRelationshipRepository
	logger *slog.Logger
}

func NewPMapperGraphService(
	config PMapperConfig,
	repository IAMRelationshipRepository,
	logger *slog.Logger,
) (*PMapperGraphService, error) {
	return newPMapperGraphService(config, repository, logger, execPMapperCommandRunner{})
}

func newPMapperGraphService(
	config PMapperConfig,
	repository IAMRelationshipRepository,
	logger *slog.Logger,
	runner PMapperCommandRunner,
) (*PMapperGraphService, error) {
	if config.Binary == "" {
		return nil, errors.New("PMapper binary must not be empty")
	}
	if !hasPlaceholder(config.ImportArgs, inputPathPlaceholder) {
		return nil, fmt.Errorf("PMapper import args must contain %s", inputPathPlaceholder)
	}
	if !hasPlaceholder(config.ExportArgs, outputPathPlaceholder) {
		return nil, fmt.Errorf("PMapper export args must contain %s", outputPathPlaceholder)
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Minute
	}
	if repository == nil {
		return nil, errors.New("IAM relationship repository must not be nil")
	}
	if runner == nil {
		return nil, errors.New("PMapper command runner must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &PMapperGraphService{
		config: config,
		runner: runner,
		repo:   repository,
		logger: logger,
	}, nil
}

// BuildGraph runs PMapper and persists its normalized relationship output.
func (service *PMapperGraphService) BuildGraph(
	ctx context.Context,
	principals []model.IAMPrincipal,
) error {
	if len(principals) == 0 {
		return errors.New("at least one IAM principal is required")
	}

	principalIDs := make(map[string]int64, len(principals))
	for _, principal := range principals {
		if principal.ID <= 0 || strings.TrimSpace(principal.ARN) == "" {
			return fmt.Errorf("principal must have a positive ID and non-empty ARN")
		}
		if _, exists := principalIDs[principal.ARN]; exists {
			return fmt.Errorf("duplicate IAM principal ARN %q", principal.ARN)
		}
		principalIDs[principal.ARN] = principal.ID
	}

	runContext, cancel := context.WithTimeout(ctx, service.config.Timeout)
	defer cancel()

	tempDir, err := os.MkdirTemp(service.config.TempDir, "pmapper-graph-*")
	if err != nil {
		return fmt.Errorf("create PMapper working directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			service.logger.Error("remove PMapper working directory", "error", err)
		}
	}()

	inputFile := filepath.Join(tempDir, "principals.json")
	outputFile := filepath.Join(tempDir, "graph.json")
	input, err := json.Marshal(principals)
	if err != nil {
		return fmt.Errorf("marshal IAM principal input: %w", err)
	}
	if err := os.WriteFile(inputFile, input, 0o600); err != nil {
		return fmt.Errorf("write PMapper principal input: %w", err)
	}

	importArgs := replacePathPlaceholder(service.config.ImportArgs, inputPathPlaceholder, inputFile)
	output, err := service.runner.Run(runContext, service.config.Binary, importArgs...)
	if err != nil {
		if runContext.Err() != nil {
			return fmt.Errorf("PMapper import timed out or was cancelled: %w", runContext.Err())
		}
		return commandError("import", output, err)
	}

	exportArgs := replacePathPlaceholder(service.config.ExportArgs, outputPathPlaceholder, outputFile)
	output, err = service.runner.Run(runContext, service.config.Binary, exportArgs...)
	if err != nil {
		if runContext.Err() != nil {
			return fmt.Errorf("PMapper graph export timed out or was cancelled: %w", runContext.Err())
		}
		return commandError("graph export", output, err)
	}

	graphJSON, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("read PMapper graph export: %w", err)
	}
	exported, err := parsePMapperGraph(graphJSON)
	if err != nil {
		return fmt.Errorf("parse PMapper graph export: %w", err)
	}

	syncVersion := graphSyncVersion(graphJSON)
	relationships := make([]model.IAMRelationship, 0, len(exported))
	for index, edge := range exported {
		principalID, ok := principalIDs[edge.PrincipalARN]
		if !ok {
			return fmt.Errorf("PMapper relationship %d references unknown principal ARN %q", index, edge.PrincipalARN)
		}
		if strings.TrimSpace(edge.Action) == "" || strings.TrimSpace(edge.Resource) == "" {
			return fmt.Errorf("PMapper relationship %d must include action and resource", index)
		}

		relationships = append(relationships, model.IAMRelationship{
			PrincipalID: int64Pointer(principalID),
			Action:      edge.Action,
			Resource:    edge.Resource,
			SourceJSON:  model.JSONB(edge.SourceJSON),
			SyncVersion: stringPointer(syncVersion),
			CreatedAt:   time.Now().UTC(),
		})
	}

	if err := service.repo.CreateRelationships(runContext, relationships); err != nil {
		return fmt.Errorf("persist PMapper relationships: %w", err)
	}

	service.logger.Info("PMapper graph imported",
		"principal_count", len(principals),
		"relationship_count", len(relationships),
		"sync_version", syncVersion,
	)
	return nil
}

// pMapperGraphTaskPayload is the Asynq payload for graph builds. Traceparent
// keeps traces continuous across the queue (asynq has no task headers);
// legacy tasks were a bare principal array and stay decodable.
type pMapperGraphTaskPayload struct {
	Principals  []model.IAMPrincipal `json:"principals"`
	Traceparent string               `json:"traceparent,omitempty"`
}

// NewPMapperGraphTask creates an Asynq task carrying IAM principal input.
func NewPMapperGraphTask(principals []model.IAMPrincipal) (*asynq.Task, error) {
	return newPMapperGraphTask(principals, "")
}

func newPMapperGraphTask(principals []model.IAMPrincipal, traceparent string) (*asynq.Task, error) {
	if len(principals) == 0 {
		return nil, errors.New("at least one IAM principal is required")
	}
	for _, principal := range principals {
		if principal.ID <= 0 || strings.TrimSpace(principal.ARN) == "" {
			return nil, errors.New("PMapper task principals must have a positive persisted ID and non-empty ARN")
		}
	}
	payload, err := json.Marshal(pMapperGraphTaskPayload{Principals: principals, Traceparent: traceparent})
	if err != nil {
		return nil, fmt.Errorf("marshal PMapper task payload: %w", err)
	}
	return asynq.NewTask(PMapperGraphTaskType, payload), nil
}

// EnqueuePMapperGraphBuild queues an asynchronous PMapper graph build.
func EnqueuePMapperGraphBuild(
	ctx context.Context,
	client *asynq.Client,
	principals []model.IAMPrincipal,
	options ...asynq.Option,
) (*asynq.TaskInfo, error) {
	if client == nil {
		return nil, errors.New("Asynq client must not be nil")
	}
	task, err := newPMapperGraphTask(principals, oteltrace.TraceParentFromContext(ctx))
	if err != nil {
		return nil, err
	}
	options = append([]asynq.Option{asynq.Queue(PMapperQueueName)}, options...)
	info, err := client.EnqueueContext(ctx, task, options...)
	if err != nil {
		return nil, fmt.Errorf("enqueue PMapper graph task: %w", err)
	}
	return info, nil
}

// HandlePMapperGraphTask adapts an Asynq task to BuildGraph.
func (service *PMapperGraphService) HandlePMapperGraphTask(
	ctx context.Context,
	task *asynq.Task,
) (err error) {
	if task == nil {
		return errors.New("PMapper graph task must not be nil")
	}
	if task.Type() != PMapperGraphTaskType {
		return fmt.Errorf("unexpected task type %q", task.Type())
	}

	var payload pMapperGraphTaskPayload
	if decodeErr := json.Unmarshal(task.Payload(), &payload); decodeErr != nil {
		// Legacy tasks carried a bare principal array without trace context.
		var principals []model.IAMPrincipal
		if legacyErr := json.Unmarshal(task.Payload(), &principals); legacyErr != nil {
			return fmt.Errorf("decode PMapper graph task payload: %w", legacyErr)
		}
		payload.Principals = principals
	}

	ctx = oteltrace.ContextWithTraceParent(ctx, payload.Traceparent)
	ctx, span := otel.Tracer("finops/pmapper").Start(ctx, "pmapper.build_graph",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(attribute.Int("principal_count", len(payload.Principals))))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if buildErr := service.BuildGraph(ctx, payload.Principals); buildErr != nil {
		service.logger.Error("PMapper graph task failed", "error", buildErr)
		return buildErr
	}
	return nil
}

type pMapperGraphExport struct {
	Relationships []json.RawMessage `json:"relationships"`
}

type pMapperRelationship struct {
	PrincipalARN string `json:"principal_arn"`
	Action       string `json:"action"`
	Resource     string `json:"resource"`
	SourceJSON   []byte `json:"-"`
}

func parsePMapperGraph(data []byte) ([]pMapperRelationship, error) {
	var rawRelationships []json.RawMessage
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &rawRelationships); err != nil {
			return nil, fmt.Errorf("decode relationships array: %w", err)
		}
	} else {
		var graph pMapperGraphExport
		if err := json.Unmarshal(data, &graph); err != nil {
			return nil, fmt.Errorf("decode relationships object: %w", err)
		}
		rawRelationships = graph.Relationships
		if rawRelationships == nil {
			return nil, errors.New("graph JSON does not contain a relationships array")
		}
	}

	relationships := make([]pMapperRelationship, 0, len(rawRelationships))
	for index, raw := range rawRelationships {
		var relationship pMapperRelationship
		if err := json.Unmarshal(raw, &relationship); err != nil {
			return nil, fmt.Errorf("decode relationship %d: %w", index, err)
		}
		relationship.SourceJSON = append([]byte(nil), raw...)
		relationships = append(relationships, relationship)
	}
	return relationships, nil
}

func commandError(operation string, output []byte, err error) error {
	detail := strings.TrimSpace(string(output))
	if detail != "" {
		return fmt.Errorf("PMapper %s command failed: %w: %s", operation, err, detail)
	}
	return fmt.Errorf("PMapper %s command failed: %w", operation, err)
}

func hasPlaceholder(args []string, placeholder string) bool {
	for _, argument := range args {
		if strings.Contains(argument, placeholder) {
			return true
		}
	}
	return false
}

func replacePathPlaceholder(args []string, placeholder, value string) []string {
	result := make([]string, len(args))
	for index, argument := range args {
		result[index] = strings.ReplaceAll(argument, placeholder, value)
	}
	return result
}

func graphSyncVersion(graphJSON []byte) string {
	checksum := sha256.Sum256(graphJSON)
	return hex.EncodeToString(checksum[:])
}

func int64Pointer(value int64) *int64 {
	return &value
}

func stringPointer(value string) *string {
	return &value
}
