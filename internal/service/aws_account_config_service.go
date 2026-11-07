package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

const (
	AWSAccountSyncAssumeRole         = "ASSUME_ROLE"
	AWSAccountSyncCurrentCredentials = "CURRENT_CREDENTIALS"
)

var (
	ErrAWSAccountConfigNotFound = errors.New("AWS account configuration not found")
	ErrAWSAccountConfigConflict = errors.New("AWS account configuration already exists")
	ErrAWSAccountConfigChanged  = errors.New("AWS account configuration changed during validation")
	ErrAWSAccountConnectivity   = errors.New("AWS account connectivity test failed")
	accountIDPattern            = regexp.MustCompile(`^[0-9]{12}$`)
	accountRoleARNPattern       = regexp.MustCompile(`^arn:aws(?:-[a-z0-9-]+)?:iam::([0-9]{12}):role/.+$`)
)

type AWSAccountConfigValidationError struct {
	Err error
}

func (validationError *AWSAccountConfigValidationError) Error() string {
	return validationError.Err.Error()
}

func (validationError *AWSAccountConfigValidationError) Unwrap() error {
	return validationError.Err
}

type AWSAccountConfigInput struct {
	AWSAccountID     string          `json:"aws_account_id"`
	OrganizationDBID *int64          `json:"organization_db_id,omitempty"`
	DisplayName      string          `json:"display_name"`
	ReadOnlyRoleARN  *string         `json:"read_only_role_arn,omitempty"`
	SyncMode         string          `json:"sync_mode"`
	SyncEnabled      bool            `json:"sync_enabled"`
	Tags             json.RawMessage `json:"tags,omitempty"`
}

type AWSAccountConnectionIdentity struct {
	AccountID string
	ARN       string
}

type AWSAccountConnectivityValidator interface {
	Validate(ctx context.Context, config AWSAccountConfigInput) (AWSAccountConnectionIdentity, error)
}

type AWSAccountConfigRepository interface {
	Create(ctx context.Context, config AWSAccountConfigInput, actorID string) (model.AWSAccountConfig, error)
	Update(ctx context.Context, id int64, config AWSAccountConfigInput, actorID string) (model.AWSAccountConfig, error)
	Get(ctx context.Context, id int64) (model.AWSAccountConfig, error)
	List(ctx context.Context, limit, offset int) ([]model.AWSAccountConfig, error)
	SetSyncEnabled(ctx context.Context, id int64, enabled bool, actorID string, expectedUpdatedAt *time.Time) (model.AWSAccountConfig, error)
	RecordConnectionTest(ctx context.Context, id int64, actorID, outcome, message string) error
}

type AWSAccountConfigService struct {
	repository AWSAccountConfigRepository
	validator  AWSAccountConnectivityValidator
	logger     *slog.Logger
}

func NewAWSAccountConfigService(
	repository AWSAccountConfigRepository,
	validator AWSAccountConnectivityValidator,
	logger *slog.Logger,
) (*AWSAccountConfigService, error) {
	if repository == nil {
		return nil, errors.New("AWS account config repository must not be nil")
	}
	if validator == nil {
		return nil, errors.New("AWS account connectivity validator must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AWSAccountConfigService{repository: repository, validator: validator, logger: logger}, nil
}

func (service *AWSAccountConfigService) Create(
	ctx context.Context,
	input AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	input, err := normalizeAWSAccountConfigInput(input)
	if err != nil {
		return model.AWSAccountConfig{}, &AWSAccountConfigValidationError{Err: err}
	}
	actorID, err = validateConfigActor(actorID)
	if err != nil {
		return model.AWSAccountConfig{}, err
	}
	if _, err := service.validator.Validate(ctx, input); err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("%w: %v", ErrAWSAccountConnectivity, err)
	}
	config, err := service.repository.Create(ctx, input, actorID)
	if errors.Is(err, ErrAWSAccountConfigConflict) {
		return model.AWSAccountConfig{}, err
	}
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("create AWS account configuration: %w", err)
	}
	return config, nil
}

func (service *AWSAccountConfigService) Update(
	ctx context.Context,
	id int64,
	input AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	if id <= 0 {
		return model.AWSAccountConfig{}, errors.New("configuration ID must be positive")
	}
	input, err := normalizeAWSAccountConfigInput(input)
	if err != nil {
		return model.AWSAccountConfig{}, &AWSAccountConfigValidationError{Err: err}
	}
	current, err := service.repository.Get(ctx, id)
	if err != nil {
		return model.AWSAccountConfig{}, err
	}
	if current.AWSAccountID != input.AWSAccountID {
		return model.AWSAccountConfig{}, &AWSAccountConfigValidationError{
			Err: errors.New("AWS account ID cannot be changed"),
		}
	}
	actorID, err = validateConfigActor(actorID)
	if err != nil {
		return model.AWSAccountConfig{}, err
	}
	if _, err := service.validator.Validate(ctx, input); err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("%w: %v", ErrAWSAccountConnectivity, err)
	}
	config, err := service.repository.Update(ctx, id, input, actorID)
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("update AWS account configuration: %w", err)
	}
	return config, nil
}

func (service *AWSAccountConfigService) Get(ctx context.Context, id int64) (model.AWSAccountConfig, error) {
	if id <= 0 {
		return model.AWSAccountConfig{}, errors.New("configuration ID must be positive")
	}
	return service.repository.Get(ctx, id)
}

func (service *AWSAccountConfigService) List(
	ctx context.Context,
	limit, offset int,
) ([]model.AWSAccountConfig, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("limit must be between 1 and 100")
	}
	if offset < 0 {
		return nil, errors.New("offset must be non-negative")
	}
	return service.repository.List(ctx, limit, offset)
}

func (service *AWSAccountConfigService) SetSyncEnabled(
	ctx context.Context,
	id int64,
	enabled bool,
	actorID string,
) (model.AWSAccountConfig, error) {
	if id <= 0 {
		return model.AWSAccountConfig{}, errors.New("configuration ID must be positive")
	}
	actorID, err := validateConfigActor(actorID)
	if err != nil {
		return model.AWSAccountConfig{}, err
	}
	var expectedUpdatedAt *time.Time
	if enabled {
		config, err := service.repository.Get(ctx, id)
		if err != nil {
			return model.AWSAccountConfig{}, err
		}
		if _, err := service.validator.Validate(ctx, awsAccountConfigInputFromModel(config)); err != nil {
			return model.AWSAccountConfig{}, fmt.Errorf("%w: %v", ErrAWSAccountConnectivity, err)
		}
		expectedUpdatedAt = &config.UpdatedAt
	}
	config, err := service.repository.SetSyncEnabled(ctx, id, enabled, actorID, expectedUpdatedAt)
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("update AWS account sync toggle: %w", err)
	}
	return config, nil
}

func (service *AWSAccountConfigService) TestConnection(
	ctx context.Context,
	id int64,
	actorID string,
) (AWSAccountConnectionIdentity, error) {
	if id <= 0 {
		return AWSAccountConnectionIdentity{}, errors.New("configuration ID must be positive")
	}
	actorID, err := validateConfigActor(actorID)
	if err != nil {
		return AWSAccountConnectionIdentity{}, err
	}
	config, err := service.repository.Get(ctx, id)
	if err != nil {
		return AWSAccountConnectionIdentity{}, err
	}
	input := awsAccountConfigInputFromModel(config)
	identity, validationErr := service.validator.Validate(ctx, input)
	outcome, message := "SUCCESS", ""
	if validationErr != nil {
		outcome, message = "FAILURE", sanitizeConnectionError(validationErr)
	}
	if err := service.repository.RecordConnectionTest(ctx, id, actorID, outcome, message); err != nil {
		service.logger.Error("record AWS account connectivity test",
			"config_id", id, "actor_id", actorID, "error", err)
		return AWSAccountConnectionIdentity{}, fmt.Errorf("record connectivity test audit: %w", err)
	}
	if validationErr != nil {
		return AWSAccountConnectionIdentity{}, fmt.Errorf("%w: %v", ErrAWSAccountConnectivity, validationErr)
	}
	return identity, nil
}

func normalizeAWSAccountConfigInput(input AWSAccountConfigInput) (AWSAccountConfigInput, error) {
	input.AWSAccountID = strings.TrimSpace(input.AWSAccountID)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.SyncMode = strings.ToUpper(strings.TrimSpace(input.SyncMode))
	if !accountIDPattern.MatchString(input.AWSAccountID) {
		return AWSAccountConfigInput{}, errors.New("aws_account_id must contain exactly 12 digits")
	}
	if input.DisplayName == "" || len(input.DisplayName) > 256 {
		return AWSAccountConfigInput{}, errors.New("display_name must contain 1 to 256 characters")
	}
	if input.OrganizationDBID != nil && *input.OrganizationDBID <= 0 {
		return AWSAccountConfigInput{}, errors.New("organization_db_id must be positive")
	}
	switch input.SyncMode {
	case AWSAccountSyncAssumeRole:
		if input.ReadOnlyRoleARN == nil {
			return AWSAccountConfigInput{}, errors.New("read_only_role_arn is required for ASSUME_ROLE mode")
		}
		roleARN := strings.TrimSpace(*input.ReadOnlyRoleARN)
		matches := accountRoleARNPattern.FindStringSubmatch(roleARN)
		if len(matches) != 2 || matches[1] != input.AWSAccountID {
			return AWSAccountConfigInput{}, errors.New("read_only_role_arn must be an IAM role ARN in the configured AWS account")
		}
		input.ReadOnlyRoleARN = &roleARN
	case AWSAccountSyncCurrentCredentials:
		if input.ReadOnlyRoleARN != nil && strings.TrimSpace(*input.ReadOnlyRoleARN) != "" {
			return AWSAccountConfigInput{}, errors.New("read_only_role_arn must be omitted for CURRENT_CREDENTIALS mode")
		}
		input.ReadOnlyRoleARN = nil
	default:
		return AWSAccountConfigInput{}, errors.New("sync_mode must be ASSUME_ROLE or CURRENT_CREDENTIALS")
	}
	tags := strings.TrimSpace(string(input.Tags))
	if tags == "" || tags == "null" {
		input.Tags = json.RawMessage(`{}`)
	} else {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(input.Tags, &value); err != nil || value == nil {
			return AWSAccountConfigInput{}, errors.New("tags must be a JSON object")
		}
		if len(input.Tags) > 16*1024 {
			return AWSAccountConfigInput{}, errors.New("tags must not exceed 16 KiB")
		}
	}
	return input, nil
}

func validateConfigActor(actorID string) (string, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" || len(actorID) > 128 {
		return "", errors.New("authenticated actor ID must contain 1 to 128 characters")
	}
	return actorID, nil
}

func awsAccountConfigInputFromModel(config model.AWSAccountConfig) AWSAccountConfigInput {
	return AWSAccountConfigInput{
		AWSAccountID: config.AWSAccountID, OrganizationDBID: config.OrganizationDBID,
		DisplayName: config.DisplayName, ReadOnlyRoleARN: config.ReadOnlyRoleARN,
		SyncMode: config.SyncMode, SyncEnabled: config.SyncEnabled,
		Tags: append(json.RawMessage(nil), config.Tags...),
	}
}

func sanitizeConnectionError(err error) string {
	message := strings.TrimSpace(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

type SQLAWSAccountConfigRepository struct {
	db *sql.DB
}

func NewSQLAWSAccountConfigRepository(db *sql.DB) (*SQLAWSAccountConfigRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLAWSAccountConfigRepository{db: db}, nil
}

func (repository *SQLAWSAccountConfigRepository) Create(
	ctx context.Context,
	input AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("begin AWS account config creation: %w", err)
	}
	defer transaction.Rollback()

	config, err := scanAWSAccountConfig(transaction.QueryRowContext(ctx, `INSERT INTO aws_account_config
		(aws_account_id, aws_account_db_id, organization_db_id, display_name,
		 read_only_role_arn, sync_mode, sync_enabled, tags, sync_status,
		 created_by, updated_by, created_at, updated_at)
		VALUES (($1)::VARCHAR, (SELECT id FROM aws_account WHERE account_id = ($1)::VARCHAR), $2, $3,
		 $4, $5, $6, $7::jsonb, CASE WHEN $6 THEN 'NEVER' ELSE 'DISABLED' END,
		 $8, $8, NOW(), NOW())
		RETURNING `+awsAccountConfigColumns,
		input.AWSAccountID, input.OrganizationDBID, input.DisplayName,
		nullableRoleARN(input.ReadOnlyRoleARN), input.SyncMode, input.SyncEnabled,
		string(input.Tags), actorID,
	))
	if err != nil {
		if isUniqueViolation(err) {
			return model.AWSAccountConfig{}, ErrAWSAccountConfigConflict
		}
		return model.AWSAccountConfig{}, fmt.Errorf("insert AWS account config: %w", err)
	}
	if err := writeAWSAccountConfigAudit(ctx, transaction, actorID, "AWS_ACCOUNT_CONFIG_CREATED", config.ID,
		map[string]interface{}{"aws_account_id": config.AWSAccountID, "sync_mode": config.SyncMode}); err != nil {
		return model.AWSAccountConfig{}, err
	}
	if err := transaction.Commit(); err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("commit AWS account config creation: %w", err)
	}
	return config, nil
}

func (repository *SQLAWSAccountConfigRepository) Update(
	ctx context.Context,
	id int64,
	input AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("begin AWS account config update: %w", err)
	}
	defer transaction.Rollback()

	config, err := scanAWSAccountConfig(transaction.QueryRowContext(ctx, `UPDATE aws_account_config SET
		organization_db_id = $2,
		display_name = $3,
		read_only_role_arn = $4,
		sync_mode = $5,
		sync_enabled = $6,
		tags = $7::jsonb,
		sync_status = CASE WHEN $6 THEN
			CASE WHEN sync_status = 'DISABLED' THEN 'NEVER' ELSE sync_status END
			ELSE 'DISABLED' END,
		updated_by = $8,
		updated_at = NOW()
		WHERE id = $1
		RETURNING `+awsAccountConfigColumns,
		id, input.OrganizationDBID, input.DisplayName, nullableRoleARN(input.ReadOnlyRoleARN),
		input.SyncMode, input.SyncEnabled, string(input.Tags), actorID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return model.AWSAccountConfig{}, ErrAWSAccountConfigNotFound
	}
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("update AWS account config: %w", err)
	}
	if err := writeAWSAccountConfigAudit(ctx, transaction, actorID, "AWS_ACCOUNT_CONFIG_UPDATED", id,
		map[string]interface{}{"sync_mode": config.SyncMode, "sync_enabled": config.SyncEnabled}); err != nil {
		return model.AWSAccountConfig{}, err
	}
	if err := transaction.Commit(); err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("commit AWS account config update: %w", err)
	}
	return config, nil
}

func (repository *SQLAWSAccountConfigRepository) Get(
	ctx context.Context,
	id int64,
) (model.AWSAccountConfig, error) {
	config, err := scanAWSAccountConfig(repository.db.QueryRowContext(ctx,
		`SELECT `+awsAccountConfigColumns+` FROM aws_account_config WHERE id = $1`, id,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return model.AWSAccountConfig{}, ErrAWSAccountConfigNotFound
	}
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("get AWS account config: %w", err)
	}
	return config, nil
}

// GetByAccountDBID resolves the config of one aws_account row. Ticket closure
// carries aws_account.id (not the config id), so the closure-triggered sync
// looks the config up through the unique aws_account_db_id column.
func (repository *SQLAWSAccountConfigRepository) GetByAccountDBID(
	ctx context.Context,
	accountDBID int64,
) (model.AWSAccountConfig, error) {
	config, err := scanAWSAccountConfig(repository.db.QueryRowContext(ctx,
		`SELECT `+awsAccountConfigColumns+` FROM aws_account_config WHERE aws_account_db_id = $1`, accountDBID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return model.AWSAccountConfig{}, ErrAWSAccountConfigNotFound
	}
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("get AWS account config by account database ID: %w", err)
	}
	return config, nil
}

func (repository *SQLAWSAccountConfigRepository) List(
	ctx context.Context,
	limit, offset int,
) ([]model.AWSAccountConfig, error) {
	rows, err := repository.db.QueryContext(ctx,
		`SELECT `+awsAccountConfigColumns+` FROM aws_account_config
		 ORDER BY id LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list AWS account configs: %w", err)
	}
	defer rows.Close()
	configs := make([]model.AWSAccountConfig, 0)
	for rows.Next() {
		config, err := scanAWSAccountConfig(rows)
		if err != nil {
			return nil, fmt.Errorf("scan AWS account config: %w", err)
		}
		configs = append(configs, config)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate AWS account configs: %w", err)
	}
	return configs, nil
}

func (repository *SQLAWSAccountConfigRepository) SetSyncEnabled(
	ctx context.Context,
	id int64,
	enabled bool,
	actorID string,
	expectedUpdatedAt *time.Time,
) (model.AWSAccountConfig, error) {
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("begin AWS account sync toggle: %w", err)
	}
	defer transaction.Rollback()

	config, err := scanAWSAccountConfig(transaction.QueryRowContext(ctx, `UPDATE aws_account_config SET
		sync_enabled = $2,
		sync_status = CASE WHEN $2 THEN
			CASE WHEN sync_status = 'DISABLED' THEN 'NEVER' ELSE sync_status END
			ELSE 'DISABLED' END,
		updated_by = $3,
		updated_at = NOW()
		WHERE id = $1 AND ($4::timestamptz IS NULL OR updated_at = $4)
		RETURNING `+awsAccountConfigColumns, id, enabled, actorID, expectedUpdatedAt,
	))
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if queryErr := transaction.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM aws_account_config WHERE id = $1)`, id,
		).Scan(&exists); queryErr != nil {
			return model.AWSAccountConfig{}, fmt.Errorf("check AWS account config after sync toggle conflict: %w", queryErr)
		}
		if exists {
			return model.AWSAccountConfig{}, ErrAWSAccountConfigChanged
		}
		return model.AWSAccountConfig{}, ErrAWSAccountConfigNotFound
	}
	if err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("set AWS account sync toggle: %w", err)
	}
	if err := writeAWSAccountConfigAudit(ctx, transaction, actorID, "AWS_ACCOUNT_SYNC_TOGGLE_CHANGED", id,
		map[string]interface{}{"sync_enabled": enabled}); err != nil {
		return model.AWSAccountConfig{}, err
	}
	if err := transaction.Commit(); err != nil {
		return model.AWSAccountConfig{}, fmt.Errorf("commit AWS account sync toggle: %w", err)
	}
	return config, nil
}

func (repository *SQLAWSAccountConfigRepository) RecordConnectionTest(
	ctx context.Context,
	id int64,
	actorID, outcome, message string,
) error {
	if outcome != "SUCCESS" && outcome != "FAILURE" {
		return errors.New("connection test outcome must be SUCCESS or FAILURE")
	}
	metadata, err := json.Marshal(map[string]string{"outcome": outcome, "message": message})
	if err != nil {
		return fmt.Errorf("marshal AWS connection test audit metadata: %w", err)
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin AWS connection test audit: %w", err)
	}
	defer transaction.Rollback()
	row := transaction.QueryRowContext(ctx, `SELECT 1 FROM aws_account_config WHERE id = $1`, id)
	var exists int
	if err := row.Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return ErrAWSAccountConfigNotFound
	} else if err != nil {
		return fmt.Errorf("read AWS connection test account: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_audit_event
		(actor_id, action, resource_type, resource_id, outcome, metadata, occurred_at)
		VALUES ($1, 'AWS_ACCOUNT_CONNECTION_TESTED', 'aws_account_config', $2, $3, $4::jsonb, NOW())`,
		actorID, fmt.Sprint(id), outcome, string(metadata),
	); err != nil {
		return fmt.Errorf("insert AWS connection test audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit AWS connection test audit: %w", err)
	}
	return nil
}

func (repository *SQLAWSAccountConfigRepository) ListEnabledForSync(
	ctx context.Context,
) ([]model.AWSAccountConfig, error) {
	rows, err := repository.db.QueryContext(ctx, `SELECT `+awsAccountConfigColumns+`
		FROM aws_account_config
		WHERE sync_enabled = TRUE
			AND (sync_status <> 'RUNNING' OR updated_at < NOW() - INTERVAL '30 minutes')
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list enabled AWS account configs: %w", err)
	}
	defer rows.Close()
	configs := make([]model.AWSAccountConfig, 0)
	for rows.Next() {
		config, err := scanAWSAccountConfig(rows)
		if err != nil {
			return nil, fmt.Errorf("scan enabled AWS account config: %w", err)
		}
		configs = append(configs, config)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enabled AWS account configs: %w", err)
	}
	return configs, nil
}

// AWSConfigSyncClaim 表示 BeginSync 抢占账号采集权的结果，调用方据此
// 区分「账号被禁用」与「已有同步在跑」——两者对用户的含义完全不同。
type AWSConfigSyncClaim int

const (
	SyncClaimed           AWSConfigSyncClaim = iota // 抢占成功，本执行者负责本轮采集
	SyncClaimDisabled                               // 账号 sync_enabled=false，采集被禁用
	SyncClaimAlreadyRunning                         // 已有同步在跑（未超 30 分钟僵死回收阈值）
)

func (claim AWSConfigSyncClaim) String() string {
	switch claim {
	case SyncClaimDisabled:
		return "disabled"
	case SyncClaimAlreadyRunning:
		return "already-running"
	default:
		return "claimed"
	}
}

func (repository *SQLAWSAccountConfigRepository) BeginSync(
	ctx context.Context,
	id int64,
) (AWSConfigSyncClaim, error) {
	result, err := repository.db.ExecContext(ctx, `UPDATE aws_account_config
		SET sync_status = 'RUNNING',
			last_sync_attempt_at = NOW(),
			last_sync_error = NULL,
			updated_at = NOW()
		WHERE id = $1 AND sync_enabled = TRUE
			AND (sync_status <> 'RUNNING' OR updated_at < NOW() - INTERVAL '30 minutes')`, id)
	if err != nil {
		return SyncClaimed, fmt.Errorf("mark AWS account config sync as running: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return SyncClaimed, fmt.Errorf("count AWS account config sync claim: %w", err)
	}
	if updated == 1 {
		return SyncClaimed, nil
	}
	// 抢占失败：区分禁用与已在跑（调用方的错误文案依赖这个区分）。
	var enabled bool
	var status string
	scanErr := repository.db.QueryRowContext(ctx,
		`SELECT sync_enabled, sync_status FROM aws_account_config WHERE id = $1`, id,
	).Scan(&enabled, &status)
	if scanErr != nil {
		return SyncClaimed, fmt.Errorf("reload AWS account config %d after failed claim: %w", id, scanErr)
	}
	if !enabled {
		return SyncClaimDisabled, nil
	}
	return SyncClaimAlreadyRunning, nil
}

func (repository *SQLAWSAccountConfigRepository) FinishSync(
	ctx context.Context,
	id int64,
	syncErr error,
) error {
	if syncErr == nil {
		_, err := repository.db.ExecContext(ctx, `UPDATE aws_account_config
			SET sync_status = CASE WHEN sync_enabled THEN 'SUCCEEDED' ELSE 'DISABLED' END,
				last_successful_sync_at = CASE WHEN sync_enabled THEN NOW() ELSE last_successful_sync_at END,
				last_sync_error = NULL,
				updated_at = NOW()
			WHERE id = $1 AND sync_status = 'RUNNING'`, id)
		if err != nil {
			return fmt.Errorf("mark AWS account config sync as succeeded: %w", err)
		}
		return nil
	}
	message := sanitizeConnectionError(syncErr)
	if _, err := repository.db.ExecContext(ctx, `UPDATE aws_account_config
		SET sync_status = CASE WHEN sync_enabled THEN 'FAILED' ELSE 'DISABLED' END,
			last_sync_error = CASE WHEN sync_enabled THEN $2 ELSE NULL END,
			updated_at = NOW()
		WHERE id = $1 AND sync_status = 'RUNNING'`, id, message); err != nil {
		return fmt.Errorf("mark AWS account config sync as failed: %w", err)
	}
	return nil
}

const awsAccountConfigColumns = `id, aws_account_id, aws_account_db_id, organization_db_id,
	display_name, read_only_role_arn, sync_mode, sync_enabled, tags, sync_status,
	last_sync_attempt_at, last_successful_sync_at, last_sync_error, created_by, updated_by,
	created_at, updated_at`

type awsAccountConfigRowScanner interface {
	Scan(...interface{}) error
}

func scanAWSAccountConfig(row awsAccountConfigRowScanner) (model.AWSAccountConfig, error) {
	var config model.AWSAccountConfig
	var accountDBID, organizationDBID sql.NullInt64
	var roleARN, lastError, createdBy, updatedBy sql.NullString
	var lastAttempt, lastSuccess sql.NullTime
	err := row.Scan(
		&config.ID, &config.AWSAccountID, &accountDBID, &organizationDBID,
		&config.DisplayName, &roleARN, &config.SyncMode, &config.SyncEnabled,
		&config.Tags, &config.SyncStatus, &lastAttempt, &lastSuccess, &lastError,
		&createdBy, &updatedBy, &config.CreatedAt, &config.UpdatedAt,
	)
	if err != nil {
		return model.AWSAccountConfig{}, err
	}
	if accountDBID.Valid {
		config.AWSAccountDBID = &accountDBID.Int64
	}
	if organizationDBID.Valid {
		config.OrganizationDBID = &organizationDBID.Int64
	}
	if roleARN.Valid {
		config.ReadOnlyRoleARN = &roleARN.String
	}
	if lastAttempt.Valid {
		config.LastSyncAttemptAt = &lastAttempt.Time
	}
	if lastSuccess.Valid {
		config.LastSuccessfulSyncAt = &lastSuccess.Time
	}
	if lastError.Valid {
		config.LastSyncError = &lastError.String
	}
	if createdBy.Valid {
		config.CreatedBy = &createdBy.String
	}
	if updatedBy.Valid {
		config.UpdatedBy = &updatedBy.String
	}
	return config, nil
}

func nullableRoleARN(roleARN *string) interface{} {
	if roleARN == nil {
		return nil
	}
	return *roleARN
}

func writeAWSAccountConfigAudit(
	ctx context.Context,
	transaction *sql.Tx,
	actorID, action string,
	id int64,
	metadata map[string]interface{},
) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal AWS account config audit metadata: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_audit_event
		(actor_id, action, resource_type, resource_id, outcome, metadata, occurred_at)
		VALUES ($1, $2, 'aws_account_config', $3, 'SUCCESS', $4::jsonb, NOW())`,
		actorID, action, fmt.Sprint(id), string(encoded),
	); err != nil {
		return fmt.Errorf("insert AWS account config audit: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
