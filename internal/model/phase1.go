package model

import "time"

type PlatformRole struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	RoleCode    string    `gorm:"column:role_code;type:varchar(64);not null;uniqueIndex" json:"role_code"`
	Description string    `gorm:"column:description;type:text;not null" json:"description"`
	IsSystem    bool      `gorm:"column:is_system;not null;default:true" json:"is_system"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (PlatformRole) TableName() string { return "platform_role" }

type UserRoleMapping struct {
	ID         int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID     string    `gorm:"column:user_id;type:varchar(128);not null" json:"user_id"`
	RoleID     int64     `gorm:"column:role_id;not null" json:"role_id"`
	AssignedBy *string   `gorm:"column:assigned_by;type:varchar(128)" json:"assigned_by,omitempty"`
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (UserRoleMapping) TableName() string { return "user_role_mapping" }

type PlatformToken struct {
	ID          int64      `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID      string     `gorm:"column:user_id;type:varchar(128);not null" json:"user_id"`
	TokenHash   []byte     `gorm:"column:token_hash;type:bytea;not null;uniqueIndex" json:"-"`
	TokenPrefix string     `gorm:"column:token_prefix;type:varchar(16);not null;index" json:"token_prefix"`
	TokenName   string     `gorm:"column:token_name;type:varchar(128);not null" json:"token_name"`
	ExpiresAt   *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
	RevokedAt   *time.Time `gorm:"column:revoked_at" json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	CreatedBy   *string    `gorm:"column:created_by;type:varchar(128)" json:"created_by,omitempty"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (PlatformToken) TableName() string { return "platform_token" }

type AWSAccountConfig struct {
	ID                   int64      `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AWSAccountID         string     `gorm:"column:aws_account_id;type:varchar(12);not null;uniqueIndex" json:"aws_account_id"`
	AWSAccountDBID       *int64     `gorm:"column:aws_account_db_id;uniqueIndex" json:"aws_account_db_id,omitempty"`
	OrganizationDBID     *int64     `gorm:"column:organization_db_id" json:"organization_db_id,omitempty"`
	DisplayName          string     `gorm:"column:display_name;type:varchar(256);not null" json:"display_name"`
	ReadOnlyRoleARN      *string    `gorm:"column:read_only_role_arn;type:varchar(512)" json:"read_only_role_arn,omitempty"`
	SyncMode             string     `gorm:"column:sync_mode;type:varchar(32);not null" json:"sync_mode"`
	SyncEnabled          bool       `gorm:"column:sync_enabled;not null;default:false" json:"sync_enabled"`
	Tags                 JSONB      `gorm:"column:tags;type:jsonb;not null" json:"tags"`
	SyncStatus           string     `gorm:"column:sync_status;type:varchar(16);not null" json:"sync_status"`
	LastSyncAttemptAt    *time.Time `gorm:"column:last_sync_attempt_at" json:"last_sync_attempt_at,omitempty"`
	LastSuccessfulSyncAt *time.Time `gorm:"column:last_successful_sync_at" json:"last_successful_sync_at,omitempty"`
	LastSyncError        *string    `gorm:"column:last_sync_error;type:text" json:"last_sync_error,omitempty"`
	CreatedBy            *string    `gorm:"column:created_by;type:varchar(128)" json:"created_by,omitempty"`
	UpdatedBy            *string    `gorm:"column:updated_by;type:varchar(128)" json:"updated_by,omitempty"`
	CreatedAt            time.Time  `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt            time.Time  `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (AWSAccountConfig) TableName() string { return "aws_account_config" }

type IAMBaseline struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AccountID      int64     `gorm:"column:account_id;not null;uniqueIndex:idx_iam_baseline_account_version,priority:1" json:"account_id"`
	Version        int       `gorm:"column:version;not null;uniqueIndex:idx_iam_baseline_account_version,priority:2" json:"version"`
	AbstractPolicy JSONB     `gorm:"column:abstract_policy;type:jsonb;not null" json:"abstract_policy"`
	Enabled        bool      `gorm:"column:enabled;not null;default:false" json:"enabled"`
	CreatedBy      *string   `gorm:"column:created_by;type:varchar(128)" json:"created_by,omitempty"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (IAMBaseline) TableName() string { return "iam_baseline" }

type TicketValidationRecord struct {
	ID            int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	TicketID      int64     `gorm:"column:ticket_id;not null" json:"ticket_id"`
	Attempt       int       `gorm:"column:attempt;not null" json:"attempt"`
	BaselineID    *int64    `gorm:"column:baseline_id" json:"baseline_id,omitempty"`
	RequestSHA256 []byte    `gorm:"column:request_sha256;type:bytea;not null" json:"request_sha256"`
	Result        string    `gorm:"column:result;type:varchar(16);not null" json:"result"`
	Checks        JSONB     `gorm:"column:checks;type:jsonb;not null" json:"checks"`
	SkippedChecks JSONB     `gorm:"column:skipped_checks;type:jsonb;not null" json:"skipped_checks"`
	CreatedAt     time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (TicketValidationRecord) TableName() string { return "ticket_validation_record" }

type IACExecutionRecord struct {
	ID                  int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	TicketID            int64     `gorm:"column:ticket_id;not null;index" json:"ticket_id"`
	Provider            string    `gorm:"column:provider;type:varchar(16);not null" json:"provider"`
	Repository          string    `gorm:"column:repository;type:varchar(256);not null" json:"repository"`
	RemoteRequestNumber *string   `gorm:"column:remote_request_number;type:varchar(64)" json:"remote_request_number,omitempty"`
	RemoteURL           *string   `gorm:"column:remote_url;type:varchar(1024)" json:"remote_url,omitempty"`
	CommitSHA           *string   `gorm:"column:commit_sha;type:varchar(128)" json:"commit_sha,omitempty"`
	PipelineID          *string   `gorm:"column:pipeline_id;type:varchar(128)" json:"pipeline_id,omitempty"`
	MergeState          string    `gorm:"column:merge_state;type:varchar(16);not null" json:"merge_state"`
	CIState             string    `gorm:"column:ci_state;type:varchar(16);not null" json:"ci_state"`
	ApplyResult         string    `gorm:"column:apply_result;type:varchar(16);not null" json:"apply_result"`
	Attempt             int       `gorm:"column:attempt;not null" json:"attempt"`
	IdempotencyKey      string    `gorm:"column:idempotency_key;type:varchar(256);not null;uniqueIndex" json:"idempotency_key"`
	SanitizedError      *string   `gorm:"column:sanitized_error;type:text" json:"sanitized_error,omitempty"`
	Metadata            JSONB     `gorm:"column:metadata;type:jsonb;not null" json:"metadata"`
	ObservedAt          time.Time `gorm:"column:observed_at;not null" json:"observed_at"`
	CreatedAt           time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (IACExecutionRecord) TableName() string { return "iac_execution_record" }
