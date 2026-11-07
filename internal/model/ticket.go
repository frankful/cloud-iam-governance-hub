package model

import "time"

type IAMTicket struct {
	ID                  int64   `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	TicketNo            *string `gorm:"column:ticket_no;type:varchar(64);uniqueIndex" json:"ticket_no,omitempty"`
	TicketType          *string `gorm:"column:ticket_type;type:varchar(32)" json:"ticket_type,omitempty"`
	AccountID           *int64  `gorm:"column:account_id" json:"account_id,omitempty"`
	PrincipalName       *string `gorm:"column:principal_name;type:varchar(256)" json:"principal_name,omitempty"`
	RequestPolicy       JSONB   `gorm:"column:request_policy;type:jsonb" json:"request_policy,omitempty"`
	ApprovalMode        string  `gorm:"column:approval_mode;type:varchar(16);not null" json:"approval_mode"`
	ApproverIDs         JSONB   `gorm:"column:approver_ids;type:jsonb;not null" json:"approver_ids"`
	TerraformCode       *string `gorm:"column:terraform_code;type:text" json:"terraform_code,omitempty"`
	GitPRURL            *string `gorm:"column:git_pr_url;type:varchar(512)" json:"git_pr_url,omitempty"`
	GitProvider         *string `gorm:"column:git_provider;type:varchar(16)" json:"git_provider,omitempty"`
	GitRepository       *string `gorm:"column:git_repository;type:varchar(256)" json:"git_repository,omitempty"`
	RemoteRequestNumber *string `gorm:"column:remote_request_number;type:varchar(64)" json:"remote_request_number,omitempty"`
	GitCommitSHA        *string `gorm:"column:git_commit_sha;type:varchar(128)" json:"git_commit_sha,omitempty"`
	RoleSnapshot        JSONB   `gorm:"column:role_snapshot;type:jsonb" json:"role_snapshot,omitempty"`
	PollAttemptCount    int     `gorm:"column:poll_attempt_count;not null;default:0" json:"poll_attempt_count"`
	// Git 侧观察状态：轮询 worker 与 CI apply 回调都会写。前端靠
	// git_apply_result=FAILED 呈现「合并已生效但 apply 失败」的横幅（A12②）。
	GitMergeState    *string    `gorm:"column:git_merge_state;type:varchar(16)" json:"git_merge_state,omitempty"`
	GitCIState       *string    `gorm:"column:git_ci_state;type:varchar(16)" json:"git_ci_state,omitempty"`
	GitApplyResult   *string    `gorm:"column:git_apply_result;type:varchar(16)" json:"git_apply_result,omitempty"`
	NextPollAt       *time.Time `gorm:"column:next_poll_at" json:"next_poll_at,omitempty"`
	LastStatusPollAt *time.Time `gorm:"column:last_status_poll_at" json:"last_status_poll_at,omitempty"`
	ClosedAt         *time.Time `gorm:"column:closed_at" json:"closed_at,omitempty"`
	ClosedBy         *string    `gorm:"column:closed_by;type:varchar(128)" json:"closed_by,omitempty"`
	ClosureReason    *string    `gorm:"column:closure_reason;type:varchar(16)" json:"closure_reason,omitempty"`
	ClosureComment   *string    `gorm:"column:closure_comment;type:text" json:"closure_comment,omitempty"`
	Status           *string    `gorm:"column:status;type:varchar(32)" json:"status,omitempty"`
	Submitter        *string    `gorm:"column:submitter;type:varchar(128)" json:"submitter,omitempty"`
	CreatedAt        time.Time  `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (IAMTicket) TableName() string {
	return "iam_ticket"
}

type TicketApproval struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	TicketID       *int64    `gorm:"column:ticket_id" json:"ticket_id,omitempty"`
	Approver       *string   `gorm:"column:approver;type:varchar(128)" json:"approver,omitempty"`
	ApprovalResult *string   `gorm:"column:approval_result;type:varchar(16)" json:"approval_result,omitempty"`
	Comment        *string   `gorm:"column:comment;type:text" json:"comment,omitempty"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (TicketApproval) TableName() string {
	return "ticket_approval"
}

// PlatformUser is an approver identity managed by the platform, independent
// from AWS IAM users and roles.
type PlatformUser struct {
	UserID      string    `gorm:"column:user_id;type:varchar(128);primaryKey" json:"user_id"`
	DisplayName string    `gorm:"column:display_name;type:varchar(256);not null" json:"display_name"`
	Email       *string   `gorm:"column:email;type:varchar(320)" json:"email,omitempty"`
	IsActive    bool      `gorm:"column:is_active;not null;default:true" json:"is_active"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (PlatformUser) TableName() string {
	return "platform_user"
}

// AWSAccountApprover binds platform users to AWS accounts for AUTO approval
// routing. The referenced account is the database ID of aws_account.
type AWSAccountApprover struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AccountID int64     `gorm:"column:account_id;not null;uniqueIndex:idx_aws_account_approver,priority:1" json:"account_id"`
	UserID    string    `gorm:"column:user_id;type:varchar(128);not null;uniqueIndex:idx_aws_account_approver,priority:2" json:"user_id"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (AWSAccountApprover) TableName() string {
	return "aws_account_approver"
}

type TicketApprovalInfo struct {
	TicketNo     string                `json:"ticket_no"`
	ApprovalMode string                `json:"approval_mode"`
	Status       string                `json:"status"`
	Approvals    []TicketApprovalEntry `json:"approvals"`
}

type TicketApprovalEntry struct {
	ApproverID  string    `json:"approver_id"`
	DisplayName string    `json:"display_name"`
	Result      *string   `json:"result,omitempty"`
	Comment     *string   `json:"comment,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}
