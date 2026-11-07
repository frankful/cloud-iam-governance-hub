package model

import "time"

type IAMPrincipal struct {
	ID            int64  `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AccountID     *int64 `gorm:"column:account_id" json:"account_id,omitempty"`
	PrincipalType string `gorm:"column:principal_type;type:varchar(16);not null" json:"principal_type"`
	PrincipalName string `gorm:"column:principal_name;type:varchar(256);not null" json:"principal_name"`
	ARN           string `gorm:"column:arn;type:varchar(512);not null;uniqueIndex" json:"arn"`
	// Path is ForceNew in the AWS provider: a baseline that omits it would
	// recreate the role or user on the first apply.
	Path        string  `gorm:"column:path;type:varchar(512);not null;default:/" json:"path"`
	TrustPolicy JSONB   `gorm:"column:trust_policy;type:jsonb" json:"trust_policy,omitempty"`
	Description *string `gorm:"column:description;type:text" json:"description,omitempty"`
	// PermissionsBoundaryARN/Type are also ForceNew; nil means no boundary.
	PermissionsBoundaryARN  *string           `gorm:"column:permissions_boundary_arn;type:varchar(512)" json:"permissions_boundary_arn,omitempty"`
	PermissionsBoundaryType *string           `gorm:"column:permissions_boundary_type;type:varchar(16)" json:"permissions_boundary_type,omitempty"`
	MaxSessionDuration      *int64            `gorm:"column:max_session_duration" json:"max_session_duration,omitempty"`
	Tags                    map[string]string `gorm:"column:tags;type:jsonb" json:"tags,omitempty"`
	LastUsedAt              *time.Time        `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	LastSeenAt              *time.Time        `gorm:"column:last_seen_at" json:"last_seen_at,omitempty"`
	IsDeleted               bool              `gorm:"column:is_deleted;not null;default:false" json:"is_deleted"`
	Policies                []IAMPolicy       `gorm:"-" json:"policies,omitempty"`
	CreatedAt               time.Time         `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt               time.Time         `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (IAMPrincipal) TableName() string {
	return "iam_principal"
}

type IAMGroup struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AccountID int64     `gorm:"column:account_id;not null;index" json:"account_id"`
	GroupName string    `gorm:"column:group_name;type:varchar(256);not null" json:"group_name"`
	ARN       string    `gorm:"column:arn;type:varchar(512);not null;uniqueIndex" json:"arn"`
	Path      string    `gorm:"column:path;type:varchar(512);not null" json:"path"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (IAMGroup) TableName() string {
	return "iam_group"
}

type IAMGroupMembership struct {
	ID              int64 `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	GroupID         int64 `gorm:"column:group_id;uniqueIndex:idx_iam_group_membership,priority:1" json:"group_id"`
	UserPrincipalID int64 `gorm:"column:user_principal_id;uniqueIndex:idx_iam_group_membership,priority:2" json:"user_principal_id"`
}

func (IAMGroupMembership) TableName() string {
	return "iam_group_membership"
}

type IAMGroupPolicy struct {
	ID       int64 `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	GroupID  int64 `gorm:"column:group_id;uniqueIndex:idx_iam_group_policy,priority:1" json:"group_id"`
	PolicyID int64 `gorm:"column:policy_id;uniqueIndex:idx_iam_group_policy,priority:2" json:"policy_id"`
}

func (IAMGroupPolicy) TableName() string {
	return "iam_group_policy"
}

// IAMInstanceProfile is one EC2 instance profile and the role it carries.
// The baseline declares it as aws_iam_instance_profile so a role rebuild
// cannot silently detach running instances.
type IAMInstanceProfile struct {
	ID                  int64             `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AccountID           int64             `gorm:"column:account_id;not null;index" json:"account_id"`
	InstanceProfileName string            `gorm:"column:instance_profile_name;type:varchar(256);not null" json:"instance_profile_name"`
	ARN                 string            `gorm:"column:arn;type:varchar(512);not null;uniqueIndex" json:"arn"`
	Path                string            `gorm:"column:path;type:varchar(512);not null;default:/" json:"path"`
	RoleARN             *string           `gorm:"column:role_arn;type:varchar(512)" json:"role_arn,omitempty"`
	Tags                map[string]string `gorm:"column:tags;type:jsonb" json:"tags,omitempty"`
	LastSeenAt          *time.Time        `gorm:"column:last_seen_at" json:"last_seen_at,omitempty"`
	IsDeleted           bool              `gorm:"column:is_deleted;not null;default:false" json:"is_deleted"`
	CreatedAt           time.Time         `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt           time.Time         `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (IAMInstanceProfile) TableName() string {
	return "iam_instance_profile"
}

// IAMIdentityProvider is one OIDC or SAML provider registered in the account.
// OIDC providers carry URL/client IDs/thumbprints, SAML providers carry the
// metadata document needed to declare aws_iam_saml_provider.
type IAMIdentityProvider struct {
	ID                   int64             `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AccountID            int64             `gorm:"column:account_id;not null;index" json:"account_id"`
	ProviderType         string            `gorm:"column:provider_type;type:varchar(8);not null" json:"provider_type"`
	ARN                  string            `gorm:"column:arn;type:varchar(512);not null;uniqueIndex" json:"arn"`
	ProviderName         string            `gorm:"column:provider_name;type:varchar(256);not null" json:"provider_name"`
	URL                  *string           `gorm:"column:url;type:text" json:"url,omitempty"`
	ClientIDList         []string          `gorm:"column:client_id_list;type:jsonb" json:"client_id_list,omitempty"`
	ThumbprintList       []string          `gorm:"column:thumbprint_list;type:jsonb" json:"thumbprint_list,omitempty"`
	SAMLMetadataDocument *string           `gorm:"column:saml_metadata_document;type:text" json:"saml_metadata_document,omitempty"`
	Tags                 map[string]string `gorm:"column:tags;type:jsonb" json:"tags,omitempty"`
	LastSeenAt           *time.Time        `gorm:"column:last_seen_at" json:"last_seen_at,omitempty"`
	IsDeleted            bool              `gorm:"column:is_deleted;not null;default:false" json:"is_deleted"`
	CreatedAt            time.Time         `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt            time.Time         `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (IAMIdentityProvider) TableName() string {
	return "iam_identity_provider"
}

type IAMPolicy struct {
	ID          int64             `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	PolicyARN   *string           `gorm:"column:policy_arn;type:varchar(512);uniqueIndex" json:"policy_arn,omitempty"`
	PolicyName  *string           `gorm:"column:policy_name;type:varchar(256)" json:"policy_name,omitempty"`
	PolicyType  *string           `gorm:"column:policy_type;type:varchar(16)" json:"policy_type,omitempty"`
	Description *string           `gorm:"column:description;type:text" json:"description,omitempty"`
	Tags        map[string]string `gorm:"column:tags;type:jsonb" json:"tags,omitempty"`
	// PolicyDocument is NULL for AWS-managed catalog rows whose document has
	// not been fetched yet (migration 0030). Attached policies always carry
	// one, because collection fetches it before saving the attachment.
	PolicyDocument JSONB     `gorm:"column:policy_document;type:jsonb" json:"policy_document"`
	RiskScore      int       `gorm:"column:risk_score;not null;default:0" json:"risk_score"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (IAMPolicy) TableName() string {
	return "iam_policy"
}

type IAMPrincipalPolicy struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	PrincipalID *int64 `gorm:"column:principal_id;uniqueIndex:idx_iam_principal_policy,priority:1" json:"principal_id,omitempty"`
	PolicyID    *int64 `gorm:"column:policy_id;uniqueIndex:idx_iam_principal_policy,priority:2" json:"policy_id,omitempty"`
}

func (IAMPrincipalPolicy) TableName() string {
	return "iam_principal_policy"
}

type IAMRelationship struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	PrincipalID *int64    `gorm:"column:principal_id" json:"principal_id,omitempty"`
	Action      string    `gorm:"column:action;type:varchar(256);not null" json:"action"`
	Resource    string    `gorm:"column:resource;type:varchar(512);not null" json:"resource"`
	SourceJSON  JSONB     `gorm:"column:source_json;type:jsonb" json:"source_json,omitempty"`
	SyncVersion *string   `gorm:"column:sync_version;type:varchar(64)" json:"sync_version,omitempty"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (IAMRelationship) TableName() string {
	return "iam_relationship"
}

type IAMRisk struct {
	ID          int64      `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	PrincipalID *int64     `gorm:"column:principal_id" json:"principal_id,omitempty"`
	RiskType    *string    `gorm:"column:risk_type;type:varchar(128)" json:"risk_type,omitempty"`
	RiskLevel   *string    `gorm:"column:risk_level;type:varchar(16)" json:"risk_level,omitempty"`
	Description *string    `gorm:"column:description;type:text" json:"description,omitempty"`
	IsResolved  bool       `gorm:"column:is_resolved;not null;default:false" json:"is_resolved"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	ResolvedAt  *time.Time `gorm:"column:resolved_at" json:"resolved_at,omitempty"`
}

func (IAMRisk) TableName() string {
	return "iam_risk"
}

type IAMAccessLog struct {
	ID           int64      `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	PrincipalARN *string    `gorm:"column:principal_arn;type:varchar(512)" json:"principal_arn,omitempty"`
	Action       *string    `gorm:"column:action;type:varchar(256)" json:"action,omitempty"`
	Resource     *string    `gorm:"column:resource;type:varchar(512)" json:"resource,omitempty"`
	EventTime    *time.Time `gorm:"column:event_time" json:"event_time,omitempty"`
}

func (IAMAccessLog) TableName() string {
	return "iam_access_log"
}
