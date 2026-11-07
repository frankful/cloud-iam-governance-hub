package model

import "time"

type AWSOrganization struct {
	ID              int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	OrgID           string    `gorm:"column:org_id;type:varchar(64);not null;uniqueIndex" json:"org_id"`
	MasterAccountID string    `gorm:"column:master_account_id;type:varchar(20);not null" json:"master_account_id"`
	Name            *string   `gorm:"column:name;type:varchar(128)" json:"name,omitempty"`
	CreatedAt       time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (AWSOrganization) TableName() string {
	return "aws_organization"
}

type AWSAccount struct {
	ID              int64      `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	OrganizationID  *int64     `gorm:"column:org_id" json:"org_id,omitempty"`
	AccountID       string     `gorm:"column:account_id;type:varchar(20);not null;uniqueIndex" json:"account_id"`
	AccountName     *string    `gorm:"column:account_name;type:varchar(128)" json:"account_name,omitempty"`
	Status          *string    `gorm:"column:status;type:varchar(32)" json:"status,omitempty"`
	ReadOnlyRoleARN *string    `gorm:"column:read_only_role_arn;type:varchar(512)" json:"read_only_role_arn,omitempty"`
	LastSyncAt      *time.Time `gorm:"column:last_sync_at" json:"last_sync_at,omitempty"`
	CreatedAt       time.Time  `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;autoCreateTime;autoUpdateTime" json:"updated_at"`
}

func (AWSAccount) TableName() string {
	return "aws_account"
}
