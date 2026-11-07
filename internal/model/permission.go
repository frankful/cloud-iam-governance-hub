package model

// AbstractPermission is the provider-neutral permission request used internally.
// Phase0 translates this DSL to AWS IAM policies only.
type AbstractPermission struct {
	Principal   PermissionPrincipal `json:"principal"`
	Permissions []PermissionGrant   `json:"permissions"`
	Description string              `json:"description"`
}

type PermissionPrincipal struct {
	Name string `json:"name"`
	Type string `json:"type"` // ServiceIdentity or HumanUser
}

type PermissionGrant struct {
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
}

const (
	ActionStorageRead  = "storage:read"
	ActionStorageWrite = "storage:write"
	ActionEC2Read      = "ec2:read"
)

// AbstractActionAWSMap maps supported abstract actions to AWS IAM actions.
var AbstractActionAWSMap = map[string][]string{
	ActionStorageRead: {
		"s3:GetObject",
		"s3:ListBucket",
	},
	ActionStorageWrite: {
		"s3:PutObject",
		"s3:DeleteObject",
	},
	ActionEC2Read: {
		"ec2:DescribeInstances",
	},
}
