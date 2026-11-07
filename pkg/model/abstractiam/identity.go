package abstractiam

// PrincipalType 统一身份主体类型
type PrincipalType string

const (
	PrincipalTypeUser           PrincipalType = "user"
	PrincipalTypeGroup          PrincipalType = "group"
	PrincipalTypeServiceAccount PrincipalType = "service_account"
	PrincipalTypeRole           PrincipalType = "role"
)

// Principal 统一身份主体
type Principal struct {
	Type      PrincipalType `json:"type"`
	Name      string        `json:"name"`
	Provider  string        `json:"provider"`   // aws, azure, gcp
	AccountID string        `json:"account_id"` // 云账号ID
	Email     string        `json:"email,omitempty"`
	ARN       string        `json:"arn,omitempty"` // 云厂商特定标识
}

// RoleDefinition 统一角色定义
type RoleDefinition struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Provider    string              `json:"provider"`
	AccountID   string              `json:"account_id"`
	Actions     []string            `json:"actions"`
	Resources   []string            `json:"resources"`
	Conditions  []AbstractCondition `json:"conditions,omitempty"`
}

// RoleMapping 角色映射：统一角色 → 各云厂商角色标识
type RoleMapping struct {
	Provider   string `json:"provider"`
	RoleID     string `json:"role_id"`       // AWS Role ID / Azure Role Definition ID / GCP Role ID
	RoleName   string `json:"role_name"`     // 各云厂商的角色名称
	ARN        string `json:"arn,omitempty"` // AWS ARN
	ResourceID string `json:"resource_id"`   // Azure Resource ID
}

// IdentityMappingTable 全局身份映射表
var IdentityMappingTable = map[string]map[string]RoleMapping{
	"role://aws/123456789012/my-role": {
		"aws": {
			Provider: "aws",
			RoleName: "my-role",
			ARN:      "arn:aws:iam::123456789012:role/my-role",
		},
	},
	"role://azure/sub-123/my-role": {
		"azure": {
			Provider:   "azure",
			RoleName:   "my-role",
			ResourceID: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/my-role",
		},
	},
	"role://gcp/my-project/my-role": {
		"gcp": {
			Provider: "gcp",
			RoleName: "my-role",
		},
	},
}

// MapRoleToProvider 将统一角色定义映射到指定云厂商的角色标识
func MapRoleToProvider(role RoleDefinition, targetProvider string) (RoleMapping, error) {
	key := "role://" + role.Provider + "/" + role.AccountID + "/" + role.Name
	mappings, ok := IdentityMappingTable[key]
	if !ok {
		return RoleMapping{}, nil
	}
	mapping, ok := mappings[targetProvider]
	if !ok {
		return RoleMapping{}, nil
	}
	return mapping, nil
}

// IsValidPrincipalType 检查是否为有效的身份主体类型
func IsValidPrincipalType(principalType PrincipalType) bool {
	switch principalType {
	case PrincipalTypeUser, PrincipalTypeGroup, PrincipalTypeServiceAccount, PrincipalTypeRole:
		return true
	default:
		return false
	}
}

// GetPrincipalTypes 获取所有支持的身份主体类型
func GetPrincipalTypes() []PrincipalType {
	return []PrincipalType{
		PrincipalTypeUser,
		PrincipalTypeGroup,
		PrincipalTypeServiceAccount,
		PrincipalTypeRole,
	}
}
