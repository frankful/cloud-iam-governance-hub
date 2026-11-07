package abstractiam

// 统一动作命名 - 跨云通用
// 这些抽象动作可以映射到不同云厂商的具体 IAM 动作
const (
	// 存储类动作
	ActionStorageRead   = "storage:read"
	ActionStorageWrite  = "storage:write"
	ActionStorageList   = "storage:list"
	ActionStorageDelete = "storage:delete"

	// 计算类动作
	ActionComputeRead   = "compute:read"
	ActionComputeWrite  = "compute:write"
	ActionComputeStart  = "compute:start"
	ActionComputeStop   = "compute:stop"
	ActionComputeDelete = "compute:delete"

	// 网络类动作
	ActionNetworkRead  = "network:read"
	ActionNetworkWrite = "network:write"

	// 数据库类动作
	ActionDatabaseRead  = "database:read"
	ActionDatabaseWrite = "database:write"

	// 安全类动作
	ActionSecurityRead  = "security:read"
	ActionSecurityWrite = "security:write"
)

// ActionMapping 定义每个云厂商的动作映射
type ActionMapping struct {
	Provider string   `json:"provider"`
	Actions  []string `json:"actions"`
}

// ActionProviderMap 全局动作映射表
// key: 抽象动作名称
// value: 各云厂商的具体动作列表
var ActionProviderMap = map[string][]ActionMapping{
	ActionStorageRead: {
		{Provider: "aws", Actions: []string{"s3:GetObject", "s3:ListBucket"}},
		{Provider: "azure", Actions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/read"}},
		{Provider: "gcp", Actions: []string{"storage.objects.get", "storage.objects.list"}},
	},
	ActionStorageWrite: {
		{Provider: "aws", Actions: []string{"s3:PutObject", "s3:DeleteObject"}},
		{Provider: "azure", Actions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/write"}},
		{Provider: "gcp", Actions: []string{"storage.objects.create", "storage.objects.delete"}},
	},
	ActionStorageList: {
		{Provider: "aws", Actions: []string{"s3:ListBucket"}},
		{Provider: "azure", Actions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/list"}},
		{Provider: "gcp", Actions: []string{"storage.objects.list"}},
	},
	ActionStorageDelete: {
		{Provider: "aws", Actions: []string{"s3:DeleteObject"}},
		{Provider: "azure", Actions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/delete"}},
		{Provider: "gcp", Actions: []string{"storage.objects.delete"}},
	},
	ActionComputeRead: {
		{Provider: "aws", Actions: []string{"ec2:DescribeInstances"}},
		{Provider: "azure", Actions: []string{"Microsoft.Compute/virtualMachines/read"}},
		{Provider: "gcp", Actions: []string{"compute.instances.get"}},
	},
	ActionComputeWrite: {
		{Provider: "aws", Actions: []string{"ec2:RunInstances"}},
		{Provider: "azure", Actions: []string{"Microsoft.Compute/virtualMachines/write"}},
		{Provider: "gcp", Actions: []string{"compute.instances.create"}},
	},
	ActionComputeStart: {
		{Provider: "aws", Actions: []string{"ec2:StartInstances"}},
		{Provider: "azure", Actions: []string{"Microsoft.Compute/virtualMachines/start/action"}},
		{Provider: "gcp", Actions: []string{"compute.instances.start"}},
	},
	ActionComputeStop: {
		{Provider: "aws", Actions: []string{"ec2:StopInstances"}},
		{Provider: "azure", Actions: []string{"Microsoft.Compute/virtualMachines/deallocate/action"}},
		{Provider: "gcp", Actions: []string{"compute.instances.stop"}},
	},
	ActionComputeDelete: {
		{Provider: "aws", Actions: []string{"ec2:TerminateInstances"}},
		{Provider: "azure", Actions: []string{"Microsoft.Compute/virtualMachines/delete"}},
		{Provider: "gcp", Actions: []string{"compute.instances.delete"}},
	},
	ActionNetworkRead: {
		{Provider: "aws", Actions: []string{"ec2:DescribeVpcs", "ec2:DescribeSubnets"}},
		{Provider: "azure", Actions: []string{"Microsoft.Network/virtualNetworks/read"}},
		{Provider: "gcp", Actions: []string{"compute.networks.get"}},
	},
	ActionNetworkWrite: {
		{Provider: "aws", Actions: []string{"ec2:CreateVpc", "ec2:CreateSubnet"}},
		{Provider: "azure", Actions: []string{"Microsoft.Network/virtualNetworks/write"}},
		{Provider: "gcp", Actions: []string{"compute.networks.insert"}},
	},
	ActionDatabaseRead: {
		{Provider: "aws", Actions: []string{"rds:DescribeDBInstances"}},
		{Provider: "azure", Actions: []string{"Microsoft.DBforPostgreSQL/servers/read"}},
		{Provider: "gcp", Actions: []string{"sql.instances.get"}},
	},
	ActionDatabaseWrite: {
		{Provider: "aws", Actions: []string{"rds:CreateDBInstance"}},
		{Provider: "azure", Actions: []string{"Microsoft.DBforPostgreSQL/servers/write"}},
		{Provider: "gcp", Actions: []string{"sql.instances.create"}},
	},
	ActionSecurityRead: {
		{Provider: "aws", Actions: []string{"iam:GetRole", "iam:GetPolicy"}},
		{Provider: "azure", Actions: []string{"Microsoft.Authorization/roleDefinitions/read"}},
		{Provider: "gcp", Actions: []string{"iam.roles.get"}},
	},
	ActionSecurityWrite: {
		{Provider: "aws", Actions: []string{"iam:CreateRole", "iam:CreatePolicy"}},
		{Provider: "azure", Actions: []string{"Microsoft.Authorization/roleDefinitions/write"}},
		{Provider: "gcp", Actions: []string{"iam.roles.create"}},
	},
}

// GetActionsForProvider 获取指定抽象动作在指定云厂商的具体动作列表
func GetActionsForProvider(abstractAction, provider string) ([]string, bool) {
	mappings, ok := ActionProviderMap[abstractAction]
	if !ok {
		return nil, false
	}
	for _, mapping := range mappings {
		if mapping.Provider == provider {
			return mapping.Actions, true
		}
	}
	return nil, false
}

// GetAllProviders 获取支持指定抽象动作的所有云厂商
func GetAllProviders(abstractAction string) []string {
	mappings, ok := ActionProviderMap[abstractAction]
	if !ok {
		return nil
	}
	providers := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		providers = append(providers, mapping.Provider)
	}
	return providers
}

// IsValidAction 检查是否为有效的抽象动作
func IsValidAction(action string) bool {
	_, ok := ActionProviderMap[action]
	return ok
}

// GetAllActions 获取所有支持的抽象动作
func GetAllActions() []string {
	actions := make([]string, 0, len(ActionProviderMap))
	for action := range ActionProviderMap {
		actions = append(actions, action)
	}
	return actions
}
