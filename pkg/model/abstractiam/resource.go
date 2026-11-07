package abstractiam

import "fmt"

// ResourceType 统一资源类型
type ResourceType string

const (
	ResourceTypeStorage  ResourceType = "storage"
	ResourceTypeCompute  ResourceType = "compute"
	ResourceTypeNetwork  ResourceType = "network"
	ResourceTypeDatabase ResourceType = "database"
	ResourceTypeSecurity ResourceType = "security"
)

// ResourceIdentifier 统一资源标识
type ResourceIdentifier struct {
	Type     ResourceType      `json:"type"`
	Provider string            `json:"provider"` // aws, azure, gcp
	Account  string            `json:"account"`  // 云账号ID
	Name     string            `json:"name"`     // 资源名称
	Region   string            `json:"region,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// ResourceMapping 资源映射：统一资源 → 各云厂商资源标识
type ResourceMapping struct {
	Provider string `json:"provider"`
	ARN      string `json:"arn"`       // AWS ARN
	ID       string `json:"id"`        // Azure Resource ID
	SelfLink string `json:"self_link"` // GCP Self Link
}

// ResourceMappingTable 全局资源映射表
// key: 统一资源标识符 (type://provider/account/name)
// value: 各云厂商的资源标识
var ResourceMappingTable = map[string]map[string]ResourceMapping{
	// S3 Bucket 映射
	"storage://aws/123456789012/my-bucket": {
		"aws": {
			Provider: "aws",
			ARN:      "arn:aws:s3:::my-bucket",
		},
	},
	"storage://azure/sub-123/my-account/my-container": {
		"azure": {
			Provider: "azure",
			ID:       "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/my-account/blobServices/default/containers/my-container",
		},
	},
	"storage://gcp/my-project/my-bucket": {
		"gcp": {
			Provider: "gcp",
			SelfLink: "//storage.googleapis.com/my-bucket",
		},
	},
}

// MapResourceToProvider 将统一资源标识映射到指定云厂商的资源标识
func MapResourceToProvider(resource ResourceIdentifier, targetProvider string) (ResourceMapping, error) {
	key := fmt.Sprintf("%s://%s/%s/%s", resource.Type, resource.Provider, resource.Account, resource.Name)
	mappings, ok := ResourceMappingTable[key]
	if !ok {
		return ResourceMapping{}, fmt.Errorf("resource mapping not found for key: %s", key)
	}
	mapping, ok := mappings[targetProvider]
	if !ok {
		return ResourceMapping{}, fmt.Errorf("resource mapping not found for provider: %s", targetProvider)
	}
	return mapping, nil
}

// ParseResourceURI 解析统一资源 URI
// 格式: type://provider/account/name
func ParseResourceURI(uri string) (ResourceIdentifier, error) {
	var resource ResourceIdentifier
	_, err := fmt.Sscanf(uri, "%s://%s/%s/%s", &resource.Type, &resource.Provider, &resource.Account, &resource.Name)
	if err != nil {
		return ResourceIdentifier{}, fmt.Errorf("invalid resource URI format: %s", uri)
	}
	return resource, nil
}

// IsValidResourceType 检查是否为有效的资源类型
func IsValidResourceType(resourceType ResourceType) bool {
	switch resourceType {
	case ResourceTypeStorage, ResourceTypeCompute, ResourceTypeNetwork, ResourceTypeDatabase, ResourceTypeSecurity:
		return true
	default:
		return false
	}
}

// GetResourceTypes 获取所有支持的资源类型
func GetResourceTypes() []ResourceType {
	return []ResourceType{
		ResourceTypeStorage,
		ResourceTypeCompute,
		ResourceTypeNetwork,
		ResourceTypeDatabase,
		ResourceTypeSecurity,
	}
}
