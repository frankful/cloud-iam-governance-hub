package model

import (
	"fmt"
	"sort"

	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

// ToAbstractPolicy 将旧的 AbstractPermission 转换为新的 AbstractPolicy
// 这是向后兼容的转换函数，用于逐步迁移到新模型
func (p AbstractPermission) ToAbstractPolicy() (abstractiam.AbstractPolicy, error) {
	policy := abstractiam.AbstractPolicy{
		Name:        p.Principal.Name,
		Description: p.Description,
		Statements:  make([]abstractiam.AbstractStatement, 0, len(p.Permissions)),
	}

	for grantIndex, grant := range p.Permissions {
		resource, err := canonicalLegacyResource(grant.Resource)
		if err != nil {
			return abstractiam.AbstractPolicy{}, fmt.Errorf("permission %d resource cannot be converted: %w", grantIndex, err)
		}

		statement := abstractiam.AbstractStatement{
			Effect:    "Allow",
			Actions:   []string{grant.Action},
			Resources: []string{resource},
		}

		if len(grant.Conditions) != 0 {
			operators := make([]string, 0, len(grant.Conditions))
			for operator := range grant.Conditions {
				operators = append(operators, operator)
			}
			sort.Strings(operators)

			for _, operator := range operators {
				conditions, ok := grant.Conditions[operator].(map[string]interface{})
				if !ok {
					return abstractiam.AbstractPolicy{}, fmt.Errorf("permission %d has unsupported condition structure", grantIndex)
				}

				keys := make([]string, 0, len(conditions))
				for key := range conditions {
					keys = append(keys, key)
				}
				sort.Strings(keys)

				for _, key := range keys {
					values, err := legacyConditionValues(conditions[key])
					if err != nil {
						return abstractiam.AbstractPolicy{}, fmt.Errorf("permission %d condition %q: %w", grantIndex, key, err)
					}
					statement.Conditions = append(statement.Conditions, abstractiam.AbstractCondition{
						Key:      key,
						Operator: operator,
						Values:   values,
					})
				}
			}
		}

		policy.Statements = append(policy.Statements, statement)
	}

	return policy, nil
}

// FromAbstractPolicy 将新的 AbstractPolicy 转换为旧的 AbstractPermission
// 这是向后兼容的转换函数，用于尚未迁移的代码路径
func FromAbstractPolicy(policy abstractiam.AbstractPolicy) (AbstractPermission, error) {
	if len(policy.Statements) == 0 {
		return AbstractPermission{}, fmt.Errorf("abstract policy must contain at least one statement")
	}

	permission := AbstractPermission{
		Principal: PermissionPrincipal{
			Name: policy.Name,
			Type: "ServiceIdentity",
		},
		Description: policy.Description,
		Permissions: make([]PermissionGrant, 0, len(policy.Statements)),
	}

	for _, statement := range policy.Statements {
		if statement.Effect != "Allow" {
			continue // 跳过 Deny 语句，旧模型不支持
		}

		for _, action := range statement.Actions {
			for _, resource := range statement.Resources {
				grant := PermissionGrant{
					Action:   action,
					Resource: resource,
				}

				if len(statement.Conditions) > 0 {
					grant.Conditions = make(map[string]interface{})
					for _, condition := range statement.Conditions {
						if grant.Conditions[condition.Operator] == nil {
							grant.Conditions[condition.Operator] = make(map[string]interface{})
						}
						operatorConditions := grant.Conditions[condition.Operator].(map[string]interface{})
						operatorConditions[condition.Key] = condition.Values
					}
				}

				permission.Permissions = append(permission.Permissions, grant)
			}
		}
	}

	return permission, nil
}

// canonicalLegacyResource 将旧格式资源转换为新格式
func canonicalLegacyResource(resource string) (string, error) {
	resource = trimSpace(resource)
	if resource == "" {
		return "", fmt.Errorf("resource must not be empty")
	}

	if hasPrefix(resource, "storage://") {
		bucket := trimPrefix(resource, "storage://")
		if bucket == "" {
			return "", fmt.Errorf("storage resource must include a bucket name")
		}
		return "arn:aws:s3:::" + bucket, nil
	}

	if contains(resource, "://") && !hasPrefix(resource, "arn:") {
		return "", fmt.Errorf("unsupported resource URI %q", resource)
	}

	return resource, nil
}

// legacyConditionValues 将条件值转换为旧格式
func legacyConditionValues(value interface{}) ([]interface{}, error) {
	switch value := value.(type) {
	case []interface{}:
		return value, nil
	case string, float64, bool, nil:
		return []interface{}{value}, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", value)
	}
}

// 辅助函数
func trimSpace(s string) string {
	return string([]byte(s)) // 简单实现，避免导入 strings
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func trimPrefix(s, prefix string) string {
	if hasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
