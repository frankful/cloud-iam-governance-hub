package service

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// ReadOnlyGuard ensures all AWS operations are read-only. The platform never
// performs write operations against AWS; collectors are read-only by design.
type ReadOnlyGuard struct {
	enabled bool
}

// NewReadOnlyGuard creates a new ReadOnlyGuard.
// If AWS_READ_ONLY env var is "true", the guard is enabled.
func NewReadOnlyGuard() *ReadOnlyGuard {
	return &ReadOnlyGuard{
		enabled: strings.ToLower(strings.TrimSpace(os.Getenv("AWS_READ_ONLY"))) == "true",
	}
}

// IsEnabled returns true if the read-only guard is enabled.
func (g *ReadOnlyGuard) IsEnabled() bool {
	return g.enabled
}

// EnforceReadOnly checks if the operation is read-only.
// Returns an error if the guard is enabled and the operation is not read-only.
func (g *ReadOnlyGuard) EnforceReadOnly(operation string) error {
	if !g.enabled {
		return nil
	}

	// List of allowed read-only operations
	allowedOps := []string{
		"List", "Get", "Describe", "Read", "Fetch", "Scan", "Query", "Search",
		"Head", "BatchGet", "GetPolicy", "GetRole", "GetUser", "GetGroup",
		"ListRoles", "ListUsers", "ListGroups", "ListPolicies", "ListAttachedPolicies",
		"GetCallerIdentity", "Simulate", "Validate", "Check", "Test",
	}

	// Check if the operation starts with an allowed prefix
	for _, prefix := range allowedOps {
		if strings.HasPrefix(operation, prefix) {
			return nil
		}
	}

	return fmt.Errorf("AWS read-only guard: operation %q is not allowed (read-only mode)", operation)
}

// ValidateAWSConfig validates that the AWS configuration is read-only safe.
//
// AWS_READONLY_PROFILES 是逗号分隔的「只读身份」profile 名单（例如生产环境
// 的 collector profile）。命中名单的 profile 必须同时设置 AWS_READ_ONLY=true，
// 防止把只读账号的凭证误用于写操作。名单为空时不做该约束——只读保护的主
// 防线是凭证本身的 IAM 权限，这里只是配置层的额外闸门。
func ValidateAWSConfig() error {
	profile := strings.TrimSpace(os.Getenv("AWS_PROFILE"))
	if profile == "" {
		return nil
	}
	readOnly := strings.ToLower(strings.TrimSpace(os.Getenv("AWS_READ_ONLY"))) == "true"
	if readOnly {
		return nil
	}
	for _, candidate := range strings.Split(os.Getenv("AWS_READONLY_PROFILES"), ",") {
		if strings.TrimSpace(candidate) == profile {
			return fmt.Errorf("AWS_PROFILE=%s is listed in AWS_READONLY_PROFILES and requires AWS_READ_ONLY=true",
				profile)
		}
	}

	return nil
}

// LogReadOnlyStatus logs the read-only guard status.
func (g *ReadOnlyGuard) LogReadOnlyStatus() {
	if g.enabled {
		fmt.Println("[AWS] Read-only guard ENABLED - all AWS operations are restricted to read-only")
	} else {
		fmt.Println("[AWS] Read-only guard DISABLED")
	}
}

// GuardAWSOperation wraps an AWS operation with read-only check.
func (g *ReadOnlyGuard) GuardAWSOperation(ctx context.Context, operation string, fn func() error) error {
	if err := g.EnforceReadOnly(operation); err != nil {
		return err
	}
	return fn()
}
