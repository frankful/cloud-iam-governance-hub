package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// BootstrapAWSAccountFromEnv 在启动时按 env 种子接入 AWS 账号，清库/新装环境
// 无需再手工录账号。配置（全部可省略，缺省即整体跳过）：
//
//	BOOTSTRAP_AWS_ACCOUNT_ID    12 位账号 ID；未设置 = 不做账号自举
//	BOOTSTRAP_AWS_ACCOUNT_NAME  展示名，默认 "aws-<id>"
//	BOOTSTRAP_AWS_SYNC_MODE     CURRENT_CREDENTIALS（默认）| ASSUME_ROLE
//	BOOTSTRAP_AWS_ROLE_ARN      ASSUME_ROLE 模式必填，须指向同一账号
//	BOOTSTRAP_AWS_SYNC_ENABLED  默认 true
//
// 语义与手工 POST /aws/account-configs 完全一致（同一 Create 路径：连通性
// STS 校验 → 落 aws_account_config；aws_account 行由首次同步的 collector
// 自动补建）。幂等：配置已存在即跳过，不覆盖手工改动。除 env 值非法外，
// 任何失败（含 STS 连通性）只记 WARN 不阻断启动——AWS 抖动不应拖垮平台，
// 账号可稍后在「同步管理」手工接入。
func BootstrapAWSAccountFromEnv(
	ctx context.Context,
	configService *AWSAccountConfigService,
	getenv func(string) string,
	logger *slog.Logger,
) error {
	if configService == nil {
		return errors.New("AWS account config service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	accountID := strings.TrimSpace(getenv("BOOTSTRAP_AWS_ACCOUNT_ID"))
	if accountID == "" {
		logger.Info("bootstrap aws account skipped", "reason", "BOOTSTRAP_AWS_ACCOUNT_ID is not set")
		return nil
	}
	displayName := strings.TrimSpace(getenv("BOOTSTRAP_AWS_ACCOUNT_NAME"))
	if displayName == "" {
		displayName = "aws-" + accountID
	}
	syncMode := strings.ToUpper(strings.TrimSpace(getenv("BOOTSTRAP_AWS_SYNC_MODE")))
	if syncMode == "" {
		syncMode = AWSAccountSyncCurrentCredentials
	}
	var roleARN *string
	if raw := strings.TrimSpace(getenv("BOOTSTRAP_AWS_ROLE_ARN")); raw != "" {
		roleARN = &raw
	}
	syncEnabled := true
	if raw := strings.TrimSpace(getenv("BOOTSTRAP_AWS_SYNC_ENABLED")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("BOOTSTRAP_AWS_SYNC_ENABLED %q is not a boolean: %w", raw, err)
		}
		syncEnabled = enabled
	}
	input := AWSAccountConfigInput{
		AWSAccountID:    accountID,
		DisplayName:     displayName,
		ReadOnlyRoleARN: roleARN,
		SyncMode:        syncMode,
		SyncEnabled:     syncEnabled,
	}

	// 幂等预检：已有同 ID 配置直接跳过（不覆盖），避免每次启动白打一次 STS。
	existing, err := configService.List(ctx, 100, 0)
	if err != nil {
		return fmt.Errorf("list AWS account configs for bootstrap: %w", err)
	}
	for _, config := range existing {
		if config.AWSAccountID == accountID {
			logger.Info("bootstrap aws account skipped",
				"reason", "configuration already exists", "aws_account_id", accountID)
			return nil
		}
	}

	if _, err := configService.Create(ctx, input, "system"); err != nil {
		if errors.Is(err, ErrAWSAccountConfigConflict) {
			logger.Info("bootstrap aws account skipped",
				"reason", "configuration already exists", "aws_account_id", accountID)
			return nil
		}
		logger.Warn("bootstrap aws account failed; add it manually under Sync Management if needed",
			"aws_account_id", accountID, "error", err)
		return nil
	}
	logger.Info("bootstrap aws account created",
		"aws_account_id", accountID, "display_name", displayName,
		"sync_mode", syncMode, "sync_enabled", syncEnabled)
	return nil
}
