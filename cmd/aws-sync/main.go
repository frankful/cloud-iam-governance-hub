package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("load .env", "error", err)
		os.Exit(1)
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	region := strings.TrimSpace(os.Getenv("AWS_REGION"))
	rawOrganizationID := strings.TrimSpace(os.Getenv("AWS_ORGANIZATION_DB_ID"))
	syncMode := strings.ToLower(strings.TrimSpace(envOrDefault("AWS_SYNC_MODE", "organization")))
	if databaseURL == "" || region == "" {
		logger.Error("DATABASE_URL and AWS_REGION are required")
		os.Exit(1)
	}
	if syncMode != "organization" && syncMode != "current-account" && syncMode != "account-config" {
		logger.Error("AWS_SYNC_MODE must be organization, current-account, or account-config")
		os.Exit(1)
	}
	var organizationID int64
	if syncMode == "organization" {
		parsedOrganizationID, err := strconv.ParseInt(rawOrganizationID, 10, 64)
		if err != nil || parsedOrganizationID <= 0 {
			logger.Error("AWS_ORGANIZATION_DB_ID must be a positive integer in organization mode")
			os.Exit(1)
		}
		organizationID = parsedOrganizationID
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		logger.Error("open PostgreSQL connection", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if err := database.PingContext(pingCtx); err != nil {
		cancel()
		logger.Error("connect to PostgreSQL", "error", err)
		os.Exit(1)
	}
	cancel()

	repository, err := service.NewSQLAWSAssetRepository(database)
	if err != nil {
		logger.Error("create AWS asset repository", "error", err)
		os.Exit(1)
	}
	collector, err := service.NewAWSCollectorService(ctx, service.AWSCollectorConfig{
		Region:              region,
		Profile:             strings.TrimSpace(os.Getenv("AWS_PROFILE")),
		RoleSessionName:     envOrDefault("AWS_ROLE_SESSION_NAME", "iam-governance-collector"),
		ExternalID:          os.Getenv("AWS_EXTERNAL_ID"),
		ManagementAccountID: os.Getenv("AWS_MANAGEMENT_ACCOUNT_ID"),
	}, repository, logger)
	if err != nil {
		logger.Error("create AWS collector", "error", err)
		os.Exit(1)
	}
	var currentAccount *int64
	if syncMode == "organization" {
		if err := collector.SyncOrganization(ctx, organizationID); err != nil {
			logger.Error("synchronize AWS organization", "organization_db_id", organizationID, "error", err)
			os.Exit(1)
		}
	} else if syncMode == "current-account" {
		account, err := collector.SyncCurrentAccount(ctx)
		if err != nil {
			logger.Error("synchronize current AWS account", "error", err)
			os.Exit(1)
		}
		currentAccount = &account.ID
	}
	var configuredAccountIDs []int64
	var configuredSyncErr error
	if syncMode == "account-config" {
		configRepository, err := service.NewSQLAWSAccountConfigRepository(database)
		if err != nil {
			logger.Error("create AWS account config repository", "error", err)
			os.Exit(1)
		}
		configuredAccountIDs, configuredSyncErr = syncEnabledAccountConfigs(ctx, configRepository, collector, logger)
	}
	riskScanner, err := service.NewIAMRiskScanner(database)
	if err != nil {
		logger.Error("create IAM risk scanner", "error", err)
		os.Exit(1)
	}
	riskSummary, err := riskScanner.Scan(ctx)
	if err != nil {
		logger.Error("scan IAM risks after inventory sync", "error", err)
		os.Exit(1)
	}
	logger.Info("static IAM risk scan completed",
		"method", riskSummary.Method,
		"scope", riskSummary.Scope,
		"principals_scanned", riskSummary.PrincipalsScanned,
		"findings_upserted", riskSummary.FindingsUpserted,
		"findings_resolved", riskSummary.FindingsResolved,
	)

	queue := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     envOrDefault("REDIS_ADDR", "127.0.0.1:6379"),
		Password: os.Getenv("REDIS_PASSWORD"),
	})
	defer queue.Close()
	var accountIDs []int64
	if currentAccount != nil {
		accountIDs = append(accountIDs, *currentAccount)
	} else if syncMode == "account-config" {
		accountIDs = configuredAccountIDs
	} else {
		rows, err := database.QueryContext(ctx, `SELECT id FROM aws_account
			WHERE org_id = $1 AND status = 'ACTIVE' ORDER BY id`, organizationID)
		if err != nil {
			logger.Error("list active organization accounts for graph jobs", "error", err)
			os.Exit(1)
		}
		for rows.Next() {
			var accountID int64
			if err := rows.Scan(&accountID); err != nil {
				rows.Close()
				logger.Error("read organization account for graph job", "error", err)
				os.Exit(1)
			}
			accountIDs = append(accountIDs, accountID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			logger.Error("iterate organization accounts for graph jobs", "error", err)
			os.Exit(1)
		}
		if err := rows.Close(); err != nil {
			logger.Error("close organization account rows", "error", err)
			os.Exit(1)
		}
	}
	queued := 0
	for _, accountID := range accountIDs {
		info, err := service.EnqueuePMapperGraphBuildForAccount(ctx, queue, database, accountID)
		if err != nil {
			if errors.Is(err, service.ErrNoPMapperPrincipals) {
				logger.Info("skipping PMapper job for account without IAM principals", "account_db_id", accountID)
				continue
			}
			logger.Error("enqueue PMapper graph job", "account_db_id", accountID, "error", err)
			os.Exit(1)
		}
		logger.Info("PMapper graph job queued", "account_db_id", accountID, "task_id", info.ID)
		queued++
	}
	if syncMode == "organization" {
		logger.Info("AWS organization synchronization completed", "organization_db_id", organizationID)
	} else if syncMode == "current-account" {
		logger.Info("current AWS account synchronization completed", "account_db_id", *currentAccount)
	} else {
		logger.Info("enabled AWS account configurations synchronization completed",
			"accounts_synchronized", len(configuredAccountIDs))
	}
	logger.Info("PMapper graph jobs queued", "count", queued)
	if configuredSyncErr != nil {
		logger.Error("one or more configured AWS accounts failed to synchronize", "error", configuredSyncErr)
		os.Exit(1)
	}
}

type configuredAWSAccountSyncer interface {
	SyncConfiguredAccount(context.Context, model.AWSAccountConfig) (model.AWSAccount, *service.AWSSyncChanges, error)
}

type configuredAWSAccountSyncRepository interface {
	ListEnabledForSync(context.Context) ([]model.AWSAccountConfig, error)
	BeginSync(context.Context, int64) (service.AWSConfigSyncClaim, error)
	FinishSync(context.Context, int64, error) error
}

func syncEnabledAccountConfigs(
	ctx context.Context,
	repository configuredAWSAccountSyncRepository,
	collector configuredAWSAccountSyncer,
	logger *slog.Logger,
) ([]int64, error) {
	configs, err := repository.ListEnabledForSync(ctx)
	if err != nil {
		return nil, err
	}
	accountIDs := make([]int64, 0, len(configs))
	var syncErrors []error
	for _, config := range configs {
		claim, err := repository.BeginSync(ctx, config.ID)
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("claim AWS account config %d: %w", config.ID, err))
			continue
		}
		if claim != service.SyncClaimed {
			logger.Info("skipping AWS account config", "config_id", config.ID, "reason", claim.String())
			continue
		}
		account, _, syncErr := collector.SyncConfiguredAccount(ctx, config)
		if finishErr := repository.FinishSync(ctx, config.ID, syncErr); finishErr != nil {
			syncErrors = append(syncErrors,
				fmt.Errorf("record sync result for AWS account config %d: %w", config.ID, finishErr))
		}
		if syncErr != nil {
			logger.Error("configured AWS account synchronization failed",
				"config_id", config.ID, "account_id", config.AWSAccountID, "error", syncErr)
			syncErrors = append(syncErrors,
				fmt.Errorf("synchronize AWS account %s: %w", config.AWSAccountID, syncErr))
			continue
		}
		accountIDs = append(accountIDs, account.ID)
		logger.Info("configured AWS account synchronization completed",
			"config_id", config.ID, "account_id", config.AWSAccountID, "account_db_id", account.ID)
	}
	return accountIDs, errors.Join(syncErrors...)
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
