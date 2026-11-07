package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type configuredSyncRepositoryFake struct {
	configs       []model.AWSAccountConfig
	claimed       map[int64]bool
	beginErrors   map[int64]error
	finishResults map[int64]error
	finishedWith  map[int64]error
}

func (repository *configuredSyncRepositoryFake) ListEnabledForSync(context.Context) ([]model.AWSAccountConfig, error) {
	return repository.configs, nil
}

func (repository *configuredSyncRepositoryFake) BeginSync(_ context.Context, id int64) (service.AWSConfigSyncClaim, error) {
	if err := repository.beginErrors[id]; err != nil {
		return service.SyncClaimed, err
	}
	if repository.claimed[id] {
		return service.SyncClaimed, nil
	}
	return service.SyncClaimAlreadyRunning, nil
}

func (repository *configuredSyncRepositoryFake) FinishSync(_ context.Context, id int64, err error) error {
	repository.finishedWith[id] = err
	return repository.finishResults[id]
}

type configuredSyncCollectorFake struct {
	errors map[int64]error
	calls  []int64
}

func (collector *configuredSyncCollectorFake) SyncConfiguredAccount(
	_ context.Context,
	config model.AWSAccountConfig,
) (model.AWSAccount, *service.AWSSyncChanges, error) {
	collector.calls = append(collector.calls, config.ID)
	if err := collector.errors[config.ID]; err != nil {
		return model.AWSAccount{}, nil, err
	}
	return model.AWSAccount{ID: config.ID * 10, AccountID: config.AWSAccountID}, nil, nil
}

func TestSyncEnabledAccountConfigsProcessesClaimedConfigsAndContinuesFailures(t *testing.T) {
	expectedFailure := errors.New("temporary account failure")
	repository := &configuredSyncRepositoryFake{
		configs: []model.AWSAccountConfig{
			{ID: 1, AWSAccountID: "111111111111", SyncEnabled: true},
			{ID: 2, AWSAccountID: "222222222222", SyncEnabled: true},
			{ID: 3, AWSAccountID: "333333333333", SyncEnabled: true},
		},
		claimed:      map[int64]bool{1: true, 2: true, 3: false},
		finishedWith: make(map[int64]error),
	}
	collector := &configuredSyncCollectorFake{
		errors: map[int64]error{2: expectedFailure},
	}
	accountIDs, err := syncEnabledAccountConfigs(
		context.Background(), repository, collector, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if !errors.Is(err, expectedFailure) {
		t.Fatalf("expected aggregated account failure, got %v", err)
	}
	if len(accountIDs) != 1 || accountIDs[0] != 10 {
		t.Fatalf("successful account IDs = %v, want [10]", accountIDs)
	}
	if len(collector.calls) != 2 || collector.calls[0] != 1 || collector.calls[1] != 2 {
		t.Fatalf("collector calls = %v, disabled/unclaimed config was not skipped", collector.calls)
	}
	if repository.finishedWith[1] != nil || !errors.Is(repository.finishedWith[2], expectedFailure) {
		t.Fatalf("sync results were not recorded: %+v", repository.finishedWith)
	}
}

func TestSyncEnabledAccountConfigsRecordsFinishFailure(t *testing.T) {
	finishFailure := errors.New("database update failed")
	repository := &configuredSyncRepositoryFake{
		configs:       []model.AWSAccountConfig{{ID: 4, AWSAccountID: "444444444444", SyncEnabled: true}},
		claimed:       map[int64]bool{4: true},
		finishResults: map[int64]error{4: finishFailure},
		finishedWith:  make(map[int64]error),
	}
	collector := &configuredSyncCollectorFake{errors: make(map[int64]error)}
	accountIDs, err := syncEnabledAccountConfigs(
		context.Background(), repository, collector, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if !errors.Is(err, finishFailure) {
		t.Fatalf("expected finish error, got %v", err)
	}
	if len(accountIDs) != 1 || accountIDs[0] != 40 {
		t.Fatalf("successfully collected account should remain eligible for post-sync processing: %v", accountIDs)
	}
}
