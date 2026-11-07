package service

import (
	"context"
	"errors"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

func newAccountBootstrapTestService(repository *accountConfigRepositoryFake, validator *accountConfigValidatorFake) *AWSAccountConfigService {
	service, err := NewAWSAccountConfigService(repository, validator, nil)
	if err != nil {
		panic(err)
	}
	return service
}

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestBootstrapAWSAccountFromEnv(t *testing.T) {
	ctx := context.Background()

	t.Run("skips entirely when BOOTSTRAP_AWS_ACCOUNT_ID is unset", func(t *testing.T) {
		repository := &accountConfigRepositoryFake{}
		service := newAccountBootstrapTestService(repository, &accountConfigValidatorFake{})
		if err := BootstrapAWSAccountFromEnv(ctx, service, envMap(nil), nil); err != nil {
			t.Fatalf("BootstrapAWSAccountFromEnv() error = %v", err)
		}
		if repository.created {
			t.Fatal("created a config without BOOTSTRAP_AWS_ACCOUNT_ID")
		}
	})

	t.Run("creates CURRENT_CREDENTIALS config with defaults", func(t *testing.T) {
		repository := &accountConfigRepositoryFake{}
		validator := &accountConfigValidatorFake{identity: AWSAccountConnectionIdentity{AccountID: "123456789012"}}
		service := newAccountBootstrapTestService(repository, validator)
		env := envMap(map[string]string{"BOOTSTRAP_AWS_ACCOUNT_ID": "123456789012"})
		if err := BootstrapAWSAccountFromEnv(ctx, service, env, nil); err != nil {
			t.Fatalf("BootstrapAWSAccountFromEnv() error = %v", err)
		}
		if !repository.created || repository.config.AWSAccountID != "123456789012" {
			t.Fatalf("config not created: %+v", repository.config)
		}
		if repository.config.DisplayName != "aws-123456789012" || repository.config.SyncMode != AWSAccountSyncCurrentCredentials {
			t.Fatalf("unexpected defaults: %+v", repository.config)
		}
		if !repository.config.SyncEnabled {
			t.Fatal("sync_enabled should default to true")
		}
		if validator.calls != 1 {
			t.Fatalf("validator calls = %d, want 1", validator.calls)
		}
		if repository.config.CreatedBy == nil || *repository.config.CreatedBy != "system" {
			t.Fatalf("actor = %v, want system", repository.config.CreatedBy)
		}
	})

	t.Run("skips when a configuration for the account already exists", func(t *testing.T) {
		repository := &accountConfigRepositoryFake{}
		repository.config = model.AWSAccountConfig{ID: 3, AWSAccountID: "123456789012", SyncMode: AWSAccountSyncCurrentCredentials}
		validator := &accountConfigValidatorFake{}
		service := newAccountBootstrapTestService(repository, validator)
		env := envMap(map[string]string{"BOOTSTRAP_AWS_ACCOUNT_ID": "123456789012"})
		if err := BootstrapAWSAccountFromEnv(ctx, service, env, nil); err != nil {
			t.Fatalf("BootstrapAWSAccountFromEnv() error = %v", err)
		}
		if repository.created {
			t.Fatal("re-created an existing configuration")
		}
		if validator.calls != 0 {
			t.Fatalf("validator calls = %d, want 0 (pre-check should short-circuit)", validator.calls)
		}
	})

	t.Run("connectivity failure warns without failing startup", func(t *testing.T) {
		repository := &accountConfigRepositoryFake{}
		validator := &accountConfigValidatorFake{err: errors.New("network unreachable")}
		service := newAccountBootstrapTestService(repository, validator)
		env := envMap(map[string]string{"BOOTSTRAP_AWS_ACCOUNT_ID": "123456789012"})
		if err := BootstrapAWSAccountFromEnv(ctx, service, env, nil); err != nil {
			t.Fatalf("bootstrap must not fail startup on connectivity error: %v", err)
		}
		if repository.created {
			t.Fatal("config created despite connectivity failure")
		}
	})

	t.Run("rejects invalid boolean for sync enabled", func(t *testing.T) {
		repository := &accountConfigRepositoryFake{}
		service := newAccountBootstrapTestService(repository, &accountConfigValidatorFake{})
		env := envMap(map[string]string{
			"BOOTSTRAP_AWS_ACCOUNT_ID":   "123456789012",
			"BOOTSTRAP_AWS_SYNC_ENABLED": "yes-please",
		})
		if err := BootstrapAWSAccountFromEnv(ctx, service, env, nil); err == nil {
			t.Fatal("expected error for invalid BOOTSTRAP_AWS_SYNC_ENABLED")
		}
	})
}
