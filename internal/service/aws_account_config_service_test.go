package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

type accountConfigRepositoryFake struct {
	config         model.AWSAccountConfig
	created        bool
	updated        bool
	syncEnabled    *bool
	testRecord     bool
	connectionTest string
}

func (repository *accountConfigRepositoryFake) Create(
	_ context.Context,
	input AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	repository.created = true
	repository.config = model.AWSAccountConfig{
		ID: 7, AWSAccountID: input.AWSAccountID, DisplayName: input.DisplayName,
		SyncMode: input.SyncMode, SyncEnabled: input.SyncEnabled,
		Tags: model.JSONB(input.Tags), CreatedBy: &actorID,
	}
	return repository.config, nil
}

func (repository *accountConfigRepositoryFake) Update(
	_ context.Context,
	id int64,
	input AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	repository.updated = true
	repository.config.ID = id
	repository.config.DisplayName = input.DisplayName
	repository.config.UpdatedBy = &actorID
	return repository.config, nil
}

func (repository *accountConfigRepositoryFake) Get(context.Context, int64) (model.AWSAccountConfig, error) {
	return repository.config, nil
}

func (repository *accountConfigRepositoryFake) List(context.Context, int, int) ([]model.AWSAccountConfig, error) {
	return []model.AWSAccountConfig{repository.config}, nil
}

func (repository *accountConfigRepositoryFake) SetSyncEnabled(
	_ context.Context,
	_ int64,
	enabled bool,
	_ string,
	_ *time.Time,
) (model.AWSAccountConfig, error) {
	repository.syncEnabled = &enabled
	repository.config.SyncEnabled = enabled
	return repository.config, nil
}

func (repository *accountConfigRepositoryFake) RecordConnectionTest(
	_ context.Context,
	_ int64,
	_, outcome, _ string,
) error {
	repository.testRecord = true
	repository.connectionTest = outcome
	return nil
}

type accountConfigValidatorFake struct {
	identity AWSAccountConnectionIdentity
	err      error
	calls    int
}

func (validator *accountConfigValidatorFake) Validate(
	_ context.Context,
	_ AWSAccountConfigInput,
) (AWSAccountConnectionIdentity, error) {
	validator.calls++
	return validator.identity, validator.err
}

func TestNormalizeAWSAccountConfigInput(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/iam-readonly"
	valid := AWSAccountConfigInput{
		AWSAccountID: "123456789012", DisplayName: "Production",
		ReadOnlyRoleARN: &roleARN, SyncMode: "assume_role",
		Tags: json.RawMessage(`{"environment":"prod"}`),
	}
	normalized, err := normalizeAWSAccountConfigInput(valid)
	if err != nil {
		t.Fatalf("normalize valid config: %v", err)
	}
	if normalized.SyncMode != AWSAccountSyncAssumeRole || string(normalized.Tags) != `{"environment":"prod"}` {
		t.Fatalf("unexpected normalized config: %+v", normalized)
	}

	tests := []struct {
		name  string
		input AWSAccountConfigInput
	}{
		{
			name: "role belongs to another account",
			input: AWSAccountConfigInput{
				AWSAccountID: "123456789012", DisplayName: "Production",
				ReadOnlyRoleARN: aws.String("arn:aws:iam::999999999999:role/readonly"),
				SyncMode:        AWSAccountSyncAssumeRole,
			},
		},
		{
			name: "tags must be object",
			input: AWSAccountConfigInput{
				AWSAccountID: "123456789012", DisplayName: "Production",
				SyncMode: AWSAccountSyncCurrentCredentials, Tags: json.RawMessage(`[]`),
			},
		},
		{
			name: "current credentials does not accept role",
			input: AWSAccountConfigInput{
				AWSAccountID: "123456789012", DisplayName: "Production",
				ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncCurrentCredentials,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeAWSAccountConfigInput(test.input); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAWSAccountConfigCreateRequiresSuccessfulConnectivityTest(t *testing.T) {
	repository := &accountConfigRepositoryFake{}
	validator := &accountConfigValidatorFake{
		identity: AWSAccountConnectionIdentity{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/admin"},
	}
	service, err := NewAWSAccountConfigService(repository, validator, nil)
	if err != nil {
		t.Fatal(err)
	}
	roleARN := "arn:aws:iam::123456789012:role/readonly"
	config, err := service.Create(context.Background(), AWSAccountConfigInput{
		AWSAccountID: "123456789012", DisplayName: "Production",
		ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncAssumeRole,
		SyncEnabled: true, Tags: json.RawMessage(`{}`),
	}, "admin")
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	if !repository.created || validator.calls != 1 || config.ID != 7 {
		t.Fatalf("connectivity/persistence sequence incomplete: created=%v validation_calls=%d config=%+v",
			repository.created, validator.calls, config)
	}

	repository = &accountConfigRepositoryFake{}
	validator = &accountConfigValidatorFake{err: errors.New("assume role denied")}
	service, _ = NewAWSAccountConfigService(repository, validator, nil)
	_, err = service.Create(context.Background(), AWSAccountConfigInput{
		AWSAccountID: "123456789012", DisplayName: "Production",
		ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncAssumeRole,
	}, "admin")
	if !errors.Is(err, ErrAWSAccountConnectivity) || repository.created {
		t.Fatalf("failed STS validation must block persistence: err=%v created=%v", err, repository.created)
	}
}

func TestAWSAccountConfigEnablingSyncRevalidatesConnectivity(t *testing.T) {
	repository := &accountConfigRepositoryFake{
		config: model.AWSAccountConfig{
			ID: 9, AWSAccountID: "123456789012", DisplayName: "Production",
			SyncMode: AWSAccountSyncCurrentCredentials,
		},
	}
	validator := &accountConfigValidatorFake{err: errors.New("identity mismatch")}
	service, err := NewAWSAccountConfigService(repository, validator, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SetSyncEnabled(context.Background(), 9, true, "admin")
	if !errors.Is(err, ErrAWSAccountConnectivity) || repository.syncEnabled != nil {
		t.Fatalf("sync enable must be blocked on failed validation: err=%v toggle=%v", err, repository.syncEnabled)
	}
	validator.err = nil
	_, err = service.SetSyncEnabled(context.Background(), 9, true, "admin")
	if err != nil {
		t.Fatalf("enable sync after successful validation: %v", err)
	}
	if repository.syncEnabled == nil || !*repository.syncEnabled || validator.calls != 2 {
		t.Fatalf("unexpected validated toggle state: toggle=%v validator_calls=%d", repository.syncEnabled, validator.calls)
	}
}

type accountConfigSTSFake struct {
	identity       *sts.GetCallerIdentityOutput
	assumeRoleResp *sts.AssumeRoleOutput
	assumeRoleErr  error
	identityErr    error
	assumeCalls    int
	identityCalls  int
}

func (client *accountConfigSTSFake) AssumeRole(
	_ context.Context,
	_ *sts.AssumeRoleInput,
	_ ...func(*sts.Options),
) (*sts.AssumeRoleOutput, error) {
	client.assumeCalls++
	return client.assumeRoleResp, client.assumeRoleErr
}

func (client *accountConfigSTSFake) GetCallerIdentity(
	_ context.Context,
	_ *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options),
) (*sts.GetCallerIdentityOutput, error) {
	client.identityCalls++
	return client.identity, client.identityErr
}

func TestAWSAccountConnectivityServiceAssumesAndVerifiesTargetAccount(t *testing.T) {
	base := &accountConfigSTSFake{
		assumeRoleResp: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("temporary-access"), SecretAccessKey: aws.String("temporary-secret"),
			SessionToken: aws.String("temporary-session"), Expiration: aws.Time(time.Now().Add(15 * time.Minute)),
		}},
	}
	target := &accountConfigSTSFake{identity: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/readonly/test"),
	}}
	factoryCalled := false
	validator := &AWSAccountConnectivityService{
		config:  AWSAccountConnectivityConfig{Region: "us-east-1", Timeout: time.Second},
		baseSTS: base,
		stsFactory: func(aws.Config) accountConfigSTSAPI {
			factoryCalled = true
			return target
		},
	}
	roleARN := "arn:aws:iam::123456789012:role/readonly"
	identity, err := validator.Validate(context.Background(), AWSAccountConfigInput{
		AWSAccountID: "123456789012", DisplayName: "Production",
		ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncAssumeRole,
	})
	if err != nil {
		t.Fatalf("validate assumed role: %v", err)
	}
	if !factoryCalled || base.assumeCalls != 1 || target.identityCalls != 1 ||
		identity.AccountID != "123456789012" {
		t.Fatalf("unexpected STS validation: factory=%v assume=%d caller_identity=%d identity=%+v",
			factoryCalled, base.assumeCalls, target.identityCalls, identity)
	}
}

func TestAWSAccountConnectivityServiceRejectsAccountMismatch(t *testing.T) {
	validator := &AWSAccountConnectivityService{
		config: AWSAccountConnectivityConfig{Region: "us-east-1"},
		baseSTS: &accountConfigSTSFake{identity: &sts.GetCallerIdentityOutput{
			Account: aws.String("999999999999"),
		}},
	}
	_, err := validator.Validate(context.Background(), AWSAccountConfigInput{
		AWSAccountID: "123456789012", DisplayName: "Production",
		SyncMode: AWSAccountSyncCurrentCredentials,
	})
	if err == nil {
		t.Fatal("expected configured-account mismatch to fail")
	}
}
