package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultAWSConnectionTimeout = 15 * time.Second

type accountConfigSTSAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type accountConfigSTSFactory func(aws.Config) accountConfigSTSAPI

type AWSAccountConnectivityConfig struct {
	Region      string
	Profile     string
	ExternalID  string
	Timeout     time.Duration
	MaxAttempts int
}

type AWSAccountConnectivityService struct {
	config     AWSAccountConnectivityConfig
	awsConfig  aws.Config
	baseSTS    accountConfigSTSAPI
	stsFactory accountConfigSTSFactory
}

func NewAWSAccountConnectivityService(
	ctx context.Context,
	settings AWSAccountConnectivityConfig,
) (*AWSAccountConnectivityService, error) {
	settings.Region = strings.TrimSpace(settings.Region)
	if settings.Region == "" {
		return nil, errors.New("AWS region must not be empty")
	}
	if settings.Timeout <= 0 {
		settings.Timeout = defaultAWSConnectionTimeout
	}
	if settings.MaxAttempts <= 0 {
		settings.MaxAttempts = defaultAWSMaxAttempts
	}
	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(settings.Region),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(options *retry.StandardOptions) {
				options.MaxAttempts = settings.MaxAttempts
			})
		}),
	}
	if profile := strings.TrimSpace(settings.Profile); profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(profile))
	}
	awsConfig, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS credentials and configuration: %w", err)
	}
	return &AWSAccountConnectivityService{
		config:     settings,
		awsConfig:  awsConfig,
		baseSTS:    sts.NewFromConfig(awsConfig),
		stsFactory: func(config aws.Config) accountConfigSTSAPI { return sts.NewFromConfig(config) },
	}, nil
}

func (validator *AWSAccountConnectivityService) Validate(
	ctx context.Context,
	input AWSAccountConfigInput,
) (AWSAccountConnectionIdentity, error) {
	normalized, err := normalizeAWSAccountConfigInput(input)
	if err != nil {
		return AWSAccountConnectionIdentity{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, validator.config.Timeout)
	defer cancel()

	targetSTS := validator.baseSTS
	if normalized.SyncMode == AWSAccountSyncAssumeRole {
		request := &sts.AssumeRoleInput{
			RoleArn:         normalized.ReadOnlyRoleARN,
			RoleSessionName: aws.String("iam-governance-connectivity-test"),
			DurationSeconds: aws.Int32(900),
		}
		if externalID := strings.TrimSpace(validator.config.ExternalID); externalID != "" {
			request.ExternalId = aws.String(externalID)
		}
		assumed, err := validator.baseSTS.AssumeRole(requestCtx, request)
		if err != nil {
			return AWSAccountConnectionIdentity{}, fmt.Errorf("assume configured read-only role: %w", err)
		}
		if assumed.Credentials == nil || aws.ToString(assumed.Credentials.AccessKeyId) == "" ||
			aws.ToString(assumed.Credentials.SecretAccessKey) == "" {
			return AWSAccountConnectionIdentity{}, errors.New("STS returned incomplete assumed-role credentials")
		}
		assumedConfig := validator.awsConfig
		assumedConfig.Credentials = credentials.NewStaticCredentialsProvider(
			aws.ToString(assumed.Credentials.AccessKeyId),
			aws.ToString(assumed.Credentials.SecretAccessKey),
			aws.ToString(assumed.Credentials.SessionToken),
		)
		targetSTS = validator.stsFactory(assumedConfig)
	}

	identity, err := targetSTS.GetCallerIdentity(requestCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return AWSAccountConnectionIdentity{}, fmt.Errorf("get AWS caller identity: %w", err)
	}
	if identity == nil || aws.ToString(identity.Account) != normalized.AWSAccountID {
		actual := ""
		if identity != nil {
			actual = aws.ToString(identity.Account)
		}
		return AWSAccountConnectionIdentity{}, fmt.Errorf(
			"configured account ID %s does not match STS caller account %s",
			normalized.AWSAccountID, actual,
		)
	}
	return AWSAccountConnectionIdentity{
		AccountID: aws.ToString(identity.Account),
		ARN:       aws.ToString(identity.Arn),
	}, nil
}
