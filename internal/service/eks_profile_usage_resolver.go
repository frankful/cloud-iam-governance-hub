package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ProfileUsageResolver 回答「哪些实例配置文件正被 EKS 托管节点组引用」。
//
// IAM 数据永远答不出这个问题：实例配置文件不支持 tag，节点组也不把实例配置文件
// 写进自己的元数据，唯一的落点是 launch template——EKS 托管节点组（以及自定义
// launch template）创建的每个节点都会携带 IamInstanceProfile 引用。把这条证据
// 抽出来，待清理清单才能把 eks-<uuid> 孤儿从「需确认」升级成「可直接执行」。
type ProfileUsageResolver interface {
	ResolveUsedProfiles(ctx context.Context, awsAccountID string) (profileUsageResult, error)
}

// profileUsageResult 是一次解析的产物。UsedProfiles 为 nil 表示解析失败或没有
// 权限，调用方必须退回「需确认」档，而不是当成「全部不在用」。
type profileUsageResult struct {
	// UsedProfiles 的 key 是实例配置文件的 ARN 与名字（都转小写，两种任一命中
	// 即算在用），value 是引用它的证据行。
	UsedProfiles map[string][]string
	// RoleNodegroups 的 key 是角色 ARN（小写），value 是使用该角色的
	// 「cluster / nodegroup」列表。当实例配置文件侧证据缺失时，它至少能说明
	// 「角色还有活着的节点组」。
	RoleNodegroups map[string][]string
	// Warnings 记录部分失败（例如某个 launch template 的版本读不到），让上层
	// 知道结果不完整。
	Warnings []string
	// EKSUnavailable 表示 EKS 侧证据完全缺失（ListClusters 被拒或失败）。
	// EKS 权限需要单独授予，缺了不该拖垮清单：实例配置文件的在用性仍由
	// EC2 launch template 证据判定，上层只需给出「EKS 侧未检查」的提示。
	EKSUnavailable bool
}

func (result profileUsageResult) available() bool {
	return result.UsedProfiles != nil
}

// eksUsageAPI / ec2UsageAPI 是测试替身需要的最小接口面。
type eksUsageAPI interface {
	ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	ListNodegroups(ctx context.Context, params *eks.ListNodegroupsInput, optFns ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
	DescribeNodegroup(ctx context.Context, params *eks.DescribeNodegroupInput, optFns ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
}

type ec2UsageAPI interface {
	DescribeLaunchTemplates(ctx context.Context, params *ec2.DescribeLaunchTemplatesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error)
	DescribeLaunchTemplateVersions(ctx context.Context, params *ec2.DescribeLaunchTemplateVersionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
}

// EKSProfileUsageResolver 是 ProfileUsageResolver 的 AWS 实现：按账号 Assume
// 只读角色后，用 EC2 找「哪些实例配置文件被 launch template 引用」，用 EKS 找
// 「哪些角色被活着的节点组使用」。后者权限要求低（eks:List* + Describe*），
// 即使 EC2 侧被拒也能给出降级结论。
//
// 一次解析要串行跑几十个 AWS API（每个 launch template 读两个版本、每个节点组
// Describe 一次），实测 7~25 秒。而这份证据的变化频率是「部署级」的——
// launch template 与节点组不会在两次页面刷新之间变——所以结果按账号做 TTL
// 缓存：成功 10 分钟，失败 1 分钟（失败短缓存只为防抖，不把瞬断钉死）。
// 缓存的 profileUsageResult 视为只读，调用方不得修改其 map。
type EKSProfileUsageResolver struct {
	db          *sql.DB
	baseConfig  aws.Config
	roleSession string
	externalID  string
	stsClient   *sts.Client
	eksFactory  func(aws.Config) eksUsageAPI
	ec2Factory  func(aws.Config) ec2UsageAPI

	cacheMu sync.Mutex
	cache   map[string]profileUsageCacheEntry
}

const (
	profileUsageCacheSuccessTTL = 10 * time.Minute
	profileUsageCacheErrorTTL   = 1 * time.Minute
)

type profileUsageCacheEntry struct {
	result    profileUsageResult
	err       error
	expiresAt time.Time
}

// NewEKSProfileUsageResolver 用采集链路同一套环境变量（AWS_REGION /
// AWS_PROFILE / AWS_EXTERNAL_ID / AWS_ROLE_SESSION_NAME）构造解析器。
func NewEKSProfileUsageResolver(
	db *sql.DB,
	region, profile, roleSession, externalID string,
) (*EKSProfileUsageResolver, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle must not be nil")
	}
	if strings.TrimSpace(region) == "" {
		return nil, fmt.Errorf("AWS region must not be empty")
	}
	loadOpts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if trimmed := strings.TrimSpace(profile); trimmed != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(trimmed))
	}
	baseConfig, err := config.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK configuration: %w", err)
	}
	if strings.TrimSpace(roleSession) == "" {
		roleSession = "iam-governance-cleanup"
	}
	return &EKSProfileUsageResolver{
		db:          db,
		baseConfig:  baseConfig,
		roleSession: roleSession,
		externalID:  externalID,
		stsClient:   sts.NewFromConfig(baseConfig),
		eksFactory:  func(member aws.Config) eksUsageAPI { return eks.NewFromConfig(member) },
		ec2Factory:  func(member aws.Config) ec2UsageAPI { return ec2.NewFromConfig(member) },
		cache:       map[string]profileUsageCacheEntry{},
	}, nil
}

// ResolveUsedProfiles 实现 ProfileUsageResolver：先查缓存，未命中才真正调 AWS。
func (resolver *EKSProfileUsageResolver) ResolveUsedProfiles(
	ctx context.Context,
	awsAccountID string,
) (profileUsageResult, error) {
	if entry, ok := resolver.cachedUsage(awsAccountID); ok {
		return entry.result, entry.err
	}
	result, err := resolver.resolveUsedProfilesUncached(ctx, awsAccountID)
	resolver.storeUsage(awsAccountID, result, err)
	return result, err
}

func (resolver *EKSProfileUsageResolver) cachedUsage(
	awsAccountID string,
) (profileUsageCacheEntry, bool) {
	resolver.cacheMu.Lock()
	defer resolver.cacheMu.Unlock()
	entry, ok := resolver.cache[awsAccountID]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(resolver.cache, awsAccountID)
		}
		return profileUsageCacheEntry{}, false
	}
	return entry, true
}

func (resolver *EKSProfileUsageResolver) storeUsage(
	awsAccountID string,
	result profileUsageResult,
	err error,
) {
	ttl := profileUsageCacheSuccessTTL
	if err != nil {
		ttl = profileUsageCacheErrorTTL
	}
	resolver.cacheMu.Lock()
	defer resolver.cacheMu.Unlock()
	resolver.cache[awsAccountID] = profileUsageCacheEntry{
		result:    result,
		err:       err,
		expiresAt: time.Now().Add(ttl),
	}
}

// resolveUsedProfilesUncached 是无缓存的原始实现。只读角色缺 EKS/EC2 权限时
// 返回错误而不是空结果：空结果会被上层误读成「全部不在用」。
//
// 凭证来源与采集链路一致：
//   - ASSUME_ROLE 模式：Assume aws_account.read_only_role_arn；
//   - CURRENT_CREDENTIALS 模式（aws_account_config 里没有角色 ARN）：直接用
//     进程自身的凭证，采集就是这么干的，解析器不搞特殊。
func (resolver *EKSProfileUsageResolver) resolveUsedProfilesUncached(
	ctx context.Context,
	awsAccountID string,
) (profileUsageResult, error) {
	var roleARN sql.NullString
	if err := resolver.db.QueryRowContext(ctx,
		`SELECT read_only_role_arn FROM aws_account WHERE account_id = $1`, awsAccountID,
	).Scan(&roleARN); err != nil {
		return profileUsageResult{}, fmt.Errorf("load account %s: %w", awsAccountID, err)
	}
	if roleARN.Valid && strings.TrimSpace(roleARN.String) != "" {
		memberConfig, err := resolver.assumeMemberConfig(ctx, awsAccountID, strings.TrimSpace(roleARN.String))
		if err != nil {
			return profileUsageResult{}, err
		}
		return collectProfileUsage(ctx, resolver.eksFactory(memberConfig), resolver.ec2Factory(memberConfig))
	}

	// 没有角色 ARN：只允许 CURRENT_CREDENTIALS 模式继续，其他情况宁可失败。
	var syncMode string
	err := resolver.db.QueryRowContext(ctx,
		`SELECT sync_mode FROM aws_account_config WHERE aws_account_id = $1`, awsAccountID,
	).Scan(&syncMode)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && syncMode != AWSAccountSyncCurrentCredentials) {
		return profileUsageResult{}, fmt.Errorf(
			"account %s has no read-only role ARN and is not in %s mode", awsAccountID, AWSAccountSyncCurrentCredentials)
	}
	if err != nil {
		return profileUsageResult{}, fmt.Errorf("load sync mode for account %s: %w", awsAccountID, err)
	}
	return collectProfileUsage(ctx,
		resolver.eksFactory(resolver.baseConfig), resolver.ec2Factory(resolver.baseConfig))
}

func (resolver *EKSProfileUsageResolver) assumeMemberConfig(
	ctx context.Context,
	awsAccountID, roleARN string,
) (aws.Config, error) {
	assumeInput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(resolver.roleSession),
	}
	if strings.TrimSpace(resolver.externalID) != "" {
		assumeInput.ExternalId = aws.String(resolver.externalID)
	}
	assumed, err := resolver.stsClient.AssumeRole(ctx, assumeInput)
	if err != nil {
		return aws.Config{}, fmt.Errorf("assume read-only role in account %s: %w", awsAccountID, err)
	}
	if assumed.Credentials == nil ||
		assumed.Credentials.AccessKeyId == nil ||
		assumed.Credentials.SecretAccessKey == nil ||
		assumed.Credentials.SessionToken == nil {
		return aws.Config{}, fmt.Errorf("AssumeRole returned incomplete credentials for account %s", awsAccountID)
	}
	memberConfig := aws.Config{Region: resolver.baseConfig.Region}
	memberConfig.Credentials = credentials.NewStaticCredentialsProvider(
		*assumed.Credentials.AccessKeyId,
		*assumed.Credentials.SecretAccessKey,
		*assumed.Credentials.SessionToken,
	)
	return memberConfig, nil
}

// collectProfileUsage 是解析的核心，与凭证无关所以可以离线测试。
//
// 权限降级原则（EKS 权限需要单独授予，缺权限不能影响清单其他部分）：
//   - EKS 侧被拒/失败：置 EKSUnavailable，EC2 证据照常返回；
//   - EC2 侧被拒/失败：没有硬证据可用，整体退回错误，由上层把 eks-<uuid>
//     条目降级为「需确认」——页面照常渲染，但绝不假装知道答案。
func collectProfileUsage(ctx context.Context, eksClient eksUsageAPI, ec2Client ec2UsageAPI) (profileUsageResult, error) {
	result := profileUsageResult{
		UsedProfiles:   map[string][]string{},
		RoleNodegroups: map[string][]string{},
	}

	// EC2 侧：launch template 引用的实例配置文件是「在用」的硬证据。
	templates, err := listLaunchTemplates(ctx, ec2Client)
	if err != nil {
		if awsAccessDenied(err) {
			return profileUsageResult{}, fmt.Errorf(
				"EC2 侧权限未授予（需要 ec2:DescribeLaunchTemplates/Versions 只读权限），实例配置文件在用性无法判定")
		}
		// 模板枚举失败意味着结果不可信，直接报错让上层退回 review 档。
		return profileUsageResult{}, fmt.Errorf("describe launch templates: %w", err)
	}
	for _, template := range templates {
		references, err := launchTemplateProfileReferences(ctx, ec2Client, template.id)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("launch template %s（%s）读取版本失败：%v", template.name, template.id, err))
			continue
		}
		for _, reference := range references {
			result.addProfile(reference, "被 launch template "+template.name+"（"+template.id+"）引用")
		}
	}

	// EKS 侧：角色级的节点组证据。这里失败只降级不致命——EC2 侧已经能回答
	// 「在不在用」，EKS 侧只是补充「谁在用」。权限被拒时置 EKSUnavailable，
	// 由上层给出固定提示，不把原始 AccessDenied 文本刷进页面。
	clusters, err := listEKSClusters(ctx, eksClient)
	if err != nil {
		result.EKSUnavailable = true
		if awsAccessDenied(err) {
			return result, nil
		}
		result.Warnings = append(result.Warnings, "EKS 集群列表读取失败："+err.Error())
		return result, nil
	}
	for _, cluster := range clusters {
		nodegroups, err := listEKSNodegroups(ctx, eksClient, cluster)
		if err != nil {
			if awsAccessDenied(err) {
				result.EKSUnavailable = true
				continue
			}
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("集群 %s 的节点组列表读取失败：%v", cluster, err))
			continue
		}
		for _, nodegroup := range nodegroups {
			detail, err := eksClient.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   aws.String(cluster),
				NodegroupName: aws.String(nodegroup),
			})
			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("集群 %s 节点组 %s 详情读取失败：%v", cluster, nodegroup, err))
				continue
			}
			if detail.Nodegroup == nil || detail.Nodegroup.NodeRole == nil {
				continue
			}
			roleKey := strings.ToLower(*detail.Nodegroup.NodeRole)
			result.RoleNodegroups[roleKey] = append(result.RoleNodegroups[roleKey],
				"cluster "+cluster+" / nodegroup "+nodegroup)
		}
	}
	return result, nil
}

// awsAccessDenied 判断 AWS API 错误是否为权限拒绝（AccessDenied /
// UnauthorizedOperation / 403）。用错误文本匹配即可：smithy 的
// OperationError 会把 api error AccessDeniedException 包在里面。
func awsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "AccessDenied") ||
		strings.Contains(message, "UnauthorizedOperation") ||
		strings.Contains(message, "not authorized to perform")
}

func (result *profileUsageResult) addProfile(reference string, evidence string) {
	key := strings.ToLower(strings.TrimSpace(reference))
	if key == "" {
		return
	}
	// ARN 与名字都作为 key：EC2 launch template 里有时写 ARN、有时只写名字，
	// 调用方持有的两种形态都必须能命中。
	result.UsedProfiles[key] = append(result.UsedProfiles[key], evidence)
	// 名字形态：arn:aws:iam::123:instance-profile/eks-xxxx 的最后一段。
	if index := strings.LastIndex(key, "/"); index >= 0 && index < len(key)-1 {
		name := key[index+1:]
		result.UsedProfiles[name] = append(result.UsedProfiles[name], evidence)
	}
}

func (result profileUsageResult) isUsed(profileARN, profileName string) bool {
	for _, key := range []string{strings.ToLower(profileARN), strings.ToLower(profileName)} {
		if _, ok := result.UsedProfiles[key]; ok {
			return true
		}
	}
	return false
}

func (result profileUsageResult) roleInUse(roleARN string) bool {
	_, ok := result.RoleNodegroups[strings.ToLower(roleARN)]
	return ok
}

type launchTemplateRef struct {
	id   string
	name string
}

func listLaunchTemplates(ctx context.Context, ec2Client ec2UsageAPI) ([]launchTemplateRef, error) {
	templates := make([]launchTemplateRef, 0, 16)
	var nextToken *string
	for {
		output, err := ec2Client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, template := range output.LaunchTemplates {
			if template.LaunchTemplateId == nil {
				continue
			}
			name := ""
			if template.LaunchTemplateName != nil {
				name = *template.LaunchTemplateName
			}
			templates = append(templates, launchTemplateRef{id: *template.LaunchTemplateId, name: name})
		}
		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}
	sort.Slice(templates, func(left, right int) bool { return templates[left].id < templates[right].id })
	return templates, nil
}

// launchTemplateProfileReferences 读取一个 launch template 的 $Default 与
// $Latest 版本，返回其中 IamInstanceProfile 引用（ARN 或名字）。
// EKS 托管节点组扩容用的是 $Default；新版本尚未成为默认时在 $Latest。
func launchTemplateProfileReferences(
	ctx context.Context,
	ec2Client ec2UsageAPI,
	templateID string,
) ([]string, error) {
	output, err := ec2Client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: aws.String(templateID),
		Versions:         []string{"$Default", "$Latest"},
	})
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	references := make([]string, 0, 4)
	for _, version := range output.LaunchTemplateVersions {
		if version.LaunchTemplateData == nil || version.LaunchTemplateData.IamInstanceProfile == nil {
			continue
		}
		profile := version.LaunchTemplateData.IamInstanceProfile
		for _, reference := range []*string{profile.Arn, profile.Name} {
			if reference == nil || strings.TrimSpace(*reference) == "" {
				continue
			}
			key := strings.ToLower(*reference)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			references = append(references, *reference)
		}
	}
	return references, nil
}

func listEKSClusters(ctx context.Context, eksClient eksUsageAPI) ([]string, error) {
	clusters := make([]string, 0, 8)
	var nextToken *string
	for {
		output, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, output.Clusters...)
		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}
	sort.Strings(clusters)
	return clusters, nil
}

func listEKSNodegroups(ctx context.Context, eksClient eksUsageAPI, cluster string) ([]string, error) {
	nodegroups := make([]string, 0, 8)
	var nextToken *string
	for {
		output, err := eksClient.ListNodegroups(ctx, &eks.ListNodegroupsInput{
			ClusterName: aws.String(cluster),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, err
		}
		nodegroups = append(nodegroups, output.Nodegroups...)
		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}
	sort.Strings(nodegroups)
	return nodegroups, nil
}
