package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// 首次全量基线的判定结论。取值是报告里的稳定字符串，前端/审计会直接展示。
const (
	// BaselineDecisionCandidate 进基线：平台要声明这个资源。
	BaselineDecisionCandidate = "candidate"
	// BaselineDecisionSkippedExternal 归属给了别的系统（CloudFormation /
	// eksctl / 其他团队的 Terraform），平台不碰。
	BaselineDecisionSkippedExternal = "skipped:external"
	// BaselineDecisionSkippedServiceLinked service-linked role 由 AWS 服务自己创建
	// 和维护，声明它等于和 AWS 抢所有权。
	BaselineDecisionSkippedServiceLinked = "skipped:service-linked-role"
	// BaselineDecisionSkippedAWSManagedPolicy AWS 托管策略本体不属于本账号，只能被引用。
	BaselineDecisionSkippedAWSManagedPolicy = "skipped:aws-managed-policy"
	// BaselineDecisionSkippedAlreadyDeclared 平台已有工单声明过它，再写一份就是
	// 同一个 Terraform 地址两个文件 → Duplicate resource，整个配置不可用。
	BaselineDecisionSkippedAlreadyDeclared = "skipped:already-declared"
	// BaselineDecisionSkippedExternalSignature 资源 tag 里带着 CloudFormation /
	// eksctl 的签名。不是「没人表态」，而是有证据：接管它会让对方的下一次
	// apply 把改动改回去，因此与 external 同样处理，但原因要写明证据来源。
	BaselineDecisionSkippedExternalSignature = "skipped:external-signature"
	// BaselineDecisionSkippedAWSLifecycle 资源的生命周期在 AWS 服务手里：服务
	// 会创建、连带删除，甚至换名字重建（EKS 托管节点组的实例配置文件就是
	// `eks-<uuid>`）。声明它只会得到一个「AWS 随时会删掉或改名」的 Terraform
	// 资源，第一次 apply 成功、第二次就报实体已不存在。
	//
	// 与 service-linked role 的区别只是「能不能被 IAM API 声明」：SLR 连创建都
	// 不允许，这里能创建但维持不住。两者都不进基线，理由要分开写清楚。
	BaselineDecisionSkippedAWSLifecycle = "skipped:aws-lifecycle"
)

// BaselineResource 是差异清单里的一行：一个资源、它的归属结论、它将被写进
// 哪个文件、占哪个 Terraform 地址。
type BaselineResource struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	ARN          string `json:"arn,omitempty"`
	Path         string `json:"path,omitempty"`
	ManagedBy    string `json:"managed_by"`
	ResourceType string `json:"resource_type,omitempty"`
	Address      string `json:"address,omitempty"`
	FileKey      string `json:"file_key,omitempty"`
	ImportID     string `json:"import_id,omitempty"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	// Description 是 AWS 资源的实态 description。aws_iam_policy 的
	// description 是 ForceNew，基线声明漏写它会让首次 apply 销毁重建策略。
	Description string `json:"description,omitempty"`
	// ExternalSignature 是资源 tag 里读到的外部 IaC 工具签名（CloudFormation
	// 栈、eksctl 集群）。非空表示「有证据表明它由别的工具创建」，与人工标注的
	// external 区分开：一个是判断，一个是证据。
	ExternalSignature string `json:"external_signature,omitempty"`
	// Tags 只用于判定外部工具签名，不进报告：报告里已有结论和证据来源。
	Tags map[string]string `json:"-"`
	// BoundRoleName / RoleTags 是实例配置文件绑定的角色与它的 tag。实例配置文件
	// 本身不支持 tag（AWS 侧就没有这个能力），但它与角色由同一个自动化成对创建，
	// 因此角色的证据就是它的证据；归属也跟着角色走，否则会出现「角色被排除、
	// 配置文件却进了基线」的悬空引用。
	BoundRoleName string            `json:"bound_role,omitempty"`
	RoleTags      map[string]string `json:"-"`
	// Owner / OwnerKind 是内联策略所属的主体。内联策略不能脱离主体谈归属：
	// 主体被排除（service-linked、AWS 生命周期托管、external 标注）时，它的
	// 内联策略跟着排除——否则主体消失后基线里留下一条指向不存在角色的声明。
	Owner     string `json:"owner,omitempty"`
	OwnerKind string `json:"owner_kind,omitempty"`
	// GeneratorReady 为 false 表示生成器还没实现，资源能进候选集但本次生成不出声明。
	GeneratorReady bool `json:"generator_ready"`
}

// ErrBaselineAccountNotFound 表示账号不在平台的 aws_account 里。上层（HTTP
// handler、待清理清单）据此区分「参数错」与「服务出错」。
var ErrBaselineAccountNotFound = errors.New("AWS account not found")

// BaselineConflict 是会让 Terraform 直接拒绝配置的撞车：两个资源落到同一
// 文件（后写的覆盖前者）或同一地址（Duplicate resource）。
type BaselineConflict struct {
	Kind      string   `json:"kind"`
	Value     string   `json:"value"`
	Resources []string `json:"resources"`
}

// BaselineRelationship 是关系类资源：成员关系与策略挂载。它们不是独立资源，
// 归属由主体决定，但已存在挂载工单的主体不能再在基线里声明挂载（双声明）。
type BaselineRelationship struct {
	Subject        string `json:"subject"`
	Kind           string `json:"kind"`
	Detail         string `json:"detail"`
	ExistingTicket bool   `json:"existing_ticket"`
	// FileKey 是声明这份关系要写的文件（membership 独立文件、attachment 按
	// 主体+策略命名）。挂载类关系的 key 与挂载工单的 resourceFileKey 同源，
	// 两条链路不会写出不同的文件名。
	FileKey string `json:"file_key,omitempty"`
}

// BaselineCandidateReport 是阶段 0 的差异清单：能逐条解释每个资源是进基线、
// 跳过还是撞车。
type BaselineCandidateReport struct {
	AccountDBID          int64                  `json:"account_db_id"`
	AWSAccountID         string                 `json:"aws_account_id"`
	GeneratedAt          time.Time              `json:"generated_at"`
	LatestSyncRunID      int64                  `json:"latest_sync_run_id,omitempty"`
	LatestSyncFinishedAt *time.Time             `json:"latest_sync_finished_at,omitempty"`
	Resources            []BaselineResource     `json:"resources"`
	Conflicts            []BaselineConflict     `json:"conflicts"`
	Relationships        []BaselineRelationship `json:"relationships"`
	Counts               map[string]int         `json:"counts"`
}

// Build 汇总一次账号的基线候选集。只读：不改库存、不生成文件、不碰仓库。
func (service *BaselineCandidateService) Build(
	ctx context.Context,
	accountRef string,
) (*BaselineCandidateReport, error) {
	ref := strings.TrimSpace(accountRef)
	if ref == "" {
		return nil, errors.New("account reference must not be empty")
	}
	report := &BaselineCandidateReport{
		GeneratedAt: time.Now().UTC(),
		Counts:      map[string]int{},
	}
	if err := service.db.QueryRowContext(ctx, `
		SELECT id, account_id FROM aws_account
		WHERE account_id = $1 OR id::text = $1
		LIMIT 1`, ref,
	).Scan(&report.AccountDBID, &report.AWSAccountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q", ErrBaselineAccountNotFound, ref)
		}
		return nil, fmt.Errorf("load AWS account %q: %w", ref, err)
	}

	declared, err := service.declaredResources(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	resource, err := service.collectResources(ctx, report, declared)
	if err != nil {
		return nil, err
	}
	report.Resources = resource
	report.Conflicts = detectBaselineConflicts(resource)
	report.Relationships, err = service.collectRelationships(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	for _, item := range resource {
		report.Counts[item.Decision]++
	}
	if err := service.loadLatestSyncRun(ctx, report); err != nil {
		return nil, err
	}
	return report, nil
}

// BaselineCandidateService 汇总首次全量基线的候选资源与冲突。
type BaselineCandidateService struct {
	db *sql.DB
}

func NewBaselineCandidateService(db *sql.DB) *BaselineCandidateService {
	return &BaselineCandidateService{db: db}
}

func (service *BaselineCandidateService) collectResources(
	ctx context.Context,
	report *BaselineCandidateReport,
	declared map[string]map[string]bool,
) ([]BaselineResource, error) {
	resources := make([]BaselineResource, 0, 256)

	principals, err := service.loadPrincipals(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	resources = append(resources, principals...)

	groups, err := service.loadGroups(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	resources = append(resources, groups...)

	policies, err := service.loadPolicies(ctx, report.AccountDBID, report.AWSAccountID)
	if err != nil {
		return nil, err
	}
	resources = append(resources, policies...)

	profiles, err := service.loadInstanceProfiles(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	resources = append(resources, profiles...)

	providers, err := service.loadIdentityProviders(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	resources = append(resources, providers...)

	inlinePolicies, err := service.loadInlinePolicies(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	resources = append(resources, inlinePolicies...)

	for index := range resources {
		item := &resources[index]
		alreadyDeclared := declared[item.Kind][item.Name]
		if item.Kind == BaselineKindInlinePolicy {
			alreadyDeclared = declared[BaselineKindInlinePolicy][item.FileKey]
		}
		item.Decision, item.Reason = classifyBaselineResource(
			*item,
			alreadyDeclared,
		)
		item.ExternalSignature = externalToolSignature(effectiveTags(*item))
	}
	sort.SliceStable(resources, func(left, right int) bool {
		if resources[left].Kind != resources[right].Kind {
			return resources[left].Kind < resources[right].Kind
		}
		return resources[left].Name < resources[right].Name
	})
	return resources, nil
}

// classifyBaselineResource 是差异清单的核心判定，顺序即优先级：
// 原理上不可声明的资源排在最前（无论归属标注成什么），然后是归属结论
// （external 标注、外部工具签名），最后才是「已被平台声明」。把
// already-declared 放在归属之后，是为了让 service-linked / AWS 托管策略永远
// 显示成自身原因，而不是显示成「已纳管」；而外部工具签名放在 already-declared
// 之后，是因为「平台已经开过工单」这件事本身就推翻了 tag 里的历史线索。
//
// 归属只影响「跳过」，不影响「能否声明」：unknown 默认进基线（平台的定位就是
// 统一 IAM 管理），跳过必须给出理由。
//
// 「AWS 生命周期托管」排在 already-declared 之前，是因为它比「谁声明过」更根本：
// 如果一个 Quick Setup 角色曾被开过工单，那条工单本身就是错的，报告要指向要清理
// 的东西，而不是把它藏进「已声明」。
func classifyBaselineResource(item BaselineResource, alreadyDeclared bool) (string, string) {
	kind, name, arn, path, managedBy := item.Kind, item.Name, item.ARN, item.Path, item.ManagedBy
	if kind == BaselineKindRole {
		if strings.HasPrefix(path, "/aws-service-role/") ||
			strings.HasPrefix(name, "AWSServiceRoleFor") {
			return BaselineDecisionSkippedServiceLinked,
				"AWS 服务自建自管（service-linked role），声明它等于和 AWS 抢所有权"
		}
	}
	if kind == BaselineKindAWSManagedPolicy {
		return BaselineDecisionSkippedAWSManagedPolicy,
			"AWS 托管策略本体不属于本账号，只能被挂载引用"
	}
	if kind == BaselineKindPolicy && isAWSManagedPolicyARN(arn) {
		return BaselineDecisionSkippedAWSManagedPolicy,
			"AWS 托管策略本体不属于本账号，只能被挂载引用"
	}
	if kind == BaselineKindInlinePolicy {
		// 内联策略不能脱离主体谈归属：主体被排除，策略跟着排除——主体消失后
		// 基线里会留下一条指向不存在角色的声明。归属标注已随主体继承
		// （见 loadInlinePolicies），这里补原理性排除的两类。
		if decision, reason := inlinePolicyOwnerReason(item); decision != "" {
			return decision, reason
		}
	}
	if reason := awsLifecycleReason(item); reason != "" {
		if alreadyDeclared {
			reason += "；平台已为它生成过工单文件，需要一并清掉，否则 Terraform 会声明一个 AWS 随时会改写的资源"
		}
		return BaselineDecisionSkippedAWSLifecycle, reason
	}
	if strings.EqualFold(strings.TrimSpace(managedBy), "external") {
		return BaselineDecisionSkippedExternal,
			"归属标注为 external（其他系统管理），纳管会与其互相覆盖"
	}
	if alreadyDeclared {
		return BaselineDecisionSkippedAlreadyDeclared,
			"平台已有工单声明过该资源；再写一份会造成同一地址双声明"
	}
	if signature := externalToolSignature(effectiveTags(item)); signature != "" {
		return BaselineDecisionSkippedExternalSignature,
			"资源 tag 显示由 " + signature + " 创建；平台接管后该工具下次运行会把改动改回去"
	}
	return BaselineDecisionCandidate, ""
}

// awsLifecycleReason 判定「生命周期不在人手里」的资源，返回排除理由；空串表示
// 这条证据不成立。
//
// 判据只有三类，全部来自采集期已入库的数据，不需要新增 AWS 权限：
//   - SSM Quick Setup 的角色固定用 `AWS-QuickSetup-*` 命名空间（部分带
//     QuickSetupManagerArn tag，部分不带，tag 缺了就漏判）；
//   - EKS 托管节点组的实例配置文件固定叫 `eks-<uuid>`，而 IAM 实例配置文件
//     **不支持 tag**，tag 证据在这类资源上永远为空，只能靠名字；
//   - AWS 自动化代建的角色会自带 `Created By: AWS ... Automation` tag，配合
//     `Amazon*` 保留名前缀构成双重证据。
//
// 刻意不排除的：CloudTrail 在 `/service-role/` 下代建的
// `CloudTrailRoleForCloudWatchLogs_*`、WorkSpaces 的 `workspaces_DefaultRole`、
// EKS Pod Identity 的 `AmazonEKSPodIdentity*Role`。它们确实是 AWS 建的，但名字
// 稳定、创建后就归客户所有，AWS 不会重写或连带删除——生命周期在人手里，正是
// 基线该接管的对象。
func awsLifecycleReason(item BaselineResource) string {
	name := item.Name
	lowerName := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(lowerName, "aws-quicksetup-") ||
		strings.HasPrefix(lowerName, "awsquicksetup") {
		return "SSM Quick Setup 生成的角色（固定命名空间）；重跑配置管理会重写它的权限，纳管后两边互相覆盖"
	}
	if item.Kind == BaselineKindInstanceProfile && isEKSManagedInstanceProfileName(lowerName) {
		return "EKS 托管节点组自动创建的实例配置文件；节点组重建会换一个新的 UUID 名，删除节点组时连带删除"
	}
	if tagSaysAWSAutomation(effectiveTags(item)) && hasAWSReservedNamePrefix(name) {
		return "tag「Created By」显示由 AWS 自动化创建；重跑该自动化会重写属性"
	}
	return ""
}

// effectiveTags 取判定用的 tag：资源自己没有 tag 时退回绑定角色的 tag。
// 只对实例配置文件生效——它是 IAM 里唯一「支持绑定角色但不支持打 tag」的资源。
func effectiveTags(item BaselineResource) map[string]string {
	if len(item.Tags) == 0 && item.Kind == BaselineKindInstanceProfile {
		return item.RoleTags
	}
	return item.Tags
}

// inlinePolicyOwnerBaselineReason 内联策略所属主体被原理性排除时的结论。
// 返回零值表示主体本身可声明，策略跟随进基线。
func inlinePolicyOwnerReason(item BaselineResource) (decision string, text string) {
	if item.OwnerKind != "role" || strings.TrimSpace(item.Owner) == "" {
		return "", ""
	}
	if strings.HasPrefix(item.Owner, "AWSServiceRoleFor") {
		return BaselineDecisionSkippedServiceLinked,
			"内联策略挂在 service-linked role 上；角色由 AWS 自建自管，声明策略会指向一个不该碰的角色"
	}
	// 主体的 AWS 生命周期证据（Quick Setup 命名空间、AWS 自动化 tag + 保留名
	// 前缀）同样适用于它的内联策略。RoleTags 已在加载时带上主体的 tag。
	ownerItem := BaselineResource{Kind: BaselineKindRole, Name: item.Owner, Tags: item.RoleTags}
	if reason := awsLifecycleReason(ownerItem); reason != "" {
		return BaselineDecisionSkippedAWSLifecycle, "内联策略所属角色被排除：" + reason
	}
	return "", ""
}

// isEKSManagedInstanceProfileName 判断 `eks-<uuid>` 形态：EKS 托管节点组创建
// 实例配置文件时用 UUID 作名字，节点组每重建一次就多一个新名字。
// 以前的孤儿（同一个角色挂着 4 个 profile）正是这么留下的。
func isEKSManagedInstanceProfileName(lowerName string) bool {
	const prefix = "eks-"
	if !strings.HasPrefix(lowerName, prefix) {
		return false
	}
	parts := strings.Split(lowerName[len(prefix):], "-")
	widths := []int{8, 4, 4, 4, 12}
	if len(parts) != len(widths) {
		return false
	}
	for index, width := range widths {
		if len(parts[index]) != width {
			return false
		}
		for _, char := range parts[index] {
			isHex := (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// tagSaysAWSAutomation 读 `Created By` tag 里的 AWS 自动化声明。只认这一个键：
// 它是 AWS 托管自动化文档（如 SSM Automation「启用 Directory Service 访问」）
// 打上的，其他键的同类描述不足以作为排除证据。
func tagSaysAWSAutomation(tags map[string]string) bool {
	for key, value := range tags {
		if !strings.EqualFold(strings.TrimSpace(key), "Created By") {
			continue
		}
		lowerValue := strings.ToLower(value)
		return strings.Contains(lowerValue, "aws") &&
			strings.Contains(lowerValue, "automation")
	}
	return false
}

// hasAWSReservedNamePrefix 判断 AWS 保留的命名前缀。与 tag 证据叠加使用，避免
// 只凭一条可被人工改写的 tag 就把资源排除出基线。
func hasAWSReservedNamePrefix(name string) bool {
	return strings.HasPrefix(name, "Amazon") || strings.HasPrefix(name, "AWS")
}

// externalToolSignature 从资源 tag 判出创建它的外部 IaC 工具。
//
// 这些 tag 都是创建方自己打的，采集期就已入库，因此判定不额外调用 AWS API、
// 也不需要给只读角色加权限：
//   - CloudFormation 会给它创建的、支持 tag 的资源自动打上 aws:cloudformation:*
//     三件套，栈名即归属；
//   - eksctl 创建的角色/实例配置文件带 alpha.eksctl.io/cluster-name；
//   - AWS SSM Quick Setup 创建的角色带 QuickSetupManagerArn 指向 configuration
//     manager，重跑该配置会把被改动的属性改回去。
func externalToolSignature(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	if stack := strings.TrimSpace(tags["aws:cloudformation:stack-name"]); stack != "" {
		return "CloudFormation 栈 " + stack
	}
	if manager := strings.TrimSpace(tags["QuickSetupManagerArn"]); manager != "" {
		return "AWS SSM Quick Setup 配置管理 " + lastPathSegment(manager)
	}
	if document := strings.TrimSpace(tags["QuickSetupDocument"]); document != "" {
		return "AWS SSM Quick Setup 配置 " + document
	}
	// eksctl（alpha.eksctl.io/*）刻意不在此列：团队决定统一纳管 eksctl 创建的
	// IAM 资源（2026-10-28 复盘）。eksctl 只在集群创建期写一次 provider/role，
	// 之后不会重写，纳管不会互相覆盖；排除反而让基线漏掉真实存在的资源。
	return ""
}

// lastPathSegment 取 ARN/URL 的最后一段，用于在报告里指认具体是哪个配置管理，
// 而不是整条 ARN（报告要能读懂，ARN 太长会挤掉表格）。
func lastPathSegment(value string) string {
	if index := strings.LastIndex(value, "/"); index >= 0 && index+1 < len(value) {
		return value[index+1:]
	}
	return value
}

// decodeResourceTags 把 tags 列（JSONB，可为 NULL）解成 map。判定只读少数几个
// 键，解析失败按「没有签名」处理：不能因为一条脏 tag 让整份差异清单报不出来。
func decodeResourceTags(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	tags := map[string]string{}
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil
	}
	return tags
}

// detectBaselineConflicts 找出两类会直接让 Terraform 拒绝配置的撞车。
// 只检查候选资源：被跳过的资源不写文件，撞车无意义。
func detectBaselineConflicts(resources []BaselineResource) []BaselineConflict {
	fileKeys := map[string][]string{}
	addresses := map[string][]string{}
	for _, item := range resources {
		if item.Decision != BaselineDecisionCandidate {
			continue
		}
		label := item.Kind + ":" + item.Name
		if item.FileKey != "" {
			fileKeys[item.FileKey] = append(fileKeys[item.FileKey], label)
		}
		if item.Address != "" {
			addresses[item.Address] = append(addresses[item.Address], label)
		}
	}
	conflicts := make([]BaselineConflict, 0)
	for key, owners := range fileKeys {
		if len(owners) > 1 {
			sort.Strings(owners)
			conflicts = append(conflicts, BaselineConflict{
				Kind:      "file-key",
				Value:     key + ".tf",
				Resources: owners,
			})
		}
	}
	for address, owners := range addresses {
		if len(owners) > 1 {
			sort.Strings(owners)
			conflicts = append(conflicts, BaselineConflict{
				Kind:      "address",
				Value:     address,
				Resources: owners,
			})
		}
	}
	sort.Slice(conflicts, func(left, right int) bool {
		if conflicts[left].Kind != conflicts[right].Kind {
			return conflicts[left].Kind < conflicts[right].Kind
		}
		return conflicts[left].Value < conflicts[right].Value
	})
	return conflicts
}

// declaredResources 返回「平台已经声明过」的资源，按资源种类归集。
// 判定口径是「成功工单」（phase4-drift-design.md §5）：只有 MERGED、或
// 关单原因为 APPLIED 的 CLOSED 工单才真正把文件写进了 main。此前的
// status <> 'REJECTED' 会把 DRAFT / PUBLISH_FAILED / 未合并 CLOSED 也算
// 成已声明——这些工单没有产生任何文件，资源会变成「谁都没声明」且
// 不出现在任何清单里。注意：有在途工单（APPROVING/APPROVED/PUBLISHING）
// 的资源回到基线候选是口径收窄的预期结果；基线发布对它们的让路
// （deferred）由 phase4 的发布预约机制负责，不在本函数。
//
// 内联策略按文件 key（InlinePolicyFileKey 的结果）归集，因为策略名只在
// 主体内唯一。ADOPT_ROLE_INLINE_POLICIES 一次性收编角色全部内联策略，
// UPDATE_GROUP_INLINE_POLICY / 角色内联更新则声明单个策略——两者都从
// request_policy 里解析出主体与策略名。
func (service *BaselineCandidateService) declaredResources(
	ctx context.Context,
	accountDBID int64,
) (map[string]map[string]bool, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT ticket_type, COALESCE(principal_name, ''), request_policy
		FROM iam_ticket
		WHERE account_id = $1 AND (
			status = 'MERGED'
			OR (status = 'CLOSED' AND closure_reason = 'APPLIED')
		)`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load declaring tickets: %w", err)
	}
	defer rows.Close()
	declared := map[string]map[string]bool{
		BaselineKindRole:         {},
		BaselineKindUser:         {},
		BaselineKindGroup:        {},
		BaselineKindPolicy:       {},
		BaselineKindInlinePolicy: {},
	}
	for rows.Next() {
		var ticketType, principalName string
		var payload []byte
		if err := rows.Scan(&ticketType, &principalName, &payload); err != nil {
			return nil, fmt.Errorf("scan declaring ticket: %w", err)
		}
		name := strings.TrimSpace(principalName)
		switch ticketType {
		case TicketTypeCreateRole, TicketTypeUpdateRole:
			if name != "" {
				declared[BaselineKindRole][name] = true
			}
		case TicketTypeCreateUser:
			if name != "" {
				declared[BaselineKindUser][name] = true
			}
		case TicketTypeCreateGroup:
			if name != "" {
				declared[BaselineKindGroup][name] = true
			}
		case TicketTypeCreateManagedPolicy, TicketTypeUpdateManagedPolicy:
			if name != "" {
				declared[BaselineKindPolicy][name] = true
			}
		case TicketTypeAdoptRoleInlinePolicies:
			// 角色收编工单同时声明角色本体与它名下的每条内联策略。
			if name != "" {
				declared[BaselineKindRole][name] = true
			}
			var payload_ struct {
				RoleInlinePolicies []struct {
					Name string `json:"name"`
				} `json:"role_inline_policies"`
			}
			if json.Unmarshal(payload, &payload_) == nil {
				for _, inline := range payload_.RoleInlinePolicies {
					if key := InlinePolicyFileKey("role", name, inline.Name); key != "" {
						declared[BaselineKindInlinePolicy][key] = true
					}
				}
			}
		case TicketTypeUpdateGroupInlinePolicy:
			var payload_ struct {
				UpdatePolicy *struct {
					GroupName        string `json:"group_name"`
					RoleName         string `json:"role_name"`
					InlinePolicyName string `json:"inline_policy_name"`
				} `json:"update_policy"`
			}
			if json.Unmarshal(payload, &payload_) == nil && payload_.UpdatePolicy != nil {
				kind, owner := "group", strings.TrimSpace(payload_.UpdatePolicy.GroupName)
				if owner == "" {
					kind, owner = "role", strings.TrimSpace(payload_.UpdatePolicy.RoleName)
				}
				if key := InlinePolicyFileKey(kind, owner, payload_.UpdatePolicy.InlinePolicyName); key != "" {
					declared[BaselineKindInlinePolicy][key] = true
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate declaring tickets: %w", err)
	}
	return declared, nil
}

// BaselineKind* 是资源种类的稳定标识，同时用于文件 key 前缀。
const (
	BaselineKindRole             = "role"
	BaselineKindUser             = "user"
	BaselineKindGroup            = "group"
	BaselineKindPolicy           = "policy"
	BaselineKindAWSManagedPolicy = "aws-managed-policy"
	BaselineKindInstanceProfile  = "instance-profile"
	BaselineKindOIDCProvider     = "oidc-provider"
	BaselineKindSAMLProvider     = "saml-provider"
	// BaselineKindInlinePolicy 是挂在某个主体（role/user/group）下的内联策略。
	// 它的文件 key 前缀跟着主体走（role-<r>-policy-<p> 等，见 InlinePolicyFileKey），
	// kind 本身只用于报告展示与判定分支。
	BaselineKindInlinePolicy = "inline-policy"
)

func (service *BaselineCandidateService) loadPrincipals(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineResource, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT principal_type, principal_name, arn, path, managed_by, tags
		FROM iam_principal
		WHERE account_id = $1 AND is_deleted = FALSE
		ORDER BY principal_type, principal_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load IAM principals: %w", err)
	}
	defer rows.Close()
	resources := make([]BaselineResource, 0, 128)
	for rows.Next() {
		var principalType, name, arn, path, managedBy string
		var tags []byte
		if err := rows.Scan(&principalType, &name, &arn, &path, &managedBy, &tags); err != nil {
			return nil, fmt.Errorf("scan IAM principal: %w", err)
		}
		item := BaselineResource{
			Name:      name,
			ARN:       arn,
			Path:      path,
			ManagedBy: managedBy,
			Tags:      decodeResourceTags(tags),
			ImportID:  name,
		}
		switch strings.ToLower(principalType) {
		case "role":
			item.Kind = BaselineKindRole
			item.ResourceType = "aws_iam_role"
			item.FileKey = ResourceFileKey(BaselineKindRole, name)
			item.Address = "aws_iam_role." + adapter.RoleResourceLabel(name)
			item.GeneratorReady = true
		case "user":
			item.Kind = BaselineKindUser
			item.ResourceType = "aws_iam_user"
			item.FileKey = ResourceFileKey(BaselineKindUser, name)
			item.Address = "aws_iam_user." + adapter.UserResourceLabel(name)
			item.GeneratorReady = true
		default:
			// 未知主体类型不进候选集：采集器只产出 Role/User。
			continue
		}
		resources = append(resources, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate IAM principals: %w", err)
	}
	return resources, nil
}

func (service *BaselineCandidateService) loadGroups(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineResource, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT group_name, arn, path, managed_by
		FROM iam_group
		WHERE account_id = $1
		ORDER BY group_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load IAM groups: %w", err)
	}
	defer rows.Close()
	resources := make([]BaselineResource, 0, 32)
	for rows.Next() {
		var name, arn, path, managedBy string
		if err := rows.Scan(&name, &arn, &path, &managedBy); err != nil {
			return nil, fmt.Errorf("scan IAM group: %w", err)
		}
		resources = append(resources, BaselineResource{
			Kind:           BaselineKindGroup,
			Name:           name,
			ARN:            arn,
			Path:           path,
			ManagedBy:      managedBy,
			ResourceType:   "aws_iam_group",
			FileKey:        ResourceFileKey(BaselineKindGroup, name),
			Address:        "aws_iam_group." + adapter.GroupResourceLabel(name),
			ImportID:       name,
			GeneratorReady: true,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate IAM groups: %w", err)
	}
	return resources, nil
}

// loadPolicies 同时载入本账号的客户自管策略与被引用的 AWS 托管策略：前者是
// 候选资源，后者要进「不可声明清单」，只作为挂载引用出现。
//
// C2 之后同步会把全量 AWS 托管策略目录（上千条）写进 iam_policy，所以「被引用」
// 必须显式判定：只取在本账号被主体或组真正挂载的官方策略，否则差异清单会被
// 上千条不可声明的目录行淹没，真正的候选资源反而被挤出预览。
func (service *BaselineCandidateService) loadPolicies(
	ctx context.Context,
	accountDBID int64,
	awsAccountID string,
) ([]BaselineResource, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT COALESCE(policy_name, ''), COALESCE(policy_arn, ''), managed_by,
		       description, tags
		FROM iam_policy
		WHERE policy_arn LIKE 'arn:aws:iam::' || $1 || ':policy/%'
		   OR (policy_arn LIKE 'arn:aws:iam::aws:policy/%'
		       AND (EXISTS (
		               SELECT 1 FROM iam_principal_policy pp
		               JOIN iam_principal p ON p.id = pp.principal_id
		               WHERE pp.policy_id = iam_policy.id
		                 AND p.account_id = $2 AND p.is_deleted = FALSE
		           )
		           OR EXISTS (
		               SELECT 1 FROM iam_group_policy gp
		               JOIN iam_group g ON g.id = gp.group_id
		               WHERE gp.policy_id = iam_policy.id AND g.account_id = $2
		           )))
		ORDER BY policy_name`, awsAccountID, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load IAM policies: %w", err)
	}
	defer rows.Close()
	resources := make([]BaselineResource, 0, 64)
	for rows.Next() {
		var name, arn, managedBy, description string
		var tags []byte
		if err := rows.Scan(&name, &arn, &managedBy, &description, &tags); err != nil {
			return nil, fmt.Errorf("scan IAM policy: %w", err)
		}
		if name == "" {
			name = adapterPolicyNameFromARN(arn)
		}
		item := BaselineResource{
			Kind:         BaselineKindPolicy,
			Name:         name,
			ARN:          arn,
			Path:         policyPathFromARN(arn),
			ManagedBy:    managedBy,
			ResourceType: "aws_iam_policy",
			ImportID:     arn,
			Description:  description,
			Tags:         decodeResourceTags(tags),
		}
		if isAWSManagedPolicyARN(arn) {
			// AWS 托管策略只作为被引用的对象出现在清单里，不能声明本体。
			item.Kind = BaselineKindAWSManagedPolicy
			item.ResourceType = "aws_iam_policy"
			item.ImportID = ""
		} else {
			item.FileKey = ResourceFileKey(BaselineKindPolicy, name)
			item.Address = "aws_iam_policy." + adapter.DefaultManagedPolicyLabel(name)
			item.GeneratorReady = true
		}
		resources = append(resources, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate IAM policies: %w", err)
	}
	return resources, nil
}

func (service *BaselineCandidateService) loadInstanceProfiles(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineResource, error) {
	// 左连绑定角色：实例配置文件不支持 tag，归属与证据都得从角色那边取。
	rows, err := service.db.QueryContext(ctx, `
		SELECT ip.instance_profile_name, ip.arn, ip.path, ip.tags,
		       COALESCE(r.principal_name, '') AS role_name,
		       COALESCE(r.managed_by, '') AS role_managed_by,
		       r.tags AS role_tags
		FROM iam_instance_profile ip
		LEFT JOIN iam_principal r
		       ON r.account_id = ip.account_id
		      AND r.principal_type = 'Role'
		      AND r.arn = ip.role_arn
		      AND r.is_deleted = FALSE
		WHERE ip.account_id = $1 AND ip.is_deleted = FALSE
		ORDER BY ip.instance_profile_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load instance profiles: %w", err)
	}
	defer rows.Close()
	resources := make([]BaselineResource, 0, 16)
	for rows.Next() {
		var name, arn, path string
		var tags, roleTags []byte
		var roleName, roleManagedBy string
		if err := rows.Scan(&name, &arn, &path, &tags, &roleName, &roleManagedBy, &roleTags); err != nil {
			return nil, fmt.Errorf("scan instance profile: %w", err)
		}
		managedBy := "unknown"
		if value := strings.TrimSpace(roleManagedBy); value != "" {
			managedBy = value
		}
		resources = append(resources, BaselineResource{
			Kind:           BaselineKindInstanceProfile,
			Name:           name,
			ARN:            arn,
			Path:           path,
			ManagedBy:      managedBy,
			Tags:           decodeResourceTags(tags),
			BoundRoleName:  roleName,
			RoleTags:       decodeResourceTags(roleTags),
			ResourceType:   "aws_iam_instance_profile",
			FileKey:        ResourceFileKey(BaselineKindInstanceProfile, name),
			Address:        "aws_iam_instance_profile." + adapter.InstanceProfileResourceLabel(name),
			ImportID:       name,
			GeneratorReady: true,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate instance profiles: %w", err)
	}
	return resources, nil
}

func (service *BaselineCandidateService) loadIdentityProviders(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineResource, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT provider_type, provider_name, arn, tags
		FROM iam_identity_provider
		WHERE account_id = $1 AND is_deleted = FALSE
		ORDER BY provider_type, provider_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load identity providers: %w", err)
	}
	defer rows.Close()
	resources := make([]BaselineResource, 0, 16)
	for rows.Next() {
		var providerType, name, arn string
		var tags []byte
		if err := rows.Scan(&providerType, &name, &arn, &tags); err != nil {
			return nil, fmt.Errorf("scan identity provider: %w", err)
		}
		item := BaselineResource{
			Kind:         strings.ToLower(providerType) + "-provider",
			Name:         name,
			ARN:          arn,
			ManagedBy:    "unknown",
			ResourceType: "aws_iam_saml_provider",
			ImportID:     arn,
			Tags:         decodeResourceTags(tags),
		}
		if strings.EqualFold(providerType, "OIDC") {
			item.Kind = BaselineKindOIDCProvider
			item.ResourceType = "aws_iam_openid_connect_provider"
			item.ImportID = arn
		}
		item.FileKey = ResourceFileKey(item.Kind, providerLabelToken(name))
		item.Address = item.ResourceType + "." + adapter.IdentityProviderResourceLabel(name)
		item.GeneratorReady = true
		resources = append(resources, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity providers: %w", err)
	}
	return resources, nil
}

// loadInlinePolicies 载入本账号的内联策略（policy_type='inline'，挂在
// role/user/group 上）。它们是候选资源：文件 key 与地址跟着主体走，归属
// 默认继承主体（内联策略行自己的 managed_by 优先——它可能是人工对策略单独
// 标过的）。主体本身被排除的排除逻辑在 classifyBaselineResource 里。
//
// 过滤维度是主体的 account_id 而不是策略行的：内联策略行没有 ARN，
// account_id 恒为 NULL（见采集器 upsertPolicy）。
func (service *BaselineCandidateService) loadInlinePolicies(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineResource, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT owner_kind, owner_name, policy_name,
		       COALESCE(policy_document::text, '') AS document,
		       COALESCE(policy_managed_by, '') AS policy_managed_by,
		       COALESCE(owner_managed_by, '') AS owner_managed_by,
		       COALESCE(owner_tags::text, '') AS owner_tags
		FROM (
			SELECT 'role' AS owner_kind, p.principal_name AS owner_name,
			       pol.policy_name, pol.policy_document,
			       pol.managed_by AS policy_managed_by,
			       p.managed_by AS owner_managed_by, p.tags AS owner_tags
			FROM iam_policy pol
			JOIN iam_principal_policy pp ON pp.policy_id = pol.id
			JOIN iam_principal p ON p.id = pp.principal_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE
			  AND p.principal_type = 'Role'
			  AND pol.policy_type = 'inline'
			UNION ALL
			SELECT 'user', p.principal_name,
			       pol.policy_name, pol.policy_document,
			       pol.managed_by, p.managed_by, p.tags
			FROM iam_policy pol
			JOIN iam_principal_policy pp ON pp.policy_id = pol.id
			JOIN iam_principal p ON p.id = pp.principal_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE
			  AND p.principal_type = 'User'
			  AND pol.policy_type = 'inline'
			UNION ALL
			SELECT 'group', g.group_name,
			       pol.policy_name, pol.policy_document,
			       pol.managed_by, g.managed_by, NULL
			FROM iam_policy pol
			JOIN iam_group_policy gp ON gp.policy_id = pol.id
			JOIN iam_group g ON g.id = gp.group_id
			WHERE g.account_id = $1 AND pol.policy_type = 'inline'
		) inline
		ORDER BY owner_kind, owner_name, policy_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load inline policies: %w", err)
	}
	defer rows.Close()
	resources := make([]BaselineResource, 0, 64)
	for rows.Next() {
		var ownerKind, ownerName, policyName, document string
		var policyManagedBy, ownerManagedBy, ownerTags string
		if err := rows.Scan(&ownerKind, &ownerName, &policyName, &document,
			&policyManagedBy, &ownerManagedBy, &ownerTags); err != nil {
			return nil, fmt.Errorf("scan inline policy: %w", err)
		}
		resourceType := map[string]string{
			"role":  "aws_iam_role_policy",
			"user":  "aws_iam_user_policy",
			"group": "aws_iam_group_policy",
		}[ownerKind]
		managedBy := strings.TrimSpace(policyManagedBy)
		if managedBy == "" {
			managedBy = strings.TrimSpace(ownerManagedBy)
		}
		if managedBy == "" {
			managedBy = "unknown"
		}
		resources = append(resources, BaselineResource{
			Kind:         BaselineKindInlinePolicy,
			Name:         policyName,
			Owner:        ownerName,
			OwnerKind:    ownerKind,
			ManagedBy:    managedBy,
			RoleTags:     decodeResourceTags([]byte(ownerTags)),
			ResourceType: resourceType,
			FileKey:      InlinePolicyFileKey(ownerKind, ownerName, policyName),
			Address: resourceType + "." +
				adapter.InlinePolicyResourceLabel(ownerKind, ownerName, policyName),
			// Terraform 的内联策略 import ID 约定：<主体名>:<策略名>。
			ImportID:       ownerName + ":" + policyName,
			GeneratorReady: true,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inline policies: %w", err)
	}
	return resources, nil
}

// collectRelationships 汇总关系类资源。它们不单独建文件，但已存在挂载工单的
// 主体必须提示：基线再声明挂载就是同一个 aws_iam_*_policy_attachment 双声明。
func (service *BaselineCandidateService) collectRelationships(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineRelationship, error) {
	relationships := make([]BaselineRelationship, 0, 64)

	memberships, err := service.loadGroupMemberships(ctx, accountDBID)
	if err != nil {
		return nil, err
	}
	relationships = append(relationships, memberships...)

	attachments, err := service.loadPolicyAttachments(ctx, accountDBID)
	if err != nil {
		return nil, err
	}
	relationships = append(relationships, attachments...)
	profiles, err := service.loadProfileBindings(ctx, accountDBID)
	if err != nil {
		return nil, err
	}
	relationships = append(relationships, profiles...)

	sort.SliceStable(relationships, func(left, right int) bool {
		if relationships[left].Kind != relationships[right].Kind {
			return relationships[left].Kind < relationships[right].Kind
		}
		return relationships[left].Subject < relationships[right].Subject
	})
	return relationships, nil
}

func (service *BaselineCandidateService) loadGroupMemberships(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineRelationship, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT g.group_name, COUNT(m.id)
		FROM iam_group g
		LEFT JOIN iam_group_membership m ON m.group_id = g.id
		WHERE g.account_id = $1
		GROUP BY g.group_name
		HAVING COUNT(m.id) > 0
		ORDER BY g.group_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load group memberships: %w", err)
	}
	defer rows.Close()
	relationships := make([]BaselineRelationship, 0, 32)
	for rows.Next() {
		var groupName string
		var members int
		if err := rows.Scan(&groupName, &members); err != nil {
			return nil, fmt.Errorf("scan group membership: %w", err)
		}
		relationships = append(relationships, BaselineRelationship{
			Subject: "group:" + groupName,
			Kind:    "group-membership",
			Detail:  fmt.Sprintf("成员 %d 人（声明为完整集合，未列出的成员会被移除）", members),
			// membership 声明放独立文件：该资源不支持 import，首个 plan 必然
			// add，独立文件让主体文件保持 import-only 干净。
			FileKey: MembershipFileKey(groupName),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate group memberships: %w", err)
	}
	return relationships, nil
}

func (service *BaselineCandidateService) loadPolicyAttachments(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineRelationship, error) {
	declared, err := service.declaredAttachmentPrincipals(ctx, accountDBID)
	if err != nil {
		return nil, err
	}
	// 组挂载在 iam_group_policy，与 User/Role 的 iam_principal_policy 合并
	// ——漏掉组的后果是报告少列组挂载、基线跳过组挂载纳管。
	rows, err := service.db.QueryContext(ctx, `
		SELECT principal_type, principal_name,
		       COUNT(*) FILTER (WHERE policy_arn LIKE 'arn:aws:iam::aws:policy/%') AS aws_managed,
		       COUNT(*) FILTER (WHERE policy_arn NOT LIKE 'arn:aws:iam::aws:policy/%'
		                          AND COALESCE(policy_arn, '') <> '') AS customer_managed
		FROM (
			SELECT p.principal_type, p.principal_name,
			       COALESCE(pol.policy_arn, '') AS policy_arn
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			JOIN iam_policy pol ON pol.id = pp.policy_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE
			UNION ALL
			SELECT 'Group', g.group_name, COALESCE(pol.policy_arn, '')
			FROM iam_group_policy gp
			JOIN iam_group g ON g.id = gp.group_id
			JOIN iam_policy pol ON pol.id = gp.policy_id
			WHERE g.account_id = $1
			  AND pol.policy_type = 'managed'
		) a
		GROUP BY principal_type, principal_name
		HAVING COUNT(*) FILTER (WHERE COALESCE(policy_arn, '') <> '') > 0
		ORDER BY principal_type, principal_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load policy attachments: %w", err)
	}
	defer rows.Close()
	relationships := make([]BaselineRelationship, 0, 64)
	for rows.Next() {
		var principalType, principalName string
		var awsManaged, customerManaged int
		if err := rows.Scan(&principalType, &principalName, &awsManaged, &customerManaged); err != nil {
			return nil, fmt.Errorf("scan policy attachment: %w", err)
		}
		detail := fmt.Sprintf("托管策略 %d 条（AWS 托管 %d / 客户自管 %d）",
			awsManaged+customerManaged, awsManaged, customerManaged)
		existing := declared[strings.ToLower(principalName)]
		if existing {
			detail += "；已有独立挂载工单，基线不得再声明挂载（否则同地址双声明）"
		}
		relationships = append(relationships, BaselineRelationship{
			Subject:        strings.ToLower(principalType) + ":" + principalName,
			Kind:           "policy-attachment",
			Detail:         detail,
			ExistingTicket: existing,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy attachments: %w", err)
	}
	return relationships, nil
}

// declaredAttachmentPrincipals 返回已有挂载工单的主体名：这些主体的挂载关系
// 已经由 attachment-*.tf 声明，基线里再写一遍就是同地址双声明。
func (service *BaselineCandidateService) declaredAttachmentPrincipals(
	ctx context.Context,
	accountDBID int64,
) (map[string]bool, error) {
	// 只有真正到达过 Terraform 的工单（MERGED / CLOSED+APPLIED）和仍在途的
	// 工单才算「已有独立挂载声明」。CLOSED+ABANDONED（API 探测残留）什么都没
	// 发布过——把它们算进来会让基线永远跳过该主体的挂载，挂载永远无法纳管，
	// 解绑也会被误判为野生挂载。
	rows, err := service.db.QueryContext(ctx, `
		SELECT DISTINCT LOWER(TRIM(COALESCE(principal_name, '')))
		FROM iam_ticket
		WHERE account_id = $1
		  AND ticket_type = $2
		  AND status <> 'REJECTED'
		  AND (status <> 'CLOSED' OR closure_reason = 'APPLIED')`,
		accountDBID, TicketTypeAttachUserPolicy)
	if err != nil {
		return nil, fmt.Errorf("load attachment tickets: %w", err)
	}
	defer rows.Close()
	declared := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan attachment ticket: %w", err)
		}
		if name != "" {
			declared[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate attachment tickets: %w", err)
	}
	return declared, nil
}

func (service *BaselineCandidateService) loadProfileBindings(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineRelationship, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT instance_profile_name, COALESCE(role_arn, '')
		FROM iam_instance_profile
		WHERE account_id = $1 AND is_deleted = FALSE
		ORDER BY instance_profile_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load instance profile bindings: %w", err)
	}
	defer rows.Close()
	relationships := make([]BaselineRelationship, 0, 16)
	for rows.Next() {
		var name, roleARN string
		if err := rows.Scan(&name, &roleARN); err != nil {
			return nil, fmt.Errorf("scan instance profile binding: %w", err)
		}
		detail := "未绑定角色"
		if roleARN != "" {
			detail = "绑定角色 " + adapterPolicyNameFromARN(roleARN)
		}
		relationships = append(relationships, BaselineRelationship{
			Subject: "instance-profile:" + name,
			Kind:    "instance-profile-binding",
			Detail:  detail,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate instance profile bindings: %w", err)
	}
	return relationships, nil
}

func (service *BaselineCandidateService) loadLatestSyncRun(
	ctx context.Context,
	report *BaselineCandidateReport,
) error {
	var runID int64
	var finishedAt sql.NullTime
	err := service.db.QueryRowContext(ctx, `
		SELECT id, finished_at FROM aws_sync_run
		WHERE aws_account_id = $1 AND status = 'SUCCEEDED'
		ORDER BY id DESC
		LIMIT 1`, report.AWSAccountID).Scan(&runID, &finishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load latest successful sync run: %w", err)
	}
	report.LatestSyncRunID = runID
	if finishedAt.Valid {
		value := finishedAt.Time
		report.LatestSyncFinishedAt = &value
	}
	return nil
}

func isAWSManagedPolicyARN(arn string) bool {
	return strings.HasPrefix(strings.TrimSpace(arn), "arn:aws:iam::aws:policy/")
}

// policyPathFromARN 从策略 ARN 反解 path：iam_policy 表没有 path 列，但 path
// 是 aws_iam_policy 的 ForceNew 属性，基线的声明必须与 ARN 里的 path 一致。
func policyPathFromARN(arn string) string {
	const marker = ":policy/"
	index := strings.Index(arn, marker)
	if index < 0 {
		return ""
	}
	remainder := arn[index+len(marker):]
	if slash := strings.LastIndex(remainder, "/"); slash >= 0 {
		// ARN 里 `:policy` 后面紧跟 path 的起始斜杠，所以反解时要补回来。
		return "/" + remainder[:slash+1]
	}
	return "/"
}

// adapterPolicyNameFromARN 与 adapter 的同名逻辑保持一致：取 ARN 最后一个
// 资源段的末段。OIDC provider 名本身含斜杠，所以只对 policy/role 这类
// 单层名字使用。
func adapterPolicyNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if index := strings.LastIndex(trimmed, "/"); index >= 0 && index+1 < len(trimmed) {
		return trimmed[index+1:]
	}
	return trimmed
}

// labelToken 与 adapter 的 label 规则保持同样的字符集，供 providerLabelToken
// 压缩 OIDC/SAML provider 名里的点与斜杠。
func labelToken(value string) string {
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9', char == '_', char == '-':
			builder.WriteRune(char)
		default:
			builder.WriteRune('_')
		}
	}
	if builder.Len() == 0 {
		return "x"
	}
	return builder.String()
}

// providerLabelToken 把 provider 名字里的点与斜杠压成下划线，避免 Terraform
// 地址里出现非法字符（OIDC provider 名是 URL 形式）。
func providerLabelToken(value string) string {
	return strings.Trim(labelToken(value), "_")
}
