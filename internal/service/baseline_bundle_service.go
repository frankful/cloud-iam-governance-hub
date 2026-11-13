package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
)

// 本文件实现 B2：把候选集报告落成「多文件 Terraform bundle」——每个资源按
// 工单链路同源的文件 key 渲染声明 + 首次接管 import 块，再叠加三类冲突
// 检测（文件已存在 / 已被工单纳管 / 地址重复）。Build 是纯函数式汇总：
// 只读库存、不改数据库、不碰仓库（文件存在性检查是只读 GET）。
//
// 确定性：同样的库存必须产出逐字节相同的 bundle——文件按 key 排序、资源
// 按报告顺序（已排序）、成员/策略列表在生成前排序、整体内容用 sha256 指纹。
// 这是「审批时看到的预览 == 发布出去的文件」的前提。

// BaselineBundleFile 是 bundle 里的一个 Terraform 文件（key 不含 .tf 后缀）。
type BaselineBundleFile struct {
	Key      string `json:"key"`
	FileName string `json:"file_name"`
	// Sources 是贡献这个文件的资源标识（kind:name / kind:owner:policy），
	// 按字典序排列，保证同输入同输出。
	Sources   []string `json:"sources"`
	Addresses []string `json:"addresses,omitempty"`
	// ImportIDs 是文件里的 import 块目标（Terraform 地址），用于审计核对。
	ImportIDs []string `json:"import_ids,omitempty"`
	// Relationship 是 true 表示这是关系类文件（membership / attachment），
	// 资源本身已在 AWS 存在，声明只为接管或维护成员集合。
	Relationship bool   `json:"relationship,omitempty"`
	Content      string `json:"content"`
	SHA256       string `json:"sha256"`
	// ExistsInRepo 是目标分支上同名文件的检查结果；nil 表示未检查
	//（仓库不可达或未配置检查器）。
	ExistsInRepo *bool `json:"exists_in_repo"`
	// RepoBlobSHA 是目标分支上同名文件的 git blob SHA（仅 ExistsInRepo 为
	// true 时有值）。发布侧与本地内容的 blob SHA 比对即可判断「内容是否
	// 变了」，无需逐文件拉取内容。
	RepoBlobSHA string `json:"repo_blob_sha,omitempty"`
}

// BaselineBundleIssue 是一类需要注意但不一定阻断的发现。kind 取值：
// file-exists / already-declared / file-key / address / generation-error。
type BaselineBundleIssue struct {
	Kind      string   `json:"kind"`
	Value     string   `json:"value"`
	Resources []string `json:"resources,omitempty"`
	// Detail 是给人看的一句话说明。它是中文原文，只作为 detail_code 缺失
	//（旧记录）或前端不认识该码时的兜底：界面语言由前端决定，服务端不
	// 承担「用户可见措辞」，否则切换语言后这一列永远是中文。
	Detail string `json:"detail,omitempty"`
	// DetailCode 是 Detail 的稳定语义码，前端按 baseline.detail.issueDetail.<code>
	// 取本地化文案；DetailParams 是文案里的插值参数（如底层错误信息）。
	DetailCode   string            `json:"detail_code,omitempty"`
	DetailParams map[string]string `json:"detail_params,omitempty"`
}

// issue 的 detail_code 取值。新增一条 issue 文案时：这里加码、前端两种语言
// 各加一条 issueDetail 词条，Detail 仍写中文原文（老客户端 / 日志用）。
const (
	IssueDetailFileKeyMerged   = "file-key-merged"
	IssueDetailFileKeyConflict = "file-key-conflict"
	IssueDetailAddressConflict = "address-conflict"
	IssueDetailAlreadyDeclared = "already-declared"
	IssueDetailGeneratorAbsent = "generator-missing"
	IssueDetailGeneratorFailed = "generator-error"
	IssueDetailFileExists      = "file-exists"
	IssueDetailRepoCheckFailed = "repo-check-failed"
	IssueDetailDeferred        = "deferred"
)

// BaselineBundleReport 是一次 bundle 构建的完整结果。
type BaselineBundleReport struct {
	AccountDBID  int64     `json:"account_db_id"`
	AWSAccountID string    `json:"aws_account_id"`
	GeneratedAt  time.Time `json:"generated_at"`
	// RepoDirectory 是 bundle 落仓库的目标目录（<terraform-path>/account-<id>），
	// 由调用方传入；空表示未配置仓库，文件存在性检查跳过。
	RepoDirectory string                `json:"repo_directory,omitempty"`
	Files         []BaselineBundleFile  `json:"files"`
	Issues        []BaselineBundleIssue `json:"issues"`
	// Counts 汇总：files / resources / relationships / generation-errors /
	// already-declared，以及各 decision 的资源数。
	Counts map[string]int `json:"counts"`
	// ContentSHA256 是全部文件（key + 内容）的确定性指纹：同库存同哈希，
	// 两次构建结果是否漂移一眼可辨。
	ContentSHA256 string `json:"content_sha256"`
	// Declarations 是本次 bundle 声明的资源意图快照（phase4 §5）：发布成功
	// 后落库，作为漂移判定的基准。与文件内容同源生成——两边都从同一份
	// 库存详情与同一组生成参数出，避免「声明与代码不一致」的误报。
	Declarations []BaselineDeclaration `json:"declarations,omitempty"`
	// LatestSyncRunID 是本次构建实际读取的库存快照（最新成功同步 run）。
	// 发布台账在 Create 时钉住一个 run；两者不一致说明中途又同步过，
	// 审计键会指向旧快照而内容来自新快照——发布侧据该校验（C-审计错位）。
	LatestSyncRunID int64 `json:"latest_sync_run_id,omitempty"`
}

// BundleRepoChecker 检查目标分支上是否已存在同名 Terraform 文件，并返回其
// git blob SHA（存在时），供发布侧做「内容是否真的变了」的本地比对——避免
// 逐文件下载内容。实现方是 GitHubPublisher（contents API 只读 GET）；nil
// 表示不检查。
type BundleRepoChecker interface {
	TerraformFileMeta(ctx context.Context, fileName string) (blobSHA string, exists bool, err error)
}

// BundleRepoTreeLister 是 BundleRepoChecker 的可选批量能力：一次返回目标
// 分支上全部 blob 的「仓库相对路径 → git blob SHA」。
//
// 为什么要它：基线发布对每个文件都要问一次「main 上有没有、内容一样吗」，
// 逐文件走 contents API 就是 N 次串行请求——单账号 338 个文件实测要 128 秒，
// 而结论往往只是「一个都没变」。整树清单（GitHub 的 git/trees?recursive=1）
// 一次就够，把这段开销从分钟级压到一次请求。
type BundleRepoTreeLister interface {
	TerraformFileTree(ctx context.Context) (map[string]string, error)
}

// loadRepoTerraformTree 尝试一次拉取整棵树的 blob 清单。返回 nil 表示调用方
// 应退回逐文件查询：读取器没有批量能力、拉取失败、或清单被截断（截断的清单
// 不能当「文件不存在」用，否则会把「更新」误判成「新建」）。
func loadRepoTerraformTree(ctx context.Context, reader interface{}) map[string]string {
	lister, ok := reader.(BundleRepoTreeLister)
	if !ok {
		return nil
	}
	blobs, err := lister.TerraformFileTree(ctx)
	if err != nil || len(blobs) == 0 {
		return nil
	}
	return blobs
}

// BaselineBundleService 把候选集报告落成多文件 Terraform bundle。
type BaselineBundleService struct {
	db         *sql.DB
	candidates *BaselineCandidateService
	adapter    adapter.AWSAdapter
	repo       BundleRepoChecker
	// terraformPath 是仓库里 Terraform 模块的根目录（发布器的同名配置）。
	// 文件存在性检查按 <terraformPath>/account-<AWS账号ID>/<key>.tf 进行，
	// 与工单发布写文件的路径完全同源。
	terraformPath string
}

func NewBaselineBundleService(
	db *sql.DB,
	candidates *BaselineCandidateService,
	repo BundleRepoChecker,
	terraformPath string,
) *BaselineBundleService {
	return &BaselineBundleService{
		db:            db,
		candidates:    candidates,
		adapter:       adapter.AWSAdapter{},
		repo:          repo,
		terraformPath: strings.TrimSpace(terraformPath),
	}
}

// Build 汇总一次账号的基线 bundle。只读。
func (service *BaselineBundleService) Build(
	ctx context.Context,
	accountRef string,
) (*BaselineBundleReport, error) {
	report, err := service.candidates.Build(ctx, accountRef)
	if err != nil {
		return nil, err
	}
	bundle := &BaselineBundleReport{
		AccountDBID:     report.AccountDBID,
		AWSAccountID:    report.AWSAccountID,
		GeneratedAt:     time.Now().UTC(),
		Files:           make([]BaselineBundleFile, 0, 128),
		Issues:          make([]BaselineBundleIssue, 0, 16),
		Counts:          map[string]int{},
		LatestSyncRunID: report.LatestSyncRunID,
	}
	// 仓库目录与工单发布同一条公式：<terraform-path>/account-<AWS账号ID>。
	repoDirectory := ""
	if service.terraformPath != "" {
		repoDirectory = path.Join(service.terraformPath, "account-"+report.AWSAccountID)
	}
	bundle.RepoDirectory = repoDirectory

	// 补充数据：报告为判定而生，bundle 为生成而生，两者需要的库存字段不同
	//（trust policy、内联策略文档、挂载 ARN 列表等）。分键加载、一次查询，
	// 全部排好序再交给生成器。
	roleDetails, err := service.loadRoleDetails(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	groupDetails, err := service.loadGroupDetails(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	inlineDocuments, err := service.loadInlineDocuments(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	policyDocuments, err := service.loadManagedPolicyDocuments(ctx, report.AWSAccountID)
	if err != nil {
		return nil, err
	}
	attachmentsByPrincipal, err := service.loadAttachmentsByPrincipal(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	membersByGroup, err := service.loadMembersByGroup(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	providerDetails, err := service.loadProviderDetails(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	profileRoleARNs, err := service.loadProfileRoleARNs(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	// 绑定角色名以报告的 bound_role 为准（LEFT JOIN 继承）；roleARNs 仅用于
	// 在报告未给出绑定角色时从 ARN 反解，避免「角色行已删但绑定仍在」的资源
	// 直接变成生成错误。
	_ = profileRoleARNs

	filesByKey := map[string]*BaselineBundleFile{}
	addFile := func(key string, relationship bool, source, address, importID, content string) error {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("empty file key for %s", source)
		}
		if existing, ok := filesByKey[key]; ok {
			// 同一文件 key 出现第二次：报告的 file-key 冲突会单独列出，
			// 这里合并来源并保留先到的内容——静默覆盖比报错更危险。
			bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
				Kind:  "file-key",
				Value: key + ".tf",
				Resources: []string{
					existing.Sources[0], source,
				},
				Detail:     "两个资源落到同一文件，保留前者的内容",
				DetailCode: IssueDetailFileKeyMerged,
			})
			existing.Sources = appendSortedUnique(existing.Sources, source)
			if address != "" {
				existing.Addresses = appendSortedUnique(existing.Addresses, address)
			}
			return nil
		}
		sum := sha256.Sum256([]byte(content))
		file := BaselineBundleFile{
			Key:          key,
			FileName:     key + ".tf",
			Sources:      []string{source},
			Relationship: relationship,
			Content:      content,
			SHA256:       hex.EncodeToString(sum[:]),
			ExistsInRepo: nil,
		}
		if address != "" {
			file.Addresses = []string{address}
		}
		if importID != "" {
			file.ImportIDs = []string{importID}
		}
		filesByKey[key] = &file
		return nil
	}
	// declare 记录一条声明快照。属性必须与生成器实际写进 HCL 的字段一致：
	// 生成器「留空不声明」的属性这里也不写，否则漂移判定会把 Terraform
	// 根本没管的默认值当成「声明值」比对，产生结构性误报。
	declare := func(fileKey, resourceKey, kind, name string, attributes map[string]any) error {
		encoded, err := canonicalJSON(attributes)
		if err != nil {
			return fmt.Errorf("canonicalize declaration %s: %w", resourceKey, err)
		}
		bundle.Declarations = append(bundle.Declarations, BaselineDeclaration{
			ResourceKey: resourceKey,
			FileKey:     fileKey,
			Kind:        kind,
			Name:        name,
			Attributes:  encoded,
		})
		return nil
	}

	// 1) 资源类文件：候选集里 decision=candidate 且 GeneratorReady 的资源。
	for _, item := range report.Resources {
		if item.Decision != BaselineDecisionCandidate {
			if item.Decision == BaselineDecisionSkippedAlreadyDeclared {
				label := item.Kind + ":" + item.Name
				bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
					Kind:       "already-declared",
					Value:      label,
					Resources:  []string{label},
					Detail:     item.Reason,
					DetailCode: IssueDetailAlreadyDeclared,
				})
				bundle.Counts["already-declared"]++
			}
			continue
		}
		bundle.Counts["resources"]++
		if !item.GeneratorReady {
			bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
				Kind:       "generation-error",
				Value:      item.Kind + ":" + item.Name,
				Detail:     "生成器未实现",
				DetailCode: IssueDetailGeneratorAbsent,
			})
			bundle.Counts["generation-errors"]++
			continue
		}
		var content string
		var genErr error
		var attributes map[string]any
		switch item.Kind {
		case BaselineKindRole:
			detail := roleDetails[item.Name]
			config := detail.config()
			content, genErr = service.adapter.GenerateWildRoleTerraform(
				item.Name,
				config,
				item.ImportID,
				adapter.RoleIdentity{
					Path:                   item.Path,
					PermissionsBoundaryARN: detail.boundary,
				},
			)
			// 与 config() 同源：它决定生成器写了哪些字段，声明就记哪些。
			attributes = map[string]any{"path": item.Path}
			if config.TrustPolicy != nil {
				attributes["trust_policy"] = *config.TrustPolicy
			}
			if config.Description != nil {
				attributes["description"] = *config.Description
			}
			if config.MaxSessionDuration != nil {
				attributes["max_session_duration"] = *config.MaxSessionDuration
			}
			if len(config.Tags) > 0 {
				attributes["tags"] = config.Tags
			}
			if detail.boundary != "" {
				attributes["permissions_boundary"] = detail.boundary
			}
		case BaselineKindUser:
			content, genErr = service.adapter.GenerateCreateUserTerraform(
				adapter.IAMUserInfo{
					Name: item.Name,
					Path: item.Path,
					// 主体 tags 在 loadPrincipals 已进 item.Tags；
					// roleDetails 是角色专用 map，user 取不到（曾致 27 个
					// user 的 tags 被清空）。
					Tags: item.Tags,
				},
				item.ImportID,
			)
			attributes = map[string]any{"path": item.Path}
			if len(item.Tags) > 0 {
				attributes["tags"] = item.Tags
			}
		case BaselineKindGroup:
			// IAM group 不支持 tagging（AWS 无 ListGroupTags，Terraform
			// aws_iam_group 也无 tags 参数），不声明 tags。
			groupPath := groupDetails[item.Name].path
			content, genErr = service.adapter.GenerateCreateGroupTerraform(
				adapter.IAMGroupInfo{
					Name: item.Name,
					Path: groupPath,
				},
				item.ImportID,
			)
			attributes = map[string]any{"path": groupPath}
		case BaselineKindPolicy:
			content, genErr = service.adapter.GenerateCreateManagedPolicyTerraform(
				adapter.ManagedPolicyInfo{
					Name:     item.Name,
					Path:     item.Path,
					Document: policyDocuments[item.Name],
					// description 是 aws_iam_policy 的 ForceNew 属性，漏写
					// 会让首次 apply 销毁重建；tags 漏写会清空实态 tag。
					Description: item.Description,
					Tags:        item.Tags,
				},
				item.ImportID,
			)
			attributes = map[string]any{
				"path":     item.Path,
				"document": canonicalPolicy(policyDocuments[item.Name]),
			}
			if item.Description != "" {
				attributes["description"] = item.Description
			}
			if len(item.Tags) > 0 {
				attributes["tags"] = item.Tags
			}
		case BaselineKindInstanceProfile:
			roleName := item.BoundRoleName
			if roleName == "" {
				if roleARN := profileRoleARNs[item.Name]; roleARN != "" {
					roleName = adapterPolicyNameFromARN(roleARN)
				}
			}
			content, genErr = service.adapter.GenerateInstanceProfileTerraform(
				item.Name,
				item.Path,
				roleName,
				item.ImportID,
			)
			attributes = map[string]any{"path": item.Path}
			if roleName != "" {
				attributes["role"] = roleName
			}
		case BaselineKindOIDCProvider:
			detail := providerDetails[item.Name]
			providerURL := normalizeOIDCProviderURL(detail.url)
			content, genErr = service.adapter.GenerateOIDCProviderTerraform(
				providerURL, detail.clientIDs, detail.thumbprints, detail.tags, item.ImportID,
			)
			attributes = map[string]any{
				"url":         providerURL,
				"client_ids":  detail.clientIDs,
				"thumbprints": detail.thumbprints,
			}
			if len(detail.tags) > 0 {
				attributes["tags"] = detail.tags
			}
		case BaselineKindSAMLProvider:
			metadata := providerDetails[item.Name].samlMetadata
			content, genErr = service.adapter.GenerateSAMLProviderTerraform(
				item.Name, metadata, item.ImportID,
			)
			attributes = map[string]any{"metadata": metadata}
		case BaselineKindInlinePolicy:
			key := InlinePolicyFileKey(item.OwnerKind, item.Owner, item.Name)
			document := inlineDocuments[key]
			content, genErr = service.adapter.GenerateBaselineInlinePolicyTerraform(
				item.OwnerKind, item.Owner, item.Name,
				document, item.ImportID,
			)
			attributes = map[string]any{
				"owner_kind": item.OwnerKind,
				"owner":      item.Owner,
				"policy":     item.Name,
				"document":   canonicalPolicy(document),
			}
		default:
			genErr = fmt.Errorf("unsupported kind %q", item.Kind)
		}
		if genErr != nil {
			bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
				Kind:       "generation-error",
				Value:      item.Kind + ":" + item.Name,
				Detail:     genErr.Error(),
				DetailCode: IssueDetailGeneratorFailed,
				DetailParams: map[string]string{
					"error": genErr.Error(),
				},
			})
			bundle.Counts["generation-errors"]++
			continue
		}
		if err := addFile(item.FileKey, false,
			item.Kind+":"+item.Name, item.Address, item.ImportID, content); err != nil {
			return nil, err
		}
		if err := declare(item.FileKey, declarationResourceKey(item),
			item.Kind, item.Name, attributes); err != nil {
			return nil, err
		}
	}

	// 2) 关系类文件：membership 与 attachment。只给仍在候选集里的主体声明，
	// 被跳过的主体（service-linked、AWS 生命周期托管、external）不碰。
	candidatePrincipals := map[string]bool{}
	for _, item := range report.Resources {
		switch item.Kind {
		case BaselineKindRole, BaselineKindUser, BaselineKindGroup:
			candidatePrincipals[item.Kind+":"+strings.ToLower(item.Name)] =
				item.Decision == BaselineDecisionCandidate
		}
	}
	declaredAttachmentPrincipals := map[string]bool{}
	for _, relationship := range report.Relationships {
		if relationship.Kind == "policy-attachment" && relationship.ExistingTicket {
			declaredAttachmentPrincipals[relationship.Subject] = true
		}
	}

	for group, members := range membersByGroup {
		if !candidatePrincipals["group:"+strings.ToLower(group)] {
			continue
		}
		if len(members) == 0 {
			continue
		}
		content, genErr := service.adapter.GenerateBaselineMembershipTerraform(group, members)
		if genErr != nil {
			bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
				Kind:       "generation-error",
				Value:      "membership:" + group,
				Detail:     genErr.Error(),
				DetailCode: IssueDetailGeneratorFailed,
				DetailParams: map[string]string{
					"error": genErr.Error(),
				},
			})
			bundle.Counts["generation-errors"]++
			continue
		}
		if err := addFile(MembershipFileKey(group), true,
			"group-membership:"+group,
			"aws_iam_group_membership."+adapter.GroupResourceLabel(group)+"_membership",
			"", content); err != nil {
			return nil, err
		}
		// 成员集合就是声明本身：成员的增减是关系类漂移。
		if err := declare(MembershipFileKey(group),
			"membership:group:"+group, "membership", group,
			map[string]any{"group": group, "members": members}); err != nil {
			return nil, err
		}
		bundle.Counts["relationships"]++
	}

	for principalKey, attachments := range attachmentsByPrincipal {
		// principalKey 形如 "Role:name"；candidatePrincipals 用小写 kind。
		parts := strings.SplitN(principalKey, ":", 2)
		if len(parts) != 2 {
			continue
		}
		kind, name := strings.ToLower(parts[0]), parts[1]
		if !candidatePrincipals[kind+":"+strings.ToLower(name)] {
			continue
		}
		if declaredAttachmentPrincipals[parts[0]+":"+name] ||
			declaredAttachmentPrincipals[kind+":"+name] {
			// 已有独立挂载工单：基线再声明挂载就是同地址双声明，报告的
			// existing_ticket 已经提示过，这里直接跳过。
			continue
		}
		for _, attachment := range attachments {
			policyName := adapterPolicyNameFromARN(attachment)
			fileKey := AttachmentFileKey(kind, name, policyName)
			if fileKey == "" {
				continue
			}
			importID := baselineAttachmentImportID(report.AdoptedKeys, kind, name, attachment)
			content, genErr := service.adapter.GenerateAttachPolicyTerraform(
				parts[0], name, attachment, importID,
				adapter.DefaultAttachmentLabel(parts[0], name, attachment),
			)
			if genErr != nil {
				bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
					Kind:       "generation-error",
					Value:      "attachment:" + name + "/" + policyName,
					Detail:     genErr.Error(),
					DetailCode: IssueDetailGeneratorFailed,
					DetailParams: map[string]string{
						"error": genErr.Error(),
					},
				})
				bundle.Counts["generation-errors"]++
				continue
			}
			address := map[string]string{
				"role":  "aws_iam_role_policy_attachment",
				"user":  "aws_iam_user_policy_attachment",
				"group": "aws_iam_group_policy_attachment",
			}[kind] + "." + adapter.DefaultAttachmentLabel(parts[0], name, attachment)
			if err := addFile(fileKey, true,
				"policy-attachment:"+name+"/"+policyName,
				address, importID, content); err != nil {
				return nil, err
			}
			if err := declare(fileKey,
				"attachment:"+kind+":"+name+":"+attachment, "attachment", policyName,
				map[string]any{
					"principal_kind": kind,
					"principal":      name,
					"policy_arn":     attachment,
				}); err != nil {
				return nil, err
			}
			bundle.Counts["relationships"]++
		}
	}

	// 3) 报告层的撞车（file-key / address）原样升级为 issue。
	for _, conflict := range report.Conflicts {
		issue := BaselineBundleIssue{
			Kind:      conflict.Kind,
			Value:     conflict.Value,
			Resources: conflict.Resources,
		}
		// 报告层冲突的说明是固定的「同一地址被两个资源占住」，按 kind 给码。
		switch conflict.Kind {
		case "file-key":
			issue.DetailCode = IssueDetailFileKeyConflict
		case "address":
			issue.DetailCode = IssueDetailAddressConflict
		}
		bundle.Issues = append(bundle.Issues, issue)
	}

	// 4) 文件列表排序 + 文件存在性检查（只读）。
	files := make([]BaselineBundleFile, 0, len(filesByKey))
	for _, file := range filesByKey {
		sort.Strings(file.Addresses)
		sort.Strings(file.ImportIDs)
		files = append(files, *file)
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].Key < files[right].Key
	})
	bundle.Files = files
	bundle.Counts["files"] = len(files)

	if service.repo != nil && repoDirectory != "" {
		// 先试整树清单（1 次请求）；拿不到才逐文件问。
		tree := loadRepoTerraformTree(ctx, service.repo)
		for index := range bundle.Files {
			fileName := repoDirectory + "/" + bundle.Files[index].FileName
			var blobSHA string
			var exists bool
			var err error
			if tree != nil {
				blobSHA, exists = tree[fileName]
			} else {
				blobSHA, exists, err = service.repo.TerraformFileMeta(ctx, fileName)
			}
			if err != nil {
				bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
					Kind:         "file-exists",
					Value:        fileName,
					Detail:       "仓库检查失败：" + err.Error(),
					DetailCode:   IssueDetailRepoCheckFailed,
					DetailParams: map[string]string{"error": err.Error()},
				})
				continue
			}
			bundle.Files[index].ExistsInRepo = &exists
			bundle.Files[index].RepoBlobSHA = blobSHA
			if exists {
				bundle.Counts["files-exist-in-repo"]++
				bundle.Issues = append(bundle.Issues, BaselineBundleIssue{
					Kind:  "file-exists",
					Value: fileName,
					Resources: []string{strings.Join(
						bundle.Files[index].Sources, ", ")},
					Detail:     "目标分支已有同名文件，发布时必须走更新而非覆盖",
					DetailCode: IssueDetailFileExists,
				})
			}
		}
		sort.SliceStable(bundle.Issues, func(left, right int) bool {
			if bundle.Issues[left].Kind != bundle.Issues[right].Kind {
				return bundle.Issues[left].Kind < bundle.Issues[right].Kind
			}
			return bundle.Issues[left].Value < bundle.Issues[right].Value
		})
	}

	bundle.ContentSHA256 = bundleContentHash(bundle.Files)
	return bundle, nil
}

// normalizeOIDCProviderURL 补全 OIDC provider 的 scheme。AWS 的
// ListOpenIDConnectProviders 返回的 Url 不带 https:// 前缀（EKS 的
// oidc.eks.<region>.amazonaws.com/id/<hash> 是典型），而 Terraform 的
// url 属性要求完整 URL——url 是 ForceNew 属性，声明必须与 provider 的
// 实际 endpoint 一致，这里只补协议头不改主体。
func normalizeOIDCProviderURL(url string) string {
	trimmed := strings.TrimSpace(url)
	if trimmed == "" ||
		strings.HasPrefix(strings.ToLower(trimmed), "https://") ||
		strings.HasPrefix(strings.ToLower(trimmed), "http://") {
		return trimmed
	}
	return "https://" + trimmed
}

// bundleContentHash 计算 bundle 的确定性指纹：按 key 排序后对
// "key\x00content\x00" 逐文件累加 sha256。空的 bundle 也有指纹（空输入的
// sha256），避免「没有文件」与「没有跑」混淆。
func bundleContentHash(files []BaselineBundleFile) string {
	sorted := make([]BaselineBundleFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(left, right int) bool {
		return sorted[left].Key < sorted[right].Key
	})
	hasher := sha256.New()
	for _, file := range sorted {
		hasher.Write([]byte(file.Key))
		hasher.Write([]byte{0})
		hasher.Write([]byte(file.Content))
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// declarationResourceKey 生成资源级声明 key。内联策略必须带主体：策略名
// 只在主体内唯一，同名的 s3-access 可能同时挂在角色与用户上，不带主体就
// 会在声明表里互相覆盖（唯一索引 account_id + resource_key）。
// baselineAttachmentImportID 渲染挂载文件的首次纳管 import ID。台账 25
// 方案 1：这条挂载已被历史基线 apply 收编进 state（adopted 命中）时返回
// 空串——资源已在 state，残留的 import 块只会制造 diff 噪音与地址漂移
// 隐患；membership 不支持 import，无此问题。nil map 安全。
func baselineAttachmentImportID(adopted map[string]bool, kind, name, attachment string) string {
	if adopted["attachment:"+kind+":"+name+":"+attachment] {
		return ""
	}
	return name + "/" + attachment
}

func declarationResourceKey(item BaselineResource) string {
	if item.Kind == BaselineKindInlinePolicy {
		return item.OwnerKind + ":" + item.Owner + ":inline:" + item.Name
	}
	return item.Kind + ":" + item.Name
}

func appendSortedUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

// roleDetail 补齐报告没有携带、但声明角色/用户必须的字段。
type roleDetail struct {
	trustPolicy json.RawMessage
	description string
	maxSession  int
	boundary    string
	tags        map[string]string
}

// config 把库存值装进工单生成器的 UpdateRoleConfig：TrustPolicy 必填（角色
// 声明没有信任策略不合法），其余属性留空就不声明——与「首个 plan 只剩
// import」同一原则，声明必须与库存一致。
func (detail roleDetail) config() *adapter.UpdateRoleConfig {
	trust := map[string]interface{}{}
	if len(detail.trustPolicy) > 0 {
		_ = json.Unmarshal(detail.trustPolicy, &trust)
	}
	config := &adapter.UpdateRoleConfig{TrustPolicy: &trust}
	if detail.description != "" {
		description := detail.description
		config.Description = &description
	}
	if detail.maxSession > 0 {
		session := detail.maxSession
		config.MaxSessionDuration = &session
	}
	if len(detail.tags) > 0 {
		config.Tags = detail.tags
	}
	return config
}

func (service *BaselineBundleService) loadRoleDetails(
	ctx context.Context,
	accountDBID int64,
) (map[string]roleDetail, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT principal_name, COALESCE(trust_policy::text, ''),
		       COALESCE(description, ''), COALESCE(max_session_duration, 0),
		       COALESCE(permissions_boundary_arn, ''), COALESCE(tags::text, '')
		FROM iam_principal
		WHERE account_id = $1 AND is_deleted = FALSE AND principal_type = 'Role'`,
		accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load role details: %w", err)
	}
	defer rows.Close()
	details := map[string]roleDetail{}
	for rows.Next() {
		var name string
		var detail roleDetail
		var trust []byte
		var tags string
		if err := rows.Scan(&name, &trust, &detail.description,
			&detail.maxSession, &detail.boundary, &tags); err != nil {
			return nil, fmt.Errorf("scan role detail: %w", err)
		}
		detail.trustPolicy = json.RawMessage(trust)
		if tags != "" {
			_ = json.Unmarshal([]byte(tags), &detail.tags)
		}
		details[name] = detail
	}
	return details, rows.Err()
}

func (service *BaselineBundleService) loadGroupDetails(
	ctx context.Context,
	accountDBID int64,
) (map[string]struct{ path string }, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT group_name, path FROM iam_group
		WHERE account_id = $1`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load group details: %w", err)
	}
	defer rows.Close()
	details := map[string]struct{ path string }{}
	for rows.Next() {
		var name, path string
		if err := rows.Scan(&name, &path); err != nil {
			return nil, fmt.Errorf("scan group detail: %w", err)
		}
		details[name] = struct{ path string }{path: path}
	}
	return details, rows.Err()
}

// loadInlineDocuments 返回账号内全部内联策略文档，键是 InlinePolicyFileKey。
func (service *BaselineBundleService) loadInlineDocuments(
	ctx context.Context,
	accountDBID int64,
) (map[string]json.RawMessage, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT owner_kind, owner_name, pol.policy_name,
		       pol.policy_document::text AS document
		FROM (
			SELECT pp.policy_id, 'role' AS owner_kind, p.principal_name AS owner_name
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE AND p.principal_type = 'Role'
			UNION ALL
			SELECT pp.policy_id, 'user', p.principal_name
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE AND p.principal_type = 'User'
			UNION ALL
			SELECT gp.policy_id, 'group', g.group_name
			FROM iam_group_policy gp
			JOIN iam_group g ON g.id = gp.group_id
			WHERE g.account_id = $1
		) owners
		JOIN iam_policy pol ON pol.id = owners.policy_id
		WHERE pol.policy_type = 'inline'`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load inline policy documents: %w", err)
	}
	defer rows.Close()
	documents := map[string]json.RawMessage{}
	for rows.Next() {
		var ownerKind, ownerName, policyName, document string
		if err := rows.Scan(&ownerKind, &ownerName, &policyName, &document); err != nil {
			return nil, fmt.Errorf("scan inline policy document: %w", err)
		}
		documents[InlinePolicyFileKey(ownerKind, ownerName, policyName)] =
			json.RawMessage(document)
	}
	return documents, rows.Err()
}

func (service *BaselineBundleService) loadManagedPolicyDocuments(
	ctx context.Context,
	awsAccountID string,
) (map[string]json.RawMessage, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT COALESCE(policy_name, ''), policy_document::text
		FROM iam_policy
		WHERE policy_arn LIKE 'arn:aws:iam::' || $1 || ':policy/%'`,
		awsAccountID)
	if err != nil {
		return nil, fmt.Errorf("load managed policy documents: %w", err)
	}
	defer rows.Close()
	documents := map[string]json.RawMessage{}
	for rows.Next() {
		var name, document string
		if err := rows.Scan(&name, &document); err != nil {
			return nil, fmt.Errorf("scan managed policy document: %w", err)
		}
		if name == "" {
			continue
		}
		documents[name] = json.RawMessage(document)
	}
	return documents, rows.Err()
}

// loadAttachmentsByPrincipal 返回每个主体的托管策略挂载 ARN 列表，键是
// "PrincipalType:name"（kind 保持库存原大小写，生成器需要 "Role"/"User"）。
func (service *BaselineBundleService) loadAttachmentsByPrincipal(
	ctx context.Context,
	accountDBID int64,
) (map[string][]string, error) {
	// 组挂载在 iam_group_policy（iam_principal_policy 只存 User/Role），
	// 必须两个来源合并——漏掉 iam_group_policy 的后果是基线永远不生成
	// attachment-group-*.tf，组挂载无法纳管、解绑被拒为野生挂载。
	rows, err := service.db.QueryContext(ctx, `
		WITH attachments AS (
			SELECT p.principal_type, p.principal_name, pol.policy_arn
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			JOIN iam_policy pol ON pol.id = pp.policy_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE
			  AND COALESCE(pol.policy_arn, '') <> ''
			UNION ALL
			SELECT 'Group' AS principal_type, g.group_name, pol.policy_arn
			FROM iam_group_policy gp
			JOIN iam_group g ON g.id = gp.group_id
			JOIN iam_policy pol ON pol.id = gp.policy_id
			WHERE g.account_id = $1
			  AND pol.policy_type = 'managed'
			  AND COALESCE(pol.policy_arn, '') <> ''
		)
		SELECT a.principal_type, a.principal_name, a.policy_arn
		FROM attachments a
		WHERE NOT EXISTS (
			-- 解绑工单进行中（未拒绝、未废弃关闭）的挂载不进基线：工单 PR
			-- 已把 attachment 文件清空，基线再声明回去就是乒乓漂移，直到
			-- apply+同步后清单里不再有这条挂载为止。
			SELECT 1 FROM iam_ticket t
			WHERE t.account_id = $1
				AND t.ticket_type = 'ATTACH_USER_POLICY'
				AND t.request_policy->>'operation' = 'detach'
				AND LOWER(t.request_policy->>'principal_type') = LOWER(a.principal_type)
				AND t.request_policy->>'principal_name' = a.principal_name
				AND t.request_policy->>'managed_policy_arn' = a.policy_arn
				AND t.status NOT IN ('REJECTED', 'CLOSED')
		)
		ORDER BY a.principal_type, a.principal_name, a.policy_arn`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load attachments: %w", err)
	}
	defer rows.Close()
	attachments := map[string][]string{}
	for rows.Next() {
		var principalType, principalName, policyARN string
		if err := rows.Scan(&principalType, &principalName, &policyARN); err != nil {
			return nil, fmt.Errorf("scan attachment: %w", err)
		}
		key := principalType + ":" + principalName
		attachments[key] = append(attachments[key], policyARN)
	}
	return attachments, rows.Err()
}

func (service *BaselineBundleService) loadMembersByGroup(
	ctx context.Context,
	accountDBID int64,
) (map[string][]string, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT g.group_name, p.principal_name
		FROM iam_group_membership m
		JOIN iam_group g ON g.id = m.group_id
		JOIN iam_principal p ON p.id = m.user_principal_id
		WHERE g.account_id = $1 AND p.is_deleted = FALSE
		  -- 组成员变更工单进行中（未拒绝、未废弃关闭）的组不进基线：工单 PR
		  -- 已改写 membership 文件，基线再声明回去就是乒乓漂移，直到
		  -- apply+同步后清单里反映新的成员关系为止。
		  AND NOT EXISTS (
			SELECT 1 FROM iam_ticket t
			WHERE t.account_id = $1
				AND t.ticket_type = 'UPDATE_GROUP_MEMBERSHIP'
				AND t.request_policy #>> '{update_membership,group_name}' = g.group_name
				AND t.status NOT IN ('REJECTED', 'CLOSED')
		  )
		  -- 带初始组的创建用户工单同理：它改写的是同一份
		  -- group-<group>-membership.tf（A8 后成员关系只有一个 owner），
		  -- 工单在途期间基线不得再按清单把成员列表写回去。
		  AND NOT EXISTS (
			SELECT 1 FROM iam_ticket t
			WHERE t.account_id = $1
				AND t.ticket_type = 'CREATE_USER'
				AND t.status NOT IN ('REJECTED', 'CLOSED')
				AND COALESCE(t.request_policy #> '{create_user,group_names}', 'null'::jsonb) ? g.group_name
		  )
		ORDER BY g.group_name, p.principal_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load group members: %w", err)
	}
	defer rows.Close()
	members := map[string][]string{}
	for rows.Next() {
		var group, user string
		if err := rows.Scan(&group, &user); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		members[group] = append(members[group], user)
	}
	return members, rows.Err()
}

// providerDetail 补齐 OIDC/SAML provider 的声明字段。
type providerDetail struct {
	url          string
	clientIDs    []string
	thumbprints  []string
	samlMetadata string
	tags         map[string]string
}

func (service *BaselineBundleService) loadProviderDetails(
	ctx context.Context,
	accountDBID int64,
) (map[string]providerDetail, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT provider_name, COALESCE(url, ''),
		       COALESCE(client_id_list::text, ''), COALESCE(thumbprint_list::text, ''),
		       COALESCE(saml_metadata_document, ''), tags
		FROM iam_identity_provider
		WHERE account_id = $1 AND is_deleted = FALSE`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load identity provider details: %w", err)
	}
	defer rows.Close()
	details := map[string]providerDetail{}
	for rows.Next() {
		var name, clientIDs, thumbprints string
		var tags []byte
		var detail providerDetail
		if err := rows.Scan(&name, &detail.url, &clientIDs, &thumbprints,
			&detail.samlMetadata, &tags); err != nil {
			return nil, fmt.Errorf("scan identity provider detail: %w", err)
		}
		detail.clientIDs = decodeStringList(clientIDs)
		detail.thumbprints = decodeStringList(thumbprints)
		sort.Strings(detail.clientIDs)
		sort.Strings(detail.thumbprints)
		detail.tags = decodeResourceTags(tags)
		details[name] = detail
	}
	return details, rows.Err()
}

func (service *BaselineBundleService) loadProfileRoleARNs(
	ctx context.Context,
	accountDBID int64,
) (map[string]string, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT instance_profile_name, COALESCE(role_arn, '')
		FROM iam_instance_profile
		WHERE account_id = $1 AND is_deleted = FALSE`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load instance profile role ARNs: %w", err)
	}
	defer rows.Close()
	roleARNs := map[string]string{}
	for rows.Next() {
		var name, roleARN string
		if err := rows.Scan(&name, &roleARN); err != nil {
			return nil, fmt.Errorf("scan instance profile role ARN: %w", err)
		}
		roleARNs[name] = roleARN
	}
	return roleARNs, rows.Err()
}

func decodeStringList(raw string) []string {
	if raw == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}
