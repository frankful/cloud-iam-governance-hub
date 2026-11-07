package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// 待清理清单的两个动作方向。合在一张表里是因为运维时是同一件事——「这些东西
// 现在该消失」，但动作危险程度差很远：删仓库文件只影响平台自己的声明，删 AWS
// 资源会影响线上。因此必须能筛。
const (
	// CleanupCategoryPlatformFile 删平台自己生成的 Terraform 声明文件：
	// 资源本身还在 AWS 上跑，只是不该由平台声明（例如被 Quick Setup 托管的角色）。
	CleanupCategoryPlatformFile = "platform-file"
	// CleanupCategoryAWSResource 删 AWS 侧的实体资源。
	CleanupCategoryAWSResource = "aws-resource"
)

// 置信度只有两档，不做「低置信」——不确定的东西不该出现在待删清单里。
const (
	// CleanupConfidenceHigh 证据完整，可以直接执行。
	CleanupConfidenceHigh = "high"
	// CleanupConfidenceReview 证据指向「大概率无用」，但判定依赖 AWS 侧信息
	// （例如哪个实例配置文件正被节点组使用），必须先确认。
	CleanupConfidenceReview = "review"
)

// CleanupEvidence 是一条证据。Text 是服务端渲染的中文原文；Code + Params 允许
// 前端按界面语言重新翻译。证据大多是「ARN、名字、数量」这类事实，但每条事实
// 前面都有一小句人话解释——那句解释不该在英文界面里仍是中文。
type CleanupEvidence struct {
	// Code 对应前端 i18n 的 cleanup.evidence.<code>；为空表示纯数据行，直接展示 Text。
	Code   string            `json:"code,omitempty"`
	Text   string            `json:"text"`
	Params map[string]string `json:"params,omitempty"`
}

// CleanupItem 是清单里的一行。每一项都必须能回答三个问题：这是什么、凭什么说
// 它没用、下一步动谁。
type CleanupItem struct {
	Category   string   `json:"category"`
	Confidence string   `json:"confidence"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	ARN        string   `json:"arn,omitempty"`
	Reason     string   `json:"reason"`
	Evidence   []CleanupEvidence `json:"evidence"`
	Action     string   `json:"action"`
	// 平台侧文件项：哪个工单生成的、合并到哪个 PR、文件名是什么。
	TicketNo       string `json:"ticket_no,omitempty"`
	PullRequestURL string `json:"pull_request_url,omitempty"`
	FileKey        string `json:"file_key,omitempty"`
	// ReasonCode / ActionCode 让前端按语言渲染；缺省时前端退回服务端原文。
	ReasonCode string            `json:"reason_code,omitempty"`
	ActionCode string            `json:"action_code,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
}

// CleanupReport 是一个账号的待清理清单。只读产物：不删除任何东西。
type CleanupReport struct {
	AccountDBID      int64             `json:"account_db_id"`
	AWSAccountID     string            `json:"aws_account_id"`
	GeneratedAt      time.Time         `json:"generated_at"`
	LatestSyncRunID  int64             `json:"latest_sync_run_id,omitempty"`
	Items            []CleanupItem     `json:"items"`
	CategoryCounts   map[string]int    `json:"category_counts"`
	ConfidenceCounts map[string]int    `json:"confidence_counts"`
	RuleGaps         []string          `json:"rule_gaps,omitempty"`
}

// CleanupService 汇总「无用、可以删」的资源与平台文件。
//
// 判定复用基线候选集：基线已经回答了「这个资源该不该由平台声明」，待清理清单
// 在此基础上只回答「已经声明错的、或 AWS 侧留下没用的，怎么收尾」。
// 这样两条链路不会各自演化出两套互相矛盾的归属判断。
type CleanupService struct {
	db         *sql.DB
	candidates *BaselineCandidateService
	profiles   ProfileUsageResolver
}

// NewCleanupService 的第三个参数是 EKS/EC2 实例配置文件引用解析器，可为 nil
// （此时 eks-<uuid> 一律退回「需确认」档）。
func NewCleanupService(
	db *sql.DB,
	candidates *BaselineCandidateService,
	profiles ProfileUsageResolver,
) (*CleanupService, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle must not be nil")
	}
	if candidates == nil {
		return nil, fmt.Errorf("baseline candidate service must not be nil")
	}
	return &CleanupService{db: db, candidates: candidates, profiles: profiles}, nil
}

// Build 只读：不删资源、不改仓库、不动库存。
func (service *CleanupService) Build(ctx context.Context, accountRef string) (*CleanupReport, error) {
	candidates, err := service.candidates.Build(ctx, accountRef)
	if err != nil {
		return nil, err
	}
	report := &CleanupReport{
		AccountDBID:      candidates.AccountDBID,
		AWSAccountID:     candidates.AWSAccountID,
		GeneratedAt:      time.Now().UTC(),
		LatestSyncRunID:  candidates.LatestSyncRunID,
		Items:            make([]CleanupItem, 0, 32),
		CategoryCounts:   map[string]int{},
		ConfidenceCounts: map[string]int{},
	}

	tickets, err := service.loadTickets(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	report.Items = append(report.Items, declaredLifecycleFiles(candidates.Resources, tickets)...)

	profiles, err := service.loadInstanceProfiles(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	usage, usageErr := service.resolveProfileUsage(ctx, report.AWSAccountID)
	report.Items = append(report.Items, unboundInstanceProfiles(profiles)...)
	report.Items = append(report.Items, eksInstanceProfileCleanup(profiles, usage, usageErr)...)

	groups, err := service.loadEmptyGroups(ctx, report.AccountDBID)
	if err != nil {
		return nil, err
	}
	report.Items = append(report.Items, emptyGroups(groups)...)

	sortCleanupItems(report.Items)
	for _, item := range report.Items {
		report.CategoryCounts[item.Category]++
		report.ConfidenceCounts[item.Confidence]++
	}
	// 明确写出「没有覆盖到的清理场景」，避免清单看起来比实际更全。
	report.RuleGaps = ruleGaps(usage, usageErr)
	return report, nil
}

// resolveProfileUsage 解析「哪些实例配置文件在用」。失败不中断清单：
// eks-<uuid> 相关条目退回「需确认」档，但清单其余部分照常给出。
func (service *CleanupService) resolveProfileUsage(
	ctx context.Context,
	awsAccountID string,
) (*profileUsageResult, error) {
	if service.profiles == nil {
		return nil, fmt.Errorf("profile usage resolver is not configured")
	}
	result, err := service.profiles.ResolveUsedProfiles(ctx, awsAccountID)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ruleGaps 汇总判定覆盖不到的场景。解析器可用时，最大的缺口（哪个实例配置文件
// 在用）已经被 EC2 launch template 证据补上，剩下的缺口如实缩小。
func ruleGaps(usage *profileUsageResult, usageErr error) []string {
	gaps := make([]string, 0, 4)
	switch {
	case usageErr != nil:
		gaps = append(gaps,
			"EKS/EC2 侧解析失败（"+usageErr.Error()+"），eks-<uuid> 实例配置文件只能标为需确认。")
	case usage == nil:
		gaps = append(gaps,
			"未配置 EKS/EC2 解析器，eks-<uuid> 实例配置文件只能标为需确认：需要 eks:List*、eks:Describe* 与 ec2:DescribeLaunchTemplates/Versions 只读权限。")
	default:
		if usage.EKSUnavailable {
			// EKS 只读权限需要单独授予；缺权限只提示，不影响清单：
			// 实例配置文件的在用性判定仍基于 EC2 launch template 证据。
			gaps = append(gaps,
				"EKS 权限提示：本账号未授予 EKS 只读权限（eks:ListClusters、eks:ListNodegroups、eks:DescribeNodegroup），已跳过 EKS 侧节点组检查；实例配置文件的在用性判定仍基于 EC2 launch template 证据，不受影响。授予 EKS 只读权限并重新同步后可获得更完整的证据。")
		}
		for _, warning := range usage.Warnings {
			gaps = append(gaps, "数据完整性提示："+warning+"。相关条目的结论可能不完整。")
		}
		gaps = append(gaps,
			"launch template 引用是「实例配置文件在用」的必要条件而非充分条件：刚删掉的节点组可能留下仍被模板引用的孤儿。删除前按证据里的节点组线索复核。")
	}
	gaps = append(gaps,
		"没有成员、但仍挂着策略的用户组只能提示待确认：可能是预建的空组。")
	return gaps
}

// cleanupTicket 是平台工单的最小投影：只关心「谁声明过、有没有真的发到仓库」。
type cleanupTicket struct {
	No        string
	Type      string
	Status    string
	PRURL     string
	Published bool
}

func (service *CleanupService) loadTickets(
	ctx context.Context,
	accountDBID int64,
) (map[string][]cleanupTicket, error) {
	// 被拒的工单没有产生文件，不构成「需要删的文件」。
	rows, err := service.db.QueryContext(ctx, `
		SELECT ticket_no, ticket_type, status,
		       COALESCE(git_pr_url, ''),
		       (terraform_code IS NOT NULL AND terraform_code <> '') AS published,
		       LOWER(TRIM(COALESCE(principal_name, ''))) AS principal_name
		FROM iam_ticket
		WHERE account_id = $1 AND status <> 'REJECTED'
		ORDER BY id`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load tickets for cleanup: %w", err)
	}
	defer rows.Close()
	tickets := map[string][]cleanupTicket{}
	for rows.Next() {
		var principalName string
		var ticket cleanupTicket
		if err := rows.Scan(
			&ticket.No, &ticket.Type, &ticket.Status, &ticket.PRURL, &ticket.Published, &principalName,
		); err != nil {
			return nil, fmt.Errorf("scan cleanup ticket: %w", err)
		}
		if principalName == "" {
			continue
		}
		tickets[principalName] = append(tickets[principalName], ticket)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cleanup tickets: %w", err)
	}
	return tickets, nil
}

// declaredLifecycleFiles 找出「平台声明了、但资源归 AWS 生命周期托管」的文件。
//
// 这是最难自己发现的一类债：文件在仓库里、terraform apply 也能过，但 AWS 下次
// 跑配置管理就会把属性改回去，两边来回拉扯。清单必须指到具体工单和 PR，否则没
// 人敢删。
func declaredLifecycleFiles(
	resources []BaselineResource,
	tickets map[string][]cleanupTicket,
) []CleanupItem {
	items := make([]CleanupItem, 0, 8)
	for _, resource := range resources {
		if resource.Decision != BaselineDecisionSkippedAWSLifecycle {
			continue
		}
		declared := tickets[strings.ToLower(strings.TrimSpace(resource.Name))]
		if len(declared) == 0 {
			continue
		}
		// 优先指向真的发过 PR 的那张工单：只攒了草稿的工单多半没写文件。
		chosen := declared[len(declared)-1]
		for index := len(declared) - 1; index >= 0; index-- {
			if declared[index].Published || declared[index].PRURL != "" {
				chosen = declared[index]
				break
			}
		}
		evidence := []CleanupEvidence{
			{Code: "baseline-reason", Text: "资源判定：" + resource.Reason, Params: map[string]string{"reason": resource.Reason}},
			{Code: "ticket", Text: fmt.Sprintf("平台工单 %s（%s / %s）", chosen.No, chosen.Type, chosen.Status),
				Params: map[string]string{"ticket": chosen.No, "type": chosen.Type, "status": chosen.Status}},
		}
		if chosen.PRURL != "" {
			evidence = append(evidence, CleanupEvidence{
				Code: "pr-merged", Text: "已合并 PR：" + chosen.PRURL,
				Params: map[string]string{"pr": chosen.PRURL},
			})
		} else {
			evidence = append(evidence, CleanupEvidence{
				Code: "pr-missing",
				Text: "工单没有关联 PR：文件可能只在草稿里，或由人工补写",
			})
		}
		fileKey := ""
		if resource.FileKey != "" {
			fileKey = resource.FileKey + ".tf"
			evidence = append(evidence, CleanupEvidence{
				Code: "file", Text: "声明文件：" + fileKey, Params: map[string]string{"file": fileKey},
			})
		}
		items = append(items, CleanupItem{
			Category:   CleanupCategoryPlatformFile,
			Confidence: CleanupConfidenceHigh,
			Kind:       resource.Kind,
			Name:       resource.Name,
			ARN:        resource.ARN,
			Reason:     "平台为它生成过声明，但该资源由 AWS 服务托管生命周期，声明无法维持",
			ReasonCode: "platform-file",
			Evidence:   evidence,
			Action:     "从 IaC 仓库删除该声明文件并归档工单；AWS 侧资源保持不动",
			ActionCode: "delete-file",
			TicketNo:   chosen.No,
			PullRequestURL: chosen.PRURL,
			FileKey:        fileKey,
		})
	}
	return items
}

// instanceProfileRow 是判定实例配置文件所需的最小事实集。
type instanceProfileRow struct {
	Name     string
	ARN      string
	RoleARN  string
	RoleName string // 为空表示绑定的角色在库存里找不到（含已删除）
}

func (service *CleanupService) loadInstanceProfiles(
	ctx context.Context,
	accountDBID int64,
) ([]instanceProfileRow, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT ip.instance_profile_name, ip.arn,
		       COALESCE(ip.role_arn, ''),
		       COALESCE(r.principal_name, '')
		FROM iam_instance_profile ip
		LEFT JOIN iam_principal r
		       ON r.account_id = ip.account_id
		      AND r.principal_type = 'Role'
		      AND r.arn = ip.role_arn
		      AND r.is_deleted = FALSE
		WHERE ip.account_id = $1 AND ip.is_deleted = FALSE
		ORDER BY ip.instance_profile_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load instance profiles for cleanup: %w", err)
	}
	defer rows.Close()
	profiles := make([]instanceProfileRow, 0, 16)
	for rows.Next() {
		var row instanceProfileRow
		if err := rows.Scan(&row.Name, &row.ARN, &row.RoleARN, &row.RoleName); err != nil {
			return nil, fmt.Errorf("scan cleanup instance profile: %w", err)
		}
		profiles = append(profiles, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cleanup instance profiles: %w", err)
	}
	return profiles, nil
}

// unboundInstanceProfiles 找出没有角色可绑的实例配置文件：这类资源留着没有任何
// 作用，也无法绑定到 EC2（实例配置文件本身就是「给实例挂角色的壳」）。
func unboundInstanceProfiles(profiles []instanceProfileRow) []CleanupItem {
	items := make([]CleanupItem, 0, 4)
	for _, profile := range profiles {
		var reasonCode string
		var reason string
		var evidence []CleanupEvidence
		switch {
		case strings.TrimSpace(profile.RoleARN) == "":
			reasonCode = "profile-no-role"
			reason = "实例配置文件没有绑定任何角色，是一个空壳"
			evidence = []CleanupEvidence{{Code: "no-role-arn", Text: "role_arn 为空"}}
		case strings.TrimSpace(profile.RoleName) == "":
			reasonCode = "profile-role-gone"
			reason = "实例配置文件绑定的角色在账号里已不存在"
			evidence = []CleanupEvidence{
				{Code: "role-arn", Text: "绑定角色 ARN：" + profile.RoleARN,
					Params: map[string]string{"arn": profile.RoleARN}},
				{Code: "role-missing", Text: "库存中找不到该角色（可能已被删除）"},
			}
		default:
			continue
		}
		items = append(items, CleanupItem{
			Category:   CleanupCategoryAWSResource,
			Confidence: CleanupConfidenceHigh,
			Kind:       BaselineKindInstanceProfile,
			Name:       profile.Name,
			ARN:        profile.ARN,
			Reason:     reason,
			ReasonCode: reasonCode,
			Evidence:   evidence,
			Action:     "aws iam delete-instance-profile --instance-profile-name " + profile.Name,
			ActionCode: "delete-profile",
			Params:     map[string]string{"name": profile.Name},
		})
	}
	return items
}

// eksInstanceProfileCleanup 处理 EKS 自动创建的 `eks-<uuid>` 实例配置文件。
//
// 这些配置文件是 EKS 托管节点组反复重建留下的：每建一次生成一个，删节点组时
// 只删自己那一个，剩下的就变成孤儿。但 IAM 数据看不出哪一个正在被使用——
// 唯一的硬证据在 EC2 侧：launch template 的 IamInstanceProfile 引用。
// usage 为 nil（解析器缺失或失败）时全部退回「需确认」，绝不假装知道答案。
func eksInstanceProfileCleanup(
	profiles []instanceProfileRow,
	usage *profileUsageResult,
	usageErr error,
) []CleanupItem {
	byRole := map[string][]instanceProfileRow{}
	for _, profile := range profiles {
		if !isEKSManagedInstanceProfileName(strings.ToLower(profile.Name)) {
			continue
		}
		roleARN := strings.TrimSpace(profile.RoleARN)
		if roleARN == "" {
			continue // 没有角色绑定的走 unboundInstanceProfiles，不重复报。
		}
		byRole[roleARN] = append(byRole[roleARN], profile)
	}

	items := make([]CleanupItem, 0, 8)
	for roleARN, group := range byRole {
		// 先区分「确认在用」「确认不在用」「无法判定」三堆。
		used := make([]instanceProfileRow, 0, len(group))
		unused := make([]instanceProfileRow, 0, len(group))
		for _, profile := range group {
			if usage != nil && usage.isUsed(profile.ARN, profile.Name) {
				used = append(used, profile)
			} else {
				unused = append(unused, profile)
			}
		}

		roleNodegroups := ""
		roleUsed := false
		if usage != nil {
			roleUsed = usage.roleInUse(roleARN)
			if lines, ok := usage.RoleNodegroups[strings.ToLower(roleARN)]; ok && len(lines) > 0 {
				roleNodegroups = strings.Join(lines, "、")
			}
		}

		for _, profile := range unused {
			var confidence, reasonCode, reason string
			var evidence []CleanupEvidence
			var actionCode, action string
			switch {
			case usage == nil:
				// 解析不了就老实说解析不了。
				confidence = CleanupConfidenceReview
				reasonCode = "profile-eks-review"
				reason = fmt.Sprintf(
					"同一角色下共 %d 个 EKS 自动创建的实例配置文件，实际只可能有 1 个在用；本条是其中之一",
					len(group))
				evidence = append(evidence, eksSiblingEvidence(group, profile)...)
				evidence = append(evidence, CleanupEvidence{
					Code: "usage-unavailable", Text: "EKS/EC2 侧证据不可用" +
						func() string {
							if usageErr != nil {
								return "：" + usageErr.Error()
							}
							return "（未配置解析器）"
						}(),
				})
				actionCode = "delete-profile-verify"
				action = "先用 aws eks list-nodegroups 与节点组的 launch template 确认在用项，其余用 aws iam delete-instance-profile 删除；节点组已删除则可全部删除"
			case len(used) > 0:
				// 有兄弟确认在用，未被引用的这一个就是干净的孤儿。
				confidence = CleanupConfidenceHigh
				reasonCode = "profile-eks-unused"
				reason = "同角色已确认有一个实例配置文件正在被节点组使用，本条未被任何 launch template 引用"
				evidence = append(evidence, eksSiblingEvidence(group, profile)...)
				evidence = append(evidence, usedEvidence(used)...)
				actionCode = "delete-profile"
				action = "aws iam delete-instance-profile --instance-profile-name " + profile.Name
			case roleUsed:
				// 角色还有活着的节点组，却没有一个 launch template 引用这堆
				// 配置文件——很反常，宁可标待确认也不能直接删。
				confidence = CleanupConfidenceReview
				reasonCode = "profile-eks-ambiguous"
				reason = "绑定角色仍被节点组使用，但本条未被任何 launch template 引用：可能节点组刚重建，证据未对齐"
				evidence = append(evidence, eksSiblingEvidence(group, profile)...)
				evidence = append(evidence, CleanupEvidence{
					Code: "role-nodegroups",
					Text: "角色仍被节点组使用：" + roleNodegroups,
					Params: map[string]string{"nodegroups": roleNodegroups},
				})
				actionCode = "delete-profile-verify"
				action = "先 aws eks describe-nodegroup 核对节点组状态与 launch template，确认后再用 aws iam delete-instance-profile 删除"
			default:
				confidence = CleanupConfidenceHigh
				if usage.EKSUnavailable {
					// EKS 侧未检查（权限未授予），理由必须如实：只能引用
					// EC2 证据，不能声称「角色没有节点组在用」。
					reasonCode = "profile-eks-unused-eks-unchecked"
					reason = "未被任何 launch template 引用（EC2 证据）；EKS 侧节点组检查因缺少 EKS 只读权限未执行，删除前可用 aws eks list-nodegroups 复核"
					evidence = append(evidence, CleanupEvidence{
						Code: "eks-permission-skipped",
						Text: "未授予 EKS 只读权限，角色级节点组证据缺失；本条结论仅基于 EC2 launch template 证据",
					})
				} else if len(group) > 1 {
					reasonCode = "profile-eks-unused-role-idle"
					reason = "同角色没有任何实例配置文件被 launch template 引用，角色也没有节点组在用"
				} else {
					reasonCode = "profile-eks-orphan"
					reason = "EKS 自动创建的实例配置文件未被任何 launch template 引用，绑定角色也没有节点组在用，是重建留下的孤儿"
				}
				evidence = append(evidence, eksSiblingEvidence(group, profile)...)
				actionCode = "delete-profile"
				action = "aws iam delete-instance-profile --instance-profile-name " + profile.Name
			}
			items = append(items, CleanupItem{
				Category:   CleanupCategoryAWSResource,
				Confidence: confidence,
				Kind:       BaselineKindInstanceProfile,
				Name:       profile.Name,
				ARN:        profile.ARN,
				Reason:     reason,
				ReasonCode: reasonCode,
				Evidence:   evidence,
				Action:     action,
				ActionCode: actionCode,
				Params: map[string]string{
					"name": profile.Name,
					"role": roleARN,
					"group_size": fmt.Sprint(len(group)),
				},
			})
		}
	}
	return items
}

// eksSiblingEvidence 给出「同角色有哪几个、谁是嫌疑」的公共证据。
func eksSiblingEvidence(group []instanceProfileRow, current instanceProfileRow) []CleanupEvidence {
	siblings := make([]string, 0, len(group))
	others := make([]string, 0, len(group))
	for _, profile := range group {
		siblings = append(siblings, profile.Name)
		if profile.Name != current.Name {
			others = append(others, profile.Name)
		}
	}
	sort.Strings(siblings)
	sort.Strings(others)
	evidence := []CleanupEvidence{
		{Code: "role-arn", Text: "绑定角色：" + current.RoleARN,
			Params: map[string]string{"arn": current.RoleARN}},
		{Code: "siblings",
			Text:   fmt.Sprintf("同角色共 %d 个：%s", len(group), strings.Join(siblings, "、")),
			Params: map[string]string{"count": fmt.Sprint(len(group)), "names": strings.Join(siblings, "、")}},
	}
	if len(others) > 0 {
		evidence = append(evidence, CleanupEvidence{
			Code:   "others",
			Text:   "其余：" + strings.Join(others, "、"),
			Params: map[string]string{"names": strings.Join(others, "、")},
		})
	}
	evidence = append(evidence, CleanupEvidence{
		Code: "eks-rebuild-note",
		Text: "EKS 每重建一次托管节点组就新建一个 UUID 命名的实例配置文件，旧的不清理",
	})
	return evidence
}

// usedEvidence 说明「谁被确认在用」——这是把其余条目升级成 high 的支点。
func usedEvidence(used []instanceProfileRow) []CleanupEvidence {
	names := make([]string, 0, len(used))
	for _, profile := range used {
		names = append(names, profile.Name)
	}
	return []CleanupEvidence{{
		Code:   "in-use",
		Text:   "在用项：" + strings.Join(names, "、") + "（被 launch template 引用）",
		Params: map[string]string{"names": strings.Join(names, "、")},
	}}
}

// groupRow 是判定空用户组所需的事实。
type groupRow struct {
	Name     string
	ARN      string
	Members  int
	Policies int
}

func (service *CleanupService) loadEmptyGroups(
	ctx context.Context,
	accountDBID int64,
) ([]groupRow, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT g.group_name, g.arn,
		       (SELECT COUNT(*) FROM iam_group_membership m WHERE m.group_id = g.id),
		       (SELECT COUNT(*) FROM iam_group_policy p WHERE p.group_id = g.id)
		FROM iam_group g
		WHERE g.account_id = $1
		ORDER BY g.group_name`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load groups for cleanup: %w", err)
	}
	defer rows.Close()
	groups := make([]groupRow, 0, 32)
	for rows.Next() {
		var row groupRow
		if err := rows.Scan(&row.Name, &row.ARN, &row.Members, &row.Policies); err != nil {
			return nil, fmt.Errorf("scan cleanup group: %w", err)
		}
		groups = append(groups, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cleanup groups: %w", err)
	}
	return groups, nil
}

// emptyGroups 找出没有成员的用户组。
//
// 完全没有成员、也没有挂策略的组是纯空壳，直接可删；还挂着策略的组有第二种
// 可能——预建但尚未投放使用，所以只能标为待确认。
func emptyGroups(groups []groupRow) []CleanupItem {
	items := make([]CleanupItem, 0, 8)
	for _, group := range groups {
		if group.Members > 0 {
			continue
		}
		confidence := CleanupConfidenceReview
		reasonCode := "group-empty-policies"
		reason := "用户组没有任何成员，但仍挂着策略：可能是预建待用，也可能是无人清理的旧组"
		evidence := []CleanupEvidence{{
			Code:   "group-stats",
			Text:   fmt.Sprintf("成员 0；挂载策略 %d 条", group.Policies),
			Params: map[string]string{"members": "0", "policies": fmt.Sprint(group.Policies)},
		}}
		actionCode := "delete-group-detach"
		action := "确认无用后先 detach 策略再删除：aws iam delete-group --group-name " + group.Name
		if group.Policies == 0 {
			confidence = CleanupConfidenceHigh
			reasonCode = "group-empty-plain"
			reason = "用户组没有任何成员、也没有挂载任何策略，是纯空壳"
			actionCode = "delete-group"
			action = "aws iam delete-group --group-name " + group.Name
		}
		items = append(items, CleanupItem{
			Category:   CleanupCategoryAWSResource,
			Confidence: confidence,
			Kind:       BaselineKindGroup,
			Name:       group.Name,
			ARN:        group.ARN,
			Reason:     reason,
			ReasonCode: reasonCode,
			Evidence:   evidence,
			Action:     action,
			ActionCode: actionCode,
			Params:     map[string]string{"name": group.Name, "policies": fmt.Sprint(group.Policies)},
		})
	}
	return items
}

// sortCleanupItems 让清单按「动作方向 → 置信度 → 类型 → 名字」稳定排序：
// 先看平台文件（可以放心删），再看 AWS 资源；同一类里先给证据充分的。
func sortCleanupItems(items []CleanupItem) {
	categoryRank := map[string]int{CleanupCategoryPlatformFile: 0, CleanupCategoryAWSResource: 1}
	confidenceRank := map[string]int{CleanupConfidenceHigh: 0, CleanupConfidenceReview: 1}
	sort.SliceStable(items, func(left, right int) bool {
		if categoryRank[items[left].Category] != categoryRank[items[right].Category] {
			return categoryRank[items[left].Category] < categoryRank[items[right].Category]
		}
		if confidenceRank[items[left].Confidence] != confidenceRank[items[right].Confidence] {
			return confidenceRank[items[left].Confidence] < confidenceRank[items[right].Confidence]
		}
		if items[left].Kind != items[right].Kind {
			return items[left].Kind < items[right].Kind
		}
		return items[left].Name < items[right].Name
	})
}
