// Command baseline-candidates 输出账号级全量基线的「候选集差异清单」（阶段 0）。
//
// 只读：读库存、算归属结论、预测文件名与 Terraform 地址，不改数据库、不生成
// Terraform 文件、不碰 IaC 仓库。配套设计见 docs/phase3-account-baseline-design.md。
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

func main() {
	account := flag.String("account", "", "AWS 账号（12 位账号 ID 或数据库 id）")
	out := flag.String("out", "", "输出 markdown 路径（留空打印到标准输出）")
	flag.Parse()

	if strings.TrimSpace(*account) == "" {
		fmt.Fprintln(os.Stderr, "缺少 -account：请指定 AWS 账号 ID 或数据库 id")
		os.Exit(2)
	}
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "加载 .env 失败:", err)
		os.Exit(1)
	}
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL 未配置")
		os.Exit(1)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接数据库失败:", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	report, err := service.NewBaselineCandidateService(db).Build(ctx, *account)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成候选集失败:", err)
		os.Exit(1)
	}
	markdown := renderMarkdown(report)
	if *out == "" {
		fmt.Print(markdown)
		return
	}
	if err := os.WriteFile(*out, []byte(markdown), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写入报告失败:", err)
		os.Exit(1)
	}
	fmt.Printf("已写入 %s（候选 %d / 跳过 %d / 冲突 %d）\n",
		*out, report.Counts[service.BaselineDecisionCandidate],
		len(report.Resources)-report.Counts[service.BaselineDecisionCandidate],
		len(report.Conflicts))
}

var kindLabels = map[string]string{
	service.BaselineKindRole:             "IAM 角色",
	service.BaselineKindUser:             "IAM 用户",
	service.BaselineKindGroup:            "IAM 用户组",
	service.BaselineKindPolicy:           "客户自管策略",
	service.BaselineKindAWSManagedPolicy: "AWS 托管策略",
	service.BaselineKindInstanceProfile:  "实例配置文件",
	service.BaselineKindOIDCProvider:     "OIDC 身份提供方",
	service.BaselineKindSAMLProvider:     "SAML 身份提供方",
	service.BaselineKindInlinePolicy:     "内联策略",
}

var decisionLabels = map[string]string{
	service.BaselineDecisionCandidate:                "进基线",
	service.BaselineDecisionSkippedExternal:          "跳过：外部系统管理",
	service.BaselineDecisionSkippedExternalSignature: "跳过：tag 显示由外部工具创建",
	service.BaselineDecisionSkippedServiceLinked:     "跳过：service-linked role",
	service.BaselineDecisionSkippedAWSManagedPolicy:  "跳过：AWS 托管策略本体",
	service.BaselineDecisionSkippedAWSLifecycle:      "跳过：AWS 生命周期托管",
	service.BaselineDecisionSkippedAlreadyDeclared:   "跳过：平台已声明",
}

func renderMarkdown(report *service.BaselineCandidateReport) string {
	var builder strings.Builder
	writeHeader(&builder, report)
	writeSummary(&builder, report)
	writeCandidates(&builder, report)
	writeSkipped(&builder, report)
	writeConflicts(&builder, report)
	writeRelationships(&builder, report)
	writeDecisionsNeeded(&builder, report)
	writeGeneratorGaps(&builder, report)
	writeOpenDecisions(&builder, report)
	return builder.String()
}

func writeHeader(builder *strings.Builder, report *service.BaselineCandidateReport) {
	builder.WriteString("# 账号 " + report.AWSAccountID + " 全量基线候选集（阶段 0 差异清单）\n\n")
	builder.WriteString("> 只读产物：本报告不修改库存、不生成 Terraform 文件、不触碰 IaC 仓库。\n")
	builder.WriteString("> 生成时间：" + report.GeneratedAt.Format(time.RFC3339) + "　")
	if report.LatestSyncRunID > 0 {
		builder.WriteString(fmt.Sprintf("库存快照：同步 run #%d", report.LatestSyncRunID))
		if report.LatestSyncFinishedAt != nil {
			builder.WriteString("（" + report.LatestSyncFinishedAt.Local().Format("2006-01-02 15:04") + "）")
		}
	} else {
		builder.WriteString("库存快照：未找到成功的同步记录")
	}
	builder.WriteString("\n\n")
	builder.WriteString("口径（docs/phase3-account-baseline-design.md §2/§6）：\n\n")
	builder.WriteString("- 归属只决定「跳过」，不决定「能否纳入」：`platform` 与 `unknown` 都进基线\n")
	builder.WriteString("  （平台定位是统一 IAM 管理，`unknown` 即「默认接管」），`external` 跳过并报告。\n")
	builder.WriteString("- tag 里带 CloudFormation 栈名 / eksctl 集群名 / QuickSetup 配置的资源视为**有证据**的外部创建，\n")
	builder.WriteString("  与 external 同样跳过并写明来源（这些 tag 采集期已入库，不需要额外 AWS 权限）。\n")
	builder.WriteString("- **AWS 生命周期托管**的资源不进基线：SSM Quick Setup 的角色（`AWS-QuickSetup-*`\n")
	builder.WriteString("  命名空间，tag 缺失时靠名字判）、EKS 托管节点组的 `eks-<uuid>` 实例配置文件、\n")
	builder.WriteString("  AWS 自动化代建且带 `Amazon*` 保留名前缀的角色。这些由服务创建、重写或连带删除，\n")
	builder.WriteString("  声明下来只会得到「下一次 plan 就报实体已不存在」的幽灵资源。\n")
	builder.WriteString("- **不进基线不等于看不见**：库存采集与风险扫描仍是全量，排除只影响是否写 Terraform 声明。\n")
	builder.WriteString("  排除规则每次重算，外部工具下线或 tag 清理后资源会自动回到候选集。\n")
	builder.WriteString("- 原理上不可声明的资源（service-linked role、AWS 托管策略本体）不进基线，但必须留清单。\n")
	builder.WriteString("- 平台已有工单声明过的资源跳过：再生成一份会造成同一 Terraform 地址双声明，配置直接不可用。\n")
	builder.WriteString("- 文件名与 Terraform 地址由**工单同一套 key 规则**推导（`service.ResourceFileKey`），\n")
	builder.WriteString("  保证基线与后续工单写同一个文件。\n\n")
}

func writeSummary(builder *strings.Builder, report *service.BaselineCandidateReport) {
	type row struct {
		kind   string
		counts map[string]int
		total  int
	}
	byKind := map[string]*row{}
	decisions := []string{
		service.BaselineDecisionCandidate,
		service.BaselineDecisionSkippedExternal,
		service.BaselineDecisionSkippedExternalSignature,
		service.BaselineDecisionSkippedAWSLifecycle,
		service.BaselineDecisionSkippedServiceLinked,
		service.BaselineDecisionSkippedAWSManagedPolicy,
		service.BaselineDecisionSkippedAlreadyDeclared,
	}
	for _, item := range report.Resources {
		entry := byKind[item.Kind]
		if entry == nil {
			entry = &row{kind: item.Kind, counts: map[string]int{}}
			byKind[item.Kind] = entry
		}
		entry.counts[item.Decision]++
		entry.total++
	}
	kinds := make([]string, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	builder.WriteString("## 1. 汇总\n\n")
	builder.WriteString("| 资源类型 | 进基线 | 外部管理 | 外部工具签名 | AWS 生命周期 | service-linked | AWS 托管策略 | 已声明 | 小计 |\n")
	builder.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	totals := map[string]int{}
	grand := 0
	for _, kind := range kinds {
		entry := byKind[kind]
		builder.WriteString("| " + kindLabel(kind) + " |")
		for _, decision := range decisions {
			builder.WriteString(fmt.Sprintf(" %d |", entry.counts[decision]))
			totals[decision] += entry.counts[decision]
		}
		builder.WriteString(fmt.Sprintf(" %d |\n", entry.total))
		grand += entry.total
	}
	builder.WriteString("| **合计** |")
	for _, decision := range decisions {
		builder.WriteString(fmt.Sprintf(" **%d** |", totals[decision]))
	}
	builder.WriteString(fmt.Sprintf(" **%d** |\n\n", grand))
	builder.WriteString(fmt.Sprintf("候选 %d 个资源将写入 %d 个 Terraform 文件（一资源一文件）。\n\n",
		totals[service.BaselineDecisionCandidate], totals[service.BaselineDecisionCandidate]))
}

func writeCandidates(builder *strings.Builder, report *service.BaselineCandidateReport) {
	candidates := filterResources(report.Resources, service.BaselineDecisionCandidate, "")
	builder.WriteString("## 2. 候选资源（将进入基线）\n\n")
	if len(candidates) == 0 {
		builder.WriteString("无。\n\n")
		return
	}
	builder.WriteString("| # | 类型 | 名称 | path | 归属 | 声明文件 | Terraform 地址 | import ID |\n")
	builder.WriteString("|---:|---|---|---|---|---|---|---|\n")
	for index, item := range candidates {
		builder.WriteString(fmt.Sprintf("| %d | %s | `%s` | `%s` | %s | `%s.tf` | `%s` | %s |\n",
			index+1, kindLabel(item.Kind), escapeCell(item.Name), escapeCell(item.Path),
			managedByLabel(item.ManagedBy), escapeCell(item.FileKey), escapeCell(item.Address),
			importIDCell(item)))
	}
	builder.WriteString("\n")
}

func writeSkipped(builder *strings.Builder, report *service.BaselineCandidateReport) {
	order := []string{
		service.BaselineDecisionSkippedExternal,
		service.BaselineDecisionSkippedExternalSignature,
		service.BaselineDecisionSkippedAWSLifecycle,
		service.BaselineDecisionSkippedServiceLinked,
		service.BaselineDecisionSkippedAWSManagedPolicy,
		service.BaselineDecisionSkippedAlreadyDeclared,
	}
	builder.WriteString("## 3. 跳过清单（不进基线，但必须有人知道）\n\n")
	any := false
	for _, decision := range order {
		items := filterResources(report.Resources, decision, "")
		if len(items) == 0 {
			continue
		}
		any = true
		builder.WriteString("### " + decisionLabel(decision) + "（" + fmt.Sprint(len(items)) + "）\n\n")
		builder.WriteString("| 类型 | 名称 | 说明 |\n|---|---|---|\n")
		for _, item := range items {
			builder.WriteString(fmt.Sprintf("| %s | `%s` | %s |\n",
				kindLabel(item.Kind), escapeCell(item.Name), escapeCell(item.Reason)))
		}
		builder.WriteString("\n")
	}
	if !any {
		builder.WriteString("无。\n\n")
	}
}

func writeConflicts(builder *strings.Builder, report *service.BaselineCandidateReport) {
	builder.WriteString("## 4. 冲突（不解决就无法 apply）\n\n")
	if len(report.Conflicts) == 0 {
		builder.WriteString("未发现文件名或 Terraform 地址撞车。\n\n")
		return
	}
	builder.WriteString("| 类型 | 冲突值 | 涉及资源 |\n|---|---|---|\n")
	for _, conflict := range report.Conflicts {
		kind := "文件名"
		if conflict.Kind == "address" {
			kind = "Terraform 地址"
		}
		builder.WriteString(fmt.Sprintf("| %s | `%s` | %s |\n",
			kind, escapeCell(conflict.Value), escapeCell(strings.Join(conflict.Resources, "、"))))
	}
	builder.WriteString("\n> 成因通常是资源名只差大小写或特殊字符：文件名 key 会统一小写、地址 label 保大小写，\n")
	builder.WriteString("> 两条规则各自可能撞车。需要人工决定保留哪一条，或调整命名。\n\n")
}

func writeRelationships(builder *strings.Builder, report *service.BaselineCandidateReport) {
	if len(report.Relationships) == 0 {
		return
	}
	builder.WriteString("## 5. 关系类资源（不单独建文件，但会影响声明）\n\n")
	byKind := map[string][]service.BaselineRelationship{}
	for _, item := range report.Relationships {
		byKind[item.Kind] = append(byKind[item.Kind], item)
	}
	labels := map[string]string{
		"group-membership":         "组成员关系",
		"policy-attachment":        "托管策略挂载",
		"instance-profile-binding": "实例配置文件 ↔ 角色绑定",
	}
	kinds := make([]string, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		items := byKind[kind]
		builder.WriteString("### " + labels[kind] + "（" + fmt.Sprint(len(items)) + "）\n\n")
		builder.WriteString("| 主体 | 说明 |\n|---|---|\n")
		for _, item := range items {
			builder.WriteString(fmt.Sprintf("| `%s` | %s |\n",
				escapeCell(item.Subject), escapeCell(item.Detail)))
		}
		builder.WriteString("\n")
	}
	builder.WriteString("> 归属由主体推导，不单独打 `managed_by`。注意：组声明里的成员、用户声明里的策略挂载\n")
	builder.WriteString("> 都是**完整集合**语义——如果同一关系已由 `attachment-*.tf` 声明，基线里不能再写，\n")
	builder.WriteString("> 否则同一 `aws_iam_*_policy_attachment` 地址双声明。\n\n")
}

// writeDecisionsNeeded 列出候选里归属仍是 unknown 的资源。
//
// unknown 默认纳入（平台定位是统一 IAM 管理），所以这一节不是「签字清单」，
// 而是「接管范围告知」：发布前不需要逐条确认，只需要知道第一次 apply 会接管
// 多少条、有没有哪一批其实该留给别的系统（那就标 external 排除）。
func writeDecisionsNeeded(builder *strings.Builder, report *service.BaselineCandidateReport) {
	unknown := make([]service.BaselineResource, 0)
	for _, item := range report.Resources {
		if item.Decision == service.BaselineDecisionCandidate && strings.EqualFold(item.ManagedBy, "unknown") {
			unknown = append(unknown, item)
		}
	}
	builder.WriteString("## 6. 接管范围：归属仍为 unknown 的候选\n\n")
	if len(unknown) == 0 {
		builder.WriteString("所有候选资源的归属都已标注。\n\n")
		return
	}
	builder.WriteString(fmt.Sprintf("候选中有 **%d** 个资源归属为 `unknown`，按口径**默认纳入**——\n", len(unknown)))
	builder.WriteString("平台定位就是统一 IAM 管理，不需要逐条签字。这一节的作用是让管理员看清\n")
	builder.WriteString("「这一次接管了哪些原本没人认领的资源」，以及在必要时按前缀批量排除。\n\n")
	builder.WriteString("> 带外部工具签名（CloudFormation / eksctl / Quick Setup）或判定为 AWS 生命周期托管的资源\n")
	builder.WriteString("> 已在第 3 节自动排除，因此这里的每一条都是「没有任何工具签名、也没有人标注」的资源。\n\n")
	counts := map[string]int{}
	for _, item := range unknown {
		counts[item.Kind]++
	}
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	builder.WriteString("| 资源类型 | unknown 数量 |\n|---|---:|\n")
	for _, kind := range kinds {
		builder.WriteString(fmt.Sprintf("| %s | %d |\n", kindLabel(kind), counts[kind]))
	}
	builder.WriteString("\n标注方式：`PUT /api/v1/iam/ownership`（`managed_by` = platform / external / unknown）。\n")
	builder.WriteString("标为 `external` 会把它从基线里排除；标为 `platform` 只是提前确认接管意图。\n\n")
}

func writeGeneratorGaps(builder *strings.Builder, report *service.BaselineCandidateReport) {
	gaps := make([]service.BaselineResource, 0)
	for _, item := range report.Resources {
		if item.Decision == service.BaselineDecisionCandidate && !item.GeneratorReady {
			gaps = append(gaps, item)
		}
	}
	builder.WriteString("## 7. 生成器缺口（能进候选集，但本次生成不出声明）\n\n")
	if len(gaps) == 0 {
		builder.WriteString("无：所有候选资源都有对应生成器。\n\n")
		return
	}
	counts := map[string]int{}
	for _, item := range gaps {
		counts[item.Kind]++
	}
	builder.WriteString("以下资源类型的声明生成器尚未实现（属 B2 工作项），阶段 0 只能列出清单：\n\n")
	builder.WriteString("| 资源类型 | 数量 | 说明 |\n|---|---:|---|\n")
	notes := map[string]string{
		service.BaselineKindInstanceProfile: "需新增 aws_iam_instance_profile 生成器，并处理 role 绑定",
		service.BaselineKindOIDCProvider:    "需新增 aws_iam_openid_connect_provider（client_id_list / thumbprint_list）",
		service.BaselineKindSAMLProvider:    "需新增 aws_iam_saml_provider（metadata document）",
	}
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		builder.WriteString(fmt.Sprintf("| %s | %d | %s |\n", kindLabel(kind), counts[kind], notes[kind]))
	}
	builder.WriteString("\n")
}

func filterResources(
	resources []service.BaselineResource,
	decision string,
	kind string,
) []service.BaselineResource {
	filtered := make([]service.BaselineResource, 0, len(resources))
	for _, item := range resources {
		if item.Decision != decision {
			continue
		}
		if kind != "" && item.Kind != kind {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

// writeOpenDecisions 把「数据已经回答了、但需要人拍板」的三件事写清楚。
// 这些不是代码问题，而是进 B2 前必须定下的口径，否则生成器写到一半会推翻重来。
func writeOpenDecisions(builder *strings.Builder, report *service.BaselineCandidateReport) {
	attachments := 0
	memberships := 0
	existingTickets := 0
	for _, item := range report.Relationships {
		switch item.Kind {
		case "policy-attachment":
			attachments++
		case "group-membership":
			memberships++
		}
		if item.ExistingTicket {
			existingTickets++
		}
	}
	builder.WriteString("## 8. 进入 B2 前要拍板的三件事\n\n")
	builder.WriteString("### 8.1 挂载关系是否进基线\n\n")
	builder.WriteString(fmt.Sprintf("本账号有 **%d** 个主体存在托管策略挂载，**%d** 个组有成员。\n\n", attachments, memberships))
	builder.WriteString("- 若基线在 `user-<name>.tf` / `role-<name>.tf` 里声明挂载，必须为每条挂载生成 import 块\n")
	builder.WriteString("  （`aws_iam_*_policy_attachment` 的 import ID 是 `<主体名>/<策略 ARN>`），否则 apply\n")
	builder.WriteString("  遇到已存在的挂载会直接报错。\n")
	builder.WriteString("- 若主体已有 `attachment-*.tf`，基线必须留空，否则同一地址两个文件双声明。\n")
	if existingTickets > 0 {
		builder.WriteString(fmt.Sprintf("  本次有 **%d** 个主体属于这种情况（见第 5 节标注）。\n", existingTickets))
	}
	builder.WriteString("\n**建议**：基线声明挂载并生成 import 块；已有挂载工单的主体例外。\n\n")

	builder.WriteString("### 8.2 幂等键\n\n")
	if report.LatestSyncRunID > 0 {
		builder.WriteString(fmt.Sprintf("建议：**账号 + 库存快照 run #%d**。\n\n", report.LatestSyncRunID))
	} else {
		builder.WriteString("建议：**账号 + 库存快照 run**。\n\n")
	}
	builder.WriteString("快照版本天然唯一、可审计（验收标准要求「基线基于哪次库存快照」可追溯）；\n")
	builder.WriteString("允许人工重跑覆盖旧分支会让 PR 里的历史审阅记录失真。\n\n")

	builder.WriteString("### 8.3 CI 门禁\n\n")
	builder.WriteString("阶段 1 的出口条件是 `terraform plan` **只有 import、0 变更**。若仓库仍无 CI，\n")
	builder.WriteString("这条门禁只能靠人工看 plan 输出——那样试点账号必须选非关键账号，且 plan 输出要存档进工单。\n\n")
}

func kindLabel(kind string) string {
	if label, ok := kindLabels[kind]; ok {
		return label
	}
	return kind
}

func decisionLabel(decision string) string {
	if label, ok := decisionLabels[decision]; ok {
		return label
	}
	return decision
}

func managedByLabel(managedBy string) string {
	switch strings.ToLower(strings.TrimSpace(managedBy)) {
	case "platform":
		return "platform"
	case "external":
		return "external"
	default:
		return "unknown"
	}
}

func importIDCell(item service.BaselineResource) string {
	if item.ImportID == "" {
		return "—"
	}
	return "`" + escapeCell(item.ImportID) + "`"
}

// escapeCell 把 markdown 表格里的竖线与换行处理掉，避免一整行错位。
func escapeCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}
