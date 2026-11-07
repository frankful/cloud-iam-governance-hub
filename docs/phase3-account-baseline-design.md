# 账号级全量 Terraform 基线（首次接户一次性生成）

> 状态：**已实现并完成首个账号试点收官**（2026-10-28，账号 111122223333，
> apply 成功，plan 归零）。设计原则与实现约束以本文为准；
> 实现过程与纳管范围明细见第 10 节。

## 1. 问题与目标

现状是**逐资源纳管**：接入账号后，每个既有角色/用户/组/策略都要单独开一张
`adopt_existing=true` 工单，靠服务端从库存取快照生成 import 块，再由人审 PR。

代价：

- 一个中等账号有几十到上百个 IAM 资源，逐张工单 × 逐次审批 × 逐个 PR，人力不可行；
- 存量资源长期不纳管，漂移检测、归属、审计都缺基线。

目标：**接入账号时一次性生成该账号全部可纳管 IAM 资源的 Terraform 基线**，
一个账号一个 PR，之后所有变更走正常工单。

## 2. 已拍板的决策（2026-10-22）

| 决策 | 取值 |
|---|---|
| 覆盖范围 | 账号内全部可纳管 IAM 资源，一次性全量 |
| PR 粒度 | **一个账号一个 PR**（多文件 bundle），不是一资源一 PR |
| 冲突处理 | 目标文件已存在/资源已纳管 → **跳过并列入报告**，不覆盖 |
| 归属边界 | `managed_by=platform` **和** `unknown` 都进基线；`external` 跳过并报告 |
| 不可纳管资源 | 不生成资源块，但**必须留清单说明**（见第 6 节） |
| 行为变更告知 | 全量纳管意味着线下改动会被下次 apply 抹平；接户授权与 plan 审查里必须写明 |

> **2026-10-27 确认：`unknown` 默认纳入，不做逐条签字。** 平台的定位就是统一 IAM
> 管理，「没人标注」不应该变成「不敢接管」——要求管理员先把 162 个资源逐条表态，
> 等于让功能永远停在第一步（归属 API 上线至今一次没被调用过，就是这个结果）。
> 风险不由人工闸门承担，而由三条硬控制承担：
>
> 1. **有证据的排除**：tag 里带 `aws:cloudformation:stack-name` 或
>    `QuickSetupManagerArn`/`QuickSetupDocument` 的资源判为
>    `skipped:external-signature`，报告写明栈名/配置管理 ID。
>    这些 tag 采集期已入库，不需要新 API、也不需要给只读角色加权限。
>    排除之外的一律接管。
>    **2026-10-28 修订：`alpha.eksctl.io/*` 从签名排除清单移除，eksctl 创建的
>    资源统一纳管**——eksctl 只在集群创建期写一次资源、之后不重写，纳管不
>    互相覆盖；排除反而让基线漏掉真实资源，且首账号试点证明了这点（排除期
>    间 6 个 eksctl addon 角色不在基线里）。CloudFormation 与 Quick Setup
>    保留排除：它们会重写资源。
> 2. **不可声明优先于归属**：service-linked role、AWS 托管策略本体永远跳过，
>    与 `managed_by` 无关（避免把「AWS 自管」误报成「平台已声明」）。
> 3. **生命周期不在人手里的排除**（`skipped:aws-lifecycle`）：SSM Quick Setup 的
>    `AWS-QuickSetup-*` 角色（tag 被清过时靠命名空间判）、EKS 托管节点组自动创建的
>    `eks-<uuid>` 实例配置文件（IAM 实例配置文件不支持 tag，只能靠名字）、AWS 自动化
>    代建且带 `Amazon*` 保留名前缀的角色。它们由服务重写或连带删除，声明下来就会在
>    下一次 plan 报「实体已不存在」。判据同样是可复核的证据，不是人工签字。
> 4. **apply 后归零校验**：第一次 plan 只有 import 证明不了没人共管——共管冲突
>    只在第二次 apply 才显形。基线 PR 合并后必须再跑一次 plan，仍为 0 变更才算接户完成。
>
> `external` 与签名排除都是「可改判」的：确认要接管就标 `platform`，下一轮基线重新纳入。

## 3. 前置改造：文件 key（已完成 2026-10-22）

全量基线要求「同一资源只有一个声明文件」。基线按资源生成 `user-<name>.tf`、
`role-<name>.tf`，如果后续 CREATE 工单仍写 `IAM-<ticket>.tf`，同一资源会被两个文件声明 →
`Duplicate resource`，整个配置不可用。

已完成：

- `CreateIAMTicketRequest.resourceFileKey()`（[ticket_service.go](../internal/service/ticket_service.go)）
  对 CREATE_ROLE / CREATE_USER / CREATE_GROUP / CREATE_MANAGED_POLICY / ATTACH_* 返回
  `role-<name>` / `user-<name>` / `group-<name>` / `policy-<name>` /
  `attachment-<type>-<principal>-<policy>`，`terraformFileTicketNo` 已接入。
- `UPDATE_MANAGED_POLICY` 改为**原地 patch**（`generateManagedPolicyTerraform` +
  `PatchInlinePolicyDocument`）：避免整文件重写丢掉 path/description/tags，而 `path`
  是 ForceNew，丢一次就等于策略重建（ARN 变化 → 全部挂载断裂）。

基线生成器**必须复用同一套 key 规则**，否则又会造出双声明。

## 4. 安全前置：采集字段缺口

AWS provider 里这些属性是 **ForceNew**，基线里漏掉 = plan 显示「删除属性」= 资源被重建
（角色/策略 ARN 变化 → 全部挂载断裂）：

| 字段 | 现状 | 影响 |
|---|---|---|
| Role `path` | 采集器未采 | 角色重建 |
| User `path` | 采集器未采 | 用户重建（连带组成员关系） |
| `permissions_boundary`（role/user） | 未采 | 重建 |
| `instance_profile` ↔ role 绑定 | 只采角色侧，未采绑定关系 | 角色重建 / EC2 实例失联 |
| User tags | 未采 | 属性丢失 |
| OIDC / SAML provider | 未采 | 影响 `aws_iam_openid_connect_provider` 类资源 |

结论：**先补采集再生成基线**，不能「先跳过这些属性」。

> **2026-10-26 更新**：本节字段已全部采集并落库（迁移 `0020`）。实际动手时发现
> 采集只是一半——`AWSRoleInfo` 与角色生成器原本也表达不出 `path` /
> `permissions_boundary` / `tags`，补了采集也写不进声明；生成器与野生角色纳管
> 路径已一并补齐（含「import 一个 `/app/` 下的角色会 plan 出重建」这个真实缺陷）。
> 仍未做：instance profile 与
> OIDC/SAML provider 的声明生成（属 B2）。

## 5. 分阶段落地

| 阶段 | 内容 | 出口条件 |
|---|---|---|
| 0（只读） | 遍历库存，为每个资源生成声明 + import 块，落到**独立分支**，不合 main；产出「差异清单」 | 差异清单能逐条解释（新增/冲突/跳过原因） |
| 1（单账号试点） | 带 import 块合入，要求 `terraform plan` **只有 import、0 变更** | plan 输出被审阅并留痕；这是比生成器本身更值钱的门禁 |
| 2 | 扩到全部接入账号，开启漂移检测（声明 vs 库存，差异开工单） | 漂移检测无误报接入 |
| 3 | 基线同步做成产品能力（手动/定时触发） | — |

阶段 0 与阶段 1 之间不能省：光生成不校验，等于把重建风险推给 apply。

### 5.1 基线预览 job（B2，已完成 2026-10-27）

阶段 0 的平台化落地。一次预览 = 从库存构建多文件 Terraform bundle + 冲突检测，
结果落库供只读审查，**不发布**（发布是 B3）。

- **job 状态机**：`iam_baseline_job`（迁移 0022）。API 收到创建请求落
  PENDING → 后台 goroutine 领取为 RUNNING → 构建成功写 COMPLETED（结果整体
  JSONB + 全 bundle 的 sha256 指纹）/ 失败写 FAILED。归属列（account_id、
  requested_by、created_at）由触发器保护不可变；进程启动时 SweepStale 把
  超时仍非终态的 job 收尾成 FAILED（重启/panic 不留僵尸）。
- **bundle 结构**：每个资源一个文件（文件 key 与工单链路同源：
  `ResourceFileKey` / `InlinePolicyFileKey` / `MembershipFileKey` /
  `AttachmentFileKey`），全部带首次接管 import 块；角色声明信任策略、path、
  permissions_boundary、max_session、tags（ForceNew 属性必须来自库存）；
  membership 与 attachment 是关系文件，只给仍在候选集的主体声明，已有挂载
  工单的主体跳过（防同地址双声明）。
- **冲突三类**：`file-exists`（GitHub contents API 只读检查目标分支，
  GitLab 待 B3）、`already-declared`（已被非 REJECTED 工单声明的资源清单，
  其挂载同样不进基线）、`file-key` / `address` 重复（候选集冲突升级）。
  冲突不阻断预览——预览的职责是把冲突摆到审批人面前。
- **确定性**：文件按 key 排序、成员/策略列表排序、整体内容 sha256。
  同库存两次构建指纹必须一致——这是「审批所见 == 发布所得」的机器可验形式
  （真实账号验证：`8891545e…` 两次一致，296 文件）。
- **API**：`POST /aws/accounts/:id/baseline-jobs`（202 异步，platform_admin）、
  `GET /aws/accounts/:id/baseline-jobs`、`GET /baseline-jobs/:id`（含完整
  文件内容）。前端在维护中心「基线预览」页。
- **已知边界**：AWS List API 返回的 OIDC URL 不带 scheme，构建时补
  `https://`（Terraform `url` 是 ForceNew）；GitLab 发布链路的文件存在性
  检查、以及把 job 执行迁入独立 worker（当前在 API 进程内 goroutine）留到
  B3 一并处理。

## 6. 「声明不了的资源」四类处理

**A. 原理上不可声明** —— service-linked role、AWS 托管策略本体、用户登录凭据/访问密钥、
跨服务资源策略（S3 bucket policy、KMS key policy、SNS topic policy）

- 不生成资源块（不声明 = Terraform 永远不动它们）；
- 但必须留清单：`UNMANAGED.md`（IaC 仓库）或平台侧清单页，写明「为什么不能声明 / 谁负责 / 怎么改」；
- 漂移检测里标「平台不管理」，**不要**当缺失告警。

平台侧清单页已落地（2026-10-27）：`/cleanup` 页 + `GET /aws/accounts/:accountID/cleanup-suggestions`
（platform_admin，只读）。它不是「未纳管清单」的重复，而是它的**收尾部分**——只列
「现在就该消失」的东西，每条给出证据和具体动作：

| 类别 | 命中规则 | 置信度 |
|---|---|---|
| 删声明文件 | 资源判定为 `skipped:aws-lifecycle` 且平台有非 REJECTED 工单（指到工单号/PR/文件名） | high |
| 删 AWS 资源 | 实例配置文件无绑定角色、或绑定角色已不存在 | high |
| 删 AWS 资源 | 同一角色下多个 `eks-<uuid>` 实例配置文件（launch template 判在用） | high / review |
| 删 AWS 资源 | 用户组无成员（无策略=纯空壳 / 有策略=可能预建） | high / review |

置信度只有两档，不确定的不进清单；`rule_gaps` 显式写出无法判定的场景。
`eks-<uuid>` 的归属判定由 `EKSProfileUsageResolver` 完成：EC2 侧枚举全部 launch
template 的 `$Default`/`$Latest` 版本提取 IamInstanceProfile 引用（「在用」的硬证据），
EKS 侧 ListClusters/ListNodegroups/DescribeNodegroup 补「角色被哪些节点组用」。
在用的不上榜；未被引用且角色无节点组的升级 high；角色仍有节点组却无引用的反常情况
保持 review。凭证走与采集一致的 ASSUME_ROLE / CURRENT_CREDENTIALS 两模式。

**「维护中心」导航分组**（2026-10-27）：待清理页挂在左侧「维护中心」分组下，
后续风险扫描等运维页面进同一组。理由：清理、修复是**低频高危**动作，与日常使用的
工单/清单/同步在心智上不是一类操作；混在一起会导致高频操作稀释对危险操作的警觉。
分组仅 platform_admin 可见，与页面权限一致。

**双轴视觉设计**：清单用两个互相独立的维度编码信息，颜色体系刻意不共用——

| 维度 | 回答的问题 | 取值与颜色 |
|---|---|---|
| 类别（category） | 删的是什么、删错的代价是什么 | 删声明文件 = 蓝（平台仓库内操作，`git revert` 可回滚）；删 AWS 资源 = 橙红（线上不可逆操作，爆炸半径大） |
| 置信度（confidence） | 证据是否闭环、现在敢不敢动手 | 可直接执行 = 绿；需确认 = 金 |

两轴必须分开的原因：**删错后的代价类型**（可回滚 vs 不可逆）与**证据的完整程度**
是正交的。`eks-<uuid>` 孤儿是「删 AWS 资源 + 可直接执行」——确实在线上、确实
不可逆，但 launch template 证据已闭环；空组是「删 AWS 资源 + 需确认」——不是不敢
删线上，而是它可能预建待用。若两类信息挤进同一套颜色，页面只剩一种红色信号，
运维反而无法一眼区分「该谨慎的动作」与「该核实的结论」。

**文案国际化三件套**：服务端不感知界面语言，每条 reason / action / evidence 以
`code + params + 原文 text` 下发；前端按 `cleanup.reason.<code>` 等键查语言包，
用 params 填充插值，**键缺失时退回服务端原文**。这样新规则上线不需要等翻译，
翻译也不阻塞数据；代价是文案存在两处定义（服务端兜底 + 语言包），新增 code 时
两边要同步补。

**B. 可声明但采集器没采** —— 见第 4 节，补采集后声明。

**C. 生命周期在 AWS 手里的** —— SSM Quick Setup 角色、EKS 托管节点组的
`eks-<uuid>` 实例配置文件、AWS 自动化代建的 `Amazon*` 角色

- 不进基线，理由与 A 不同：A 是「IAM 不允许声明」，这里是「能声明但维持不住」——
  服务会重写属性、删除节点组时连带删除、重建时换名字；
- 判据全部来自已入库数据（tag + 命名空间 + `eks-<uuid>` 形态），不新增 AWS 权限；
- **不进基线不等于看不见**：库存与风险扫描仍是全量，排除只影响是否写 Terraform；
- 排除规则每轮重算：外部工具下线、tag 清理后资源自动回到候选集。

**D. 被别的系统管的** —— CloudFormation / eksctl / 其他团队的 Terraform

- 接户时声明纳管边界（显式列表 + 前缀通配）；
- 采集/基线按 `managed_by` 过滤：`platform`、`unknown` 生成（**unknown = 默认接管**），
  `external` 跳过并报告；tag 里带 CloudFormation/Quick Setup 签名的按证据跳过并写明来源
  （**eksctl 2026-10-28 起改为纳管**，见第 2 节修订）；
- 因为不做逐条签字，「谁被接管」必须逐条可解释：报告的每一行都要有结论和原因，
  签名排除要能说出是哪个栈、哪个集群；
- 没有归属划分就全量纳管 = 和 CloudFormation 抢同一个角色，两边互相覆盖——
  这类冲突只能靠 apply 后的第二次 plan 发现（见第 9 节）。

运维节奏：未纳管清单随每次接户/账号变更复核；新增「声明不了」的资源时刷新清单，避免过期。

## 7. 工作项拆解与参考工时

按依赖排序（`depends on` 必须先生效）。工时为**单人串行参考值**，不含真实账号试点窗口。

| # | 工作项 | 关键产出 | 依赖 | 参考工时 |
|---|---|---|---|---|
| 1 | 补齐基线采集字段 | role/user path、permissions boundary、instance profile 绑定、user tags、OIDC/SAML provider 的采集 + schema 迁移 + 单测 | — | 3–4 人日 |
| 2 | 账号资源清单与归属处理 | 按 `managed_by` 生成候选集（platform/unknown），`external` 与不可声明资源进「未纳管清单」 | 1 | 2–3 人日 |
| 3 | Terraform 基线预览 | 复用现有生成器输出多文件 bundle + import 块；冲突检测（文件已存在/资源已纳管/地址重复）；确定性输出（同库存同结果） | 1、2 | 4–5 人日 |
| 4 | 账号级多文件 PR 发布 | 复用 `TerraformBundlePublisher.PublishBundle`，单账号单分支单 PR；幂等（重复触发不产生第二个 PR） | 3 | 3–4 人日 |
| 5 | API 与前端 | 预览接口（只读）、未纳管/冲突报告、发布动作（平台管理员）、权限与审计 | 3、4 | 2–3 人日 |
| 6 | 验证与文档 | 单账号试点（plan 只有 import、0 变更）、runbook、未纳管清单模板 | 1–5 | 2–3 人日 |

合计 **16–22 人日**（约 3.5–4.5 周单人；含试点和 plan 审查等待时间另计）。

现有可复用能力：

- 单资源生成器：`internal/adapter/aws_adapter.go`（`GenerateCreate{Terraform}` 系列，含 import 块）；
- 多文件发布接口：`TerraformBundlePublisher.PublishBundle`（[ticket_service.go](../internal/service/ticket_service.go)）；
- 归属标记：`internal/service/iam_ownership_service.go`（`managed_by` = platform / external / unknown，迁移 `0019_iam_resource_ownership`）；
- 库存查询：`iam_principal` / `iam_group` / `iam_policy` / 关系表；
- 单资源纳管的库存快照路径（`GetGroupAdoptionSnapshot` 等），可作为基线取数参考。

## 8. 决策状态

已拍板（2026-10-23）：

1. **归属边界以资源 key 表达**：`role-<name>` / `user-<name>` / `group-<name>` /
   `policy-<name>` / `attachment-<type>-<principal>-<policy>`，与 Terraform 文件 key 同一套
   规则（`resourceFileKey`）。生成器必须保证**同一资源只声明一次**：文件 key 复用同一函数，
   发布前做地址去重校验；冲突（文件已存在/资源已纳管/地址重复）一律报告并跳过，不覆盖。
2. **未纳管清单两处都放**：IaC 仓库 `UNMANAGED.md`（由平台按库存生成，不手写）+
   平台侧资源展示。实现从简：归属/未纳管状态入库为资源属性，列表打标志、可筛选。
3. **差异清单签字人**：平台管理员（资源入库与归属标注本就是管理员职责）。
4. **`unknown` 默认纳入**（2026-10-27）：平台的定位是统一 IAM 管理，未标注不等于
   不接管；排除只基于证据（外部工具 tag 签名）或原理（不可声明）。代价是归属标注
   从「出版条件」降级为「可选的事前声明」，控制改由 apply 后归零校验承担。
5. **基线声明挂载并生成 import 块**（2026-10-27）：基线 bundle 包含挂载关系
   （attachment）声明并生成首次接管 import 块——与 B2 实现一致（membership
   不支持 import，只出声明不出 import 块；已有挂载工单的关系跳过，防同地址
   双声明）。
6. **幂等键 = 账号 + 库存快照 run**（2026-10-27）：同账号同快照 run 判定为
   重复基线，不重复发布；快照更新（新 run）后允许生成新基线。不允许人工
   重跑覆盖旧分支。

仍待拍板：无。

7. **发布分支策略 = 方案 A：一账号一分支一 PR**（2026-10-28 拍板）—— 短生命周期
   分支（从 main 切出、合入 main、apply 只在 main，见 2026-10-28 的 state 同源
   论证）。三个子项：① 同一 run 的多账号可显式聚合成一个 PR（批量选项，非默认）；
   ② 分支保留为配置开关，**默认合并即删**，开启则保留分支作审计痕迹（需配清理
   策略）；③ main 演进时自动 rebase，前提是无冲突且产物可确定性重放——有风险
   时不自动做，报告并建议新 run 重新生成。

已暂缓：

8. **批量纳管自动合并依赖 CI**（2026-10-27 暂缓）：CI 需要很高的权限，
   必须先确保安全的执行环境才能接入；在此之前维持原有设计（人工合并）。

## 9. 验收标准

- 单账号基线 PR 的 `terraform plan`：只有 `import`，0 change / 0 destroy；
  唯一的例外是 `aws_iam_group_membership`（该资源不支持 import，首 apply 必然 add，
  数量与组成员关系行数一致）；
- **apply 后归零校验**：合并并 apply 之后，再跑一次 plan 必须仍是 0 change / 0 destroy。
  这是「有没有人和你共管同一个角色」的唯一可靠发现点——共管时第一次 plan 照样干净，
  冲突在对方下一次 apply 后才出现，表现为我方 plan 想把对方的改动改回去；
- 报告里每个资源都有归属结论（纳管 / external 跳过 / 签名跳过 / 不可声明），
  且签名跳过必须带来源（栈名/集群名），无「沉默遗漏」；
- 重复触发同一账号不产生第二个 PR；
- 基线 PR 合并后，该账号任意一个资源走正常工单时不再生成 import 块（已在 state 中）；
- 审计记录能还原：谁触发、基于哪次库存快照、纳管了哪些资源、跳过了哪些及原因。

## 10. 实现收官与首账号试点（2026-10-28）

首个账号 **111122223333**（ap-southeast-1）完成全链路接户：基线 PR 合并、
`terraform apply` 成功。最终 plan：

```
Plan: 283 to import, 19 to add, 0 to change, 0 to destroy.
```

19 个 add 全部是 `aws_iam_group_membership`（provider 限制不可 import，符合第 9 节
的唯一例外）。**2026-11-03 补**：apply 后第二次 plan 已跑，结果为 `No changes`，
第 9 节的归零验收闭合。

### 10.1 发布链路（B3）落地形态

- **发布台账**：`iam_baseline_publication`（迁移 0027）。幂等键 =
  账号 + 库存快照 run；`Create` 幂等命中返回既有记录，不开新分支。
- **发布分支**：一账号一分支一 PR（`baseline/<account>/<run>`），合并即删
  （`keep_branch=false`）。
- **归属感知门禁**（解决「PR 合并后基线文件已在 main，重新发布自锁」）：
  对每个待发布文件做本地 git blob SHA 比对，三分类——
  1. 内容相同 → 跳过（257/294 文件走了这条）；
  2. 内容不同但在本账号既往 PUBLISHED 台账的 files 清单里 → 作为基线拥有者更新；
  3. 内容不同且不在清单 → 拒绝发布（防止覆盖别的系统管理的文件）。
  全部文件无变化时直接 PUBLISHED 不开 PR。
- **batch 发布**：`POST /aws/baseline-publications/batch`，多账号可聚合单 PR
  （D7 选项），部分失败不影响其余。

### 10.2 试点过程中发现并修复的缺陷

| 缺陷 | 根因 | 修复 |
|---|---|---|
| plan 显示 8 destroy | `aws_iam_policy.description` 是 ForceNew，采集漏写 = plan 判定清空 = 替换重建 | 采集改取 `GetPolicy`（**`ListPolicies` 不返回 Description**，这是 AWS API 的坑） |
| 同步 upsert 报 NOT NULL 违反 | AWS 侧 description 为 NULL 撞 `0026` 约束 | upsert 用 `COALESCE($4,'')` |
| tags 被清空 | 同类 ForceNew 问题（`aws_iam_openid_connect_provider.tags` 等） | policy/user/group/oidc 全部采集并声明 tags（group 无 tagging，AWS 没有 ListGroupTags API） |
| OIDC 带 tags 的文件静默丢失 | 生成器把含 `tags =` 前缀的整段声明当 value 传给属性拼装，产出 `tags = tags = {...}`，HCL 校验失败 | 改用 `terraformTagsExpression`（纯表达式），加回归测试 |
| 重新发布自锁 | 旧门禁「文件已存在即拒绝」 | 归属感知门禁（10.1） |

**教训**：ForceNew 属性漏写不会在生成时报错，只会让 plan 悄悄把资源标记为重建；
生成器的 HCL 校验是最后防线，任何生成失败必须显式进 issues，不允许静默吞掉。

### 10.3 纳管范围明细（以 111122223333 / run 29 为例）

库存总量（`iam_principal`/`iam_policy` 等表）与纳管结果：

| 资源类型 | 库存 | 纳管 | 排除与理由 |
|---|---|---|---|
| Role | 81 | 57 | 24 个 service-linked（`/aws-service-role/`、`AWSServiceRoleFor*`）不可声明 |
| User | 59 | 59 | — |
| Group | 23 | 21 | 2 个已 declared（SRETeam、iam-readonly 有在册工单，防双声明） |
| Customer managed policy | 16 | 16 | — |
| Inline policy | 71 | 55 | 已 declared 的 16 个随主体跳过 |
| 策略挂载（attachment） | 175 | 159 | 已 declared 主体的挂载随主体跳过 |
| Group membership | 68 行 | 68 | membership 不支持 import，首次 apply 以 add 落地 |
| Instance profile | 11 | 11 | — |
| OIDC provider | 5 | 5 | — |
| SAML provider | 1 | 1 | — |

*排除明细随每次预览重算，以预览报告为准；上表为收官时点快照。*

**默认纳管**（unknown 一律接管，2026-10-27 决策 + 2026-10-28 eksctl 修订后）：

- 全部客户自建 role/user/group/customer managed policy/inline policy 及其挂载关系；
- OIDC/SAML provider（含 tags——`url`、`client_id_list` 是 ForceNew，必须原样声明）；
- instance profile（含与角色的绑定关系）；
- **eksctl 创建的资源**（集群 OIDC provider、addon 角色、节点组角色）——只在集群
  创建期写一次，之后不重写。

**eksctl 纳管的已知风险与运营约定**（2026-10-28，推广阶段判定「短时间内还会用
eksctl 操作集群」后拍板保留纳管）：

- **风险**：Terraform 接管后 eksctl 并不知道。有人直接重跑 eksctl 改 IAM
  （重跑 addon、升级改信任策略、更新 eksctl-version tag）时，基线 plan 会把改动
  改回去，形成乒乓漂移；`eksctl delete cluster` 删掉的资源会让 state 报
  「实体已不存在」。
- **为什么不回滚到排除**：排除策略已实际造成过破坏（main 残留无 tags 声明的文件，
  plan 清掉 eksctl 集群标记）；且 PR #40 发布的 6 个 eksctl 资源回滚后会变成
  孤儿文件，需要发布支持「删除文件」才收拾得干净。
- **运营约定（推广阶段）**：
  1. eksctl 操作集群视为一次 IAM 变更源——操作完成后**触发账号同步 + 基线发布**，
     让基线收敛 eksctl 的改动（归属感知门禁支持「基线拥有者更新」， eksctl 的
     改动会以正常 diff 进 PR），而不是放任两边各改各的；
  2. 推广材料与接户授权里写明：**纳管后 IAM 变更一律走基线/工单**，eksctl 只用于
     建集群初次拉起，之后的调整进基线；
  3. 集群退役顺序：先 `eksctl delete cluster` → 同步后基线 plan 会显示资源消失 →
     按报告清理 state（`state rm`）与声明文件；
  4. 出现乒乓漂移（同一资源反复互改）视为共管冲突信号，按第 9 节归零校验的处置：
     要么把该集群资源标回 `managed_by=external`（下一轮基线让出），要么停用
     eksctl 直改。

**默认排除**（每条都有可复核证据，报告中带来源）：

| 排除类别 | 判据 | 理由 |
|---|---|---|
| service-linked role | path `/aws-service-role/` 或名字 `AWSServiceRoleFor*` | AWS 自建自管，声明等于和 AWS 抢所有权 |
| AWS 托管策略本体 | ARN `arn:aws:iam::aws:policy/*` | 不属于账号，只能挂载引用 |
| SSM Quick Setup 角色 | 名字 `AWS-QuickSetup-*` 或 tag `QuickSetupManagerArn`/`QuickSetupDocument` | 重跑配置管理会重写权限 |
| EKS 节点组实例配置文件 | 名字 `eks-<uuid>` 形态 | 节点组重建换 UUID 名、删除时连带删除 |
| AWS 自动化代建角色 | tag `Created By: AWS ...` + `Amazon*` 保留前缀 | 重跑自动化会重写属性 |
| CloudFormation 管理资源 | tag `aws:cloudformation:stack-name` | 栈更新会改回去，报告写明栈名 |
| 已 declared 资源 | 有非 REJECTED 工单声明过 | 防同地址双声明 |
| 归属 external | `managed_by=external` | 标注为其他系统管理 |

刻意**不排除**的：CloudTrail 在 `/service-role/` 下代建的角色、WorkSpaces
`workspaces_DefaultRole`、EKS Pod Identity `AmazonEKSPodIdentity*Role`——AWS 创建
但名字稳定、创建后归客户所有，正是基线该接管的对象。

### 10.4 试点 PR 链

| PR | 内容 | 说明 |
|---|---|---|
| #37 | 初版全量 292 文件 | 首次发布，暴露 description/tags 采集缺口 |
| #38 | 37 文件：policy description/tags、user tags 补充 | 归属感知门禁首次实战（257 unchanged 跳过） |
| #39 | 1 文件：OIDC C473 +tags | 生成器 bug 修复后 |
| #40 | 7 文件：OIDC C16D +eksctl tags、6 个 eksctl addon 角色/挂载 | eksctl 纳管决策落地 |

全部已合并。发布分支随合并删除，无残留。

### 10.5 尾项完成（2026-10-28，30c7db8 + 3b62445 + 22521c5）

原三项尾项已全部落地：

- **GitLab 发布链路**：`GitLabSDKPublisher` 实现 `PublishBranch`（建分支 / 逐文件
  幂等提交 / 复用开放 MR）、`TerraformFileMeta`（GitLab `blob_id` 与 git blob SHA
  同算法，归属感知门禁直接可用）与 `DeleteBranch`；`PUBLISHER=gitlab` 即启用完整
  发布面，无需改装配。
- **预览 job 迁独立 worker**：API 只落 PENDING 行并入 asynq 队列（`baseline` 队列，
  与采集 `sync` 队列隔离背压），sync-worker 消费构建；入队失败 job 直接落 FAILED，
  不留永久 PENDING。发布（publication）执行仍在 API 进程（低频写远端操作）。
- **PR 合并感知**：sync-worker 周期（5 分钟）轮询 PUBLISHED 台账的远端 PR
  （githost 中立接口，GitHub/GitLab 共用）：MERGED → 台账记 `MERGED` 并按
  `keep_branch` 删除远端分支；CLOSED（未合并被拒）→ 记 `CLOSED` 留审计；
  删分支失败不阻塞状态流转。迁移 0028 扩充状态枚举。
  实战验证：4 条 PUBLISHED 台账一个周期内全部翻 `MERGED`，4 个远端分支清理完成。

唯一保留的人工动作：归零校验（apply 后第二次 plan）目前靠人工执行，可考虑平台化留痕。

### 10.6 回归修复与组成员变更工单（2026-10-29）

回归测试发现并修复三类问题，随后补齐缺失的组成员变更功能：

**归属判定与 import 消费（aaf839c + 53ae8f3 + 8fb362d + 43dc80e）**：

- `BaselineOwnsAttachmentFile` 与台账 files 清单做精确匹配时漏了 `.tf` 后缀，
  基线纳管的挂载解绑仍误报「野生挂载」——修为 `elem->>'file' = $2 || '.tf'`；
- 归属感知门禁的既往发布清单只认 `PUBLISHED`，MERGED（已合并进 main）的基线
  文件再更新会被误判「not owned by baseline」——修为 `PUBLISHED ∪ MERGED`
  （CLOSED 未落 main，保持排除）；
- 挂载工单撞已纳管挂载报 500——新增 `AttachmentConflictError`（409
  ATTACHMENT_CONFLICT），文案引导直接发解绑工单；
- 基线纳管文件的已消费 import 块残留在更新预览里（apply 后残留 import 会让
  plan 报 "Resource already managed"）——`PatchRoleAttributes` 与策略 patch
  路径统一剔除 `to` 指向本资源类型的 import 块及其注释头（item-23 同款约定）。

**组成员变更工单 UPDATE_GROUP_MEMBERSHIP（0fc7605）**：

- 语义：`update_membership = {group_name, operation: add|remove, users}`，
  原地改写 `group-<group>-membership.tf` 的 users 列表（资源 label/name/group
  字节不动，地址永不漂移）；文件缺失时按清单全量生成（`aws_iam_group_membership`
  不支持 import，首次 apply 以声明采纳现状——所以必须生成完整列表而非增量）；
  移除最后一名成员 → 注释空文件 → plan 销毁 membership 资源；
- 校验：组/用户须在清单、add 拒绝已是成员、remove 拒绝非成员、同组并发锁
  （一次只允许一个进行中的成员变更工单）；快照支持 ROLLBACK 恢复变更前成员；
- 乒乓防护：基线 bundle 生成跳过有进行中成员变更工单的组（与挂载同款）；
- 前端：新建工单页新增「组成员变更」页签（选组 + 加/移 + 多选用户），i18n 齐。

### 10.7 试点深化：组挂载纳管闭环与台账审计（2026-10-29 下午）

试点账号的解绑回归暴露出「组挂载从未被纳管」的链路缺口，顺带完善了发布
台账的审计语义。

**① 基线数据源补齐：组挂载（0e9f041，本日最重要修复）**

- 根因：`loadAttachmentsByPrincipal` 只查 `iam_principal_policy`（User/Role），
  **组挂载存在 `iam_group_policy`，从未被读入基线**——`attachment-group-*.tf`
  从第一天起就不可能生成，组挂载天然无法纳管，解绑只能走「先挂载后解绑」
  两步。此前修的 ABANDONED 工单抑制（见下）只是叠加因素。
- 修复：bundle 加载器与候选报告统一 UNION 组分支，显式限定
  `policy_type='managed'`（内联策略无 ARN，由 inline-policy 文件纳管，
  双保险防双声明）；进行中解绑工单的乒乓抑制条件补 principal_type 比较
  （此前只比名字和 ARN，组与同名用户会互误）。
- 已核实：ABANDONED（CLOSED + closure_reason=ABANDONED）挂载工单是 API
  探测、从未发布过任何东西，不再抑制基线纳管；抑制只认 MERGED /
  CLOSED+APPLIED / 在途工单。

**② 发布台账的重发语义与审计（2361140，迁移 0029）**

- 台账行以（账号，快照 run）为唯一键，**一行 = 一次快照的全部发布历史**：
  同 run 重发（MERGED/CLOSED 后补增量文件、FAILED 重试）原地刷新该行，
  不开新行；新行只由新 run 或新账号产生。
- 重发不再无声覆盖旧 PR：被替代 PR（编号/URL/终态/发布时间）先归档进行内
  `superseded` JSONB（迁移 0029），台账 API 与基线页详情抽屉展示「历史 PR」卡。
  归属门禁、纳管检测读的是**最新一次发布的 files**，不受历史影响。
- 合并感知（5 分钟轮询）对 GitHub/GitLab 的读请求带传输层重试：一次网络
  抖动不再浪费整轮对账周期（当日实测 EOF 连发曾造成 17 分钟的状态延迟）。

**③ 已纳管检测的统一约定（7d47d28 + 385696c）**

- 「导入既有资源」与「UPDATE_ROLE 零变更」共用同一判定基座
  `roleFirstTimeAdoption` / `rejectIfAlreadyAdopted`：源工单 → 已应用工单 →
  main 文件探测三层，**fail-closed**（GitHub 异常时拒绝放行而非冒险双声明）。
- 注释空文件 = 资源已销毁，不算已纳管（允许重新导入）——与解绑落注释文件
  的约定闭环：销毁后可重新纳管，销毁前重复导入被拒。
- 双层检测：台账 `BaselineOwnsResourceFile`（PUBLISHED ∪ MERGED）覆盖 +
  main 同名非空文件探测（早期工单/手工发布兜底）。

**④ GitHub 瞬态故障的容错口径（201119f + c1e4dda）**

- 试点网络到 GitHub 的 contents API 丢包率实测可达 ~50%（EOF/000）。
  口径：**读路径重试、404 不重试**（404 是「文件不在 main」的有效答案）；
  `FetchTerraformFile` 5 次退避（~4s，成功率 ~97%），githost GET 3 次。
- 解绑校验的源工单分支须在抓文件前回填 `request.AWSAccountID`
  （shape 校验阶段未回填——同款坑在 adopt 检测也出现过）。

**试点当前状态**：PR #43（6 条组挂载声明）已合并，apply 后组挂载入 state；
gitlab-only 等组的解绑可直接走基线文件改写路径，两步纳管降级为兜底手段。

## 11. 运行前置与导航归属（2026-11-02）

**依赖方向是单向的：同步 → 基线，反向不成立。**

- **同步不依赖基线**：`aws_sync_run_service` 不引用任何基线概念——同步是纯
  AWS 库存采集（API 拉取 → 落库存表），随时可以直接跑，账号没有任何基线
  发布也不报错（2026-11-02 v1.0.0 清库重部署实测：`aws_baseline_publication`
  为空时全量同步照样 SUCCEEDED）。
- **基线依赖同步**：发布基线要求该账号**至少有一次成功的库存同步 run**
  （`ErrBaselineNoSyncRun`），因为幂等键 = 账号 + 库存快照 run（见 §8.6），
  没有快照就无法确定幂等键。基线预览/发布读取的也是同步采集的库存表。

因此标准操作顺序为：**先同步 → 再发起基线预览 → 再发布基线**。

**导航归属**：基线管理与同步是同一条数据链路，前端菜单从「维护中心」
迁到「同步管理」分组下作为子项（`同步管理 → 同步账号 / 基线管理`）；
「维护中心」只保留低频高危动作（待清理、后续风险扫描）。基线子项仅
platform_admin 可见，与原「维护中心」的可见性一致。

## 12. CI 自动 apply 与平台同步（A1/A12，2026-11-03）

**是否接入 CI 由使用方决定（2026-11-03 拍板）**。平台不强制、不内置 CI：
不接回调时沿用下面的默认流程；接入回调后，关单时机与失败留痕才改变。

**当前默认流程（无 CI 阶段的临时缓解，保持不变）**：gitstatus 轮询检测到
基线 PR 合并 → 自动关单 APPLIED → 触发一次清单同步，固定延迟 5 分钟
（给人工 apply 留落地窗口）。该路径完全不知道「apply 是否真的成功」。

**CI 接入后的目标流程（A1 全量方案，本期只铺管道）**：

1. CI 在 merge 后执行 `terraform apply`；
2. CI 按结果写 commit status `finops/terraform-apply`（success/failure，
   绑定合并后 commit SHA）——**由 CI 直写，平台不代写**；
3. CI **回调平台**通知结果，平台立即反应：
   `POST /api/v1/tickets/:no/apply-result`（platform_admin）。

**回调契约**：

| 字段 | 说明 |
| --- | --- |
| `status` | `succeeded` \| `failed`（必填，其余值 400） |
| `commit_sha` | 实际 apply 的 commit（通常是 PR 合并 commit），可空 |
| `ci_url` | pipeline/job 链接，便于排障，可空 |
| `note` | 自由文本，succeeded 时作为关单备注，可空 |

语义：
- `succeeded` → 以 CI 身份关单 `APPLIED` 并**立即**触发该账号清单同步
  （复用人工关单的 `TriggerSyncForManuallyClosedTicket`：delay=0、在途
  同步去重、同步停用仅记日志）——取代 5 分钟延迟；
- `failed` → **不关单**，仅记 warn 日志供值班处理（工单留开放态，待
  后续加显式失败标记）；
- 已关单工单重复回调幂等 200（CI 重试 / 与合并自动关单竞态都安全）。

**认证**：为 CI runner 签发专用 platform token（platform_admin 角色），
`docker exec finops-api /app/platform-token -user-id admin -name ci-runner`。

**切换条件**：CI 侧在 apply job 成功/失败后各加一次 curl 即可接入；接入后
平台行为自动切换（先回调先赢，合并自动关单路径保留兜底）。上线 CI 前需
完成 G3 的安全前置（隔离 runner、最小权限凭据、审计）。
