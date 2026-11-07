# Phase 4：漂移检测（Drift）设计

状态：**已实施**（P1–P4 于 2026-11-04 全部落地，文档按实现回写）。
日期：2026-11-03。
范围：平台侧语义漂移检测 + 文件级发布互斥 + CI plan 上报。不含平台内运行 terraform（Phase 3，暂缓）。

---

## 0. 背景与问题陈述

当前流程「生成基线 → 检测到变化 → 发起变更」把**检测**绑定在**开基线 PR** 这个动作上，检测器实际是 MR 审批人，检测频率等于人工操作频率。经代码核对，存在以下结构性问题：

| # | 问题 | 代码依据 |
|---|---|---|
| 1 | **检测范围随工单增加而收缩**：资源只要开过工单就退出基线再生成视野；越常用的资源越不在 diff 里 | `declaredResources`（baseline_candidate_service.go:519）、挂载跳过（baseline_bundle_service.go:393） |
| 2 | **判定口径过宽**：`status <> 'REJECTED'` 把 DRAFT（尚未提交）、PUBLISH_FAILED、未合并 CLOSED 都算成「已声明」，这些工单没有产生任何文件，资源变成「谁都没声明」且不出现在任何清单 | baseline_candidate_service.go:527 |
| 3 | **属性变化结构性看不见**：`diffIAMAssets` 只按 ARN 判存在性；`CurrentIAMAsset.Attached` 采了未入 diff；策略文档、信任策略、tags、path、boundary 全都比不了——而控制台手改策略文档恰是最常见事故 | aws_collector_service.go diffIAMAssets |
| 4 | **无零变更心跳**：无法区分「没漂移 / 没跑过 / 跑挂了」 | baseline_publish_service.go finishUnchanged |
| 5 | **合并 ≠ 生效**：无 CI 回调时 merge 自动关单写 APPLIED 是乐观假设 | gitstatus_worker.go:466 autoCloseTicket |
| 6 | **冲突整账号失败**：一个非归属文件导致整个发布 FAILED，表现为「发布失败」而非「这里有漂移」 | baseline_publish_service.go:346-351（ErrBaselineFilesExistInRepo） |
| 7 | **字节级比较被误用**：blob SHA 判「变化」正确用途是发布去重（代码↔代码），不能当漂移判定（声明↔AWS） | baseline_publish_service.go:336 |
| 8 | **无时间维度、无告警出口**：漂移被下次发布覆盖后不留痕；平台只有日志和 UI | — |
| 9 | UNMANAGED.md 在 README/CONTRIBUTING 中被声明但**无生成器**（文档超前） | 全仓库无 writer |

核心结论：**把「检测」和「收敛」拆开**。PR 保留为变更载体；检测变成只读、可定时（跟随同步）、覆盖全部已声明资源的独立动作。

---

## 1. 设计原则

1. **基准 = 声明快照（declared intent）**，不是「上次库存」（那是变更日志，会把自己 apply 的变更也算进去）。声明快照在发布基线时落库，发布工单时同步纳入。
2. **平台只读 AWS，不持有 state**。真正的 terraform plan 由客户 CI 执行并上报结果（source='ci'）；平台自查用语义比对（source='inventory'）。
3. **检测不写 AWS、不需要新权限面**。比对在库内完成（声明快照表 vs 库存表），挂在同步结束点，边际成本≈0，不需要调度器。
4. **收敛必须人工点**，且提供双路：追认（重发基线）与回滚（UPDATE_* 工单）。
5. **互斥精确到文件**，不用账号级单写者；多工单并发是正常需求。

---

## 2. 数据模型（迁移 0031–0035）

表结构以 `migrations/*.up.sql` 为**唯一事实来源**，本文只记录「为什么这么设计」：

| 迁移 | 对象 | 关键约束与用途 |
| --- | --- | --- |
| `0031_publish_reservation` | `publish_reservation` | 文件级发布预约（互斥锁）。唯一索引 `(account_id, file_key) WHERE status='OPEN'` + `ON CONFLICT DO NOTHING` 兜并发抢锁；约束是「RELEASED ⇔ released_at 非空」——MERGED 同样是未释放，写成「OPEN ⇔ released_at 为空」会在首次合并时违约 |
| `0032_iam_baseline_declaration` | `iam_baseline_declaration` | 声明快照。`(account_id, resource_key) WHERE superseded_at IS NULL` 保证一资源一条当前声明，历史行保留供追责；`content_blob_sha` 是声明时该文件的 git blob SHA，供 `baseline_stale` 核对；`declared_at` 表示「声明何时落库」 |
| `0033_iam_baseline_declaration_consistency` | 同上 | 一致性维护：`superseded_reason`（`REPLACED` 可恢复 / `VOIDED` 撤销，NULL↔未退场由 CHECK 成对约束）+ `stale_at` / `stale_reason`；历史行回填 `REPLACED` |
| `0034_iam_drift_finding` | `iam_drift_finding` + `aws_account_config` 心跳列 | 发现台账。部分唯一索引 `WHERE resolved_at IS NULL`；状态只有 `SUSPECT / OPEN / PENDING / PENDING_REBASELINE / IGNORED`——**不设 RESOLVED**，已解决由 `resolved_at` 表达；`file_key` 供新鲜度分组与收敛双路定位文件 |
| `0035_iam_baseline_publication_apply` | `iam_baseline_publication` | apply 回执：`applied_at / applied_commit_sha / applied_ci_url`，首次写入生效（`COALESCE` 幂等），重复回调不覆盖 |

> 为什么不贴 DDL：贴了就有两份事实，迁移改了文档不会跟着改。上一版本这里贴的
> DDL 已经与实现分叉（状态枚举多了 `RESOLVED`、声明表缺 `content_blob_sha`、
> 漂移表缺 `file_key`、迁移编号错位），2026-11-04 复核后改为摘要。

要点：

- `file_key` 是声明↔工单的天然关联键，两边用同一 `resourceFileKey()` 推导，不再造映射。
- 预约表发布前把本次要写的**文件集合**原子预约（`INSERT ... ON CONFLICT DO NOTHING`）；check-then-write 竞态由唯一索引兜住。
- 零差异**不写行**，只更新 `last_drift_clean_at`；同资源恢复一致 → 置 `resolved_at`（自动恢复）。

---

## 3. 判定流水线（六层过滤，按顺序短路）

| # | 层 | 规则 |
|---|---|---|
| 1 | **覆盖域** | 只判「有 MERGED 且已落声明」的账号与资源；无基线 → 页面显式写「未纳管，不检测」+ 未纳管清单入口，不假装干净 |
| 2 | **归一化** | path 补 `/`、tags 排序、策略文档用 `comparePolicyDocuments`（ticket_service.go:3518）语义比较、ARN partition 归并。接受「数组重排即变更」的假阳性 → 漂移记录允许 LOW 级差异 |
| 3 | **工单豁免** | 同一 `file_key` 在声明之后有成功工单（MERGED ∪ CLOSED+APPLIED）→ 记 `PENDING_REBASELINE`（不是漂移，是基线该更新了）。**工单不豁免自己**：`declaration.ticket_id == activity.ticket_id` 时不打这个标签——否则工单自有文件上的真实改动会被永久标成「基线该更新」，而 0027 又禁止对这类文件重发基线。**子资源分支同规则**：undeclared_extra 的判定取父声明的声明时间与工单（`drift_engine.go` 子资源循环） |
| 4 | **在途门禁** | 文件被在途预约（OPEN/MERGED reservation）占用 → 本轮跳过。**跳过数必须可见**：`DriftEvaluation.skipped_files` 随心跳写进 `aws_account_config.last_drift_skipped_files`（迁移 `0036`，2026-11-05），Drift 页按账号渲染「上轮跳过 N 个文件」——只在检测响应里返回等于刷新即消失，页面又会回到「0 条发现＝干净」的误读（台账 C13） |
| 5 | **稳定窗口** | 首次出现记 `SUSPECT`，连续两轮同步仍在 → 升 `OPEN`（避开 IAM 最终一致性与 apply 后同步抖动）；无 CI 回调的账号，merge 后 24h 内的差异记 `PENDING`（apply 未确认），超窗仍存在则**当轮即升 `OPEN`**——既存发现已有一轮 `PENDING` 作证据，不再重复稳定窗口。实现：`DriftPendingWindow = 24h`，判据用 `iam_ticket.updated_at`（merge 时刻的代理） |
| 6 | **去重与自动恢复** | 按唯一索引 upsert；`last_seen_at`/`occurrences` 递增；恢复一致即关闭 |

另外：检测时用 `TerraformFileMeta`（github_publisher.go:336，只读 GET）把声明快照与 **main 现文件 blob** 核对一次——不一致（有人在 main 手改 tf，或后续 PR 改了它）报 `baseline_stale` 而非漂移，提示「基准过期，请重发基线」。

**心跳必须能看出「没检测」（2026-11-05 补，台账 C7）**：判定频率等于同步频率，同步停摆时页面依然是 0 条发现。Drift 页对「已纳管但从未检测」与「上次检测超过 48h」分别渲染显式告警，并把「上轮跳过 N 个文件 / N 个文件基准过期」并列展示——三者共同回答「这个 0 是怎么来的」。

## 4. 竞态与门禁（拍板记录）

### 4.1 文件级发布预约（替代账号级互斥）

| 并存场景 | 规则 |
|---|---|
| 工单 A × 工单 B（不同资源） | **并存 ✓** |
| 工单 A × 工单 B（同资源） | 后者被拒，错误指明「被工单 X / PR Y 占用」 |
| 基线 × 工单 | 基线只被**文件相交**的在途工单挡住：相交文件进 `deferred`（PR 描述列出原因），其余照发。无全账号冻结 |
| 基线 × 基线（同账号） | 拒——现有 (账号, sync_run) 幂等键已保证 |

**锁点 = 发布动作**（工单 PUBLISHING 入口 / 基线 publication 创建），**审批不锁**（人工决策不被机器挡）。

### 4.2 释放规则（拍板：工单无 TTL，异常人工干预）

| 触发 | 动作 |
|---|---|
| REJECTED / CLOSED（未合并）/ PUBLISH_FAILED | 直接 RELEASED（SweepStale 顺带回收僵尸 PUBLISHING） |
| MERGED | 转 `MERGED`，**不立即释放**：等 apply 确认（apply-result 回调）或下一次同步消化后释放；期间基线对该文件继续 deferred |
| 长期挂死 | 影响面被文件级锁死——只挡自己那几个文件。提供**管理员手动释放**入口（audited）。无 TTL 是安全的：文件级下无 TTL 只冻一个文件 |
| 紧急旁路 | ROLLBACK、凭据泄露类紧急工单越过预约强制发布，强制审计事件 |

### 4.3 精确作废（旧快照回退新变更——第二道防线）

发布前检查 `publication.sync_run_id` 之后出现的工单，状态集 **`APPLIED ∪ MERGED ∪ PUBLISHING`**，**凡与本次发布文件有交集才作废/跳过**（拍板：精确判定，不做全账号作废）。注意这抓不住「基线 merge 后、apply 前，T1 merge 落入窗口」的时序——该窗口靠预约表的 MERGED 态 + CI 前置 plan 兜底。

### 4.4 在途工单 × 基线全量的两个时序

- **时序 A（基线先 apply，T1 后批准）**：T1 发布遇基线持有的文件 → **工单接管**（归属 baseline→ticket；工单是日常变更通道），不拒绝。
- **时序 B（T1 merge 落入基线 merge→apply 窗口）**：基线 t0 快照会把 T1 成果回退。兜底：① 预约表 MERGED 态使基线 apply 前可见；② CI apply 前置 plan 会显示回退 diff（部署文档 §10.5 写明「基线 apply 前确认无新合并工单」）；③ 中期把 apply-result 端点扩展接受 `publication_id`（基线也有 applied 未确认态）。

### 4.5 已实现（P1，2026-11-04）

| 层 | 实现 |
|---|---|
| 表 | `0031_publish_reservation`：`(account_id, file_key)` + 部分唯一索引 `WHERE status='OPEN'`，`ON CONFLICT DO NOTHING` 兜并发 |
| 服务 | `PublishReservationService`：`ReserveForTicket`（all-or-nothing）/ `ReserveForPublication`（部分让路）/ `Release` / `MarkMerged` / `ReleaseMergedForAccount` / `SweepBaselineExpired` / `ReleaseExpiredForAdmin` / `List` |
| 工单 | `publishApprovedTicket` 发布前预约；冲突整单 PUBLISH_FAILED（可重试，错误带占用者）；发布失败自动释放；关单/拒绝/废弃释放；PR 合并转 MERGED |
| 基线 | `Run` 与 `RunBatch`（聚合模式）都走预约：冲突文件 deferred，不进归属清单，PR 描述与台账 issues 可见；全部让路不开空 PR，记 PUBLISHED + `file_count=0` |
| 释放 | 同步成功后释放该账号 MERGED 预约（失败同步不释放）；基线 OPEN 预约 72h TTL；工单无 TTL |
| API | `GET /api/v1/publish-reservations`（默认只列 OPEN+MERGED）、`POST /api/v1/publish-reservations/release`（platform_admin，body `{channel, ref}`），请求日志已由审计中间件覆盖 |

### 4.6 声明快照：基线侧（P2a，2026-11-04）

| 层 | 实现 |
|---|---|
| 表 | `0032_iam_baseline_declaration`：`(account_id, resource_key)` 部分唯一索引 `WHERE superseded_at IS NULL`，旧声明打 `superseded_at` 保留追溯 |
| 生成 | `BaselineBundleService.Build` 在生成每个文件的同时产出 `Declarations`（同源：属性取自喂给生成器的同一组值，`roleDetail.config()` 里「留空不声明」的字段声明里也不写） |
| 资源 key | `role:foo` / `policy:bar` / `attachment:role:foo:arn:...` / `membership:group:g` / `<ownerKind>:<owner>:inline:<policy>`（内联策略策略名只在主体内唯一，必须带主体） |
| 落库 | `BaselineDeclarationService.RecordDeclarations`：只记本次真正写进仓库的文件（deferred 排除），带 `content_blob_sha`（git blob SHA，供 `baseline_stale` 核对）；失败只告警不阻断发布 |
| 路径 | `Run` 成功、`RunBatch` 聚合成功、`finishUnchanged`（无变化，2026-11-05 补，台账 C9）三处都记；`finishFullyDeferred` 不记（本轮什么都没声明） |

### 4.7 声明快照：工单侧（P2b，2026-11-04）

**做法：从发布内容反解，不写逐类型 request → 属性映射。**

原计划（本文档上一版）是给 20+ 种工单类型各写一份映射。实际动手时否掉了，原因三条：

1. **更新类是块级 patch**：`UPDATE_ROLE` / `UPDATE_MANAGED_POLICY` / 内联策略更新只改用户动过的属性，完整声明必须拿 main 现文件合并才知道；请求里没有的字段只能靠猜。
2. **一个文件多条声明**：`CREATE_ROLE` 的一个文件里可能有角色、内联策略（`<role>-policy`）和若干挂载；`CREATE_USER/GROUP` 还会附带成员文件。按类型写死映射，每种类型都要复刻一遍生成器的组合逻辑。
3. **生成器才是唯一事实**：基线与工单共用同一组 `adapter` 生成器，内容里写的才是「到底声明了什么」。反解一次覆盖全部类型，新工单类型不需要在这里加代码。

| 层 | 实现 |
|---|---|
| 反解器 | `ExtractDeclarations(files, labels)`：`hclsyntax` 解析 → 资源块 → 归一化属性；`jsonencode/jsondecode/merge` 用 cty 纯函数求值（文件自包含，不需要 Terraform 运行时） |
| 覆盖类型 | `aws_iam_role` / `user` / `group` / `policy` / `*_policy`（内联）/ `*_policy_attachment` / `group_membership` / `instance_profile` / `openid_connect_provider` / `saml_provider` |
| 主体身份 | 引用（`aws_iam_role.role_foo.id`）与字面量（`role = "app-server"`）两种写法都认：label 被净化过（大小写/符号丢失），不能当名称用；跨文件引用由批内索引 + 请求提示兜底 |
| 形状一致性 | 属性名沿用 P2a 词汇（`trust_policy` / `document` / `members` / `principal_kind` …），并有测试拿基线 bundle 的声明与反解结果逐条比对（`TestExtractDeclarationsMatchesBaselineBundle`）——两套来源永不走偏 |
| 写入时机 | 工单发布成功后（PR 一开，声明即确定，与基线侧同口径）；带 `ticket_id` 与文件 blob SHA |
| 作废 | ① 废弃关单（PR 关闭未合并）→ `VoidForTicket` 撤回该工单的当前声明；② **零声明发布**（回滚清空、移除最后一名成员）→ 按 `TouchedFiles` 作废该文件旧声明，不插入 |
| 作用范围 | `Save` 的作废从「账号级」改为「文件级 + 资源级」：基线与工单共享一张表，账号级作废会让一次基线发布抹掉所有工单声明 |
| 覆盖缺口 | 解析失败 / 主体引用解析不到 → 记 `DeclarationGap`（日志 + 不进 `TouchedFiles`），不写半条错声明；P3 的 Drift 页必须展示缺口，不能宣称「全账号已覆盖」 |

**已知限制**：

- P2b 之前发布的历史工单没有声明：这些文件要等下一次基线重发或该工单文件被再次发布才进入覆盖。
- 反解只认纯函数表达式；手写在 main 上的 `local.*` / 变量引用求值不到，对应属性按「未声明」处理（少比对，不误报）。

### 4.8 声明一致性：作废恢复与新鲜度（P2c，2026-11-04）

P2a/P2b 解决了「声明怎么来」，P2c 解决「声明什么时候不算数」。三条规则，对应三种让基准不可信的情况：

| 场景 | 处理 | 为什么不能只做一半 |
|---|---|---|
| 基线 PR 关闭未合并（发布被拒） | `VoidForPublication`：作废这次发布落下的当前声明 | 与工单废弃同一件事——这次发布从未进 main。不撤，漂移检测拿一份幽灵意图当基准，把线上正确的资源全报成被改坏 |
| 作废后该资源原本有声明 | 恢复「被它取代的上一条有效声明」（`superseded_reason='REPLACED'`，优先同文件、按退场时间倒序取最近一条） | 只作废不恢复 = 制造覆盖空洞：资源有实态、无基准，看起来像从未纳管。main 上本来还是上一版内容，恢复才是事实 |
| 有人绕过平台改 main 上的 tf | 新鲜度核对：比对声明记的 `content_blob_sha` 与 main 现文件，写 `stale_at` / `stale_reason` | 不核对就把「手改 tf」报成漂移，天天误报之后所有人学会忽略告警 |

实现要点：

| 层 | 实现 |
|---|---|
| 迁移 | `0033`：`superseded_reason`（REPLACED 可恢复 / VOIDED 撤销，NULL↔未退场由 CHECK 约束成对）+ `stale_at` + `stale_reason`；历史行回填 REPLACED |
| 作废 | 事务内 `SELECT ... FOR UPDATE` 查出本次发布/工单的当前声明 → 逐行标 VOIDED → 逐条恢复上一条 REPLACED。恢复只认 REPLACED：VOIDED 的历史行本身也是一次没落地的发布，恢复它等于复活幽灵基准 |
| 新鲜度 | `ReconcileFreshness(ctx, accountID, repoDirectory, reader)`：按 `(file_key, content_blob_sha)` 分组 → `TerraformFileMeta` 读 main 的 blob SHA（只读元信息，不下载内容）→ 结论写回。原因分 `FILE_MISSING` / `CONTENT_CHANGED` / `NO_CONTENT_HASH` |
| 只在状态翻转时写 | 周期性核对绝大多数轮次什么都不变；反复刷 `stale_at` 会让页面上「过期多久」失真 |
| 读不到就保持原状 | 远端报错只计「未核对」（`verified=false`），绝不标记过期：一次网络抖动不能静默关掉漂移检测 |
| 路径同源 | `BaselineRepoDirectory(terraformPath, awsAccountID)` = `<terraformPath>/account-<id>`，与发布器写文件、bundle 存在性检查同一个公式 |
| 运维面 | `GET /api/v1/baseline-declarations?account_id=`（声明 + 按文件汇总 + 过期计数）、`POST /api/v1/baseline-declarations/refresh`（手动触发核对；未配发布器时 409，不返回「全部新鲜」的假报告）。均限 platform_admin |

**为什么新鲜度不做成常驻定时循环**：核对成本是「账号数 × 文件数」次远端调用，而它只在判定前才有意义。P3 判定器在每次同步结束点按账号调用一次，成本与同步频率同阶（每日量级）；做成 5 分钟循环反而会对几十个账号的上百个文件持续打 API。

**仍待人工**：工单的 PR 被关闭未合并不自动关单，工单停在 APPROVED/PUBLISHING，它的声明与预约都跟着工单走——需要运维废弃关单才会作废。这是 §4.2「工单无 TTL、异常人工干预」的既定口径，不是遗漏。

### 4.9 漂移判定与页面（P3，2026-11-04）

| 层 | 实现 |
|---|---|
| 表 | `0034_iam_drift_finding`：`(account_id, source, COALESCE(resource_key,''), COALESCE(resource_address,''))` 部分唯一索引 `WHERE resolved_at IS NULL`；`fields` 存字段级差异 `[{field, declared, live}]`，判定当时的证据随发现存档 |
| 状态 | `SUSPECT` / `OPEN` / `PENDING` / `PENDING_REBASELINE` / `IGNORED`，**解决不设状态**：`resolved_at` 非空即已解决。两套事实（状态列 + 时间列）必然有一天互相矛盾，只留时间列 |
| 判定器 | `DriftService.EvaluateAccount`：读声明 → 读库存快照（一次加载，判定期间不重复查询）→ 在途预约 → 工单活动 → 纯函数 `buildDriftCandidates` 产出候选 → upsert/自动关闭 → 心跳 |
| 覆盖域 | 只判有声明的资源；**`undeclared_extra` 只对「父资源已声明」的子资源**（挂载 / 成员 / 内联策略）报，否则一个没建过基线的账号会瞬间刷出几百条噪音 |
| 归一化 | 只比对**声明里写了的字段**（生成器没写 = Terraform 不管）；path 斜杠、tags 顺序/类型、策略文档键序与数组顺序、数字 Go 类型全部折叠。真差异一律报（宁可误报，不可漏报） |
| 工单豁免 | 用 `publish_reservation(channel='ticket', ref=ticket_no, file_key)` 把「工单 ↔ 文件」关联起来：声明之后该文件又有成功工单（MERGED ∪ CLOSED+APPLIED）→ `PENDING_REBASELINE`；工单 MERGED 但 `git_apply_result` 未成功 → `PENDING` |
| 稳定窗口 | 首轮 `SUSPECT`，第二轮仍在才升 `OPEN`（`occurrences >= 2`）；`IGNORED` 不被下一轮翻回，只有恢复一致才自动关闭 |
| 自动恢复 | 本轮没再看到的未解决发现 → `resolved_at=NOW(), resolved_by='auto'` |
| 心跳 | `aws_account_config.last_drift_check_at` / `last_drift_clean_at`：`last_drift_clean_at` 只在干净时前移，回答「上次全绿是什么时候」 |
| 触发 | `AWSSyncRunService.HandleAWSAccountSyncTask` 在 `runs.Finish` 成功后按账号跑一次；判定失败只记日志，绝不把同步报成失败（库存已经可信，重跑采集代价高且无益） |
| API | `GET /api/v1/drift-findings`（account_id/status/severity/change_type/include_resolved/page）、`GET /summary`（账号覆盖 + 计数 + 心跳）、`GET /:id`、`POST /:id/{ignore,reopen,resolve}`、`POST /check`（body `{account_id}`）。读对所有登录角色开放，写限 platform_admin |
| 页面 | `/drift`：账号卡片（声明数 / 未解决 / 基准过期 / 上次检测，0 声明显式标「未纳管，不检测」）+ 筛选 + 发现列表（行展开看字段级 declared vs live）+ 处置按钮；Dashboard 增加「未解决漂移」计数 |

**刻意不做**：

- 没有常驻定时循环：库存不变时重复判定只会得到同样结论，判定挂在同步结束点就够。
- `last_drift_clean_at` 不做趋势/时长统计：这一期只回答「上次全绿是什么时候」。
- `file_conflict`（§6 场景 B）升级为独立发现已完成（P4，见 §4.11）：发布因归属冲突失败时写 `source=publish` 的发现，成功发布自动关闭。

**P4 已完成（2026-11-04）**：CI plan 上报、webhook、apply-result 接受 `publication_id`，见 §4.11。

### 4.10 收敛双路入口（P3 尾，2026-11-04）

| 项 | 实现 |
|---|---|
| 接口 | `POST /api/v1/drift-findings/:id/remediate`，body `{route: acknowledge｜rollback}`，`platform_admin` |
| 追认 | 复用基线发布：`BaselinePublishService.Create` 落台账 + handler spawn `Run`（与发布页同一条路径、同一个幂等键）；`already_published=true` 时不重复跑 |
| 回滚 | `BuildDriftRollbackTicket` 把 `declaration.attributes` 翻成 `CreateIAMTicketRequest`，经 `TicketService.CreateDraft` 落**草稿**；返回 `ticket_no`，前端跳转工单详情 |
| 回填范围 | 只回填 `finding.fields` 里出现过的字段。声明里其他属性本来就一致，一起写进去只会放大 diff |
| 映射 | `role` → `UPDATE_ROLE`（description / max_session_duration / trust_policy / tags）；`policy` → `UPDATE_MANAGED_POLICY`（ARN 由账号 + 声明 path + name 还原）；`inline-policy` → `UPDATE_GROUP_INLINE_POLICY`（属主 Group/Role，用户内联无对应类型） |
| 归属分流 | `declaration.ticket_id` 非空 = 工单声明 → 只给回滚（0027 更新门禁会拒基线重发）；否则两路都给；无声明快照（子资源发现）只给追认 |
| 拒绝而非造假 | `declared_missing` / `undeclared_extra` / `baseline_stale` / `file_conflict` 没有「改回旧值」的工单语义，返回 `reason` 由页面按解释展示；path / 权限边界这类无更新通道的字段同样拒绝 |
| 审批 | 审批人由账号绑定解析（`AUTO` 只决定审批人集合，不是免审批）；草稿仍需人提交才进审批流。解析不出来（账号没绑其他审批人）时连同「角色不在库存」「已有在途工单」一起返回 `reason`，让运维先补前置条件 |
| 降级 | 未配置 git 发布器时 handler 不装配收敛面，接口回 `501`，不让页面以为「点一下就能重发」 |

**仍不做**：不替人提交草稿（审批是唯一的人工闸门）；不做「批量回滚」（一次一条，避免把一次误点放大成几十张工单）。

### 4.11 CI plan 上报 / webhook / 已应用确认（P4，2026-11-04）

全仓只有一张发现表，`source` 是唯一的区分。三条写入路径各自回答一个不同的问题：

| 来源 | 谁在说 | 说什么 | 语义 |
|---|---|---|---|
| `inventory` | 平台自查（同步结束点） | 声明 vs 库存逐字段比对 | 追加/替换，六层过滤 + 两轮稳定窗口 |
| `ci` | 客户 CI（plan-only） | `terraform plan -detailed-exitcode` 的结果 | **替换**：本轮没报 = plan 没差异 = 已恢复；空上报即干净 |
| `publish` | 平台发布器 | 归属门禁拒绝覆盖某文件 | 发布失败即记录，该账号任一次发布成功即关闭 |

**CI 上报**：`POST /api/v1/aws/drift-reports`（`platform_admin`，用 CI runner 专用 platform token）

```json
{
  "account_id": "123456789012",
  "commit_sha": "…", "ci_url": "…",
  "findings": [
    {"resource_address": "aws_iam_role.foo", "resource_key": "role:foo",
     "kind": "role", "file_key": "role-foo", "change_type": "attribute",
     "severity": "HIGH", "summary": "…",
     "fields": [{"field": "trust_policy", "declared": "…", "live": "…"}]}
  ]
}
```

- 每条至少要 `resource_key` 或 `resource_address`（后者兜底成 `address:<地址>`），缺标识直接 400——写进一条谁也定位不了的发现比报错糟。
- 允许的 `change_type`：`attribute` / `declared_missing` / `undeclared_extra` / `file_conflict`；`baseline_stale` 是平台侧的新鲜度结论，CI 报不了。
- **不做稳定窗口**：plan 已经对着真实 state 跑过，不存在「apply 后库存还没同步」的抖动，首轮即 `OPEN`。人工忽略仍不被翻回，只有 plan 恢复干净才自动关闭。
- 心跳与 inventory 共用：`last_drift_check_at` 前移，`last_drift_clean_at` 只在账号整体无未解决发现时前移。
- 账号未纳管返回 404（不是「记下来了但没人看」）。
- `summary` 可省略：省略时平台按 `change_type` 自己生成措辞，并带语义码
  `summary_code` + `summary_params`，界面按当前语言渲染（台账 C16）；CI 自己给了
  summary 就原样保留——那是外部系统的文本，翻译它只会丢信息。

**webhook**：`DRIFT_WEBHOOK_URL` 配置即用，新发现/升级时一条 JSON POST（`event` / `occurred_at` / `total` / `truncated` / `findings`）。

- 异步、10s 超时、**不重试**：告警丢了比把同步拖垮划算，发现本身在库里。
- 一次最多 50 条，超出置 `truncated=true` 并带 `total`——判定可能一次冒出上百条，不能把接收方打爆。
- 事件：`drift.detected`（inventory 判定）、`drift.ci_report`（CI 上报）、`drift.publish_conflict`（发布冲突）。

**已应用确认**（迁移 `0035`，`iam_baseline_publication.applied_at / applied_commit_sha / applied_ci_url`）：

- `POST /api/v1/aws/baseline-publications/:id/apply-result`：基线没有工单号，必须能按 publication 回报。`succeeded` → 首次写入生效（幂等），`failed` → 只记日志不动状态（合并这个事实没变）。
- `POST /api/v1/tickets/:no/apply-result` 增加可选 `publication_id`：一次 main 提交可能同时应用了工单 PR 与基线 PR。归属校验发生在**关单之前**——先关单再发现「应用的是别的账号」是最难收拾的顺序。
- 只有 `PUBLISHED` / `MERGED` 的发布可以标记已应用；`PUBLISHING` 还没开完 PR，`FAILED` 没有可应用的东西。

**发布前差异预览**（2026-11-05 补，台账 C10）：

- `GET /api/v1/aws/accounts/:accountID/baseline-preview` → `{files, unchanged, to_publish, conflicts}`。构建 bundle 并与 main 逐文件比对（`Build` 顺带填好 `ExistsInRepo`/`RepoBlobSHA`），**只读**：不落台账、不占预约。
- 分类逻辑与 `Run`/`RunBatch` 共用同一个 `classifyBaselineFiles`——预览自己抄一遍判定，迟早会与真实发布走偏，而它存在的全部意义就是说真话。
- 不含在途预约的让路结果（预约是发布时才写的），所以「to_publish」是上界；页面不能承诺「一定会推 N 个」。
- 没有成功同步时与发布同因返回 **409**，绝不返回「0 个待发布」。

**发布冲突发现：已在测试机真实验证（2026-11-05，台账 C11）**：

- 做法：让 bundle 多出一个 main 里没有的文件键（测试机在库存里补一条组挂载），并在 main 同一路径提交一个内容不同的**纯注释**探针文件——归属门禁看到的是「有人占了我要写的文件」，与生产里手工/别的工具写入同一目录完全同型。
- 结果：发布 `FAILED`，`error` 为 `…1 file(s) not owned by baseline: attachment-group-sreteam-deny_access_without_mfa.tf`；`iam_drift_finding` 落一条 `source=publish` / `change_type=file_conflict` / `resource_key=file:<key>` / `severity=MEDIUM` / `status=OPEN`，`summary` 带完整原因，`baseline_publication_id` 指向本次台账。列表接口与汇总的 `open` 计数都能看到它。
- 重复冲突不刷屏：同一文件再发一次仍是**同一行**（唯一键 `account+source+resource_key`），只 `occurrences` +1、`last_seen_at` 前移。
- 关闭：删掉探针与库存夹具后发布成功（无变化路径），发现被自动置 `resolved_at`、`resolved_by=auto`，从开放列表消失，`include_resolved=true` 仍可审计。
- 验证方法上的坑：发布幂等键是「账号 + 快照 run」，同 run 已有 `PUBLISHED` 台账时 `Create` 直接返回旧记录、**不重建 bundle**。所以库存侧的临时变更必须先有一次新的成功同步（本次是新跑一次真实同步生成 run 4），否则改了库存也发不出去。

**仍不做**：平台内跑 terraform；CloudTrail 归因；webhook 重试队列。

## 5. 声明口径（拍板）

**只认成功工单**：

| 工单状态 | 算已声明 | 理由 |
|---|---|---|
| MERGED | ✓ | 文件进了 main |
| CLOSED 且 closure_reason='APPLIED' | ✓ | 自动关单后的终态 |
| DRAFT / APPROVING / APPROVED / PUBLISHING | ✗ | 未产生 main 文件；基线发布时作为 deferred 让路（显式化，不是丢失） |
| PUBLISH_FAILED / REJECTED / CLOSED(未合并) | ✗ | 发布没成功 |

口径收窄后，「被草稿/失败工单误摘」的资源会回到基线候选（一次性影响，已拍板接受）。工单更新的数据新鲜度现状已满足：`UPDATE_*` 是 `FetchTerraformFile` 读 main 现文件做块级 patch。整文件重写类工单（`ROLLBACK`）的归属检查**已落地（2026-11-05，台账 C6）**：

- **文件键只能由目标工单推导**：`target_file_key` 是服务端字段，请求体里带进来的一律忽略（`validateRequestShape` 清空），`buildCreateRollbackBundle` 再比对一次目标工单自己的 `resourceFileKey()`，不一致直接 400。此前客户端传什么就清空什么——填一个基线文件键就能把别人的声明删掉。
- **清空前校验声明归属**：回滚**主文件**被整份清空（只留注释头）时，必须满足「该文件当前生效声明归被回滚的工单」。基线发布声明的文件拒绝（提示先收回基线或走漂移处置），被另一张工单接管的文件也拒绝。membership 这类副作用文件不参与判断：基线维护的成员关系里清掉最后一名成员，是回滚本身必须做的事（实测拦下来会让这类回滚永远做不了）。
- **没有声明快照时放行**：P2 之前的存量文件没有声明行，一律拒绝会让历史回滚全部失败；这类文件只能靠人工 review。取舍写在 `rejectEmptyingForeignDeclarations` 的注释里。

上面的检查只保证「清空时不误删别人的文件」，还有另一半：**清空的是不是该清的文件**。多文件工单（批量纳管，每个策略一份文件）以前没有可映射的单文件，落到兜底分支按工单号生成注释空文件——PR 合并、plan 零变更、工单却标记已回滚（台账 C14）。现按目标类型收口（2026-11-05）：`RollbackSupportedTargetType` 只放行能反向映射到自己写过文件的类型，其余在校验层 400 并给出替代路径；`buildRollbackTerraform` 的兜底只保留「按工单号命名的存量 CREATE_* 声明」这一种合法历史形态。

## 6. 「基线没有对应 PR」的五场景

工单永远有 PR（发布即开），「无 PR」只在基线侧：

| 场景 | 处理 |
|---|---|
| A. 无变更发布（finishUnchanged） | **合法声明，直接当基准**：main 上本来就有这些文件，0027 台账记 files，声明同样落库（2026-11-05 补，台账 C9）。早先不落声明，会让「首次全量发布恰好无变化」的账号 publication=PUBLISHED 而 declarations=0，被判「未纳管」整账号跳过检测 |
| B. 发布失败（含 ErrBaselineFilesExistInRepo） | 不进基准，沿用上一条 MERGED 的声明；**冲突文件升级为独立发现**（`change_type='file_conflict'`，source='publish'）——「这个文件被别人占了」本身是需要人看的事，现在被埋在 error 字符串里 |
| C. PR 开了但被关闭未合并 | 声明作废：状态迁移钩子把该 publication 的归属/预约标记回「无主」，防幽灵归属 |
| D. MERGED 但未 apply | 见 §3 第 5 层：merge 后 24h 内记 `PENDING`；超窗仍未确认 → **当轮即升 `OPEN`**（`DriftPendingWindow`，既存发现已有一轮 PENDING 作证据）。**不能无限期停在 PENDING**：无 CI 回调的账号会因此永久漏报 |
| E. 账号从未发基线 | 检测范围=空，页面写「未纳管，不检测」+ 未纳管清单入口 |

## 7. 收敛双路（都必须人工点）

| 路 | 动作 | 语义 |
|---|---|---|
| **接受现状（追认）** | 重发基线 → 既有 B3 流程，0027 更新门禁已支持 | 把当前状态写成代码，**不是回滚**；文案必须写清；因涉及批量追认，二次确认 |
| **回滚到声明** | 用 declaration.attributes 里的旧值预填 UPDATE_* 工单（按 kind 路由），走正常审批 → 发布 → apply | 真正的收敛；快照落库使请求体可直接填好 |

按归属分流：`owner=baseline` → 两路都给；`owner=ticket` → **只能**开 UPDATE_* 工单（重发基线改不动它，0027 门禁会拒）。

## 8. 出口与调度

- **UI**：Drift 页（账号、未解决/已解决、SUSPECT/OPEN/PENDING 分级、severity 置顶）+ Dashboard 未解决计数 + 账号卡片「上次检测/上次干净」（心跳）。页面必须写明「本页不包含未纳管资源」。
- **webhook**：一条 JSON POST（事件、账号、资源、diff、链接），`DRIFT_WEBHOOK_URL` 配置即用。不接邮件/Slack。
- **调度**：平台侧无调度器（跟随同步触发，SaveAccountIAM 之后）；CI 侧 6h plan-only workflow（`terraform plan -detailed-exitcode`：0→clean、2→drift、1→error，上报 `POST /api/v1/aws/drift-reports`，CI 专用 token）。
- **不做**：平台内跑 terraform（需隔离 runner + state 只读凭证，与 G3 同前置，暂缓）；CloudTrail 归因（配置重、覆盖不全）。

## 9. 实施计划

| 阶段 | 内容 | 依赖 |
|---|---|---|
| **P0** | already-declared 口径收窄（MERGED ∪ CLOSED+APPLIED）；README/CONTRIBUTING 的 UNMANAGED.md 说法改为「清单页标记，仓库侧待实现」 | 无 |
| **P1** | `0031 publish_reservation` 文件级预约 + 工单/基线/批量发布接线 + 关单/合并/同步释放钩子 + 基线 deferred + 基线预约 TTL + 预约表 API（列表 + 管理员手动释放）（**已完成，2026-11-04**） | P0 |
| **P2** | `0032 iam_baseline_declaration` 声明快照落库 + `baseline_stale` 核对 + 精确作废（文件相交）。**P2a（基线侧声明落库）2026-11-04 已完成**；**P2b（工单侧声明：从发布内容反解 + 废弃作废 + 文件级作废范围）2026-11-04 已完成**；**P2c（`0033` 作废恢复 + 基线 PR 关闭作废 + 新鲜度核对 + 声明的运维面 API）2026-11-04 已完成** | P1 |
| **P3** | `0034 iam_drift_finding` + `0034` 心跳列 + 判定器挂同步结束点 + Drift API/页 + Dashboard 计数；收敛双路入口（§4.10）（**已完成，2026-11-04**） | P2 |
| **P4** | CI plan-only 上报端点 + 通用 webhook + 部署文档 §10 workflow 片段 + apply-result 扩展 publication_id + 发布冲突升级为发现（§4.11）（**已完成，2026-11-04**） | P3 |

## 10. 决策日志

| 决策 | 结论 | 日期 |
|---|---|---|
| 基准口径 | 声明快照（资源级属性 JSON），范围 = baseline ∪ ticket | 2026-11-03 |
| 声明口径 | 只认成功工单：MERGED ∪ (CLOSED, APPLIED) | 2026-11-03 |
| 工单声明来源 | 从发布内容反解（不写逐类型 request→属性映射）：patch 类工单只有内容里有完整声明，生成器是唯一事实 | 2026-11-04 |
| 声明作废范围 | 文件级 + 资源级，不做账号级：基线与工单共享声明表 | 2026-11-04 |
| 零声明发布 | 按 `TouchedFiles` 作废该文件旧声明（回滚清空/移除最后一名成员），不是「什么都没发生」 | 2026-11-04 |
| 作废 ≠ 删除 | 作废行标 VOIDED 保留审计；同时恢复被它取代的上一条 REPLACED 声明，不留覆盖空洞 | 2026-11-04 |
| 基线 PR 关闭 | 与工单废弃同口径：`VoidForPublication` 撤回本次发布的声明 | 2026-11-04 |
| 基准过期 | 声明 blob SHA ≠ main 现文件 → 标 `baseline_stale` 并跳过比对（差异不是漂移）；远端读不到时不改状态 | 2026-11-04 |
| 陈旧作废 | 文件相交精确判定（APPLIED ∪ MERGED ∪ PUBLISHING），不做账号级 | 2026-11-03 |
| 互斥粒度 | 文件级发布预约（publish_reservation），账号级互斥取消 | 2026-11-03 |
| 锁点 | 发布动作；审批不锁 | 2026-11-03 |
| TTL | 工单侧无 TTL，异常管理员手动释放 + 审计 | 2026-11-03 |
| 紧急旁路 | ROLLBACK/凭据类越过互斥，强制审计 | 2026-11-03 |
| 无 PR 场景 | §6 五场景表 | 2026-11-03 |
| 生效判定 | 无 CI 回调账号 merge 后 24h 差异记 PENDING；超窗回落到 SUSPECT→OPEN（2026-11-04 落实为 `DriftPendingWindow`，此前只有文字承诺、无代码） | 2026-11-03 |
| file_conflict | 升级为独立发现（source='publish'） | 2026-11-03 |
| 收敛 | 双路（追认/回滚）人工确认，按归属分流 | 2026-11-03 |
| Phase 3（平台跑 plan） | 暂缓，等隔离 runner + 最小权限 | 2026-11-03 |
| 发现状态模型 | 只保留处理中状态；已解决由 `resolved_at` 表达，不设 RESOLVED 状态 | 2026-11-04 |
| 未声明多余的范围 | 只对父资源已声明的子资源（挂载/成员/内联策略）报，未纳管主体留给清单页 | 2026-11-04 |
| 判定触发 | 同步成功后按账号一次；不做常驻循环，失败不反噬同步 | 2026-11-04 |
| 工单豁免的关联键 | `publish_reservation(channel='ticket', ref=ticket_no, file_key)`，不新增工单-文件映射表 | 2026-11-04 |
