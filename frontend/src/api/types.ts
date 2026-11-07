// 后端 DTO 镜像（与 internal/model、internal/service 的 json tag 对齐）

export interface Ticket {
  id: number;
  ticket_no?: string;
  ticket_type?: string;
  account_id?: number;
  principal_name?: string;
  request_policy?: unknown;
  approval_mode: string;
  approver_ids: string[];
  terraform_code?: string;
  git_pr_url?: string;
  git_provider?: string;
  git_repository?: string;
  remote_request_number?: string;
  git_commit_sha?: string;
  poll_attempt_count: number;
  // Git 侧观察状态（轮询 worker 与 CI apply 回调都会写）。
  // git_apply_result=FAILED 表示「PR 已合并但 terraform 没应用成功」。
  git_merge_state?: string;
  git_ci_state?: string;
  git_apply_result?: string;
  next_poll_at?: string;
  last_status_poll_at?: string;
  closed_at?: string;
  closed_by?: string;
  closure_reason?: string;
  closure_comment?: string;
  status?: string;
  submitter?: string;
  created_at: string;
  updated_at: string;
}

export interface TicketListResponse {
  tickets: Ticket[];
  total: number;
  limit: number;
  offset: number;
}

export interface TicketApprovalEntry {
  approver_id: string;
  display_name: string;
  result?: string;
  comment?: string;
  created_at: string;
}

export interface TicketApprovalInfo {
  ticket_no: string;
  approval_mode: string;
  status: string;
  approvals: TicketApprovalEntry[];
}

export interface ExecutionRecord {
  id: number;
  ticket_no: string;
  provider: string;
  repository: string;
  remote_request_number?: string;
  remote_url?: string;
  commit_sha?: string;
  merge_state: string;
  ci_state: string;
  apply_result: string;
  attempt: number;
  observed_at: string;
}

export interface PlatformUser {
  user_id: string;
  display_name: string;
  email?: string;
  is_active: boolean;
  roles?: string[];
  created_at?: string;
  updated_at?: string;
}

// 令牌元数据（不含明文；明文只在签发时返回一次）
export interface PlatformTokenInfo {
  id: number;
  user_id: string;
  name: string;
  prefix: string;
  expires_at?: string;
  revoked_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface IssuedPlatformToken {
  id: number;
  user_id: string;
  name: string;
  prefix: string;
  token: string;
  expires_at?: string;
}

/** 平台用户一键开通到云：逐账号结果（失败内联，不中断整批）。 */
export interface PlatformProvisionResult {
  account_id: number;
  ticket_no?: string;
  /** 非空表示该账号存在同名 IAM 用户冲突（当前仅 "user_exists"）。 */
  conflict?: string;
  error?: string;
}

export type AuthMode = "development" | "api-token";

export interface AuthConfig {
  mode: AuthMode;
}

export interface AuthUser {
  user_id: string;
  roles: string[];
}

export interface AWSAccountRef {
  id: number;
  aws_account_id: string;
  account_name?: string;
  read_only_role_arn?: string;
  /** false = 未接入平台配置或已停用同步，不应作为开通/建单目标 */
  sync_enabled: boolean;
}

export interface AWSAccountConfig {
  id: number;
  aws_account_id: string;
  aws_account_db_id: number;
  display_name: string;
  read_only_role_arn?: string;
  sync_mode: string;
  sync_enabled: boolean;
  tags: Record<string, unknown>;
  sync_status: string;
  last_sync_attempt_at?: string;
  last_successful_sync_at?: string;
  created_at: string;
  updated_at: string;
}

/**
 * 创建/更新账号接入配置的载荷。
 * 安全约定：平台不存储任何目标账号密钥——凭证只来自收集者自身身份
 * （CURRENT_CREDENTIALS）或跨账只读角色（ASSUME_ROLE）。
 */
export interface AWSAccountConfigInput {
  aws_account_id: string;
  display_name: string;
  sync_mode: "CURRENT_CREDENTIALS" | "ASSUME_ROLE";
  read_only_role_arn?: string;
  sync_enabled: boolean;
  tags?: Record<string, unknown>;
}

/** 连通性测试结果（STS GetCallerIdentity 回显）。 */
export interface AWSAccountConnectionIdentity {
  AccountID?: string;
  ARN?: string;
}

/** 单个账号的审批人绑定（aws_account_approver，AUTO 审批解析依据）。 */
export interface AccountApproverBinding {
  account_id: number;
  user_id: string;
  display_name: string;
  email?: string;
  is_active: boolean;
  roles: string[];
  created_at: string;
}

/** 有资格当审批人的平台用户（active platform_admin / approval_admin）。 */
export interface AccountApproverCandidate {
  user_id: string;
  display_name: string;
  email?: string;
  /** 是否已绑定到目标账号。 */
  bound: boolean;
}

/** 用户仍是审批人的账号（停用/降级警告用，A9③乙）。 */
export interface ApproverAccountSummary {
  account_db_id: number;
  account_no: string;
  account_name?: string;
  bound_at: string;
}

export interface AWSSyncRun {
  id: number;
  aws_account_config_id: number;
  aws_account_id: string;
  trigger_source: string;
  triggered_by: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  last_error?: string;
  has_changes: boolean;
  created_at: string;
  updated_at: string;
}

/** 同步 worker 存活状态（心跳 + 队列积压）。 */
export interface AWSSyncWorkerStatus {
  online: boolean;
  last_heartbeat?: string;
  pending_runs: number;
}

export interface PrincipalSummary {
  id: number;
  account_db_id: number;
  aws_account_id: string;
  principal_type: string;
  principal_name: string;
  arn: string;
  last_seen_at?: string;
  updated_at: string;
  managed_by?: string;
  /** 生命周期在 AWS 手里（service-linked / QuickSetup / AWS 自动化创建）：只展示，不可工单修改。 */
  aws_lifecycle?: boolean;
}

export interface AttachedPolicy {
  policy_id: number;
  policy_name?: string;
  policy_type?: string;
  policy_arn?: string;
}

// 托管策略清单条目（GET /aws/policies）
export interface ManagedPolicySummary {
  id: number;
  policy_name: string;
  policy_arn?: string;
  policy_type?: string;
  managed_by?: string;
  /** AWS 托管策略（arn:aws:iam::aws:policy/）：只读引用，不可编辑。 */
  aws_managed?: boolean;
}

// 内联策略清单条目（GET /aws/inline-policies）：内联策略自身无 ARN，
// 账号归属来自所属主体；aws_managed 跟随主体的 AWS 归属判定。
export interface InlinePolicySummary {
  policy_id: number;
  account_db_id: number;
  aws_account_id: string;
  policy_name: string;
  owner_kind: "role" | "user" | "group";
  owner_name: string;
  owner_arn: string;
  aws_managed: boolean;
  last_seen_at?: string;
}

// 内联策略详情（GET /aws/inline-policies/:policyID）：带当前文档。
export interface InlinePolicyDetail extends InlinePolicySummary {
  policy_document?: unknown;
}

// 实例配置文件清单条目（GET /aws/instance-profiles）：没有对应工单类型，
// 一律只读；eks_managed 标记托管节点组自建的 eks-<uuid> 配置文件。
export interface InstanceProfileSummary {
  id: number;
  account_db_id: number;
  aws_account_id: string;
  instance_profile_name: string;
  arn: string;
  path: string;
  role_arn?: string;
  role_name: string;
  eks_managed: boolean;
  last_seen_at?: string;
}

// 实例配置文件详情（GET /aws/instance-profiles/:profileID）：带标签。
export interface InstanceProfileDetail extends InstanceProfileSummary {
  tags?: Record<string, string>;
}

// 托管策略详情（GET /aws/policies/:policyID）：带当前文档用于编辑器预填，
// 以及引用计数（挂载主体/组数量）作为变更风险提示。
export interface ManagedPolicyDetail extends ManagedPolicySummary {
  policy_document?: unknown;
  attached_principals: number;
  attached_groups: number;
  group_references: number;
}

export interface GroupRef {
  id: number;
  group_name: string;
  arn: string;
}

export interface PrincipalDetail extends PrincipalSummary {
  description?: string;
  trust_policy?: unknown;
  tags?: Record<string, string>;
  policies: AttachedPolicy[];
  groups: GroupRef[];
}

export interface GroupSummary {
  id: number;
  account_db_id: number;
  aws_account_id: string;
  group_name: string;
  arn: string;
  path: string;
  member_count: number;
  updated_at: string;
  managed_by?: string;
}

/**
 * 纳管归属标记：platform=平台纳管（Terraform 声明它），external=别的系统管，
 * unknown=未标注（等管理员拍板）。
 */
export type OwnershipMark = "platform" | "external" | "unknown";

/** 一条资源的归属标记（GET /aws/ownership）。 */
export interface ResourceOwnership {
  key: string;
  kind: string;
  name: string;
  managed_by: string;
  account_db_id: number;
}

export interface PrincipalRef {
  id: number;
  principal_name: string;
  arn: string;
}

export interface GroupDetail extends GroupSummary {
  members: PrincipalRef[];
  policies: AttachedPolicy[];
}

export interface AuditEventView {
  id: number;
  request_id?: string;
  actor_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  outcome: string;
  http_status?: number;
  metadata: Record<string, unknown>;
  occurred_at: string;
}

export interface DashboardSummary {
  tickets: { total: number; by_status: Record<string, number> };
  risks: { open: number; open_by_level: Record<string, number> };
  inventory: { users: number; roles: number; groups: number };
  sync: {
    configs_total: number;
    configs_enabled: number;
    by_sync_status: Record<string, number>;
    runs_last_24h_by_status: Record<string, number>;
  };
  drift?: {
    unresolved: number;
    by_status: Record<string, number>;
    by_severity: Record<string, number>;
  };
  generated_at: string;
}

/** 漂移判定：声明快照与线上实态的差异（phase4-drift-design.md §3）。 */
export type DriftChangeType =
  | "attribute"
  | "declared_missing"
  | "undeclared_extra"
  | "file_conflict"
  | "baseline_stale";

export type DriftStatus = "SUSPECT" | "OPEN" | "PENDING" | "PENDING_REBASELINE" | "IGNORED";

export type DriftSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** 一个字段的「本该是什么 / 实际是什么」，判定当时的证据随发现存档。 */
export interface DriftFieldDiff {
  field: string;
  declared: unknown;
  live: unknown;
}

export interface DriftFinding {
  id: number;
  account_db_id: number;
  aws_account_id: string;
  source: "inventory" | "ci" | "publish";
  resource_key?: string;
  resource_address?: string;
  kind?: string;
  file_key?: string;
  change_type: DriftChangeType;
  fields: DriftFieldDiff[];
  severity: DriftSeverity;
  status: DriftStatus;
  baseline_publication_id?: number;
  summary?: string;
  /** 摘要的语义码：前端按界面语言渲染；summary 是服务端原文兜底（C16）。 */
  summary_code?: string;
  /** 摘要插值参数：resource / child / file / fields。 */
  summary_params?: Record<string, string>;
  first_seen_at: string;
  last_seen_at: string;
  occurrences: number;
  resolved_at?: string;
  resolved_by?: string;
}

export interface DriftFindingPage {
  items: DriftFinding[];
  total: number;
  page: number;
  page_size: number;
}

/** 账号维度：声明覆盖 + 心跳。0 条发现和「从未检测」必须能区分。 */
export interface DriftAccountSummary {
  account_id: number;
  aws_account_id: string;
  display_name: string;
  declarations: number;
  stale_declarations: number;
  open: number;
  suspect: number;
  pending: number;
  pending_rebaseline: number;
  last_check_at?: string;
  last_clean_at?: string;
  /** 上一轮判定因在途变更被跳过的文件数（>0 时页面必须提示，C13）。 */
  last_skipped_files: number;
  /** 上一轮判定中基准已过期（与 main 不一致）的文件数。 */
  last_stale_files: number;
}

export interface DriftEvaluation {
  account_id: number;
  aws_account_id: string;
  unmanaged: boolean;
  declarations: number;
  stale_files: number;
  skipped_files: number;
  surfaced: number;
  promoted: number;
  resolved: number;
  pending: number;
  open_findings: number;
  checked_at: string;
}

/** 收敛双路：追认 = 重发基线（把现状写成代码），回滚 = 建 UPDATE_* 草稿。 */
export type DriftRemediationRoute = "acknowledge" | "rollback";

export interface DriftRemediation {
  finding_id: number;
  route: DriftRemediationRoute;
  owner: "baseline" | "ticket";
  allowed_routes: DriftRemediationRoute[];
  ticket_type?: string;
  ticket_no?: string;
  publication?: BaselinePublication;
  already_published?: boolean;
  /** 该账号已有同快照的发布在跑：返回既有台账，不会再驱动一次。 */
  in_flight?: boolean;
  /** 非空表示这条路当前走不通：是能力边界，页面按解释展示而不是报错。 */
  reason?: string;
}

export interface ValidationCheck {
  code: string;
  result: string;
  description: string;
}

export interface ValidationSnapshot {
  baseline_id?: number;
  request_sha256: string;
  checks: ValidationCheck[];
  terraform_preview?: string;
}

// 新建工单请求（CreateIAMTicketRequest）
export interface CreateTicketRequest {
  ticket_type: string;
  account_id: number;
  principal_name?: string;
  request_policy?: unknown;
  abstract_policy?: AbstractPolicy;
  role?: { name: string; [key: string]: unknown };
  create_managed_policy?: CreateManagedPolicyConfig; // CREATE_MANAGED_POLICY
  create_user?: CreateUserConfig; // CREATE_USER
  create_group?: CreateGroupConfig; // CREATE_GROUP
  adopt_existing?: boolean; // CREATE_*：import 既有资源而不是新建
  managed_policy_arn?: string;
  principal_type?: string; // ATTACH_USER_POLICY：授权主体类型 User/Group
  target_ticket_no?: string;
  update_role?: UpdateRoleConfig;
  source_ticket_no?: string;
  operation?: string; // ATTACH_USER_POLICY：attach（默认）| detach
  update_policy?: UpdatePolicyConfig; // UPDATE_MANAGED_POLICY / UPDATE_GROUP_INLINE_POLICY
  update_membership?: UpdateMembershipConfig; // UPDATE_GROUP_MEMBERSHIP
  approval_mode: string;
  approver_ids?: string[];
}

export interface CreateManagedPolicyConfig {
  name: string;
  description?: string;
  path?: string;
  document: Record<string, unknown>;
  tags?: Record<string, string>;
}

export interface CreateUserConfig {
  name: string;
  path?: string;
  tags?: Record<string, string>;
  group_names?: string[];
  policy_arns?: string[];
}

export interface CreateGroupConfig {
  name: string;
  path?: string;
  tags?: Record<string, string>;
  member_user_names?: string[];
  policy_arns?: string[];
}

// 策略更新配置：托管策略更新用 PolicyARN+Document；组内嵌策略更新用
// GroupName+InlinePolicyName+Document。document 是策略 JSON 对象
// （后端 json.RawMessage，必须是对象）。
export interface UpdatePolicyConfig {
  policy_arn?: string;
  policy_name?: string;
  group_name?: string;
  /** 内嵌策略归属主体为角色时填写；与 group_name 二选一。 */
  role_name?: string;
  inline_policy_name?: string;
  document: Record<string, unknown>;
}

// UPDATE_ROLE 工单的期望状态配置（收窄为角色属性；内嵌策略/托管挂载已拆出）
export interface UpdateRoleConfig {
  trust_policy?: Record<string, unknown>;
  description?: string;
  max_session_duration?: number;
  tags?: Record<string, string>;
}

// UPDATE_GROUP_MEMBERSHIP：组成员变更。users 是受影响的 IAM 用户名列表
// （增量），目标成员列表由后端按 main 上的 membership 文件（或清单）计算。
export interface UpdateMembershipConfig {
  group_name: string;
  operation: 'add' | 'remove';
  users: string[];
}

// pkg/model/abstractiam.AbstractPolicy
export interface AbstractPolicy {
  id?: string;
  name?: string;
  description?: string;
  statements: AbstractStatement[];
}

export interface AbstractStatement {
  effect: string;
  actions?: string[];
  resources?: string[];
  not_actions?: string[];
  not_resources?: string[];
  conditions?: AbstractCondition[];
}

export interface AbstractCondition {
  key: string;
  operator: string;
  values: unknown[];
}

// ---- 待清理清单 ----
export type CleanupCategory = "platform-file" | "aws-resource";
export type CleanupConfidence = "high" | "review";

// 证据条目：text 是服务端渲染的原文；code + params 允许前端按语言翻译。
export interface CleanupEvidence {
  code?: string;
  text: string;
  params?: Record<string, string>;
}

export interface CleanupItem {
  category: CleanupCategory;
  confidence: CleanupConfidence;
  kind: string;
  name: string;
  arn?: string;
  reason: string;
  evidence: CleanupEvidence[];
  action: string;
  ticket_no?: string;
  pull_request_url?: string;
  file_key?: string;
  reason_code?: string;
  action_code?: string;
  params?: Record<string, string>;
}

export interface CleanupReport {
  account_db_id: number;
  aws_account_id: string;
  generated_at: string;
  latest_sync_run_id?: number;
  items: CleanupItem[];
  category_counts: Record<string, number>;
  confidence_counts: Record<string, number>;
  rule_gaps?: string[];
}

// ---- 基线预览 job（B2）----

export type BaselineJobStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";

export interface BaselinePreviewJob {
  id: number;
  account_db_id: number;
  aws_account_id: string;
  status: BaselineJobStatus;
  requested_by?: string;
  error?: string;
  /** 只在 COMPLETED 出现：完整 bundle 报告（含文件内容）。 */
  result?: BaselineBundleReport;
  content_sha256?: string;
  started_at?: string;
  finished_at?: string;
  created_at: string;
}

export interface BaselineBundleFile {
  key: string;
  file_name: string;
  sources: string[];
  addresses?: string[];
  import_ids?: string[];
  relationship?: boolean;
  content: string;
  sha256: string;
  /** undefined 表示仓库检查未执行（未配置或不可达）。 */
  exists_in_repo?: boolean;
}

export interface BaselineBundleIssue {
  kind: string;
  value: string;
  resources?: string[];
  /**
   * 中文原文说明，仅作兜底：界面文案由 detail_code 决定（旧记录没有码时才
   * 直接显示它），否则切换界面语言后这一列不会跟着变。
   */
  detail?: string;
  /** 说明的稳定语义码，前端按 baseline.detail.issueDetail.<code> 取文案。 */
  detail_code?: string;
  /** 文案插值参数（例如底层错误信息）。 */
  detail_params?: Record<string, string>;
}

export interface BaselineBundleReport {
  account_db_id: number;
  aws_account_id: string;
  generated_at: string;
  repo_directory?: string;
  files: BaselineBundleFile[];
  issues: BaselineBundleIssue[];
  counts: Record<string, number>;
  content_sha256: string;
}

// ---- 基线发布（B3：一账号一分支一 PR）----

export type BaselinePublicationStatus =
  | "PUBLISHING"
  | "PUBLISHED"
  | "FAILED"
  | "MERGED"
  | "CLOSED";

/** 同 run 重发时被替代归档的旧 PR 记录。 */
/** 发布前差异概览（C10）：只读，不含在途预约让路结果。 */
export interface BaselinePublishPreview {
  account_id: number;
  aws_account_id: string;
  sync_run_id: number;
  repo_directory: string;
  files: number;
  /** 与 main 内容一致、不会推送的文件数。 */
  unchanged: number;
  /** 会被推送的文件数（新文件或基线拥有的文件）。 */
  to_publish: number;
  /** 内容不同且不属于基线的文件：发布会整体失败，并记为冲突发现。 */
  conflicts: string[];
}

export interface BaselinePublicationSupersede {
  remote_request_number: string;
  pull_request_url: string;
  status: BaselinePublicationStatus;
  published_at?: string;
  superseded_at: string;
}

export interface BaselinePublication {
  id: number;
  account_db_id: number;
  aws_account_id: string;
  sync_run_id: number;
  status: BaselinePublicationStatus;
  branch: string;
  pull_request_url: string;
  remote_request_number: string;
  repo_directory: string;
  file_count: number;
  content_sha256: string;
  keep_branch: boolean;
  error: string;
  requested_by: string;
  published_at?: string;
  created_at: string;
  updated_at: string;
  /** 只在 PUBLISHED 出现：发布时 bundle 的统计快照。 */
  counts?: Record<string, number>;
  issues?: BaselineBundleIssue[];
  /** 本行历史上被重发替代的 PR 记录（新在前）。 */
  superseded?: BaselinePublicationSupersede[];
}
