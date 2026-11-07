import type {
  AuditEventView,
  AuthConfig,
  AuthMode,
  AuthUser,
  AccountApproverBinding,
  AccountApproverCandidate,
  ApproverAccountSummary,
  AWSAccountConfig,
  AWSAccountConfigInput,
  AWSAccountConnectionIdentity,
  AWSAccountRef,
  AWSSyncRun,
  AWSSyncWorkerStatus,
  BaselinePreviewJob,
  BaselinePublishPreview,
  BaselinePublication,
  CleanupReport,
  CreateTicketRequest,
  DashboardSummary,
  DriftAccountSummary,
  DriftEvaluation,
  DriftFinding,
  DriftFindingPage,
  DriftRemediation,
  DriftRemediationRoute,
  ExecutionRecord,
  GroupDetail,
  GroupSummary,
  InstanceProfileDetail,
  InstanceProfileSummary,
  InlinePolicyDetail,
  InlinePolicySummary,
  IssuedPlatformToken,
  ManagedPolicyDetail,
  ManagedPolicySummary,
  PlatformProvisionResult,
  PlatformTokenInfo,
  PlatformUser,
  PrincipalDetail,
  PrincipalSummary,
  ResourceOwnership,
  Ticket,
  TicketApprovalInfo,
  TicketListResponse,
  ValidationSnapshot,
} from "./types";
import i18n from "../i18n";

const BASE = "/api/v1";
const TOKEN_KEY = "platform-token";
const AUTH_MODE_KEY = "auth-mode";
const AUTH_USER_KEY = "auth-user";
const DEV_USER_KEY = "dev-user";

/** 统一错误信封：{code, message, details} */
export class ApiError extends Error {
  status: number;
  code: string;
  details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function getAuthMode(): AuthMode | null {
  const value = sessionStorage.getItem(AUTH_MODE_KEY);
  return value === "development" || value === "api-token" ? value : null;
}

export function setAuthMode(mode: AuthMode): void {
  sessionStorage.setItem(AUTH_MODE_KEY, mode);
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

export function setAuthUser(user: AuthUser): void {
  sessionStorage.setItem(AUTH_USER_KEY, user.user_id);
}

export function clearAuthUser(): void {
  sessionStorage.removeItem(AUTH_USER_KEY);
}

export function getDevUser(): string {
  return localStorage.getItem(DEV_USER_KEY) ?? "";
}

export function setDevUser(userID: string): void {
  localStorage.setItem(DEV_USER_KEY, userID);
}

// currentUser is the identity of the authenticated session (or the explicit
// development switch). Exported so pages can tell which approval row belongs
// to the operator (e.g. to disable the approve button once they have decided).
export function currentUser(): string {
  return sessionStorage.getItem(AUTH_USER_KEY) ?? getDevUser();
}

export function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  // The backend accepts X-User-ID only when AUTH_MODE=development; never send
  // it in api-token mode so a stale local dev identity cannot leak into logs.
  if (getAuthMode() === "development") {
    const devUser = getDevUser();
    if (devUser) headers["X-User-ID"] = devUser;
  }
  return headers;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...authHeaders(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "NETWORK", i18n.t("error.network"));
  }
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown> & {
    code?: string;
    message?: string;
    details?: Record<string, unknown>;
  };
  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      clearAuthUser();
      window.dispatchEvent(new Event("auth-expired"));
    }
    throw new ApiError(
      res.status,
      data.code ?? "UNKNOWN",
      (data.message as string) ?? res.statusText,
      data.details,
    );
  }
  return data as T;
}

function qs(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

export const api = {
  // ---- 认证 ----
  getAuthConfig: () => request<AuthConfig>("GET", "/auth/config"),
  getMe: async () => {
    const user = await request<AuthUser>("GET", "/auth/me");
    setAuthUser(user);
    return user;
  },
  loginWithToken: async (token: string) => {
    setToken(token.trim());
    try {
      const user = await request<AuthUser>("GET", "/auth/me");
      setAuthUser(user);
      return user;
    } catch (error) {
      clearToken();
      clearAuthUser();
      throw error;
    }
  },
  logout: () => {
    clearToken();
    clearAuthUser();
  },

  // ---- 账号 ----
  listAccounts: () =>
    request<{ accounts: AWSAccountRef[] }>("GET", "/aws/accounts").then((r) => r.accounts),

  // ---- 工单 ----
  listTickets: (params: {
    status?: string;
    account_id?: number;
    submitter?: string;
    ticket_type?: string;
    q?: string;
    limit?: number;
    offset?: number;
  }) => request<TicketListResponse>("GET", `/tickets${qs(params)}`),

  listRoles: (params: { account_id: number; q?: string }) =>
    request<{ principals: PrincipalSummary[] }>(
      "GET",
      `/aws/principals${qs({ account_id: params.account_id, type: "Role", q: params.q, limit: 100 })}`,
    ).then((r) => r.principals),

  listUsers: (params: { account_id: number; q?: string }) =>
    request<{ principals: PrincipalSummary[] }>(
      "GET",
      `/aws/principals${qs({ account_id: params.account_id, type: "User", q: params.q, limit: 100 })}`,
    ).then((r) => r.principals),

  listPolicies: (params: { q?: string; account_id?: number }) =>
    request<{ policies: ManagedPolicySummary[] }>(
      "GET",
      `/aws/policies${qs({ q: params.q, account_id: params.account_id, limit: 100 })}`,
    ).then((r) => r.policies),

  /** 托管策略详情：带当前文档（编辑器预填）与引用计数（风险提示）。 */
  getPolicy: (policyId: number) =>
    request<{ policy: ManagedPolicyDetail }>("GET", `/aws/policies/${policyId}`).then(
      (r) => r.policy,
    ),

  /** 组内联策略清单（组详情里的 policies 列表，policy_type='inline'）。 */
  listGroupPolicies: (groupId: number) =>
    request<{ group: GroupDetail }>("GET", `/aws/groups/${groupId}`).then((r) => r.group.policies),

  getRoleDetail: (principalId: number) =>
    request<{ principal: PrincipalDetail }>(
      "GET",
      `/aws/principals/${principalId}`,
    ).then((r) => r.principal),

  getTicket: (ticketNo: string) =>
    request<{ ticket: Ticket }>("GET", `/tickets/${encodeURIComponent(ticketNo)}`).then(
      (r) => r.ticket,
    ),

  // 详情页 Terraform 预览：已发布返回存库原文，未发布按需渲染将要发布的 HCL。
  getTerraformPreview: (ticketNo: string) =>
    request<{ terraform_preview: string }>(
      "GET",
      `/tickets/${encodeURIComponent(ticketNo)}/terraform`,
    ).then((r) => r.terraform_preview),

  getApprovalInfo: (ticketNo: string) =>
    request<{ approval: TicketApprovalInfo }>(
      "GET",
      `/tickets/${encodeURIComponent(ticketNo)}/approval`,
    ).then((r) => r.approval),

  getExecutionRecords: (ticketNo: string, limit = 5) =>
    request<{ execution_records: ExecutionRecord[] }>(
      "GET",
      `/tickets/${encodeURIComponent(ticketNo)}/execution-records?limit=${limit}`,
    ).then((r) => r.execution_records),

  listApprovers: (accountId?: number) =>
    request<{ approvers: PlatformUser[] }>(
      "GET",
      `/approvers${qs({ account_id: accountId })}`,
    ).then((r) => r.approvers),

  validateTicket: (payload: CreateTicketRequest) =>
    request<{ validation: ValidationSnapshot }>(
      "POST",
      "/tickets/validate",
      payload,
    ).then((r) => r.validation),

  createTicket: (payload: CreateTicketRequest) =>
    request<{ ticket: Ticket }>("POST", "/tickets", payload).then((r) => r.ticket),

  submitTicket: (ticketNo: string) =>
    request<{ ticket: Ticket }>(
      "POST",
      `/tickets/${encodeURIComponent(ticketNo)}/submit`,
    ).then((r) => r.ticket),

  decideTicket: (ticketNo: string, result: "APPROVE" | "REJECT", comment: string) =>
    request<{ ticket: Ticket }>(
      "POST",
      `/tickets/${encodeURIComponent(ticketNo)}/decision`,
      { result, comment },
    ).then((r) => r.ticket),

  retryPublish: (ticketNo: string) =>
    request<{ ticket: Ticket }>(
      "POST",
      `/tickets/${encodeURIComponent(ticketNo)}/publish`,
    ).then((r) => r.ticket),

  rearmPoll: (ticketNo: string) =>
    request<{ poll_rearmed: boolean }>(
      "POST",
      `/tickets/${encodeURIComponent(ticketNo)}/poll`,
    ),

  closeTicket: (
    ticketNo: string,
    reason: "APPLIED" | "ABANDONED",
    comment?: string,
    triggerSync?: boolean,
  ) =>
    request<{ ticket: Ticket }>(
      "POST",
      `/tickets/${encodeURIComponent(ticketNo)}/close`,
      { reason, comment: comment ?? "", trigger_sync: triggerSync },
    ).then((r) => r.ticket),

  // ---- 资产清单 ----
  listPrincipals: (params: {
    account_id?: number;
    type?: string;
    q?: string;
    managed_by?: string;
    /** true=仅 AWS 自动创建的角色，false=排除它们。 */
    aws?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ principals: PrincipalSummary[]; total: number; limit: number; offset: number }>(
      "GET",
      `/aws/principals${qs(params)}`,
    ),

  getPrincipal: (id: number) =>
    request<{ principal: PrincipalDetail }>("GET", `/aws/principals/${id}`).then(
      (r) => r.principal,
    ),

  listGroups: (params: {
    account_id?: number;
    q?: string;
    managed_by?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ groups: GroupSummary[]; total: number; limit: number; offset: number }>(
      "GET",
      `/aws/groups${qs(params)}`,
    ),

  listPoliciesV2: (params: {
    q?: string;
    account_id?: number;
    /** true=仅 AWS 托管策略，false=仅客户自管策略。 */
    aws?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ policies: ManagedPolicySummary[]; total: number; limit: number; offset: number }>(
      "GET",
      `/aws/policies${qs(params)}`,
    ),

  listInlinePolicies: (params: {
    account_id?: number;
    q?: string;
    /** true=仅 AWS 主体的内联策略，false=仅可工单修改的。 */
    aws?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ policies: InlinePolicySummary[]; total: number; limit: number; offset: number }>(
      "GET",
      `/aws/inline-policies${qs(params)}`,
    ),

  listInstanceProfiles: (params: {
    account_id?: number;
    q?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ profiles: InstanceProfileSummary[]; total: number; limit: number; offset: number }>(
      "GET",
      `/aws/instance-profiles${qs(params)}`,
    ),

  getInlinePolicy: (policyId: number) =>
    request<{ policy: InlinePolicyDetail }>("GET", `/aws/inline-policies/${policyId}`).then(
      (r) => r.policy,
    ),

  getInstanceProfile: (profileId: number) =>
    request<{ profile: InstanceProfileDetail }>("GET", `/aws/instance-profiles/${profileId}`).then(
      (r) => r.profile,
    ),

  // ---- 待清理清单（仅平台管理员）----
  getCleanupSuggestions: (accountRef: string | number) =>
    request<{ cleanup: CleanupReport }>(
      "GET",
      `/aws/accounts/${encodeURIComponent(String(accountRef))}/cleanup-suggestions`,
    ).then((r) => r.cleanup),

  // ---- 基线预览 job（仅平台管理员）----
  createBaselineJob: (accountRef: string | number) =>
    request<{ job: BaselinePreviewJob }>(
      "POST",
      `/aws/accounts/${encodeURIComponent(String(accountRef))}/baseline-jobs`,
    ).then((r) => r.job),

  listBaselineJobs: (accountRef: string | number, limit = 20) =>
    request<{ jobs: BaselinePreviewJob[] }>(
      "GET",
      `/aws/accounts/${encodeURIComponent(String(accountRef))}/baseline-jobs${qs({ limit })}`,
    ).then((r) => r.jobs),

  /** 详情带完整 bundle（文件内容可能上 MB），只在打开抽屉时调用。 */
  getBaselineJob: (jobId: number) =>
    request<{ job: BaselinePreviewJob }>("GET", `/baseline-jobs/${jobId}`).then((r) => r.job),

  // ---- 基线发布（B3：一账号一分支一 PR，仅平台管理员）----
  /** 幂等：同账号同快照 run 已发布时返回 already_published=true 与既有记录。 */
  createBaselinePublication: (accountRef: string | number) =>
    request<{ publication: BaselinePublication; already_published: boolean }>(
      "POST",
      `/aws/accounts/${encodeURIComponent(String(accountRef))}/baseline-publications`,
    ),

  /**
   * 发布前差异概览（C10）：构建 bundle 并与 main 比对，只读。
   * 不含在途预约的让路结果——预约是真实发布时才写的。
   */
  previewBaselinePublication: (accountRef: string | number) =>
    request<BaselinePublishPreview>(
      "GET",
      `/aws/accounts/${encodeURIComponent(String(accountRef))}/baseline-preview`,
    ),

  listBaselinePublications: (accountRef: string | number, limit = 20) =>
    request<{ publications: BaselinePublication[] }>(
      "GET",
      `/aws/accounts/${encodeURIComponent(String(accountRef))}/baseline-publications${qs({ limit })}`,
    ).then((r) => r.publications),

  getBaselinePublication: (publicationId: number) =>
    request<{ publication: BaselinePublication }>(
      "GET",
      `/baseline-publications/${publicationId}`,
    ).then((r) => r.publication),

  // ---- 纳管归属（仅平台管理员可写）----
  listOwnership: (params: { account_id?: number; kind?: string; managed_by?: string }) =>
    request<{ ownership: ResourceOwnership[] }>("GET", `/aws/ownership${qs(params)}`).then(
      (r) => r.ownership,
    ),

  setOwnership: (key: string, accountId: number, managedBy: string) =>
    request<{ key: string; managed_by: string }>(
      "PUT",
      `/aws/ownership/${encodeURIComponent(key)}`,
      { account_id: accountId, managed_by: managedBy },
    ),

  getGroup: (id: number) =>
    request<{ group: GroupDetail }>("GET", `/aws/groups/${id}`).then((r) => r.group),

  // ---- 用户与令牌（仅平台管理员）----
  listPlatformUsers: () =>
    request<{ users: PlatformUser[] }>("GET", "/platform/users").then((r) => r.users),

  upsertPlatformUser: (user: {
    user_id: string;
    display_name: string;
    email?: string;
    is_active?: boolean;
    roles: string[];
  }) =>
    request<{ user_id: string }>(
      "PUT",
      `/platform/users/${encodeURIComponent(user.user_id)}`,
      user,
    ).then((r) => r.user_id),

  listPlatformTokens: (userId?: string) =>
    request<{ tokens: PlatformTokenInfo[] }>(
      "GET",
      `/platform/tokens${qs({ user_id: userId })}`,
    ).then((r) => r.tokens),

  // 明文令牌只在这次响应里出现一次。
  issuePlatformToken: (userId: string, name: string, expiresInHours: number) =>
    request<IssuedPlatformToken>(
      "POST",
      `/platform/users/${encodeURIComponent(userId)}/tokens`,
      { name, expires_in_hours: expiresInHours },
    ),

  revokePlatformToken: (tokenId: number) =>
    request<void>("POST", `/platform/tokens/${tokenId}/revoke`),

  // 平台用户一键开通到云：每个目标账号生成一张 CREATE_USER 工单。
  provisionPlatformUser: (
    userId: string,
    payload: {
      accounts: number[];
      approval_mode: string;
      approver_ids?: string[];
      groups?: string[];
      policy_arns?: string[];
      tags?: Record<string, string>;
    },
  ) =>
    request<{ results: PlatformProvisionResult[] }>(
      "POST",
      `/platform/users/${encodeURIComponent(userId)}/provision`,
      payload,
    ).then((r) => r.results),

  // ---- 同步 ----
  listAccountConfigs: () =>
    request<{ configs: AWSAccountConfig[] }>("GET", "/aws/account-configs").then(
      (r) => r.configs,
    ),

  /** 某账号当前的审批人绑定（AUTO 审批解析依据）。 */
  getAccountApprovers: (accountDbId: number) =>
    request<{ approvers: AccountApproverBinding[] }>(
      "GET",
      `/aws/accounts/${accountDbId}/approvers`,
    ).then((r) => r.approvers),

  /** 整体替换某账号的审批人绑定（传空数组 = 清空）。 */
  replaceAccountApprovers: (accountDbId: number, userIds: string[]) =>
    request<{ approvers: AccountApproverBinding[] }>(
      "PUT",
      `/aws/accounts/${accountDbId}/approvers`,
      { user_ids: userIds },
    ).then((r) => r.approvers),

  /** 有资格当审批人的平台用户 + 是否已绑定（设置弹窗的数据源）。 */
  listAccountApproverCandidates: (accountDbId: number) =>
    request<{ candidates: AccountApproverCandidate[] }>(
      "GET",
      `/aws/accounts/${accountDbId}/approver-candidates`,
    ).then((r) => r.candidates),

  /** 某用户仍是审批人的账号列表（停用/降级前警告用，A9③乙）。 */
  listApproverAccountsForUser: (userId: string) =>
    request<{ accounts: ApproverAccountSummary[] }>(
      "GET",
      `/aws/approver-bindings/${encodeURIComponent(userId)}`,
    ).then((r) => r.accounts),

  /**
   * 反向写路径：整体替换「该用户可审批的账号」集合（用户编辑页）。
   * 只影响这一个用户的绑定行，同账号的其他审批人保持不变。
   */
  replaceApproverAccounts: (userId: string, accountIds: number[]) =>
    request<{ accounts: ApproverAccountSummary[] }>(
      "PUT",
      `/aws/approver-bindings/${encodeURIComponent(userId)}`,
      { account_ids: accountIds },
    ).then((r) => r.accounts),

  triggerSync: (configId: number) =>
    request<{ sync_run: AWSSyncRun }>(
      "POST",
      `/aws/account-configs/${configId}/sync`,
    ).then((r) => r.sync_run),

  setSyncEnabled: (configId: number, enabled: boolean) =>
    request<{ config: AWSAccountConfig }>(
      "PATCH",
      `/aws/account-configs/${configId}/sync-enabled`,
      { sync_enabled: enabled },
    ).then((r) => r.config),

  /** 录入账号（创建即做 STS 连通性校验，失败 400/502 不落库）。 */
  createAccountConfig: (payload: AWSAccountConfigInput) =>
    request<{ config: AWSAccountConfig }>("POST", "/aws/account-configs", payload).then(
      (r) => r.config,
    ),

  /** 编辑账号（账号 ID 不可改；保存前同样做连通性校验）。 */
  updateAccountConfig: (configId: number, payload: AWSAccountConfigInput) =>
    request<{ config: AWSAccountConfig }>(
      "PUT",
      `/aws/account-configs/${configId}`,
      payload,
    ).then((r) => r.config),

  /** 手动连通性测试（STS GetCallerIdentity，返回实际身份 ARN）。 */
  testAccountConnection: (configId: number) =>
    request<{ identity: AWSAccountConnectionIdentity }>(
      "POST",
      `/aws/account-configs/${configId}/test-connection`,
    ).then((r) => r.identity),

  /** 同步 worker 心跳与队列积压（worker 未运行时触发会一直 PENDING）。 */
  getSyncWorkerStatus: () =>
    request<{ worker: AWSSyncWorkerStatus }>("GET", "/aws/sync/worker-status").then(
      (r) => r.worker,
    ),

  listSyncRuns: (params: {
    config_id?: number;
    account_id?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ sync_runs: AWSSyncRun[]; total: number; limit: number; offset: number }>(
      "GET",
      `/aws/sync-runs${qs(params)}`,
    ),

  /** 下载一次同步运行的清单差集 CSV（新增/移除的主体与组）。 */
  downloadSyncChanges: async (runId: number) => {
    let res: Response;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    try {
      res = await fetch(`${BASE}/aws/sync-runs/${runId}/changes.csv`, {
        headers: authHeaders(),
        signal: controller.signal,
      });
    } catch {
      throw new ApiError(0, "NETWORK", i18n.t("error.network"));
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as {
        code?: string;
        message?: string;
      };
      throw new ApiError(
        res.status,
        data.code ?? "UNKNOWN",
        data.message ?? i18n.t("error.requestFailed", { status: res.status }),
      );
    }
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") ?? "";
    const match = /filename="?([^";]+)"?/.exec(disposition);
    const filename = match?.[1] ?? `sync-run-${runId}-changes.csv`;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    // Delay cleanup: revoking the blob URL or removing the anchor in the same
    // tick as the click silently cancels the pending download in Firefox and
    // some Edge versions (click appears to do nothing).
    window.setTimeout(() => {
      anchor.remove();
      URL.revokeObjectURL(url);
    }, 10_000);
  },

  // ---- 审计 ----
  listAuditEvents: (params: {
    actor_id?: string;
    action?: string;
    resource_type?: string;
    resource_id?: string;
    outcome?: string;
    from?: string;
    to?: string;
    limit?: number;
    offset?: number;
  }) =>
    request<{ events: AuditEventView[]; total: number; limit: number; offset: number }>(
      "GET",
      `/audit/events${qs(params)}`,
    ),

  // ---- Dashboard ----
  dashboardSummary: () =>
    request<{ summary: DashboardSummary }>("GET", "/dashboard/summary").then((r) => r.summary),

  // ---- 漂移发现 ----
  listDriftFindings: (params: {
    account_id?: string;
    status?: string;
    severity?: string;
    change_type?: string;
    include_resolved?: boolean;
    page?: number;
    page_size?: number;
  }) =>
    request<DriftFindingPage>(
      "GET",
      `/drift-findings${qs({
        account_id: params.account_id,
        status: params.status,
        severity: params.severity,
        change_type: params.change_type,
        include_resolved: params.include_resolved ? "true" : undefined,
        page: params.page,
        page_size: params.page_size,
      })}`,
    ),
  driftAccounts: () =>
    request<{ accounts: DriftAccountSummary[] }>("GET", "/drift-findings/summary").then(
      (r) => r.accounts,
    ),
  checkDrift: (accountId: number) =>
    request<DriftEvaluation>("POST", "/drift-findings/check", { account_id: accountId }),
  driftAction: (id: number, action: "ignore" | "reopen" | "resolve") =>
    request<DriftFinding>("POST", `/drift-findings/${id}/${action}`),
  remediateDrift: (id: number, route: DriftRemediationRoute) =>
    request<DriftRemediation>("POST", `/drift-findings/${id}/remediate`, { route }),
};
