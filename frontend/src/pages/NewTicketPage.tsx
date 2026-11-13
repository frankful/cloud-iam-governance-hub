import {
  Alert,
  AutoComplete,
  Button,
  Card,
  Col,
  Divider,
  Form,
  Input,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
  message,
} from "antd";
import {
  CopyOutlined,
  SafetyCertificateOutlined,
  SendOutlined,
  TeamOutlined,
} from "@ant-design/icons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { api, ApiError } from "../api/client";
import type {
  AttachedPolicy,
  AWSAccountRef,
  CreateTicketRequest,
  PlatformUser,
  UpdateRoleConfig,
  ValidationCheck,
} from "../api/types";
import AccountApproverModal from "../components/AccountApproverModal";
import ValidationErrors from "../components/ValidationErrors";
import { hasRole, useAuth } from "../auth";
import {
  ABSTRACT_POLICY_TEMPLATE,
  AbstractPolicyParseError,
  parseAbstractPolicyText,
} from "../lib/abstractPolicy";
import { iamPathFromARN } from "../lib/iamArn";

const { Title, Text } = Typography;
const { TextArea } = Input;

const TRUST_POLICY_TEMPLATE = JSON.stringify(
  {
    version: "2012-10-17",
    statements: [
      {
        effect: "Allow",
        principal: { service: "ec2.amazonaws.com" },
        actions: ["sts:AssumeRole"],
      },
    ],
  },
  null,
  2,
);

/**
 * parsePolicyDocument 解析策略文档编辑器的文本为 JSON 对象。
 * 后端 UpdatePolicyConfig.document 是 json.RawMessage，要求是 JSON 对象
 * （不能是字符串/数组）；解析失败时给出提示并返回 null。
 */
function parsePolicyDocument(
  text: string | undefined,
  t: TFunction,
): Record<string, unknown> | null {
  const raw = (text ?? "").trim();
  if (!raw) {
    message.error(t("newTicket.form.policyDocumentRequired"));
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    message.error(t("newTicket.error.policyDocumentInvalidJson"));
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    message.error(t("newTicket.error.policyDocumentNotObject"));
    return null;
  }
  return parsed as Record<string, unknown>;
}

// buildUpdateRolePayload 从表单值构建 UpdateRoleConfig，解析 JSON 字段。
// 返回 null 表示 JSON 格式错误（已提示用户）。
function buildUpdateRolePayload(
  values: {
    update_trust_policy: string;
    update_description: string;
    update_max_session_duration: number;
    update_tags: string;
  },
  base: CreateTicketRequest,
  form: { setFieldsValue: (values: Record<string, unknown>) => void },
  tagsLoaded: boolean,
  t: TFunction,
): UpdateRoleConfig | null {
  const config: UpdateRoleConfig = {};
  // 信任策略
  const trustText = values.update_trust_policy?.trim() ?? "";
  if (trustText) {
    try {
      config.trust_policy = JSON.parse(trustText);
    } catch {
      message.error(t("newTicket.error.trustPolicyInvalidJson"));
      return null;
    }
  }
  // 描述
  const desc = values.update_description?.trim() ?? "";
  if (desc) config.description = desc;
  // 最大会话时长
  if (values.update_max_session_duration) {
    config.max_session_duration = values.update_max_session_duration;
  }
  // 标签（key=value 每行一个）。只有标签已从当前角色成功回填后才允许提交，
  // 避免读取失败时按空标签生成 Terraform、apply 时删掉角色现有 tags。
  if (!tagsLoaded) {
    message.error(t("newTicket.error.roleTagsNotLoaded"));
    return null;
  }
  const tags: Record<string, string> = {};
  const tagLines = (values.update_tags ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const line of tagLines) {
    const idx = line.indexOf("=");
    if (idx <= 0) {
      message.error(
        t("newTicket.error.tagFormatInvalid", { field: t("newTicket.field.tag"), line }),
      );
      return null;
    }
    tags[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  // Always send the full tag map: the caller prefills current tags, so an
  // explicitly emptied editor means "remove all tags". Sending {} for a role
  // with no tags is a harmless no-op.
  config.tags = tags;
  // 信任策略变更检测 → 强制人工审批
  if (config.trust_policy && base.approval_mode !== "MANUAL") {
    message.warning(t("newTicket.warning.trustPolicyChange"));
    base.approval_mode = "MANUAL";
    form.setFieldsValue({ approval_mode: "MANUAL" });
  }
  return config;
}

const POLICY_TEMPLATE = JSON.stringify(
  {
    statements: [
      {
        effect: "Allow",
        actions: ["iam:GetRole"],
        resources: ["*"],
      },
    ],
  },
  null,
  2,
);

type TicketType =
  | "CREATE_ROLE"
  | "CREATE_MANAGED_POLICY"
  | "CREATE_USER"
  | "CREATE_GROUP"
  | "ATTACH_USER_POLICY"
  | "ROLLBACK"
  | "UPDATE_ROLE"
  | "UPDATE_MANAGED_POLICY"
  | "UPDATE_GROUP_INLINE_POLICY"
  | "UPDATE_GROUP_MEMBERSHIP"
  | "ADOPT_ROLE_INLINE_POLICIES";

/** 顶部标签页文案 key（配合 TICKET_TABS 使用）。 */
type TicketTabLabelKey =
  | "newTicket.tab.createRole"
  | "newTicket.tab.createManagedPolicy"
  | "newTicket.tab.createUser"
  | "newTicket.tab.createGroup"
  | "newTicket.tab.updateRole"
  | "newTicket.tab.attachPolicy"
  | "newTicket.tab.updateManagedPolicy"
  | "newTicket.tab.updateInlinePolicy"
  | "newTicket.tab.updateGroupMembership"
  | "newTicket.tab.adoptRolePolicies"
  | "newTicket.tab.rollback";

/** 工单类型 → 顶部标签页 key（所有页签共用一张表单）。 */
const TICKET_TABS: { value: TicketType; labelKey: TicketTabLabelKey }[] = [
  { value: "CREATE_ROLE", labelKey: "newTicket.tab.createRole" },
  { value: "CREATE_MANAGED_POLICY", labelKey: "newTicket.tab.createManagedPolicy" },
  { value: "CREATE_USER", labelKey: "newTicket.tab.createUser" },
  { value: "CREATE_GROUP", labelKey: "newTicket.tab.createGroup" },
  { value: "UPDATE_ROLE", labelKey: "newTicket.tab.updateRole" },
  { value: "ATTACH_USER_POLICY", labelKey: "newTicket.tab.attachPolicy" },
  { value: "UPDATE_MANAGED_POLICY", labelKey: "newTicket.tab.updateManagedPolicy" },
  { value: "UPDATE_GROUP_INLINE_POLICY", labelKey: "newTicket.tab.updateInlinePolicy" },
  { value: "UPDATE_GROUP_MEMBERSHIP", labelKey: "newTicket.tab.updateGroupMembership" },
  { value: "ADOPT_ROLE_INLINE_POLICIES", labelKey: "newTicket.tab.adoptRolePolicies" },
  { value: "ROLLBACK", labelKey: "newTicket.tab.rollback" },
];

/** parseTagLines 解析每行一个 key=value 的标签编辑器。空文本返回 {}。 */
function parseTagLines(
  text: string | undefined,
  fieldLabel: string,
  t: TFunction,
): Record<string, string> | null {
  const tags: Record<string, string> = {};
  const lines = (text ?? "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  for (const line of lines) {
    const idx = line.indexOf("=");
    if (idx <= 0) {
      message.error(t("newTicket.error.tagFormatInvalid", { field: fieldLabel, line }));
      return null;
    }
    tags[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return tags;
}

interface FormValues {
  ticket_type: TicketType;
  account_id?: number;
  principal_name: string;
  policy_text: string;
  trust_policy: string;
  managed_policy_arn: string;
  principal_type: "User" | "Group" | "Role";
  operation: "attach" | "detach";
  target_ticket_no: string;
  update_trust_policy: string;
  update_description: string;
  update_max_session_duration: number;
  update_tags: string;
  // UPDATE_MANAGED_POLICY / UPDATE_GROUP_INLINE_POLICY
  update_policy_id?: number;
  update_policy_document: string;
  update_inline_principal_type: string;
  update_inline_group: string;
  update_inline_role: string;
  update_inline_policy_id?: string;
  // UPDATE_GROUP_MEMBERSHIP
  membership_group: string;
  membership_operation: "add" | "remove";
  membership_users: string[];
  // CREATE_MANAGED_POLICY / CREATE_USER / CREATE_GROUP
  adopt_existing: boolean;
  create_policy_description: string;
  create_policy_path: string;
  create_policy_document: string;
  create_policy_tags: string;
  create_user_path: string;
  create_user_groups: string[];
  create_user_policy_arns: string[];
  create_user_tags: string;
  create_group_path: string;
  create_group_members: string[];
  create_group_policy_arns: string[];
  create_group_tags: string;
  create_role_policy_arns: string[];
  approval_mode: "MANUAL" | "AUTO";
  approver_ids: string[];
}

type PolicyARNField =
  | "create_user_policy_arns"
  | "create_group_policy_arns"
  | "create_role_policy_arns";

function isIAMPolicyARN(value: string): boolean {
  const parts = value.trim().split(":");
  return (
    parts.length === 6 &&
    parts[0] === "arn" &&
    ["aws", "aws-cn", "aws-us-gov"].includes(parts[1]) &&
    parts[2] === "iam" &&
    parts[3] === "" &&
    (parts[4] === "aws" || /^\d{12}$/.test(parts[4])) &&
    parts[5].startsWith("policy/") &&
    parts[5].length > "policy/".length
  );
}

export default function NewTicketPage() {
  const { t } = useTranslation();
  const policyARNRules = useMemo(
    () => [
      {
        validator: (_rule: unknown, values?: string[]) => {
          const invalid = (values ?? []).find((value) => !isIAMPolicyARN(value));
          return invalid
            ? Promise.reject(new Error(t("newTicket.form.policyArnMustBeComplete")))
            : Promise.resolve();
        },
      },
    ],
    [t],
  );
  const navigate = useNavigate();
  const location = useLocation();
  const preset = (location.state ?? {}) as {
    ticket_type?: string;
    target_ticket_no?: string;
    account_id?: number;
    // 清单抽屉"预填并跳转"：托管策略/内嵌策略编辑
    policy_id?: number;
    policy_arn?: string;
    group_name?: string;
    inline_policy_name?: string;
    operation?: string;
    principal_name?: string;
    principal_type?: string;
  };

  const [form] = Form.useForm<FormValues>();
  const handlePolicyARNChange = useCallback(
    (field: PolicyARNField, values: string[]) => {
      const validValues = values.filter(isIAMPolicyARN);
      if (validValues.length === values.length) return;
      form.setFieldValue(field, validValues);
      message.warning(t("newTicket.form.policyArnMustBeComplete"));
    },
    [form, t],
  );
  const [accounts, setAccounts] = useState<AWSAccountRef[]>([]);
  const [approvers, setApprovers] = useState<PlatformUser[]>([]);
  // AUTO 模式缺审批人时就地配置，不用跳出去再回来（表单填写会丢）。
  const [approverModalOpen, setApproverModalOpen] = useState(false);
  const { user: currentUser } = useAuth();
  const isAdmin = hasRole(currentUser, "platform_admin");
  const [submitting, setSubmitting] = useState(false);
  const [validationError, setValidationError] = useState<ApiError | null>(null);
  const [validationOk, setValidationOk] = useState<string | null>(null);
  const [validationChecks, setValidationChecks] = useState<ValidationCheck[]>([]);
  const [terraformPreview, setTerraformPreview] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // UPDATE_ROLE must not generate Terraform until the role's current tags have
  // been read back. An empty editor is otherwise indistinguishable from a
  // failed read, and sending {} would delete every existing AWS tag.
  const [roleTagsLoaded, setRoleTagsLoaded] = useState(false);
  const [roleTagsError, setRoleTagsError] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const ticketType = Form.useWatch("ticket_type", form) ?? "CREATE_ROLE";
  const accountId = Form.useWatch("account_id", form) as number | undefined;
  const approvalMode = Form.useWatch("approval_mode", form) ?? "MANUAL";
  const adoptExisting = Form.useWatch("adopt_existing", form) as boolean | undefined;
  const [roleOptions, setRoleOptions] = useState<
    { value: string; label: string; id?: number }[]
  >([]);
  const [userOptions, setUserOptions] = useState<
    { value: string; label: string; id?: number }[]
  >([]);
  const [policyOptions, setPolicyOptions] = useState<
    { value: string; label: string; name: string; arn?: string; id: number }[]
  >([]);
  const [policyOptionsError, setPolicyOptionsError] = useState<string | null>(null);
  useEffect(() => {
    if (ticketType === "ADOPT_ROLE_INLINE_POLICIES" && approvalMode !== "MANUAL") {
      form.setFieldsValue({ approval_mode: "MANUAL" });
    }
  }, [approvalMode, form, ticketType]);
  // UPDATE_GROUP_INLINE_POLICY：组 + 组内联策略选择
  const [groupOptions, setGroupOptions] = useState<{ value: string; label: string; id: number }[]>(
    [],
  );
  const groupSearchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadGroups = useCallback(
    (q?: string) => {
      if (!accountId) {
        setGroupOptions([]);
        return;
      }
      api
        .listGroups({ account_id: accountId, q, limit: 100 })
        .then((res) =>
          setGroupOptions(
            res.groups.map((g) => ({ value: g.group_name, label: g.group_name, id: g.id })),
          ),
        )
        .catch(() => setGroupOptions([]));
    },
    [accountId],
  );
  const handleGroupSearch = useCallback(
    (value: string) => {
      if (groupSearchTimer.current) clearTimeout(groupSearchTimer.current);
      groupSearchTimer.current = setTimeout(() => loadGroups(value.trim()), 300);
    },
    [loadGroups],
  );
  // CREATE_GROUP：可选成员用户清单。
  const [createMemberOptions, setCreateMemberOptions] = useState<
    { value: string; label: string; id: number }[]
  >([]);
  // UPDATE_GROUP_MEMBERSHIP：成员候选按组内现状收敛——移除只列组内成员，
  // 加入则排除已是成员的用户（后端同样会拒，提前收敛选项避免误选）。
  const [membershipMembers, setMembershipMembers] = useState<
    { value: string; label: string }[]
  >([]);
  const [membershipMembersLoading, setMembershipMembersLoading] = useState(false);
  const membershipGroupName = (Form.useWatch("membership_group", form) as string) || "";
  const membershipOperation =
    (Form.useWatch("membership_operation", form) as string) || "add";
  const membershipGroupId = useMemo(
    () => groupOptions.find((g) => g.value === membershipGroupName)?.id,
    [groupOptions, membershipGroupName],
  );
  const [inlinePolicyOptions, setInlinePolicyOptions] = useState<
    { value: number; label: string; name: string }[]
  >([]);
  // 选中策略的详情（文档预填 + 引用计数风险提示）
  const [policyDetail, setPolicyDetail] = useState<{
    document?: unknown;
    attached_principals: number;
    attached_groups: number;
  } | null>(null);

  useEffect(() => {
    api
      .listAccounts()
      .then(setAccounts)
      .catch((err) => setLoadError(err instanceof ApiError ? err.message : String(err)));
    api
      .listApprovers()
      .then(setApprovers)
      .catch(() => setApprovers([]));
  }, []);

  // 预填：从详情页/清单抽屉跳转而来（工单类型 + 目标对象）
  useEffect(() => {
    if (preset.ticket_type) {
      const patch: Record<string, unknown> = {
        ticket_type: preset.ticket_type as TicketType,
      };
      if (preset.target_ticket_no) patch.target_ticket_no = preset.target_ticket_no;
      // 账号一并预填：跳转过来时不用再选一次，挂载清单预览也才能立刻加载。
      if (preset.account_id) patch.account_id = preset.account_id;
      if (preset.principal_name) patch.principal_name = preset.principal_name;
      if (preset.principal_type) patch.principal_type = preset.principal_type;
      if (preset.operation) patch.operation = preset.operation;
      if (preset.policy_arn) patch.managed_policy_arn = preset.policy_arn;
      if (preset.policy_id) patch.update_policy_id = preset.policy_id;
      // 内嵌策略预填：角色跳转带 principal_type=Role + principal_name，
      // 组跳转带 group_name。
      if (
        preset.principal_type === "Role" &&
        preset.principal_name &&
        preset.ticket_type === "UPDATE_GROUP_INLINE_POLICY"
      ) {
        patch.update_inline_principal_type = "Role";
        patch.update_inline_role = preset.principal_name;
      } else if (preset.group_name) {
        patch.update_inline_group = preset.group_name;
      }
      form.setFieldsValue(patch);
    }
  }, [preset, form]);

  // 账号选定后加载首批角色；输入时防抖调后端 q 过滤全量库存。
  const roleSearchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadRoles = useCallback(
    (q?: string) => {
      if (
        ticketType !== "UPDATE_ROLE" &&
        ticketType !== "UPDATE_GROUP_INLINE_POLICY" &&
        ticketType !== "ADOPT_ROLE_INLINE_POLICIES"
      ) {
        setRoleOptions([]);
        return;
      }
      if (!accountId) {
        setRoleOptions([]);
        return;
      }
      api
        .listRoles({ account_id: accountId, q })
        .then((roles) =>
          setRoleOptions(
            roles.map((r) => ({
              value: r.principal_name,
              label: r.principal_name,
              id: r.id,
            })),
          ),
        )
        .catch(() => setRoleOptions([]));
    },
    [ticketType, accountId],
  );
  useEffect(() => {
    if (
      (ticketType !== "UPDATE_ROLE" &&
        ticketType !== "UPDATE_GROUP_INLINE_POLICY" &&
        ticketType !== "ADOPT_ROLE_INLINE_POLICIES") ||
      !accountId
    ) {
      setRoleOptions([]);
      return;
    }
    loadRoles();
  }, [ticketType, accountId, loadRoles]);
  const handleRoleSearch = useCallback(
    (value: string) => {
      if (roleSearchTimer.current) clearTimeout(roleSearchTimer.current);
      roleSearchTimer.current = setTimeout(() => loadRoles(value.trim()), 300);
    },
    [loadRoles],
  );

  // ATTACH_USER_POLICY：加载授权主体（用户/组/角色，按 principal_type 切换，服务端搜索）
  const attachPrincipalType = (Form.useWatch("principal_type", form) as string) || "User";
  const attachOperation = (Form.useWatch("operation", form) as string) || "attach";
  const detachOperation = attachOperation === "detach";
  // 主体选择器的文案随类型切换（三种类型共用一套 Select）。
  const attachHint =
    attachPrincipalType === "Group"
      ? {
          label: t("newTicket.form.pickGroupFromInventory"),
          pick: t("newTicket.attach.group.pick"),
          search: t("newTicket.attach.group.search"),
          none: t("newTicket.attach.group.none"),
        }
      : attachPrincipalType === "Role"
        ? {
            label: t("newTicket.form.pickRoleFromInventory"),
            pick: t("newTicket.attach.role.pick"),
            search: t("newTicket.attach.role.search"),
            none: t("newTicket.attach.role.none"),
          }
        : {
            label: t("newTicket.form.pickUserFromInventory"),
            pick: t("newTicket.attach.user.pick"),
            search: t("newTicket.attach.user.search"),
            none: t("newTicket.attach.user.none"),
          };
  const userSearchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadPrincipals = useCallback(
    (q?: string) => {
      if (ticketType !== "ATTACH_USER_POLICY" || !accountId) {
        setUserOptions([]);
        return;
      }
      if (attachPrincipalType === "Role") {
        api
          .listRoles({ account_id: accountId, q })
          .then((roles) =>
            setUserOptions(
              roles.map((r) => ({ value: r.principal_name, label: r.principal_name, id: r.id })),
            ),
          )
          .catch(() => setUserOptions([]));
        return;
      }
      if (attachPrincipalType === "Group") {
        api
          .listGroups({ account_id: accountId, q, limit: 100 })
          .then((res) =>
            setUserOptions(
              res.groups.map((g) => ({ value: g.group_name, label: g.group_name, id: g.id })),
            ),
          )
          .catch(() => setUserOptions([]));
        return;
      }
      api
        .listUsers({ account_id: accountId, q })
        .then((users) =>
          setUserOptions(
            users.map((u) => ({
              value: u.principal_name,
              label: u.principal_name,
              id: u.id,
            })),
          ),
        )
        .catch(() => setUserOptions([]));
    },
    [ticketType, accountId, attachPrincipalType],
  );
  useEffect(() => {
    if (ticketType !== "ATTACH_USER_POLICY" || !accountId) {
      setUserOptions([]);
      return;
    }
    loadPrincipals();
  }, [ticketType, accountId, loadPrincipals]);
  // 切换主体类型（用户/组/角色）时清空已选主体，避免不同类型的名字混填。
  // 预填跳转会一次性写入 principal_type + principal_name：挂载时表单还是默认的
  // "User"，预填落地会把它变成目标类型——这一次跳变不是用户切换，必须跳过，
  // 否则预填的主体刚写进去就被清掉了。之后真正的用户切换照常清空。
  const presetPrincipalType = preset.principal_type ? String(preset.principal_type) : "";
  const skipPresetJump = useRef(presetPrincipalType !== "");
  const prevAttachPrincipalType = useRef<string | null>(null);
  useEffect(() => {
    if (skipPresetJump.current && attachPrincipalType === presetPrincipalType) {
      skipPresetJump.current = false;
      prevAttachPrincipalType.current = attachPrincipalType;
      return;
    }
    if (
      prevAttachPrincipalType.current !== null &&
      prevAttachPrincipalType.current !== attachPrincipalType
    ) {
      form.setFieldValue("principal_name", undefined);
    }
    prevAttachPrincipalType.current = attachPrincipalType;
  }, [attachPrincipalType, form, presetPrincipalType]);
  const handleUserSearch = useCallback(
    (value: string) => {
      if (userSearchTimer.current) clearTimeout(userSearchTimer.current);
      userSearchTimer.current = setTimeout(() => loadPrincipals(value.trim()), 300);
    },
    [loadPrincipals],
  );

  // 选中主体后拉取它当前挂载的托管策略：解绑用它收敛选项（只列能解绑的），
  // 挂载用它给选择器打「已挂载」标注——不标注的话，挂载时根本看不出哪些已经挂着。
  // 数据源就是资产清单的主体详情接口，和挂载选择器同源，不引入新的后端能力。
  const attachPrincipalName =
    ((Form.useWatch("principal_name", form) as string | undefined) || "").trim();
  const selectedAttachPolicy =
    ((Form.useWatch("managed_policy_arn", form) as string | undefined) || "").trim();
  const [attachedPolicies, setAttachedPolicies] = useState<AttachedPolicy[] | null>(null);
  const [attachedLoading, setAttachedLoading] = useState(false);
  const [attachedFailed, setAttachedFailed] = useState(false);
  const attachedRequest = useRef(0);
  useEffect(() => {
    if (ticketType !== "ATTACH_USER_POLICY" || !accountId || !attachPrincipalName) {
      attachedRequest.current += 1;
      setAttachedPolicies(null);
      setAttachedLoading(false);
      setAttachedFailed(false);
      return;
    }
    const requestId = ++attachedRequest.current;
    setAttachedLoading(true);
    setAttachedFailed(false);
    const finish = (policies: AttachedPolicy[] | null) => {
      if (attachedRequest.current !== requestId) return;
      setAttachedLoading(false);
      if (policies === null) {
        setAttachedFailed(true);
        setAttachedPolicies(null);
        return;
      }
      setAttachedPolicies(policies);
    };
    const load = async () => {
      try {
        let detail: AttachedPolicy[];
        if (attachPrincipalType === "Role") {
          const roles = await api.listRoles({
            account_id: accountId,
            q: attachPrincipalName,
          });
          const role = roles.find((r) => r.principal_name === attachPrincipalName);
          if (!role) return finish([]);
          detail = (await api.getPrincipal(role.id)).policies ?? [];
        } else if (attachPrincipalType === "Group") {
          const groups = await api.listGroups({
            account_id: accountId,
            q: attachPrincipalName,
            limit: 50,
          });
          const group = groups.groups.find((g) => g.group_name === attachPrincipalName);
          if (!group) return finish([]);
          detail = (await api.getGroup(group.id)).policies ?? [];
        } else {
          const users = await api.listUsers({ account_id: accountId, q: attachPrincipalName });
          const user = users.find((u) => u.principal_name === attachPrincipalName);
          if (!user) return finish([]);
          detail = (await api.getPrincipal(user.id)).policies ?? [];
        }
        // 解绑只销毁托管策略挂载关系，内联策略不在本工单类型范围内。
        return finish(detail.filter((p) => p.policy_type === "managed"));
      } catch {
        return finish(null);
      }
    };
    void load();
  }, [ticketType, accountId, attachPrincipalType, attachPrincipalName]);

  // ATTACH_USER_POLICY / UPDATE_MANAGED_POLICY：加载托管策略清单（服务端搜索，
  // 名称+ARN）。UPDATE_MANAGED_POLICY 只列客户自管策略（AWS 托管策略不可变更）。
  // CREATE_MANAGED_POLICY 打开 import 时同样需要清单：纳管只能选本账号已存在的
  // 客户自管策略（AWS 托管策略的 ARN 在 aws 分区，不可能被本账号 import）。
  const customerManagedOnly =
    ticketType === "UPDATE_MANAGED_POLICY" ||
    (ticketType === "CREATE_MANAGED_POLICY" && Boolean(adoptExisting));
  const needsPolicyCatalog =
    ticketType === "ATTACH_USER_POLICY" ||
    ticketType === "UPDATE_MANAGED_POLICY" ||
    ticketType === "CREATE_USER" ||
    ticketType === "CREATE_GROUP" ||
    ticketType === "CREATE_ROLE" ||
    customerManagedOnly;
  const policySearchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const policyLoadRequestRef = useRef(0);
  const loadPolicies = useCallback(
    (q?: string) => {
      const requestID = ++policyLoadRequestRef.current;
      // 必须先选账号：不带账号的策略下拉会泄漏其他账号的资源。
      if (!needsPolicyCatalog || !accountId) {
        setPolicyOptions([]);
        setPolicyOptionsError(null);
        return;
      }
      setPolicyOptionsError(null);
      api
        .listPolicies({ q, account_id: accountId })
        .then((policies) => {
          if (requestID !== policyLoadRequestRef.current) return;
          const filtered = customerManagedOnly
            ? policies.filter(
                (p) => p.policy_arn && !p.policy_arn.startsWith("arn:aws:iam::aws:policy/"),
              )
            : policies;
          setPolicyOptions(
            filtered.map((p) => ({
              value: p.policy_arn ?? p.policy_name,
              label: `${p.policy_name}${p.policy_arn ? `（${p.policy_arn}）` : ""}`,
              name: p.policy_name,
              arn: p.policy_arn,
              id: p.id,
            })),
          );
        })
        .catch((error: unknown) => {
          if (requestID !== policyLoadRequestRef.current) return;
          setPolicyOptionsError(
            error instanceof ApiError ? error.message : String(error),
          );
        });
    },
    [needsPolicyCatalog, customerManagedOnly, accountId],
  );
  useEffect(() => {
    if (!needsPolicyCatalog) {
      policyLoadRequestRef.current++;
      setPolicyOptions([]);
      setPolicyOptionsError(null);
      return;
    }
    loadPolicies();
  }, [needsPolicyCatalog, loadPolicies]);
  const handlePolicySearch = useCallback(
    (value: string) => {
      if (policySearchTimer.current) clearTimeout(policySearchTimer.current);
      policySearchTimer.current = setTimeout(() => loadPolicies(value.trim()), 300);
    },
    [loadPolicies],
  );

  // 解绑时选择器收敛到"该主体当前真正挂着的策略"：在全量策略里盲猜最容易选错。
  // 拿不到挂载清单（加载中/接口失败）时退回全量搜索，不阻断操作。
  // 挂载时保留全量搜索，但给已挂载的项打 attached 标记（下拉里渲染成「已挂载」）。
  const attachPolicyOptions = useMemo(() => {
    if (!detachOperation) {
      if (!attachedPolicies) return policyOptions;
      const attachedArns = new Set<string>();
      attachedPolicies.forEach((p) => {
        if (p.policy_arn) attachedArns.add(p.policy_arn);
      });
      return policyOptions.map((option) => ({
        ...option,
        attached: Boolean(option.arn && attachedArns.has(option.arn)),
      }));
    }
    if (!attachedPolicies) return policyOptions;
    const options = attachedPolicies
      .filter((p) => p.policy_arn && p.policy_name)
      .map((p) => ({
        value: p.policy_arn as string,
        label: `${p.policy_name}（${p.policy_arn}）`,
        name: p.policy_name as string,
        arn: p.policy_arn,
        id: p.policy_id,
      }));
    const selected = (form.getFieldValue("managed_policy_arn") as string | undefined) ?? "";
    if (selected && !options.some((option) => option.value === selected)) {
      options.push({ value: selected, label: selected, name: selected, arn: selected, id: 0 });
    }
    return options;
  }, [detachOperation, attachedPolicies, policyOptions, form]);
  // 拿到挂载清单后才把选择器收敛到已挂载策略；加载中/失败仍是全量搜索。
  const detachScoped = detachOperation && attachedPolicies !== null;
  // 仅在"确实没有可解绑的挂载、且表单也没预填值"时禁用，避免挡住库存跳转的预填流程。
  const detachNothingToPick =
    detachOperation &&
    attachedPolicies !== null &&
    attachedPolicies.length === 0 &&
    !selectedAttachPolicy;
  // 挂载模式下当前选中的策略是否已是该主体的挂载：选中存量挂载时提示
  // 提交后预览会带 import（平台无历史工单的挂载走 import 纳管）。
  const selectedPolicyAttached =
    !detachOperation &&
    attachedPolicies !== null &&
    selectedAttachPolicy !== "" &&
    attachedPolicies.some((p) => p.policy_arn === selectedAttachPolicy);

  // UPDATE_MANAGED_POLICY：选中策略后拉取详情，预填文档编辑器并显示引用计数。
  const selectedPolicyId = Form.useWatch("update_policy_id", form) as number | undefined;
  const policyDetailRef = useRef<number | null>(null);
  useEffect(() => {
    if (ticketType !== "UPDATE_MANAGED_POLICY" || !selectedPolicyId) {
      setPolicyDetail(null);
      return;
    }
    if (policyDetailRef.current === selectedPolicyId) return;
    policyDetailRef.current = selectedPolicyId;
    api
      .getPolicy(selectedPolicyId)
      .then((detail) => {
        setPolicyDetail({
          document: detail.policy_document,
          attached_principals: detail.attached_principals,
          attached_groups: detail.attached_groups,
        });
        if (detail.policy_document) {
          form.setFieldValue(
            "update_policy_document",
            JSON.stringify(detail.policy_document, null, 2),
          );
        }
      })
      .catch(() => setPolicyDetail(null));
  }, [ticketType, selectedPolicyId, form]);

  // Load groups for inline-policy editing, user creation, existing-group adoption,
  // and group membership tickets.
  useEffect(() => {
    if (
      (ticketType !== "UPDATE_GROUP_INLINE_POLICY" &&
        ticketType !== "CREATE_USER" &&
        ticketType !== "CREATE_GROUP" &&
        ticketType !== "UPDATE_GROUP_MEMBERSHIP") ||
      !accountId
    ) {
      setGroupOptions([]);
      return;
    }
    loadGroups();
  }, [ticketType, accountId, loadGroups]);

  // CREATE_GROUP / UPDATE_GROUP_MEMBERSHIP：加载可选成员用户清单。
  useEffect(() => {
    if ((ticketType !== "CREATE_GROUP" && ticketType !== "UPDATE_GROUP_MEMBERSHIP") || !accountId) {
      setCreateMemberOptions([]);
      return;
    }
    api
      .listUsers({ account_id: accountId })
      .then((users) =>
        setCreateMemberOptions(
          users.map((u) => ({ value: u.principal_name, label: u.principal_name, id: u.id })),
        ),
      )
      .catch(() => setCreateMemberOptions([]));
  }, [ticketType, accountId]);

  // UPDATE_GROUP_MEMBERSHIP：拉取所选组的现有成员。移除的候选就是这份名单，
  // 加入的候选则是「清单用户 - 这份名单」。组来自预填而尚未进入选项列表时，
  // 按组名精确回查一次 id。
  useEffect(() => {
    if (ticketType !== "UPDATE_GROUP_MEMBERSHIP" || !accountId || !membershipGroupName) {
      setMembershipMembers([]);
      return;
    }
    let cancelled = false;
    const resolveGroupId = () => {
      if (membershipGroupId) return Promise.resolve(membershipGroupId);
      return api
        .listGroups({ account_id: accountId, q: membershipGroupName, limit: 50 })
        .then((res) => res.groups.find((g) => g.group_name === membershipGroupName)?.id)
        .catch(() => undefined);
    };
    setMembershipMembersLoading(true);
    resolveGroupId()
      .then((id) => (id ? api.getGroup(id) : null))
      .then((group) => {
        if (cancelled) return;
        setMembershipMembers(
          (group?.members ?? []).map((member) => ({
            value: member.principal_name,
            label: member.principal_name,
          })),
        );
      })
      .catch(() => {
        if (!cancelled) setMembershipMembers([]);
      })
      .finally(() => {
        if (!cancelled) setMembershipMembersLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ticketType, accountId, membershipGroupName, membershipGroupId]);

  const membershipMemberNames = useMemo(
    () => new Set(membershipMembers.map((member) => member.value)),
    [membershipMembers],
  );
  const membershipUserOptions = useMemo(
    () =>
      membershipOperation === "remove"
        ? membershipMembers
        : createMemberOptions.filter((user) => !membershipMemberNames.has(user.value)),
    [membershipOperation, membershipMembers, createMemberOptions, membershipMemberNames],
  );
  // 换组或切换增删方向时候选集整体变了，已选用户必须先清掉，否则会把
  // 不属于新候选集的用户名带进工单。
  const membershipSelectionKey = `${membershipGroupName}|${membershipOperation}`;
  const lastMembershipSelectionKey = useRef(membershipSelectionKey);
  useEffect(() => {
    if (lastMembershipSelectionKey.current === membershipSelectionKey) return;
    lastMembershipSelectionKey.current = membershipSelectionKey;
    form.setFieldsValue({ membership_users: [] });
  }, [membershipSelectionKey, form]);

  // CREATE_USER：打开 import 后从资产清单选择要纳管的既有用户（服务端搜索，
  // 用户量超过一屏时也不会漏）。选名字而不是手输：手输拼错会拿到 import 一个
  // 不存在的资源，Terraform 到 apply 阶段才失败。
  const [adoptUserOptions, setAdoptUserOptions] = useState<
    { value: string; label: string; arn: string }[]
  >([]);
  const adoptUserSearchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadAdoptUsers = useCallback(
    (q?: string) => {
      if (ticketType !== "CREATE_USER" || !adoptExisting || !accountId) {
        setAdoptUserOptions([]);
        return;
      }
      api
        .listUsers({ account_id: accountId, q })
        .then((users) =>
          setAdoptUserOptions(
            users.map((u) => ({ value: u.principal_name, label: u.principal_name, arn: u.arn })),
          ),
        )
        .catch(() => setAdoptUserOptions([]));
    },
    [ticketType, adoptExisting, accountId],
  );
  useEffect(() => {
    loadAdoptUsers();
  }, [loadAdoptUsers]);
  const handleAdoptUserSearch = useCallback(
    (value: string) => {
      if (adoptUserSearchTimer.current) clearTimeout(adoptUserSearchTimer.current);
      adoptUserSearchTimer.current = setTimeout(() => loadAdoptUsers(value.trim()), 300);
    },
    [loadAdoptUsers],
  );

  // 纳管已存在资源时 path 不能靠手填：策略的 import ID 就是 ARN（含 path），
  // 用户/角色的 path 又是 ForceNew 属性。填错轻则 apply 失败，重则计划出资源
  // 替换（ARN 变化 → 挂载关系与实例配置全部断裂）。ARN 清单里已经有了，直接反解。
  const handleAdoptUserSelect = useCallback(
    (name: string) => {
      const option = adoptUserOptions.find((candidate) => candidate.value === name);
      if (!option?.arn) return;
      form.setFieldValue("create_user_path", iamPathFromARN(option.arn, "user"));
    },
    [adoptUserOptions, form],
  );
  const handleAdoptPolicySelect = useCallback(
    (name: string) => {
      const option = policyOptions.find((candidate) => candidate.name === name);
      if (!option) return;
      form.setFieldValue(
        "create_policy_path",
        option.arn ? iamPathFromARN(option.arn, "policy") : "/",
      );
      // 纳管只认策略文档，预填现网文档，避免手写一份「近似」文档后 apply 把策略内容覆盖掉。
      if (!option.id) return;
      api
        .getPolicy(option.id)
        .then((detail) => {
          if (detail.policy_document === undefined || detail.policy_document === null) return;
          form.setFieldValue(
            "create_policy_document",
            JSON.stringify(detail.policy_document, null, 2),
          );
        })
        .catch(() => {
          // 预填失败不阻断：用户仍可手填文档，提交时后端照常校验。
        });
    },
    [policyOptions, form],
  );
  // 纳管下拉以策略名作为提交值（后端用 path + name 定位资源并校验存在性）。
  // 同名不同 path 的客户自管策略在单账号内极罕见，按名字去重避免重复 key 让
  // antd 的选中项错位；label 里保留了完整 ARN，用户仍可核对是哪一条。
  const adoptPolicyOptions = useMemo(() => {
    const seen = new Set<string>();
    const options: { value: string; label: string }[] = [];
    policyOptions.forEach((policy) => {
      if (seen.has(policy.name)) return;
      seen.add(policy.name);
      options.push({ value: policy.name, label: policy.label });
    });
    return options;
  }, [policyOptions]);

  const selectedInlinePrincipalType = Form.useWatch(
    "update_inline_principal_type",
    form,
  ) as string | undefined;
  const selectedInlineGroup = Form.useWatch("update_inline_group", form) as
    | string
    | undefined;
  const selectedInlineRole = Form.useWatch("update_inline_role", form) as
    | string
    | undefined;
  useEffect(() => {
    if (ticketType !== "UPDATE_GROUP_INLINE_POLICY") {
      setInlinePolicyOptions([]);
      return;
    }
    if (selectedInlinePrincipalType === "Role") {
      const role = roleOptions.find((r) => r.value === selectedInlineRole);
      if (!role?.id) {
        setInlinePolicyOptions([]);
        return;
      }
      api
        .getPrincipal(role.id)
        .then((detail) =>
          setInlinePolicyOptions(
            (detail.policies ?? [])
              .filter((p) => p.policy_type === "inline")
              .map((p) => ({
                value: p.policy_id,
                label: p.policy_name ?? String(p.policy_id),
                name: p.policy_name ?? "",
              })),
          ),
        )
        .catch(() => setInlinePolicyOptions([]));
      return;
    }
    if (!selectedInlineGroup) {
      setInlinePolicyOptions([]);
      return;
    }
    const group = groupOptions.find((g) => g.value === selectedInlineGroup);
    if (!group) return;
    api
      .listGroupPolicies(group.id)
      .then((policies) =>
        setInlinePolicyOptions(
          (policies ?? [])
            .filter((p) => p.policy_type === "inline")
            .map((p) => ({
              value: p.policy_id,
              label: p.policy_name ?? String(p.policy_id),
              name: p.policy_name ?? "",
            })),
        ),
      )
      .catch(() => setInlinePolicyOptions([]));
  }, [
    ticketType,
    selectedInlinePrincipalType,
    selectedInlineGroup,
    selectedInlineRole,
    groupOptions,
    roleOptions,
  ]);

  // 选中内联策略后拉取文档预填。内联策略以「策略名」为表单值：清单里没有的
  // 策略（被线下删除 / 尚未同步）也能直接输入名字提单，Terraform 侧按声明恢复。
  const selectedInlinePolicyName = Form.useWatch("update_inline_policy_id", form) as
    | string
    | undefined;
  const inlineDetailRef = useRef<string | null>(null);
  useEffect(() => {
    if (ticketType !== "UPDATE_GROUP_INLINE_POLICY" || !selectedInlinePolicyName) {
      return;
    }
    const policyName = selectedInlinePolicyName.trim();
    if (!policyName || inlineDetailRef.current === policyName) return;
    const option = inlinePolicyOptions.find((p) => p.name === policyName);
    if (!option) {
      // 自定义（清单外）策略名：没有现网文档可预填，由用户自行填写。
      return;
    }
    inlineDetailRef.current = policyName;
    // 内联策略必须走 /aws/inline-policies/:id（GetInlinePolicy）；此前调用的
    // /aws/policies/:id 只查托管策略表，内联策略必然 404，被 catch 吞掉后
    // 编辑器预填为空。
    api
      .getInlinePolicy(option.value)
      .then((detail) => {
        if (detail.policy_document) {
          form.setFieldValue(
            "update_policy_document",
            JSON.stringify(detail.policy_document, null, 2),
          );
        }
      })
      .catch(() => {});
  }, [ticketType, selectedInlinePolicyName, inlinePolicyOptions, form]);

  // UPDATE_ROLE：选中角色后回填当前配置（信任策略/描述/tags），便于在其基础上修改。
  // tags 必须完整回填：AWS provider 的 tags 是整表覆盖，漏掉就会在 apply 时删除。
  const selectedRole = Form.useWatch("principal_name", form) as string | undefined;
  const backfilledRef = useRef<string>("");
  useEffect(() => {
    if (ticketType !== "UPDATE_ROLE" || !accountId || !selectedRole) {
      backfilledRef.current = "";
      setRoleTagsLoaded(false);
      setRoleTagsError(null);
      return;
    }
    const roleKey = `${accountId}:${selectedRole}`;
    if (backfilledRef.current === roleKey) return;
    backfilledRef.current = roleKey;
    let cancelled = false;
    setRoleTagsLoaded(false);
    setRoleTagsError(null);
    api
      .listRoles({ account_id: accountId, q: selectedRole })
      .then(async (roles) => {
        const match = roles.find((r) => r.principal_name === selectedRole);
        if (!match) {
          throw new Error(t("newTicket.error.roleAssetNotFound", { name: selectedRole }));
        }
        return api.getRoleDetail(match.id);
      })
      .then((detail) => {
        if (cancelled) return;
        const tags = detail.tags ?? {};
        const patch: Record<string, unknown> = {
          update_trust_policy: detail.trust_policy
            ? JSON.stringify(detail.trust_policy, null, 2)
            : "",
          update_description: detail.description ?? "",
          update_tags: Object.entries(tags)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([key, value]) => `${key}=${value}`)
            .join("\n"),
        };
        form.setFieldsValue(patch);
        setRoleTagsLoaded(true);
        setRoleTagsError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        backfilledRef.current = "";
        const reason =
          error instanceof Error ? error.message : t("newTicket.error.roleDetailLoadFailed");
        const messageText = t("newTicket.error.roleTagsReadFailed", {
          name: selectedRole,
          reason,
        });
        setRoleTagsLoaded(false);
        setRoleTagsError(messageText);
        message.error(messageText);
      });
    return () => {
      cancelled = true;
    };
  }, [ticketType, accountId, selectedRole, form, t]);

  // UPDATE_ROLE：信任策略变更时强制人工审批（后端也会强制校验）
  const trustPolicyText = Form.useWatch("update_trust_policy", form) as string | undefined;
  const trustPolicyChanged = useMemo(() => {
    if (ticketType !== "UPDATE_ROLE") return false;
    const text = trustPolicyText;
    if (!text || !text.trim()) return false;
    try {
      const parsed = JSON.parse(text);
      return JSON.stringify(parsed) !== JSON.stringify(JSON.parse(TRUST_POLICY_TEMPLATE));
    } catch {
      return false;
    }
  }, [ticketType, trustPolicyText]);

  useEffect(() => {
    if (trustPolicyChanged && approvalMode !== "MANUAL") {
      form.setFieldsValue({ approval_mode: "MANUAL" });
      message.warning(t("newTicket.warning.trustPolicyChange"));
    }
  }, [trustPolicyChanged, approvalMode, form, t]);

  // 审批人列表随账号变化
  useEffect(() => {
    if (!accountId) {
      setApprovers([]);
      return;
    }
    api.listApprovers(accountId).then(setApprovers).catch(() => setApprovers([]));
  }, [accountId]);

  const buildPayload = useCallback((): CreateTicketRequest | null => {
    const values = form.getFieldsValue();
    const base: CreateTicketRequest = {
      ticket_type: values.ticket_type,
      account_id: values.account_id ?? 0,
      approval_mode: values.approval_mode,
      approver_ids: values.approval_mode === "MANUAL" ? values.approver_ids ?? [] : [],
    };
    if (values.ticket_type !== "ROLLBACK") {
      base.principal_name = values.principal_name?.trim() ?? "";
    }
    if (values.ticket_type === "ATTACH_USER_POLICY") {
      base.managed_policy_arn = values.managed_policy_arn?.trim();
      base.principal_type =
        values.principal_type === "Role"
          ? "Role"
          : values.principal_type === "Group"
            ? "Group"
            : "User";
      base.operation = values.operation === "detach" ? "detach" : "attach";
      // 必须 return：否则落入尾部 CREATE_ROLE 解析块，把 abstract_policy/role
      // 垃圾字段塞进挂载 payload（此前靠 principal_name 恰好非空才"碰巧能用"）。
      return base;
    }
    if (values.ticket_type === "ROLLBACK") {
      base.target_ticket_no = values.target_ticket_no?.trim();
      // 同上：不 return 会落入 CREATE_ROLE 尾块，空角色名直接 return null，
      // 回滚工单永远无法构建 payload（提示「角色名不能为空」，极具误导性）。
      return base;
    }
    if (values.ticket_type === "ADOPT_ROLE_INLINE_POLICIES") {
      base.principal_type = "Role";
      return base;
    }
    if (values.ticket_type === "UPDATE_ROLE") {
      const config = buildUpdateRolePayload(values, base, form, roleTagsLoaded, t);
      if (!config) return null;
      base.update_role = config;
      return base;
    }
    if (values.ticket_type === "UPDATE_MANAGED_POLICY") {
      const option = policyOptions.find((p) => p.id === values.update_policy_id);
      if (!option?.arn) {
        message.error(t("newTicket.error.selectManagedPolicyToUpdate"));
        return null;
      }
      const document = parsePolicyDocument(values.update_policy_document, t);
      if (document === null) return null;
      base.principal_name = option.name;
      base.update_policy = {
        policy_arn: option.arn,
        policy_name: option.name,
        document,
      };
      return base;
    }
    if (values.ticket_type === "UPDATE_GROUP_INLINE_POLICY") {
      // 策略名可直接输入（清单外的策略名 = 被线下删除/未同步，按声明恢复）。
      const inlineName = (values.update_inline_policy_id ?? "").trim();
      const principalType = values.update_inline_principal_type === "Role" ? "Role" : "Group";
      const ownerName =
        principalType === "Role" ? values.update_inline_role : values.update_inline_group;
      if (!ownerName || !inlineName) {
        message.info(
          principalType === "Role"
            ? t("newTicket.error.selectRoleAndInlinePolicy")
            : t("newTicket.error.selectGroupAndInlinePolicy"),
        );
        return null;
      }
      const document = parsePolicyDocument(values.update_policy_document, t);
      if (document === null) return null;
      base.principal_name = ownerName;
      base.principal_type = principalType;
      base.update_policy = {
        ...(principalType === "Role"
          ? { role_name: ownerName }
          : { group_name: ownerName }),
        inline_policy_name: inlineName,
        document,
      };
      return base;
    }
    if (values.ticket_type === "UPDATE_GROUP_MEMBERSHIP") {
      const group = values.membership_group?.trim();
      const users = (values.membership_users ?? []).map((u) => u.trim()).filter(Boolean);
      if (!group || users.length === 0) {
        message.error(t("newTicket.error.selectGroupAndMembers"));
        return null;
      }
      base.principal_name = group;
      base.principal_type = "Group";
      base.update_membership = {
        group_name: group,
        operation: values.membership_operation === "remove" ? "remove" : "add",
        users,
      };
      return base;
    }
    if (values.ticket_type === "CREATE_MANAGED_POLICY") {
      const name = values.principal_name?.trim() ?? "";
      if (!name) {
        message.error(t("newTicket.error.policyNameRequired"));
        return null;
      }
      const document = parsePolicyDocument(values.create_policy_document, t);
      if (document === null) return null;
      const tags = parseTagLines(values.create_policy_tags, t("newTicket.field.tag"), t);
      if (tags === null) return null;
      base.principal_name = name;
      base.principal_type = "Policy";
      base.adopt_existing = Boolean(values.adopt_existing);
      base.create_managed_policy = {
        name,
        description: values.create_policy_description?.trim() || undefined,
        path: values.create_policy_path?.trim() || "/",
        document,
        tags,
      };
      return base;
    }
    if (values.ticket_type === "CREATE_USER") {
      const name = values.principal_name?.trim() ?? "";
      if (!name) {
        message.error(t("newTicket.error.userNameRequired"));
        return null;
      }
      const tags = parseTagLines(values.create_user_tags, t("newTicket.field.tag"), t);
      if (tags === null) return null;
      // 纳管既有用户时不能声明成员/挂载集合：这些是「完整集合」语义，Terraform
      // 会把未列出的关系删掉，而后端同样拒绝这种组合。开关打开前填过的值在这里
      // 收敛掉，否则提交直接被拒。
      const adopting = Boolean(values.adopt_existing);
      base.principal_name = name;
      base.principal_type = "User";
      base.adopt_existing = adopting;
      base.create_user = {
        name,
        path: values.create_user_path?.trim() || "/",
        group_names: adopting ? [] : values.create_user_groups ?? [],
        policy_arns: adopting ? [] : values.create_user_policy_arns ?? [],
        tags,
      };
      return base;
    }
    if (values.ticket_type === "CREATE_GROUP") {
      const name = values.principal_name?.trim() ?? "";
      if (!name) {
        message.error(t("newTicket.error.groupNameRequired"));
        return null;
      }
      const adopting = Boolean(values.adopt_existing);
      const tags = adopting
        ? {}
        : parseTagLines(values.create_group_tags, t("newTicket.field.tag"), t);
      if (tags === null) return null;
      base.principal_name = name;
      base.principal_type = "Group";
      base.adopt_existing = adopting;
      base.create_group = {
        name,
        path: adopting ? "/" : values.create_group_path?.trim() || "/",
        member_user_names: adopting ? [] : values.create_group_members ?? [],
        policy_arns: adopting ? [] : values.create_group_policy_arns ?? [],
        tags,
      };
      return base;
    }
    // CREATE_ROLE：解析抽象策略 JSON 和信任策略
    // 角色名
    const roleName = values.principal_name?.trim() ?? "";
    if (!roleName) {
      message.error(t("newTicket.error.roleNameRequired"));
      return null;
    }
    // 抽象策略可选：留空表示不声明任何权限（零权限角色）——不发送
    // abstract_policy，后端据此只生成角色本体。
    // 文本框同时接受抽象写法与 AWS IAM 文档写法：AWS 文档（Statement/Action/
    // Resource）就地转成抽象模型再提交，动作映射与风险评审链路不变。
    const policyText = (values.policy_text ?? "").trim();
    if (policyText) {
      try {
        base.abstract_policy = parseAbstractPolicyText(policyText, roleName);
      } catch (error) {
        message.error(
          t("newTicket.error.policyInvalidJson", {
            message: error instanceof AbstractPolicyParseError ? error.detail : String(error),
          }),
        );
        return null;
      }
    }
    let trustPolicy: Record<string, unknown> = {};
    try {
      trustPolicy = JSON.parse(values.trust_policy || "{}");
    } catch (error) {
      message.error(t("newTicket.error.trustPolicyInvalidJsonDetail", { message: String(error) }));
      return null;
    }
    base.role = {
      name: roleName,
      trust_policy: trustPolicy,
      policy_arns: values.create_role_policy_arns ?? [],
    };
    return base;
  }, [form, policyOptions, roleTagsLoaded, t]);

  // 实时校验的就绪门槛：必填项齐全才发请求。缺失时静默跳过并清掉旧结果——
  // 此前残缺 payload（account_id=0、空主体名、空目标工单号等）必然 400，
  // UPDATE_MANAGED_POLICY / UPDATE_GROUP_INLINE_POLICY 还会自动弹出
  // 「请选择…」toast，未操作先报错，误导用户。
  const autoValidateReady = useCallback((): boolean => {
    const values = form.getFieldsValue();
    // 人工审批必须已选审批人（自动审批无需），否则后端 400 噪音。
    if ((values.approval_mode ?? "MANUAL") !== "AUTO" && !(values.approver_ids ?? []).length) {
      return false;
    }
    if (values.ticket_type === "ROLLBACK") {
      return Boolean(values.target_ticket_no?.trim());
    }
    if (!values.account_id) return false;
    if (values.ticket_type === "ATTACH_USER_POLICY") {
      return Boolean(values.principal_name?.trim()) && Boolean(values.managed_policy_arn?.trim());
    }
    if (values.ticket_type === "UPDATE_GROUP_MEMBERSHIP") {
      // 主体由所选组唯一确定（payload 里补 Group + 组名），就绪只看组与成员；
      // 不能落到末尾的 principal_name 兜底判断上，否则永远提示“补全必填项”。
      return (
        Boolean(values.membership_group?.trim()) &&
        (values.membership_users ?? []).some((user) => Boolean(user?.trim()))
      );
    }
    if (values.ticket_type === "UPDATE_MANAGED_POLICY") {
      const option = policyOptions.find((p) => p.id === values.update_policy_id);
      // 文档由选中策略后异步预填，未就绪前不发（避免空文档 toast 与 400）。
      return Boolean(option?.arn) && Boolean((values.update_policy_document ?? "").trim());
    }
    if (values.ticket_type === "UPDATE_GROUP_INLINE_POLICY") {
      const principalType = values.update_inline_principal_type === "Role" ? "Role" : "Group";
      const ownerName =
        principalType === "Role" ? values.update_inline_role : values.update_inline_group;
      return (
        Boolean(ownerName) &&
        Boolean((values.update_inline_policy_id ?? "").trim()) &&
        Boolean((values.update_policy_document ?? "").trim())
      );
    }
    if (values.ticket_type === "UPDATE_ROLE") {
      // 标签未回填成功前不自动校验：空 tags 会被当成“删除全部 tags”。
      return Boolean(values.principal_name?.trim()) && roleTagsLoaded;
    }
    if (values.ticket_type === "CREATE_MANAGED_POLICY") {
      return (
        Boolean(values.principal_name?.trim()) &&
        Boolean((values.create_policy_document ?? "").trim())
      );
    }
    if (values.ticket_type === "CREATE_USER" || values.ticket_type === "CREATE_GROUP") {
      return Boolean(values.principal_name?.trim());
    }
    // CREATE_ROLE：账号 + 角色名（其余字段可留空后补；零权限角色仅提示不阻断）。
    return Boolean(values.principal_name?.trim());
  }, [form, policyOptions, roleTagsLoaded]);

  // 防抖实时校验（与提交走同一后端校验路径）
  const scheduleValidate = useCallback(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      if (!autoValidateReady()) {
        // 必填项未齐：静默跳过，仅清掉上一次的过期结果。
        setValidationError(null);
        setValidationOk(null);
        setValidationChecks([]);
        setTerraformPreview(null);
        return;
      }
      const payload = buildPayload();
      if (!payload) return;
      api
        .validateTicket(payload)
        .then((res) => {
          setValidationError(null);
          setValidationOk(t("newTicket.hint.validationPassed"));
          setValidationChecks(Array.isArray(res.checks) ? res.checks : []);
          setTerraformPreview(res.terraform_preview ?? null);
        })
        .catch((err) => {
          if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
            // 4xx 都是真实校验消息（基线违规 422 / 回滚前置缺失 400 等）：
            // 就绪门槛已保证必填项齐全，不再静默吞掉。
            setValidationError(err);
            setValidationOk(null);
          }
          setValidationChecks([]);
          setTerraformPreview(null);
        });
    }, 600);
  }, [buildPayload, autoValidateReady, t]);

  useEffect(() => {
    scheduleValidate();
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [scheduleValidate, ticketType, accountId]);

  const submit = async () => {
    try {
      await form.validateFields();
    } catch {
      return;
    }
    const payload = buildPayload();
    if (!payload) return;
    setSubmitting(true);
    try {
      const ticket = await api.createTicket(payload);
      message.success(t("newTicket.success.ticketCreated", { ticketNo: ticket.ticket_no }));
      navigate(`/tickets/${ticket.ticket_no}`);
    } catch (err) {
      if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
        // 4xx 都是后端校验/规则消息（查重 400、自批禁令、审批人缺失等）：
        // 与实时校验一致落到右侧结果面板，持久可见，不用一闪而过的 toast。
        setValidationError(err);
      } else {
        message.error(err instanceof ApiError ? err.message : String(err));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const typeOptions = useMemo(
    () =>
      ticketType === "ROLLBACK"
        ? []
        : [{ value: "abstract_policy", label: t("newTicket.form.abstractPolicyOption") }],
    [ticketType, t],
  );

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("newTicket.title")}
        </Title>
        <Button
          icon={<SafetyCertificateOutlined />}
          onClick={async () => {
            // 手动校验先跑表单必填校验（高亮缺失项），再走后端。
            try {
              await form.validateFields();
            } catch {
              return;
            }
            if (!autoValidateReady()) {
              // 具体缺哪项已由 validateFields 标红，这里不再列举字段名
              //（各类型字段不同，列举反而误导，如回滚没有账号/主体输入框）。
              message.info(t("newTicket.hint.fillRequiredFields"));
              return;
            }
            scheduleValidate();
          }}
        >
          {t("newTicket.action.validateNow")}
        </Button>
      </Space>
      {loadError && <Alert style={{ marginBottom: 16 }} type="error" message={loadError} />}

      <Row gutter={16}>
        <Col span={16}>
          <Card size="small">
            <Form
              form={form}
              layout="vertical"
              // 校验失败时滚到第一个出错字段：动态表单字段多，光提示“补全必填项”
              // 找不到缺在哪。
              scrollToFirstError={{ behavior: "smooth", block: "center" }}
              initialValues={{
                ticket_type: "CREATE_ROLE",
                approval_mode: "MANUAL",
                policy_text: POLICY_TEMPLATE,
                adopt_existing: false,
                create_policy_document: POLICY_TEMPLATE,
                create_policy_path: "/",
                create_user_path: "/",
                create_group_path: "/",
              }}
              onValuesChange={() => {
                // 编辑即清掉过期结果并重新防抖校验；就绪门槛在 scheduleValidate
                // 里，必填项未齐会静默跳过，不产生 400 噪音。
                setValidationError(null);
                setValidationOk(null);
                scheduleValidate();
              }}
            >
              <Form.Item
                name="ticket_type"
                label={t("newTicket.form.ticketType")}
                rules={[{ required: true }]}
              >
                <Radio.Group
                  disabled={Boolean(preset.ticket_type)}
                  optionType="button"
                  buttonStyle="solid"
                  options={TICKET_TABS.map((tab) => ({
                    value: tab.value,
                    label: t(tab.labelKey),
                  }))}
                />
              </Form.Item>

              {ticketType === "ROLLBACK" ? (
                <Form.Item
                  name="target_ticket_no"
                  label={t("newTicket.form.rollbackTarget")}
                  rules={[
                    { required: true, message: t("newTicket.form.rollbackTargetRequired") },
                  ]}
                >
                  <Input
                    placeholder={t("newTicket.form.rollbackTargetPlaceholder")}
                    className="mono"
                  />
                </Form.Item>
              ) : (
                <>
                  <Form.Item
                    name="account_id"
                    label={t("newTicket.form.account")}
                    rules={[{ required: true, message: t("newTicket.form.accountRequired") }]}
                  >
                    <Select
                      showSearch
                      optionFilterProp="label"
                      placeholder={t("newTicket.form.accountPlaceholder")}
                      options={accounts.map((a) => ({
                        value: a.id,
                        label: t("newTicket.form.accountOption", {
                          accountId: a.aws_account_id,
                          accountName: a.account_name ?? t("newTicket.form.accountUnnamed"),
                          id: a.id,
                        }),
                      }))}
                    />
                  </Form.Item>

                  {ticketType === "UPDATE_ROLE" ||
                  ticketType === "ADOPT_ROLE_INLINE_POLICIES" ? (
                    <Form.Item
                      name="principal_name"
                      label={
                        ticketType === "ADOPT_ROLE_INLINE_POLICIES"
                          ? t("newTicket.form.batchAdoptionRoleSelect")
                          : t("newTicket.form.roleSelectFromInventory")
                      }
                      rules={[
                        {
                          required: true,
                          message:
                            ticketType === "ADOPT_ROLE_INLINE_POLICIES"
                              ? t("newTicket.form.batchAdoptionRoleRequired")
                              : t("newTicket.form.roleToUpdateRequired"),
                        },
                      ]}
                    >
                      <Select
                        showSearch
                        filterOption={false}
                        onSearch={handleRoleSearch}
                        placeholder={
                          accountId
                            ? t("newTicket.form.searchAllRoles")
                            : t("newTicket.form.selectAccountFirst")
                        }
                        options={roleOptions}
                        notFoundContent={
                          accountId
                            ? t("newTicket.form.noMatchingRoles")
                            : t("newTicket.form.selectAccountFirst")
                        }
                      />
                    </Form.Item>
                  ) : ticketType === "CREATE_GROUP" && adoptExisting ? (
                    <Form.Item
                      name="principal_name"
                      label={t("newTicket.form.adoptGroupSelect")}
                      rules={[
                        {
                          required: true,
                          message: t("newTicket.form.adoptGroupRequired"),
                        },
                      ]}
                    >
                      <Select
                        showSearch
                        filterOption={false}
                        onSearch={handleGroupSearch}
                        placeholder={
                          accountId
                            ? t("newTicket.form.searchGroupsForImport")
                            : t("newTicket.form.selectAccountFirst")
                        }
                        options={groupOptions}
                        notFoundContent={
                          accountId
                            ? t("newTicket.form.noMatchingGroupsShort")
                            : t("newTicket.form.selectAccountFirst")
                        }
                      />
                    </Form.Item>
                  ) : ticketType === "CREATE_USER" && adoptExisting ? (
                    <Form.Item
                      name="principal_name"
                      label={t("newTicket.form.adoptUserSelect")}
                      rules={[
                        {
                          required: true,
                          message: t("newTicket.form.adoptUserRequired"),
                        },
                      ]}
                    >
                      <Select
                        showSearch
                        filterOption={false}
                        onSearch={handleAdoptUserSearch}
                        onChange={handleAdoptUserSelect}
                        placeholder={
                          accountId
                            ? t("newTicket.form.searchUsersForImport")
                            : t("newTicket.form.selectAccountFirst")
                        }
                        options={adoptUserOptions}
                        notFoundContent={
                          accountId
                            ? t("newTicket.form.noMatchingUsersShort")
                            : t("newTicket.form.selectAccountFirst")
                        }
                      />
                    </Form.Item>
                  ) : ticketType === "CREATE_MANAGED_POLICY" && adoptExisting ? (
                    <Form.Item
                      name="principal_name"
                      label={t("newTicket.form.adoptPolicySelect")}
                      rules={[
                        {
                          required: true,
                          message: t("newTicket.form.adoptPolicyRequired"),
                        },
                      ]}
                    >
                      <Select
                        showSearch
                        filterOption={false}
                        onSearch={handlePolicySearch}
                        onChange={handleAdoptPolicySelect}
                        placeholder={
                          accountId
                            ? t("newTicket.form.searchPoliciesForImport")
                            : t("newTicket.form.selectAccountFirst")
                        }
                        options={adoptPolicyOptions}
                        notFoundContent={
                          policyOptionsError
                            ? t("newTicket.form.policyLoadFailed", { message: policyOptionsError })
                            : t("newTicket.form.noMatchingCustomerPolicies")
                        }
                      />
                    </Form.Item>
                  ) : ticketType === "ATTACH_USER_POLICY" ||
                    ticketType === "UPDATE_MANAGED_POLICY" ||
                    ticketType === "UPDATE_GROUP_INLINE_POLICY" ||
                    // 组成员变更的主体由「选择组」唯一确定，无需再填主体名。
                    ticketType === "UPDATE_GROUP_MEMBERSHIP" ? null : (
                    <Form.Item
                      name="principal_name"
                      label={
                        ticketType === "CREATE_ROLE"
                          ? t("newTicket.form.roleName")
                          : ticketType === "CREATE_MANAGED_POLICY"
                            ? t("newTicket.form.managedPolicyName")
                            : ticketType === "CREATE_USER"
                              ? t("newTicket.form.userName")
                              : ticketType === "CREATE_GROUP"
                                ? t("newTicket.form.groupName")
                                : t("newTicket.form.principalName")
                      }
                      rules={[{ required: true, message: t("newTicket.form.required") }]}
                    >
                      <Input
                        placeholder={
                          ticketType === "CREATE_MANAGED_POLICY"
                            ? t("newTicket.form.managedPolicyNameExample")
                            : ticketType === "CREATE_USER"
                              ? t("newTicket.form.userNameExample")
                              : ticketType === "CREATE_GROUP"
                                ? t("newTicket.form.groupNameExample")
                                : t("newTicket.form.roleNameExample")
                        }
                        className="mono"
                      />
                    </Form.Item>
                  )}
                  {ticketType === "ADOPT_ROLE_INLINE_POLICIES" && (
                    <Alert
                      type="info"
                      showIcon
                      message={t("newTicket.form.batchAdoptionRoleHint")}
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  {ticketType === "UPDATE_ROLE" && (
                    <>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.updateRoleFieldsHint")}
                      </Text>
                      <Form.Item
                        name="update_trust_policy"
                        label={t("newTicket.form.trustPolicyLabel")}
                      >
                        <TextArea rows={10} className="mono" placeholder={TRUST_POLICY_TEMPLATE} style={{ marginTop: 4 }} />
                      </Form.Item>
                      <Form.Item name="update_description" label={t("newTicket.form.roleDescription")}>
                        <Input
                          placeholder={t("newTicket.form.leaveBlankNoChange")}
                          className="mono"
                        />
                      </Form.Item>
                      <Form.Item
                        name="update_max_session_duration"
                        label={t("newTicket.form.maxSessionDuration")}
                      >
                        <Input
                          type="number"
                          placeholder={t("newTicket.form.leaveBlankNoChange")}
                          className="mono"
                          style={{ marginTop: 4 }}
                        />
                      </Form.Item>
                      <Form.Item
                        name="update_tags"
                        label={t("newTicket.form.updateTagsLabel")}
                      >
                        <TextArea
                          rows={4}
                          className="mono"
                          disabled={!roleTagsLoaded}
                          placeholder={
                            roleTagsLoaded
                              ? t("newTicket.form.updateTagsPlaceholderEmpty")
                              : t("newTicket.form.updateTagsPlaceholderLoading")
                          }
                          style={{ marginTop: 4 }}
                        />
                      </Form.Item>
                      {roleTagsError && (
                        <Alert
                          type="error"
                          showIcon
                          message={t("newTicket.error.roleTagsNotBackfilled")}
                          description={roleTagsError}
                          style={{ marginBottom: 12 }}
                        />
                      )}
                    </>
                  )}

                  {ticketType === "CREATE_MANAGED_POLICY" && (
                    <>
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={t("newTicket.info.createManagedPolicyTitle")}
                        description={t("newTicket.info.createManagedPolicyDesc")}
                      />
                      <Form.Item
                        name="adopt_existing"
                        label={t("newTicket.form.adoptExistingPolicy")}
                        valuePropName="checked"
                      >
                        <Switch
                          checkedChildren={t("newTicket.form.switchImport")}
                          unCheckedChildren={t("newTicket.form.switchNew")}
                        />
                      </Form.Item>
                      <Form.Item name="create_policy_path" label={t("newTicket.form.iamPath")}>
                        <Input placeholder="/" className="mono" />
                      </Form.Item>
                      <Form.Item
                        name="create_policy_description"
                        label={t("newTicket.form.descriptionOptional")}
                      >
                        <Input
                          placeholder={t("newTicket.form.policyDescriptionExample")}
                        />
                      </Form.Item>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.policyDocumentTitle")}
                      </Text>
                      <Form.Item
                        name="create_policy_document"
                        rules={[
                          { required: true, message: t("newTicket.form.policyDocumentRequired") },
                        ]}
                      >
                        <TextArea rows={14} className="mono" style={{ marginTop: 4 }} />
                      </Form.Item>
                      <Form.Item
                        name="create_policy_tags"
                        label={t("newTicket.form.tagsLabelOptional")}
                      >
                        <TextArea rows={3} className="mono" placeholder="team=platform" />
                      </Form.Item>
                    </>
                  )}

                  {ticketType === "CREATE_USER" && (
                    <>
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={t("newTicket.info.createUserTitle")}
                        description={t("newTicket.info.createUserDesc")}
                      />
                      <Form.Item
                        name="adopt_existing"
                        label={t("newTicket.form.adoptExistingUser")}
                        valuePropName="checked"
                      >
                        <Switch
                          checkedChildren={t("newTicket.form.switchImport")}
                          unCheckedChildren={t("newTicket.form.switchNew")}
                        />
                      </Form.Item>
                      {adoptExisting && (
                        <Alert
                          type="warning"
                          showIcon
                          style={{ marginBottom: 12 }}
                          message={t("newTicket.warning.adoptNoGroupOrPolicy")}
                          description={t("newTicket.warning.adoptUserDesc")}
                        />
                      )}
                      <Form.Item name="create_user_path" label={t("newTicket.form.iamPath")}>
                        <Input placeholder="/" className="mono" />
                      </Form.Item>
                      <Form.Item
                        name="create_user_groups"
                        label={t("newTicket.form.initialGroups")}
                      >
                        <Select
                          mode="multiple"
                          allowClear
                          showSearch
                          optionFilterProp="label"
                          placeholder={
                            accountId
                              ? t("newTicket.form.selectExistingGroups")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          options={groupOptions}
                          disabled={Boolean(adoptExisting)}
                        />
                      </Form.Item>
                      <Form.Item
                        name="create_user_policy_arns"
                        label={t("newTicket.form.initialPolicyArns")}
                        rules={policyARNRules}
                      >
                        <Select
                          mode="tags"
                          allowClear
                          showSearch
                          filterOption={false}
                          tokenSeparators={[","]}
                          onChange={(values: string[]) =>
                            handlePolicyARNChange("create_user_policy_arns", values)
                          }
                          onSearch={handlePolicySearch}
                          placeholder={
                            accountId
                              ? t("newTicket.form.searchOrEnterPolicyArn")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          options={policyOptions.map((p) => ({ value: p.value, label: p.label }))}
                          notFoundContent={
                            policyOptionsError
                              ? t("newTicket.form.policyLoadFailed", { message: policyOptionsError })
                              : t("newTicket.form.noMatchingPolicies")
                          }
                          disabled={Boolean(adoptExisting)}
                        />
                      </Form.Item>
                      {!adoptExisting && (
                        <Text
                          type="secondary"
                          style={{ display: "block", marginTop: -16, marginBottom: 16 }}
                        >
                          {t("newTicket.hint.policyArnInput")}
                        </Text>
                      )}
                      <Form.Item
                        name="create_user_tags"
                        label={t("newTicket.form.tagsLabelOptional")}
                      >
                        <TextArea rows={3} className="mono" placeholder="team=platform" />
                      </Form.Item>
                    </>
                  )}

                  {ticketType === "CREATE_GROUP" && (
                    <>
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={t("newTicket.info.createGroupTitle")}
                        description={t("newTicket.info.createGroupDesc")}
                      />
                      <Form.Item
                        name="adopt_existing"
                        label={t("newTicket.form.adoptExistingGroup")}
                        valuePropName="checked"
                      >
                        <Switch
                          checkedChildren={t("newTicket.form.switchImport")}
                          unCheckedChildren={t("newTicket.form.switchNew")}
                        />
                      </Form.Item>
                      {adoptExisting && (
                        <Alert
                          type="info"
                          showIcon
                          style={{ marginBottom: 12 }}
                          message={t("newTicket.info.adoptGroupSnapshotTitle")}
                          description={t("newTicket.info.adoptGroupSnapshotDesc")}
                        />
                      )}
                      <Form.Item
                        name="create_group_path"
                        label={t("newTicket.form.iamPath")}
                        hidden={Boolean(adoptExisting)}
                      >
                        <Input placeholder="/" className="mono" />
                      </Form.Item>
                      <Form.Item
                        name="create_group_members"
                        label={t("newTicket.form.initialMembers")}
                        hidden={Boolean(adoptExisting)}
                      >
                        <Select
                          mode="multiple"
                          allowClear
                          showSearch
                          optionFilterProp="label"
                          placeholder={
                            accountId
                              ? t("newTicket.form.selectExistingUsers")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          options={createMemberOptions}
                          disabled={Boolean(adoptExisting)}
                        />
                      </Form.Item>
                      <Form.Item
                        name="create_group_policy_arns"
                        label={t("newTicket.form.initialPolicyArns")}
                        rules={policyARNRules}
                        hidden={Boolean(adoptExisting)}
                      >
                        <Select
                          mode="tags"
                          allowClear
                          showSearch
                          filterOption={false}
                          tokenSeparators={[","]}
                          onChange={(values: string[]) =>
                            handlePolicyARNChange("create_group_policy_arns", values)
                          }
                          onSearch={handlePolicySearch}
                          placeholder={
                            accountId
                              ? t("newTicket.form.searchOrEnterPolicyArn")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          options={policyOptions.map((p) => ({ value: p.value, label: p.label }))}
                          notFoundContent={
                            policyOptionsError
                              ? t("newTicket.form.policyLoadFailed", { message: policyOptionsError })
                              : t("newTicket.form.noMatchingPolicies")
                          }
                          disabled={Boolean(adoptExisting)}
                        />
                      </Form.Item>
                      {!adoptExisting && (
                        <Text
                          type="secondary"
                          style={{ display: "block", marginTop: -16, marginBottom: 16 }}
                        >
                          {t("newTicket.hint.policyArnInput")}
                        </Text>
                      )}
                      <Form.Item
                        name="create_group_tags"
                        label={t("newTicket.form.tagsLabelOptional")}
                        hidden={Boolean(adoptExisting)}
                      >
                        <TextArea rows={3} className="mono" placeholder="team=platform" />
                      </Form.Item>
                    </>
                  )}

                  {ticketType === "ATTACH_USER_POLICY" && (
                    <>
                      <Form.Item
                        name="operation"
                        label={t("newTicket.form.operation")}
                        initialValue="attach"
                      >
                        <Radio.Group
                          optionType="button"
                          buttonStyle="solid"
                          options={[
                            { value: "attach", label: t("newTicket.form.operationAttach") },
                            { value: "detach", label: t("newTicket.form.operationDetach") },
                          ]}
                        />
                      </Form.Item>
                      <Form.Item
                        name="principal_type"
                        label={t("newTicket.form.principalType")}
                        initialValue="User"
                      >
                        <Radio.Group
                          optionType="button"
                          buttonStyle="solid"
                          options={[
                            { value: "User", label: t("newTicket.form.principalTypeUser") },
                            { value: "Group", label: t("newTicket.form.principalTypeGroup") },
                            { value: "Role", label: t("newTicket.form.principalTypeRole") },
                          ]}
                        />
                      </Form.Item>
                      <Form.Item
                        name="principal_name"
                        label={attachHint.label}
                        rules={[{ required: true, message: attachHint.pick }]}
                      >
                        <Select
                          showSearch
                          filterOption={false}
                          onSearch={handleUserSearch}
                          placeholder={
                            accountId ? attachHint.search : t("newTicket.form.selectAccountFirst")
                          }
                          options={userOptions}
                          notFoundContent={
                            accountId ? attachHint.none : t("newTicket.form.selectAccountFirst")
                          }
                        />
                      </Form.Item>
                      <div style={{ marginBottom: 12 }}>
                        <Text type="secondary" style={{ fontSize: 12 }}>
                          {attachPrincipalName
                            ? detachOperation
                              ? t("newTicket.hint.attachedPoliciesDetach", {
                                  name: attachPrincipalName,
                                })
                              : t("newTicket.hint.attachedPoliciesAttach", {
                                  name: attachPrincipalName,
                                })
                            : t("newTicket.hint.selectPrincipalFirst")}
                        </Text>
                        <div
                          style={{
                            marginTop: 6,
                            display: "flex",
                            flexWrap: "wrap",
                            gap: 6,
                            minHeight: 24,
                          }}
                        >
                          {attachedLoading ? (
                            <Spin size="small" />
                          ) : attachedFailed ? (
                            <Text type="danger" style={{ fontSize: 12 }}>
                              {t("newTicket.hint.attachListLoadFailed")}
                            </Text>
                          ) : attachedPolicies === null ? null : attachedPolicies.length === 0 ? (
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              {detachOperation
                                ? t("newTicket.hint.noAttachedPoliciesDetach")
                                : t("newTicket.hint.noAttachedPoliciesAttach")}
                            </Text>
                          ) : (
                            attachedPolicies.map((policy) => (
                              <Tag.CheckableTag
                                key={policy.policy_id}
                                checked={selectedAttachPolicy === (policy.policy_arn ?? "")}
                                onChange={() =>
                                  form.setFieldValue("managed_policy_arn", policy.policy_arn)
                                }
                              >
                                {policy.policy_name}
                              </Tag.CheckableTag>
                            ))
                          )}
                        </div>
                      </div>
                      <Form.Item
                        name="managed_policy_arn"
                        label={
                          detachOperation
                            ? t("newTicket.form.policyToDetach")
                            : t("newTicket.form.managedPolicyLabel")
                        }
                        rules={[{ required: true, message: t("newTicket.form.managedPolicyRequired") }]}
                      >
                        <Select
                          showSearch
                          filterOption={false}
                          onSearch={detachScoped ? undefined : handlePolicySearch}
                          placeholder={
                            detachScoped
                              ? detachNothingToPick
                                ? t("newTicket.form.noDetachablePolicies")
                                : t("newTicket.form.onlyAttachedPolicies")
                              : detachOperation && attachedLoading
                                ? t("newTicket.form.loadingAttachList")
                                : t("newTicket.form.searchPolicyPlaceholder")
                          }
                          options={attachPolicyOptions}
                          notFoundContent={
                            detachScoped
                              ? t("newTicket.form.noAttachedPolicies")
                              : t("newTicket.form.noMatchingPolicies")
                          }
                          optionFilterProp="label"
                          optionRender={(oriOption) => {
                            const attached = Boolean(
                              (oriOption.data as { attached?: boolean }).attached,
                            );
                            if (!attached) return oriOption.label;
                            return (
                              <span
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "space-between",
                                  gap: 8,
                                }}
                              >
                                {oriOption.label}
                                <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                                  {t("newTicket.form.attachedTag")}
                                </Tag>
                              </span>
                            );
                          }}
                          disabled={detachNothingToPick}
                        />
                      </Form.Item>
                      {!detachOperation && selectedPolicyAttached && (
                        <Text
                          type="secondary"
                          style={{ display: "block", fontSize: 12, marginBottom: 12 }}
                        >
                          {t("newTicket.hint.policyAlreadyAttached", { name: attachPrincipalName })}
                        </Text>
                      )}
                      {detachOperation && (
                        <Alert
                          type="warning"
                          showIcon
                          style={{ marginBottom: 12 }}
                          message={t("newTicket.warning.detachManagedOnly")}
                          description={t("newTicket.warning.detachManagedOnlyDesc")}
                        />
                      )}
                    </>
                  )}

                  {ticketType === "UPDATE_MANAGED_POLICY" && (
                    <>
                      <Form.Item
                        name="update_policy_id"
                        label={t("newTicket.form.customerManagedPolicy")}
                        rules={[
                          { required: true, message: t("newTicket.form.policyToUpdateRequired") },
                        ]}
                      >
                        <Select
                          showSearch
                          filterOption={false}
                          onSearch={handlePolicySearch}
                          placeholder={t("newTicket.form.searchCustomerPolicyPlaceholder")}
                          options={policyOptions.map((p) => ({ value: p.id, label: p.label }))}
                          notFoundContent={t("newTicket.form.noMatchingCustomerPolicies")}
                          optionFilterProp="label"
                        />
                      </Form.Item>
                      {policyDetail && (
                        <Alert
                          type="info"
                          showIcon
                          style={{ marginBottom: 12 }}
                          message={t("newTicket.info.policyReferenced", {
                            principals: policyDetail.attached_principals,
                            groups: policyDetail.attached_groups,
                          })}
                          description={t("newTicket.info.policyReferencedDesc")}
                        />
                      )}
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.targetPolicyDocument")}
                      </Text>
                      <Form.Item
                        name="update_policy_document"
                        rules={[
                          { required: true, message: t("newTicket.form.policyDocumentRequired") },
                        ]}
                      >
                        <TextArea rows={14} className="mono" style={{ marginTop: 4 }} />
                      </Form.Item>
                    </>
                  )}

                  {ticketType === "UPDATE_GROUP_INLINE_POLICY" && (
                    <>
                      <Alert
                        type="warning"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={t("newTicket.warning.inlinePolicyChange")}
                        description={t("newTicket.warning.inlinePolicyChangeDesc")}
                      />
                      <Form.Item
                        name="update_inline_principal_type"
                        label={t("newTicket.form.inlinePrincipalType")}
                        initialValue="Group"
                        rules={[
                          { required: true, message: t("newTicket.form.inlinePrincipalTypeRequired") },
                        ]}
                      >
                        <Radio.Group
                          onChange={() => {
                            // 切换主体类型时清空另一侧与已选内联策略，
                            // 避免组/角色混填。
                            form.setFieldsValue({
                              update_inline_group: undefined,
                              update_inline_role: undefined,
                              update_inline_policy_id: undefined,
                            });
                            setInlinePolicyOptions([]);
                          }}
                        >
                          <Radio value="Group">{t("newTicket.form.inlineGroup")}</Radio>
                          <Radio value="Role">{t("newTicket.form.inlineRole")}</Radio>
                        </Radio.Group>
                      </Form.Item>
                      {selectedInlinePrincipalType === "Role" ? (
                        <Form.Item
                          name="update_inline_role"
                          label={t("newTicket.form.pickRoleFromInventory")}
                          rules={[{ required: true, message: t("newTicket.form.inlineRoleRequired") }]}
                        >
                          <Select
                            showSearch
                            placeholder={
                              accountId
                                ? t("newTicket.form.selectRole")
                                : t("newTicket.form.selectAccountFirst")
                            }
                            options={roleOptions}
                            notFoundContent={
                              accountId
                                ? t("newTicket.form.noMatchingRolesShort")
                                : t("newTicket.form.selectAccountFirst")
                            }
                            optionFilterProp="label"
                            onSearch={(value) => {
                              if (roleSearchTimer.current) {
                                clearTimeout(roleSearchTimer.current);
                              }
                              roleSearchTimer.current = setTimeout(
                                () => loadRoles(value),
                                300,
                              );
                            }}
                          />
                        </Form.Item>
                      ) : (
                        <Form.Item
                          name="update_inline_group"
                          label={t("newTicket.form.pickGroupFromInventory")}
                          rules={[
                            { required: true, message: t("newTicket.form.inlineGroupRequired") },
                          ]}
                        >
                          <Select
                            showSearch
                            placeholder={
                              accountId
                                ? t("newTicket.form.selectGroup")
                                : t("newTicket.form.selectAccountFirst")
                            }
                            options={groupOptions}
                            notFoundContent={
                              accountId
                                ? t("newTicket.form.noMatchingGroupsShort")
                                : t("newTicket.form.selectAccountFirst")
                            }
                            optionFilterProp="label"
                          />
                        </Form.Item>
                      )}
                      <Form.Item
                        name="update_inline_policy_id"
                        label={t("newTicket.form.inlinePolicy")}
                        rules={[
                          { required: true, message: t("newTicket.form.inlinePolicyRequired") },
                        ]}
                      >
                        <AutoComplete
                          placeholder={
                            selectedInlinePrincipalType === "Role"
                              ? selectedInlineRole
                                ? t("newTicket.form.selectInlinePolicy")
                                : t("newTicket.form.selectRoleFirst")
                              : selectedInlineGroup
                                ? t("newTicket.form.selectInlinePolicy")
                                : t("newTicket.form.selectGroupFirst")
                          }
                          options={inlinePolicyOptions.map((p) => ({ value: p.name, label: p.name }))}
                          filterOption={(input, option) =>
                            (option?.label ?? "").toLowerCase().includes(input.toLowerCase())
                          }
                          notFoundContent={t("newTicket.form.inlinePolicyNotFound")}
                        />
                      </Form.Item>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.inlinePolicyDocument")}
                      </Text>
                      <Form.Item
                        name="update_policy_document"
                        rules={[
                          {
                            required: true,
                            message: t("newTicket.form.inlinePolicyDocumentRequired"),
                          },
                        ]}
                      >
                        <TextArea rows={14} className="mono" style={{ marginTop: 4 }} />
                      </Form.Item>
                    </>
                  )}

                  {ticketType === "UPDATE_GROUP_MEMBERSHIP" && (
                    <>
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={t("newTicket.warning.membershipChange")}
                        description={t("newTicket.warning.membershipChangeDesc")}
                      />
                      <Form.Item
                        name="membership_group"
                        label={t("newTicket.form.pickGroupFromInventory")}
                        rules={[{ required: true, message: t("newTicket.form.inlineGroupRequired") }]}
                      >
                        <Select
                          showSearch
                          placeholder={
                            accountId
                              ? t("newTicket.form.selectGroup")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          options={groupOptions}
                          notFoundContent={
                            accountId
                              ? t("newTicket.form.noMatchingGroupsShort")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          optionFilterProp="label"
                          onSearch={handleGroupSearch}
                        />
                      </Form.Item>
                      <Form.Item
                        name="membership_operation"
                        label={t("newTicket.form.membershipOperation")}
                        initialValue="add"
                        rules={[
                          { required: true, message: t("newTicket.form.membershipOperationRequired") },
                        ]}
                      >
                        <Radio.Group>
                          <Radio value="add">{t("newTicket.form.membershipAdd")}</Radio>
                          <Radio value="remove">{t("newTicket.form.membershipRemove")}</Radio>
                        </Radio.Group>
                      </Form.Item>
                      <Form.Item
                        name="membership_users"
                        label={t("newTicket.form.membershipUsers")}
                        rules={[
                          { required: true, message: t("newTicket.form.membershipUsersRequired") },
                        ]}
                      >
                        <Select
                          mode="multiple"
                          showSearch
                          optionFilterProp="label"
                          loading={membershipMembersLoading}
                          disabled={!membershipGroupName}
                          placeholder={
                            !accountId
                              ? t("newTicket.form.selectAccountFirst")
                              : !membershipGroupName
                                ? t("newTicket.form.membershipSelectGroupFirst")
                                : membershipOperation === "remove"
                                  ? t("newTicket.form.membershipRemoveUsersPlaceholder")
                                  : t("newTicket.form.membershipAddUsersPlaceholder")
                          }
                          options={membershipUserOptions}
                          notFoundContent={
                            membershipMembersLoading ? (
                              <Spin size="small" />
                            ) : !accountId ? (
                              t("newTicket.form.selectAccountFirst")
                            ) : !membershipGroupName ? (
                              t("newTicket.form.membershipSelectGroupFirst")
                            ) : membershipOperation === "remove" ? (
                              t("newTicket.form.membershipNoMemberToRemove")
                            ) : (
                              t("newTicket.form.membershipAllUsersAreMembers")
                            )
                          }
                        />
                      </Form.Item>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.membershipPreview")}
                      </Text>
                    </>
                  )}

                  {ticketType === "CREATE_ROLE" && (
                    <>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.trustPolicyTitle")}
                      </Text>
                      <Form.Item
                        name="trust_policy"
                        rules={[{ required: true, message: t("newTicket.form.trustPolicyRequired") }]}
                      >
                        <TextArea
                          rows={8}
                          className="mono"
                          placeholder={TRUST_POLICY_TEMPLATE}
                          style={{ marginTop: 4 }}
                          onChange={scheduleValidate}
                        />
                      </Form.Item>
                      <Form.Item
                        name="create_role_policy_arns"
                        label={t("newTicket.form.initialPolicyArns")}
                        rules={policyARNRules}
                      >
                        <Select
                          allowClear
                          showSearch
                          filterOption={false}
                          onSearch={handlePolicySearch}
                          placeholder={
                            accountId
                              ? t("newTicket.form.searchOrEnterPolicyArn")
                              : t("newTicket.form.selectAccountFirst")
                          }
                          options={policyOptions.map((p) => ({ value: p.value, label: p.label }))}
                          mode="tags"
                          tokenSeparators={[","]}
                          onChange={(values: string[]) =>
                            handlePolicyARNChange("create_role_policy_arns", values)
                          }
                          notFoundContent={
                            policyOptionsError
                              ? t("newTicket.form.policyLoadFailed", { message: policyOptionsError })
                              : t("newTicket.form.noMatchingPolicies")
                          }
                        />
                      </Form.Item>
                      <Text
                        type="secondary"
                        style={{ display: "block", marginTop: -16, marginBottom: 16 }}
                      >
                        {t("newTicket.hint.policyArnInput")}
                      </Text>
                      {policyOptionsError && (
                        <Alert
                          type="warning"
                          showIcon
                          style={{ marginTop: -16, marginBottom: 16 }}
                          message={t("newTicket.form.policyLoadFailed", {
                            message: policyOptionsError,
                          })}
                        />
                      )}
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {t("newTicket.hint.abstractPolicy")}
                      </Text>
                      <Form.Item name="policy_text">
                        <TextArea
                          rows={12}
                          className="mono"
                          placeholder={ABSTRACT_POLICY_TEMPLATE}
                          style={{ marginTop: 4 }}
                          onChange={scheduleValidate}
                        />
                      </Form.Item>
                    </>
                  )}
                </>
              )}

              <Divider style={{ margin: "8px 0 16px" }} />
              {ticketType === "ADOPT_ROLE_INLINE_POLICIES" && (
                <Alert
                  type="warning"
                  showIcon
                  message={t("newTicket.form.batchAdoptionManualApproval")}
                  style={{ marginBottom: 12 }}
                />
              )}
              <Form.Item name="approval_mode" label={t("newTicket.form.approvalMode")}>
                <Radio.Group
                  optionType="button"
                  options={[
                    {
                      value: "MANUAL",
                      label: t("newTicket.form.approvalManual"),
                    },
                    {
                      value: "AUTO",
                      label: trustPolicyChanged
                        ? t("newTicket.form.approvalAutoTrustChanged")
                        : t("newTicket.form.approvalAuto"),
                      disabled:
                        trustPolicyChanged || ticketType === "ADOPT_ROLE_INLINE_POLICIES",
                    },
                  ]}
                />
              </Form.Item>
              {/* 审批人对所有类型（含 ROLLBACK）都需选择：后端 SubmitTicket
                  硬性要求工单必须有指定审批人，MANUAL 模式无豁免。 */}
              {accountId && approvers.length === 0 && (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 8 }}
                  message={t("newTicket.form.approversEmpty")}
                  description={
                    <Space direction="vertical" size={4}>
                      <span>
                        {approvalMode === "AUTO"
                          ? t("newTicket.form.approversEmptyAutoHint")
                          : t("newTicket.form.approversEmptyHint")}
                      </span>
                      {isAdmin && (
                        <Button
                          size="small"
                          icon={<TeamOutlined />}
                          onClick={() => setApproverModalOpen(true)}
                        >
                          {t("newTicket.form.configureApprovers")}
                        </Button>
                      )}
                    </Space>
                  }
                />
              )}
              {approvalMode === "MANUAL" && (
                <Form.Item
                  name="approver_ids"
                  label={t("newTicket.form.approvers")}
                  rules={[{ required: true, message: t("newTicket.form.approversRequired") }]}
                >
                  <Select
                    mode="multiple"
                    placeholder={t("newTicket.form.selectApprovers")}
                    options={approvers.map((u) => ({
                      value: u.user_id,
                      label: `${u.display_name}（${u.user_id}）`,
                    }))}
                  />
                </Form.Item>
              )}
            </Form>
          </Card>
        </Col>
        <Col span={8}>
          <Card
            size="small"
            title={t("newTicket.panel.validationResult")}
            style={{ position: "sticky", top: 16 }}
          >
            {validationOk && <Alert type="success" message={validationOk} />}
            {validationChecks.length > 0 && (
              <div style={{ marginTop: 8 }}>
                {validationChecks.map((check) => (
                  <div key={check.code} style={{ marginBottom: 4 }}>
                    <Space size={8} wrap>
                      <Tag
                        color={
                          check.result === "PASSED"
                            ? "green"
                            : check.result === "FAILED"
                              ? "red"
                              : "default"
                        }
                      >
                        {check.code}
                      </Tag>
                      <Text type="secondary">{check.description}</Text>
                    </Space>
                  </div>
                ))}
              </div>
            )}
            {validationError && <ValidationErrors error={validationError} />}
            {!validationOk && !validationError && (
              <Text type="secondary">{t("newTicket.hint.autoValidation")}</Text>
            )}
            {terraformPreview && (
              <>
                <Divider />
                <Card
                  size="small"
                  title={t("newTicket.panel.terraformPreview")}
                  extra={
                    <Button
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={() => {
                        void navigator.clipboard
                          ?.writeText(terraformPreview ?? "")
                          .then(
                            () => message.success(t("newTicket.success.copied")),
                            () => message.error(t("newTicket.error.copyFailed")),
                          );
                      }}
                    >
                      {t("newTicket.action.copy")}
                    </Button>
                  }
                >
                  <pre className="mono terraform-code">{terraformPreview}</pre>
                </Card>
              </>
            )}
            <Divider />
            <Space>
              <Button
                type="primary"
                icon={<SendOutlined />}
                loading={submitting}
                onClick={() => void submit()}
                disabled={Boolean(validationError)}
              >
                {t("newTicket.action.submit")}
              </Button>
              <Button onClick={() => navigate("/tickets")}>{t("newTicket.action.cancel")}</Button>
            </Space>
            {typeOptions.length > 0 && <div style={{ display: "none" }}>{typeOptions.length}</div>}
          </Card>
        </Col>
      </Row>
      <AccountApproverModal
        accountDbId={accountId ?? null}
        accountLabel={
          accounts.find((account) => account.id === accountId)?.account_name ??
          accounts.find((account) => account.id === accountId)?.aws_account_id ??
          ""
        }
        open={approverModalOpen}
        onClose={() => setApproverModalOpen(false)}
        onSaved={() => {
          if (accountId) {
            api.listApprovers(accountId).then(setApprovers).catch(() => setApprovers([]));
          }
        }}
      />
    </div>
  );
}
