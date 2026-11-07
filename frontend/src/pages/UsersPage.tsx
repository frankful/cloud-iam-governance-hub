import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { PlusOutlined, ReloadOutlined, CloudUploadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type {
  AWSAccountRef,
  IssuedPlatformToken,
  PlatformProvisionResult,
  PlatformTokenInfo,
  PlatformUser,
} from "../api/types";

const { Title, Text } = Typography;

const ROLE_VALUES = ["platform_admin", "approval_admin", "standard_user"];

// GET /aws/groups 的 limit 上限是 100，传更大直接 400。这里按页拉全：
// 组数超过一页时只读第一页，交集会漏掉合法组，用户在下拉里选不到。
async function loadAccountGroupNames(accountID: number): Promise<Set<string>> {
  const pageSize = 100;
  const names = new Set<string>();
  for (let offset = 0; ; offset += pageSize) {
    const page = await api.listGroups({ account_id: accountID, limit: pageSize, offset });
    page.groups.forEach((group) => names.add(group.group_name));
    if (page.groups.length < pageSize || offset + pageSize >= page.total) break;
  }
  return names;
}

interface UserFormValues {
  user_id: string;
  display_name: string;
  email?: string;
  roles: string[];
  is_active: boolean;
  /** 该用户可审批的账号（aws_account.id 列表），只有审批角色才展示。 */
  approver_account_ids?: number[];
}

interface TokenFormValues {
  name: string;
  expires_in_hours: number;
}

interface ProvisionFormValues {
  account_ids: number[];
  groups?: string[];
  approval_mode: "AUTO" | "MANUAL";
  approver_ids?: string[];
}

export default function UsersPage() {
  const { t } = useTranslation();
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [userModalOpen, setUserModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<PlatformUser | null>(null);
  const [savingUser, setSavingUser] = useState(false);
  const [userForm] = Form.useForm<UserFormValues>();

  const [tokenUser, setTokenUser] = useState<PlatformUser | null>(null);
  const [tokens, setTokens] = useState<PlatformTokenInfo[]>([]);
  const [tokensLoading, setTokensLoading] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [issuedToken, setIssuedToken] = useState<IssuedPlatformToken | null>(null);
  const [tokenForm] = Form.useForm<TokenFormValues>();

  const [provisionUser, setProvisionUser] = useState<PlatformUser | null>(null);
  const [accounts, setAccounts] = useState<AWSAccountRef[]>([]);
  const [approverAccountsLoading, setApproverAccountsLoading] = useState(false);
  const approverRoles = Form.useWatch("roles", userForm) ?? [];
  const [provisionResults, setProvisionResults] = useState<PlatformProvisionResult[] | null>(null);
  const [provisioning, setProvisioning] = useState(false);
  const [provisionForm] = Form.useForm<ProvisionFormValues>();
  // 组候选项取「所有选中账号的交集」：CREATE_USER 的组名必须在该账号台账里
  // 存在，只出现在部分账号的组会让其余账号的工单在创建时就校验失败。
  const [provisionGroupOptions, setProvisionGroupOptions] = useState<
    { value: string; label: string }[]
  >([]);
  const [provisionGroupsLoading, setProvisionGroupsLoading] = useState(false);
  // 显式记录已选账号：Modal 内容挂载时机晚于组件，useWatch 在未挂载时拿不到
  // 值，会让组候选永远不加载；直接接管 Select 的 onChange 最稳。
  const [provisionAccountIDs, setProvisionAccountIDs] = useState<number[]>([]);
  const provisionAccountKey = provisionAccountIDs.join(",");

  useEffect(() => {
    const ids = provisionAccountKey
      ? provisionAccountKey.split(",").map((value) => Number(value))
      : [];
    if (ids.length === 0) {
      setProvisionGroupOptions([]);
      return;
    }
    let cancelled = false;
    setProvisionGroupsLoading(true);
    Promise.all(ids.map((id) => loadAccountGroupNames(id)))
      .then((perAccount) => {
        if (cancelled) return;
        const common = Array.from(perAccount[0] ?? []).filter((name) =>
          perAccount.every((names) => names.has(name)),
        );
        common.sort((left, right) => left.localeCompare(right));
        setProvisionGroupOptions(common.map((name) => ({ value: name, label: name })));
      })
      .catch(() => {
        if (cancelled) return;
        setProvisionGroupOptions([]);
        message.warning(t("users.provision.groupsLoadFailed"));
      })
      .finally(() => {
        if (!cancelled) setProvisionGroupsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [provisionAccountKey, t]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setUsers(await api.listPlatformUsers());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const loadTokens = useCallback(async (user: PlatformUser) => {
    setTokensLoading(true);
    try {
      setTokens(await api.listPlatformTokens(user.user_id));
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setTokensLoading(false);
    }
  }, []);

  // 账号下拉是「该用户审批哪些账号」的数据源；同步管理页的账号视角编辑写的是
  // 同一张 aws_account_approver 表，两边互相可见。
  const ensureAccounts = async () => {
    if (accounts.length > 0) return;
    try {
      setAccounts(await api.listAccounts());
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    }
  };

  const loadApproverAccounts = async (user: PlatformUser) => {
    setApproverAccountsLoading(true);
    try {
      const bound = await api.listApproverAccountsForUser(user.user_id);
      userForm.setFieldsValue({
        approver_account_ids: bound.map((account) => account.account_db_id),
      });
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setApproverAccountsLoading(false);
    }
  };

  const openUserModal = (user: PlatformUser | null) => {
    setEditingUser(user);
    setUserModalOpen(true);
    void ensureAccounts();
    if (user) {
      userForm.setFieldsValue({
        user_id: user.user_id,
        display_name: user.display_name,
        email: user.email ?? "",
        roles: user.roles ?? [],
        is_active: user.is_active,
        approver_account_ids: [],
      });
      void loadApproverAccounts(user);
    } else {
      userForm.resetFields();
      userForm.setFieldsValue({
        roles: ["standard_user"],
        is_active: true,
        approver_account_ids: [],
      });
    }
  };

  const saveUser = async () => {
    const values = await userForm.validateFields();
    // A9③乙：停用或剥夺审批角色前，警告操作者该用户还是哪些账号的审批人——
    // 否则账号审批链静默缺人，AUTO 建单开始报错时没人知道为什么。
    if (editingUser) {
      const wasQualified =
        editingUser.is_active &&
        (editingUser.roles ?? []).some(
          (role) => role === "platform_admin" || role === "approval_admin",
        );
      const stillQualified =
        values.is_active &&
        (values.roles ?? []).some(
          (role) => role === "platform_admin" || role === "approval_admin",
        );
      if (wasQualified && !stillQualified) {
        const accounts = await api
          .listApproverAccountsForUser(editingUser.user_id)
          .catch(() => []);
        if (accounts.length > 0) {
          const names = accounts
            .map((a) => a.account_name || a.account_no)
            .join("、");
          const proceed = await new Promise<boolean>((resolve) => {
            Modal.confirm({
              title: t("users.approverWarn.title", { count: accounts.length }),
              content: t("users.approverWarn.content", { accounts: names }),
              okText: t("users.approverWarn.confirm"),
              cancelText: t("common.cancel"),
              onOk: () => resolve(true),
              onCancel: () => resolve(false),
            });
          });
          if (!proceed) return;
        }
      }
    }
    setSavingUser(true);
    try {
      const userID = values.user_id.trim();
      await api.upsertPlatformUser({
        user_id: userID,
        display_name: values.display_name.trim(),
        email: values.email?.trim() ?? "",
        is_active: values.is_active,
        roles: values.roles,
      });
      // 审批账号的绑定必须在用户落库之后再写：后端会校验「启用中的
      // platform_admin/approval_admin」，顺序反了会 422。失去审批角色或停用
      // 的用户不写（后端同样会拒），残留绑定由上面的降级警告覆盖。
      const canApprove =
        values.is_active &&
        (values.roles ?? []).some(
          (role) => role === "platform_admin" || role === "approval_admin",
        );
      if (canApprove && (editingUser || (values.approver_account_ids ?? []).length > 0)) {
        await api.replaceApproverAccounts(userID, values.approver_account_ids ?? []);
      }
      message.success(editingUser ? t("users.toast.updated") : t("users.toast.created"));
      setUserModalOpen(false);
      await load();
    } catch (err) {
      if (err instanceof ApiError) {
        message.error(err.message);
      }
    } finally {
      setSavingUser(false);
    }
  };

  const openTokenModal = (user: PlatformUser) => {
    setTokenUser(user);
    setIssuedToken(null);
    tokenForm.resetFields();
    tokenForm.setFieldsValue({ name: t("users.token.defaultName"), expires_in_hours: 720 });
    void loadTokens(user);
  };

  const issueToken = async () => {
    if (!tokenUser) return;
    const values = await tokenForm.validateFields();
    setIssuing(true);
    try {
      const issued = await api.issuePlatformToken(
        tokenUser.user_id,
        values.name.trim(),
        values.expires_in_hours,
      );
      setIssuedToken(issued);
      message.success(t("users.toast.tokenIssued"));
      await loadTokens(tokenUser);
    } catch (err) {
      if (err instanceof ApiError) {
        message.error(err.message);
      }
    } finally {
      setIssuing(false);
    }
  };

  const openProvisionModal = async (user: PlatformUser) => {
    setProvisionUser(user);
    setProvisionResults(null);
    setProvisionGroupOptions([]);
    setProvisionAccountIDs([]);
    provisionForm.resetFields();
    provisionForm.setFieldsValue({ approval_mode: "AUTO" });
    try {
      setAccounts(await api.listAccounts());
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    }
  };

  const submitProvision = async () => {
    if (!provisionUser) return;
    const values = await provisionForm.validateFields();
    setProvisioning(true);
    try {
      const results = await api.provisionPlatformUser(provisionUser.user_id, {
        accounts: values.account_ids,
        groups: values.groups ?? [],
        approval_mode: values.approval_mode,
        approver_ids: values.approver_ids,
      });
      setProvisionResults(results);
      const failed = results.filter((r) => r.error).length;
      if (failed === 0) {
        message.success(t("users.provision.toastAll"));
      } else {
        message.warning(t("users.provision.toastPartial", { failed }));
      }
    } catch (err) {
      if (err instanceof ApiError) {
        message.error(err.message);
      }
    } finally {
      setProvisioning(false);
    }
  };

  const revokeToken = async (token: PlatformTokenInfo) => {
    try {
      await api.revokePlatformToken(token.id);
      message.success(t("users.toast.tokenRevoked"));
      if (tokenUser) await loadTokens(tokenUser);
    } catch (err) {
      if (err instanceof ApiError) {
        message.error(err.message);
      }
    }
  };

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("users.title")}
        </Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>
            {t("common.refresh")}
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => openUserModal(null)}>
            {t("users.action.createUser")}
          </Button>
        </Space>
      </Space>
      <Alert
        style={{ marginBottom: 12 }}
        type="info"
        showIcon
        message={t("users.hint.title")}
        description={t("users.hint.body")}
      />
      {error && <Card size="small">{error}</Card>}
      <Table<PlatformUser>
        rowKey="user_id"
        loading={loading}
        dataSource={users}
        pagination={false}
        columns={[
          { title: t("users.column.userId"), dataIndex: "user_id" },
          { title: t("users.column.displayName"), dataIndex: "display_name" },
          {
            title: t("users.column.roles"),
            dataIndex: "roles",
            render: (roles: string[] | undefined) => (
              <Space wrap>
                {(roles ?? []).map((role) => (
                  <Tag
                    key={role}
                    color={
                      role === "platform_admin"
                        ? "blue"
                        : role === "approval_admin"
                          ? "gold"
                          : "default"
                    }
                  >
                    {role}
                  </Tag>
                ))}
              </Space>
            ),
          },
          {
            title: t("common.status"),
            dataIndex: "is_active",
            render: (active: boolean) =>
              active ? (
                <Tag color="green">{t("common.enabled")}</Tag>
              ) : (
                <Tag color="red">{t("common.disabled")}</Tag>
              ),
          },
          {
            title: t("common.actions"),
            render: (_: unknown, user: PlatformUser) => (
              <Space>
                <Button size="small" onClick={() => openUserModal(user)}>
                  {t("common.edit")}
                </Button>
                <Button size="small" onClick={() => openTokenModal(user)}>
                  {t("users.action.tokens")}
                </Button>
                <Button
                  size="small"
                  icon={<CloudUploadOutlined />}
                  onClick={() => void openProvisionModal(user)}
                >
                  {t("users.action.provision")}
                </Button>
              </Space>
            ),
          },
        ]}
      />

      {/* 审批账号加载中禁止保存：此时表单是空集合，提前保存会清掉已有绑定。 */}
      <Modal
        title={editingUser ? t("users.modal.editTitle", { id: editingUser.user_id }) : t("users.modal.createTitle")}
        open={userModalOpen}
        onCancel={() => setUserModalOpen(false)}
        onOk={() => void saveUser()}
        confirmLoading={savingUser}
        okText={t("common.save")}
        cancelText={t("common.cancel")}
        okButtonProps={{ disabled: approverAccountsLoading }}
      >
        <Form form={userForm} layout="vertical">
          <Form.Item
            name="user_id"
            label={t("users.form.userId")}
            rules={[{ required: true, message: t("users.form.userIdRequired") }]}
            extra={t("users.form.userIdHint")}
          >
            <Input disabled={Boolean(editingUser)} placeholder="alice" />
          </Form.Item>
          <Form.Item
            name="display_name"
            label={t("users.form.displayName")}
            rules={[{ required: true, message: t("users.form.displayNameRequired") }]}
          >
            <Input placeholder="Alice Zhang" />
          </Form.Item>
          <Form.Item name="email" label={t("common.email")}>
            <Input placeholder="alice@example.com" />
          </Form.Item>
          <Form.Item
            name="roles"
            label={t("common.role")}
            rules={[{ required: true, message: t("users.form.roleRequired") }]}
            extra={t("users.form.roleHint")}
          >
            <Select
              mode="multiple"
              options={ROLE_VALUES.map((role) => ({
                value: role,
                label: `${role} · ${t(`role.${role}`)}`,
              }))}
            />
          </Form.Item>
          <Form.Item name="is_active" label={t("common.enabled")} valuePropName="checked">
            <Switch />
          </Form.Item>
          {approverRoles.some(
            (role: string) => role === "platform_admin" || role === "approval_admin",
          ) && (
            <Form.Item
              name="approver_account_ids"
              label={t("users.form.approverAccounts")}
              extra={t("users.form.approverAccountsHint")}
            >
              <Select
                mode="multiple"
                loading={approverAccountsLoading}
                placeholder={t("users.form.approverAccountsPlaceholder")}
                options={accounts.map((account) => ({
                  value: account.id,
                  label: `${account.account_name || account.aws_account_id}（${account.aws_account_id}）`,
                }))}
              />
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Modal
        title={tokenUser ? t("users.modal.tokenTitle", { id: tokenUser.user_id }) : t("users.modal.tokenTitleGeneric")}
        open={Boolean(tokenUser)}
        onCancel={() => {
          setTokenUser(null);
          setIssuedToken(null);
        }}
        footer={null}
        width={720}
      >
        {issuedToken && (
          <Alert
            style={{ marginBottom: 12 }}
            type="warning"
            showIcon
            message={t("users.token.secretTitle")}
            description={
              <Space direction="vertical" style={{ width: "100%" }}>
                <Text code copyable={{ text: issuedToken.token }}>
                  {issuedToken.token}
                </Text>
                <Text type="secondary">{t("users.token.secretHint")}</Text>
              </Space>
            }
          />
        )}
        <Card size="small" style={{ marginBottom: 12 }} title={t("users.token.issueTitle")}>
          <Form form={tokenForm} layout="inline" onFinish={() => void issueToken()}>
            <Form.Item
              name="name"
              label={t("common.name")}
              rules={[{ required: true, message: t("users.token.nameRequired") }]}
            >
              <Input style={{ width: 200 }} placeholder="laptop" />
            </Form.Item>
            <Form.Item name="expires_in_hours" label={t("users.token.expiryHours")}>
              <InputNumber min={1} max={8760} style={{ width: 140 }} />
            </Form.Item>
            <Form.Item>
              <Button type="primary" loading={issuing} onClick={() => void issueToken()}>
                {t("users.action.issueToken")}
              </Button>
            </Form.Item>
          </Form>
        </Card>
        <Table<PlatformTokenInfo>
          rowKey="id"
          size="small"
          loading={tokensLoading}
          dataSource={tokens}
          pagination={false}
          columns={[
            { title: t("common.name"), dataIndex: "name" },
            { title: t("users.token.column.prefix"), dataIndex: "prefix" },
            {
              title: t("common.status"),
              render: (_: unknown, token: PlatformTokenInfo) =>
                token.revoked_at ? (
                  <Tag color="red">{t("users.token.revoked")}</Tag>
                ) : (
                  <Tag color="green">{t("users.token.active")}</Tag>
                ),
            },
            {
              title: t("users.token.column.expires"),
              dataIndex: "expires_at",
              render: (value?: string) => (value ? new Date(value).toLocaleString() : t("common.notExpired")),
            },
            {
              title: t("users.token.column.lastUsed"),
              dataIndex: "last_used_at",
              render: (value?: string) => (value ? new Date(value).toLocaleString() : t("common.never")),
            },
            {
              title: t("common.actions"),
              render: (_: unknown, token: PlatformTokenInfo) =>
                token.revoked_at ? null : (
                  <Button size="small" danger onClick={() => void revokeToken(token)}>
                    {t("users.action.revokeToken")}
                  </Button>
                ),
            },
          ]}
        />
      </Modal>

      <Modal
        title={provisionUser ? t("users.provision.title", { id: provisionUser.user_id }) : ""}
        open={Boolean(provisionUser)}
        onCancel={() => setProvisionUser(null)}
        footer={
          provisionResults ? (
            <Button type="primary" onClick={() => setProvisionUser(null)}>
              {t("common.close")}
            </Button>
          ) : (
            <Button
              type="primary"
              icon={<CloudUploadOutlined />}
              loading={provisioning}
              onClick={() => void submitProvision()}
            >
              {t("users.provision.submit")}
            </Button>
          )
        }
        width={680}
      >
        {provisionResults ? (
          <>
            <Alert
              type={provisionResults.every((r) => !r.error) ? "success" : "warning"}
              showIcon
              message={t("users.provision.resultsTitle")}
              description={
                <>
                  {t("users.provision.resultsHint")}
                  {provisionResults.some((r) => r.conflict) ? (
                    <div style={{ marginTop: 6 }}>{t("users.provision.conflictHint")}</div>
                  ) : null}
                </>
              }
              style={{ marginBottom: 12 }}
            />
            <Table<PlatformProvisionResult>
              rowKey="account_id"
              size="small"
              dataSource={provisionResults}
              pagination={false}
              columns={[
                {
                  title: t("users.provision.colAccount"),
                  dataIndex: "account_id",
                  render: (id: number) =>
                    accounts.find((a) => a.id === id)?.account_name ||
                    accounts.find((a) => a.id === id)?.aws_account_id ||
                    id,
                },
                {
                  title: t("users.provision.colTicket"),
                  dataIndex: "ticket_no",
                  render: (no?: string) =>
                    no ? (
                      <Link to={`/tickets/${encodeURIComponent(no)}`} className="mono">
                        {no}
                      </Link>
                    ) : (
                      "-"
                    ),
                },
                {
                  title: t("common.status"),
                  render: (_: unknown, r: PlatformProvisionResult) =>
                    r.error ? (
                      <Space direction="vertical" size={2}>
                        {r.conflict ? (
                          <Tag color="orange">{t("users.provision.conflictTag")}</Tag>
                        ) : null}
                        <Text type={r.conflict ? "warning" : "danger"}>{r.error}</Text>
                      </Space>
                    ) : (
                      <Tag color="green">{t("users.provision.created")}</Tag>
                    ),
                },
              ]}
            />
          </>
        ) : (
          <Form form={provisionForm} layout="vertical">
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message={t("users.provision.hint")}
            />
            <Form.Item
              name="account_ids"
              label={t("users.provision.accounts")}
              extra={
                accounts.some((account) => !account.sync_enabled)
                  ? t("users.provision.disabledFiltered", {
                      count: accounts.filter((account) => !account.sync_enabled).length,
                    })
                  : undefined
              }
              rules={[{ required: true, message: t("users.provision.accountsRequired") }]}
            >
              <Select
                mode="multiple"
                loading={!accounts.length}
                maxTagCount={6}
                onChange={(value: number[]) => setProvisionAccountIDs(value ?? [])}
                options={accounts
                  .filter((account) => account.sync_enabled)
                  .map((account) => ({
                    value: account.id,
                    label: account.account_name
                      ? `${account.account_name} (${account.aws_account_id})`
                      : account.aws_account_id,
                  }))}
              />
            </Form.Item>
            <Form.Item
              name="groups"
              label={t("users.provision.groups")}
              extra={t("users.provision.groupsHint")}
            >
              <Select
                mode="multiple"
                allowClear
                showSearch
                optionFilterProp="label"
                loading={provisionGroupsLoading}
                disabled={provisionAccountIDs.length === 0}
                placeholder={
                  provisionAccountIDs.length
                    ? t("users.provision.groupsPlaceholder")
                    : t("users.provision.groupsPlaceholderNoAccount")
                }
                options={provisionGroupOptions}
              />
            </Form.Item>
            <Form.Item
              name="approval_mode"
              label={t("users.provision.approvalMode")}
              rules={[{ required: true }]}
            >
              <Select
                options={[
                  { value: "AUTO", label: t("users.provision.modeAuto") },
                  { value: "MANUAL", label: t("users.provision.modeManual") },
                ]}
              />
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(prev, next) => prev.approval_mode !== next.approval_mode}>
              {({ getFieldValue }) =>
                getFieldValue("approval_mode") === "MANUAL" ? (
                  <Form.Item
                    name="approver_ids"
                    label={t("users.provision.approvers")}
                    rules={[{ required: true, message: t("users.provision.approversRequired") }]}
                  >
                    <Select
                      mode="multiple"
                      options={users
                        .filter(
                          (candidate) =>
                            candidate.user_id !== provisionUser?.user_id &&
                            candidate.is_active &&
                            (candidate.roles ?? []).some(
                              (role) => role === "platform_admin" || role === "approval_admin",
                            ),
                        )
                        .map((candidate) => ({ value: candidate.user_id, label: candidate.user_id }))}
                    />
                  </Form.Item>
                ) : null
              }
            </Form.Item>
          </Form>
        )}
      </Modal>
    </div>
  );
}
