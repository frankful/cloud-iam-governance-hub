import {
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Input,
  List,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { ReloadOutlined, EditOutlined, DisconnectOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type {
  AWSAccountRef,
  AttachedPolicy,
  GroupDetail,
  GroupSummary,
  InlinePolicyDetail,
  InlinePolicySummary,
  InstanceProfileDetail,
  InstanceProfileSummary,
  ManagedPolicyDetail,
  ManagedPolicySummary,
  PrincipalDetail,
  PrincipalSummary,
} from "../api/types";

const { Title, Text } = Typography;

// 两个顶层分类：用户自定义（生命周期在人手里，可工单修改）vs 官方托管
// （AWS 服务自建自管，只能看不能改）。分类与后端 aws 过滤参数一一对应，
// 翻页在服务端完成。
type Category = "ticket" | "aws";
type SubTab = "users" | "roles" | "groups" | "policies" | "inline" | "profiles";

const TABS_BY_CATEGORY: Record<Category, SubTab[]> = {
  ticket: ["users", "roles", "groups", "policies", "inline"],
  aws: ["roles", "policies", "inline", "profiles"],
};

// 详情抽屉的五类内容：主体/组沿用原有抽屉，策略/内联策略/配置文件为新增。
type DetailState =
  | { kind: "principal"; data: PrincipalDetail }
  | { kind: "group"; data: GroupDetail }
  | { kind: "policy"; data: ManagedPolicyDetail }
  | { kind: "inline"; data: InlinePolicyDetail }
  | { kind: "profile"; data: InstanceProfileDetail };

export default function InventoryPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [accounts, setAccounts] = useState<AWSAccountRef[]>([]);
  const [category, setCategory] = useState<Category>("ticket");
  const [tab, setTab] = useState<SubTab>("users");
  const [accountId, setAccountId] = useState<number | undefined>();
  const [q, setQ] = useState("");
  const [principals, setPrincipals] = useState<PrincipalSummary[]>([]);
  const [groups, setGroups] = useState<GroupSummary[]>([]);
  const [policies, setPolicies] = useState<ManagedPolicySummary[]>([]);
  const [inlinePolicies, setInlinePolicies] = useState<InlinePolicySummary[]>([]);
  const [profiles, setProfiles] = useState<InstanceProfileSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState({ limit: 20, offset: 0 });
  const [detail, setDetail] = useState<DetailState | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  // 切分类时把子 tab 归位到该分类的第一项。
  const switchCategory = (next: Category) => {
    setCategory(next);
    setTab(TABS_BY_CATEGORY[next][0]);
    setPage((prev) => ({ ...prev, offset: 0 }));
  };

  const load = useCallback(async () => {
    // 必须先选账号：全量跨账号清单既慢又容易误读（同名资源分属多账号）。
    if (!accountId) {
      setPrincipals([]);
      setGroups([]);
      setPolicies([]);
      setInlinePolicies([]);
      setProfiles([]);
      setTotal(0);
      setError(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const params = {
        account_id: accountId,
        q: q || undefined,
        limit: page.limit,
        offset: page.offset,
      };
      switch (tab) {
        case "users": {
          const res = await api.listPrincipals({ ...params, type: "User" });
          setPrincipals(res.principals);
          setTotal(res.total);
          break;
        }
        case "roles": {
          const res = await api.listPrincipals({
            ...params,
            type: "Role",
            // ticket=排除官方托管的角色；aws=只看它们。
            aws: category === "ticket" ? "false" : "true",
          });
          setPrincipals(res.principals);
          setTotal(res.total);
          break;
        }
        case "groups": {
          const res = await api.listGroups(params);
          setGroups(res.groups);
          setTotal(res.total);
          break;
        }
        case "policies": {
          const res = await api.listPoliciesV2({
            account_id: params.account_id,
            q: params.q,
            limit: params.limit,
            offset: params.offset,
            aws: category === "ticket" ? "false" : "true",
          });
          setPolicies(res.policies);
          setTotal(res.total);
          break;
        }
        case "inline": {
          const res = await api.listInlinePolicies({
            ...params,
            aws: category === "ticket" ? "false" : "true",
          });
          setInlinePolicies(res.policies);
          setTotal(res.total);
          break;
        }
        case "profiles": {
          const res = await api.listInstanceProfiles(params);
          setProfiles(res.profiles);
          setTotal(res.total);
          break;
        }
      }
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("inventory.error.loadFailed", { message: String(err) }),
      );
    } finally {
      setLoading(false);
    }
  }, [accountId, category, tab, q, page, t]);

  useEffect(() => {
    api.listAccounts().then(setAccounts).catch(() => setAccounts([]));
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const showDetail = (next: DetailState) => {
    setDetail(next);
    setDetailOpen(true);
  };

  const openPrincipalOrGroup = async (id: number) => {
    setError(null);
    try {
      if (tab === "groups") {
        showDetail({ kind: "group", data: await api.getGroup(id) });
      } else {
        showDetail({ kind: "principal", data: await api.getPrincipal(id) });
      }
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("inventory.error.detailFailed", { message: String(err) }),
      );
    }
  };

  /** 托管策略详情（含文档与引用计数）；官方托管策略同样可看，只是不可改。 */
  const openPolicyDetail = async (id: number) => {
    setError(null);
    try {
      showDetail({ kind: "policy", data: await api.getPolicy(id) });
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("inventory.error.detailFailed", { message: String(err) }),
      );
    }
  };

  /** 内联策略详情（含文档与所属主体）。 */
  const openInlineDetail = async (policyId: number) => {
    setError(null);
    try {
      showDetail({ kind: "inline", data: await api.getInlinePolicy(policyId) });
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("inventory.error.detailFailed", { message: String(err) }),
      );
    }
  };

  /** 实例配置文件详情（含标签与绑定角色）。 */
  const openProfileDetail = async (id: number) => {
    setError(null);
    try {
      showDetail({ kind: "profile", data: await api.getInstanceProfile(id) });
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("inventory.error.detailFailed", { message: String(err) }),
      );
    }
  };

  // 清单抽屉 → 预填并跳转到新建工单页。
  const gotoNewTicket = (state: Record<string, unknown>) => {
    setDetailOpen(false);
    navigate("/tickets/new", { state });
  };

  /** 托管策略解绑：ATTACH 工单 operation=detach（仅平台纳管的挂载可解绑）。 */
  const gotoDetach = (
    principalType: string,
    principalName: string,
    policyArn?: string,
    accountDbId?: number,
  ) => {
    if (!policyArn) return;
    gotoNewTicket({
      ticket_type: "ATTACH_USER_POLICY",
      operation: "detach",
      principal_type: principalType,
      principal_name: principalName,
      policy_arn: policyArn,
      // 带上账号，新建工单页才能立刻拉到该主体的挂载清单做预览。
      account_id: accountDbId,
    });
  };

  /** 托管策略编辑：UPDATE_MANAGED_POLICY（仅用户自定义策略，官方托管策略不可变更）。 */
  const gotoUpdatePolicy = (
    policyId: number,
    policyArn?: string,
    policyName?: string,
    accountDbId?: number,
  ) => {
    // 官方托管策略（arn:aws:iam::aws:policy/）不可编辑，直接忽略。
    if (!policyArn || policyArn.startsWith("arn:aws:iam::aws:policy/")) return;
    gotoNewTicket({
      ticket_type: "UPDATE_MANAGED_POLICY",
      policy_id: policyId,
      policy_arn: policyArn,
      principal_name: policyName,
      // 带上账号，新建工单页的实时校验与预填立即可用。
      account_id: accountDbId,
    });
  };

  /** 内嵌策略编辑：UPDATE_GROUP_INLINE_POLICY（组 / 角色内联策略）。 */
  const gotoUpdateInlinePolicy = (
    principalType: string,
    principalName: string,
    policyId: number,
    policyName?: string,
    accountDbId?: number,
  ) => {
    gotoNewTicket({
      ticket_type: "UPDATE_GROUP_INLINE_POLICY",
      principal_type: principalType,
      principal_name: principalName,
      group_name: principalType === "Group" ? principalName : undefined,
      policy_id: policyId,
      inline_policy_name: policyName,
      // 带上账号，新建工单页才能立刻加载主体清单与内联策略。
      account_id: accountDbId,
    });
  };

  /** 渲染一条策略行的解绑/编辑动作按钮。 */
  const renderPolicyActions = (
    principalType: string,
    principalName: string,
    policy: AttachedPolicy,
    accountDbId?: number,
  ) => {
    const isInline = policy.policy_type === "inline";
    const isAWSPolicy = (policy.policy_arn ?? "").startsWith("arn:aws:iam::aws:policy/");
    return (
      <Space size={4}>
        {!isInline && (
          <Button
            size="small"
            icon={<DisconnectOutlined />}
            disabled={
              principalType !== "User" && principalType !== "Group" && principalType !== "Role"
            }
            onClick={() =>
              gotoDetach(principalType, principalName, policy.policy_arn, accountDbId)
            }
          >
            {t("inventory.action.detach")}
          </Button>
        )}
        {isInline ? (
          <Button
            size="small"
            icon={<EditOutlined />}
            disabled={principalType !== "Group" && principalType !== "Role"}
            onClick={() =>
              gotoUpdateInlinePolicy(
                principalType,
                principalName,
                policy.policy_id,
                policy.policy_name,
                accountDbId,
              )
            }
          >
            {t("inventory.action.editInlinePolicy")}
          </Button>
        ) : (
          !isAWSPolicy && (
            <Button
              size="small"
              icon={<EditOutlined />}
              onClick={() =>
                gotoUpdatePolicy(policy.policy_id, policy.policy_arn, policy.policy_name, accountDbId)
              }
            >
              {t("inventory.action.editManagedPolicy")}
            </Button>
          )
        )}
      </Space>
    );
  };

  const pagination = {
    current: Math.floor(page.offset / page.limit) + 1,
    pageSize: page.limit,
    total,
    showSizeChanger: false,
    onChange: (p: number, size: number) => setPage({ limit: size, offset: (p - 1) * size }),
  };
  const accountColumn = { title: t("inventory.column.awsAccount"), dataIndex: "aws_account_id", width: 140 };
  const arnColumn = { title: t("inventory.column.arn"), dataIndex: "arn", ellipsis: true, className: "mono" };

  /** 主体表（users/roles 两个 tab 共用；roles 按 aws 过滤在服务端完成）。 */
  const principalTable = (
    <Table<PrincipalSummary>
      rowKey="id"
      loading={loading}
      dataSource={principals}
      scroll={{ x: 1100 }}
      pagination={pagination}
      columns={[
        {
          title: t("inventory.column.name"),
          dataIndex: "principal_name",
          width: 260,
          render: (v: string, r: PrincipalSummary) => (
            <a onClick={() => void openPrincipalOrGroup(r.id)}>{v}</a>
          ),
        },
        {
          title: t("inventory.column.type"),
          dataIndex: "principal_type",
          width: 90,
          render: (v: string) => <Tag color={v === "User" ? "blue" : "geekblue"}>{v}</Tag>,
        },
        accountColumn,
        arnColumn,
        { title: t("inventory.column.lastSynced"), dataIndex: "last_seen_at", width: 170 },
      ]}
    />
  );

  const groupTable = (
    <Table<GroupSummary>
      rowKey="id"
      loading={loading}
      dataSource={groups}
      scroll={{ x: 900 }}
      pagination={pagination}
      columns={[
        {
          title: t("inventory.column.groupName"),
          dataIndex: "group_name",
          width: 260,
          render: (v: string, r: GroupSummary) => (
            <a onClick={() => void openPrincipalOrGroup(r.id)}>{v}</a>
          ),
        },
        accountColumn,
        { title: t("inventory.column.memberCount"), dataIndex: "member_count", width: 90 },
        arnColumn,
      ]}
    />
  );

  const policyTable = (
    <Table<ManagedPolicySummary>
      rowKey="id"
      loading={loading}
      dataSource={policies}
      scroll={{ x: 900 }}
      pagination={pagination}
      columns={[
        {
          title: t("inventory.column.policyName"),
          dataIndex: "policy_name",
          width: 280,
          render: (v: string, r: ManagedPolicySummary) => (
            <a onClick={() => void openPolicyDetail(r.id)}>{v}</a>
          ),
        },
        accountColumn,
        arnColumn,
        {
          title: t("common.actions"),
          key: "actions",
          width: 120,
          render: (_: unknown, r: ManagedPolicySummary) =>
            category === "ticket" ? (
              <Button
                size="small"
                icon={<EditOutlined />}
                onClick={() => gotoUpdatePolicy(r.id, r.policy_arn, r.policy_name)}
              >
                {t("inventory.action.editManagedPolicy")}
              </Button>
            ) : (
              <Tag>{t("inventory.officialTag")}</Tag>
            ),
        },
      ]}
    />
  );

  const inlineTable = (
    <Table<InlinePolicySummary>
      rowKey={(r) => `${r.owner_kind}-${r.owner_name}-${r.policy_id}-${r.policy_name}`}
      loading={loading}
      dataSource={inlinePolicies}
      scroll={{ x: 1000 }}
      pagination={pagination}
      columns={[
        {
          title: t("inventory.column.policyName"),
          dataIndex: "policy_name",
          width: 240,
          render: (v: string, r: InlinePolicySummary) => (
            <a onClick={() => void openInlineDetail(r.policy_id)}>{v}</a>
          ),
        },
        {
          title: t("inventory.column.owner"),
          key: "owner",
          width: 260,
          render: (_: unknown, r: InlinePolicySummary) => (
            <Space size={6}>
              <Tag color={r.owner_kind === "group" ? "cyan" : r.owner_kind === "user" ? "blue" : "geekblue"}>
                {r.owner_kind.toUpperCase()}
              </Tag>
              <Text>{r.owner_name}</Text>
            </Space>
          ),
        },
        accountColumn,
        { title: t("inventory.column.ownerArn"), dataIndex: "owner_arn", ellipsis: true, className: "mono" },
        {
          title: t("common.actions"),
          key: "actions",
          width: 120,
          render: (_: unknown, r: InlinePolicySummary) =>
            category === "ticket" ? (
              <Button
                size="small"
                icon={<EditOutlined />}
                onClick={() =>
                  gotoUpdateInlinePolicy(
                    r.owner_kind === "role" ? "Role" : r.owner_kind === "user" ? "User" : "Group",
                    r.owner_name,
                    r.policy_id,
                    r.policy_name,
                    r.account_db_id,
                  )
                }
              >
                {t("inventory.action.editInlinePolicy")}
              </Button>
            ) : (
              <Tag>{t("inventory.officialTag")}</Tag>
            ),
        },
      ]}
    />
  );

  const profileTable = (
    <Table<InstanceProfileSummary>
      rowKey="id"
      loading={loading}
      dataSource={profiles}
      scroll={{ x: 1000 }}
      pagination={pagination}
      columns={[
        {
          title: t("inventory.column.profileName"),
          dataIndex: "instance_profile_name",
          width: 300,
          render: (v: string, r: InstanceProfileSummary) => (
            <Space size={6}>
              <a onClick={() => void openProfileDetail(r.id)}>{v}</a>
              {r.eks_managed && (
                <Tooltip title={t("inventory.eksManagedTip")}>
                  <Tag color="orange">EKS</Tag>
                </Tooltip>
              )}
            </Space>
          ),
        },
        { title: t("inventory.column.boundRole"), dataIndex: "role_name", width: 220 },
        accountColumn,
        arnColumn,
        { title: t("inventory.column.lastSynced"), dataIndex: "last_seen_at", width: 170 },
      ]}
    />
  );

  const tableByTab: Record<SubTab, ReactNode> = {
    users: principalTable,
    roles: principalTable,
    groups: groupTable,
    policies: policyTable,
    inline: inlineTable,
    profiles: profileTable,
  };

  /** JSON 文档统一缩进展示。 */
  const renderDocument = (doc: unknown) => (
    <pre className="mono terraform-code" style={{ maxHeight: 420, overflow: "auto" }}>
      {JSON.stringify(doc, null, 2)}
    </pre>
  );

  const drawerTitle = detail
    ? detail.kind === "principal"
      ? detail.data.principal_name
      : detail.kind === "group"
        ? detail.data.group_name
        : detail.kind === "policy" || detail.kind === "inline"
          ? detail.data.policy_name
          : detail.data.instance_profile_name
    : "";

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("inventory.title")}
        </Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()} disabled={!accountId}>
          {t("inventory.action.refresh")}
        </Button>
      </Space>
      <Card size="small" style={{ marginBottom: 16 }}>
        <Space wrap>
          <Segmented
            value={category}
            onChange={(v) => switchCategory(v as Category)}
            options={[
              { value: "ticket", label: t("inventory.category.ticket") },
              { value: "aws", label: t("inventory.category.aws") },
            ]}
          />
          <Select
            style={{ width: 140 }}
            value={tab}
            onChange={(v) => {
              setTab(v);
              setPage({ ...page, offset: 0 });
            }}
            options={TABS_BY_CATEGORY[category].map((value) => ({
              value,
              label: t(`inventory.tab.${value}`),
            }))}
          />
          <Select
            style={{ width: 260 }}
            placeholder={t("inventory.filter.selectAccount")}
            value={accountId}
            onChange={(v) => {
              setAccountId(v);
              setPage({ ...page, offset: 0 });
            }}
            options={accounts.map((a) => ({
              value: a.id,
              label: t("inventory.account.option", {
                id: a.aws_account_id,
                name: a.account_name ?? t("inventory.account.unnamed"),
              }),
            }))}
          />
          <Input.Search
            style={{ width: 220 }}
            placeholder={t("inventory.filter.searchPlaceholder")}
            allowClear
            disabled={!accountId}
            onSearch={(v) => {
              setQ(v);
              setPage({ ...page, offset: 0 });
            }}
          />
        </Space>
      </Card>
      {error && <Card size="small">{error}</Card>}
      {!accountId ? (
        <Card size="small">
          <Empty description={t("inventory.selectAccountFirst")} />
        </Card>
      ) : (
        tableByTab[tab]
      )}

      <Drawer
        width={560}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
        title={drawerTitle}
      >
        {detail?.kind === "principal" ? (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text type="secondary" className="mono">
              {detail.data.arn}
            </Text>
            {detail.data.description && <div>{detail.data.description}</div>}
            {/* 角色才有信任策略 */}
            {detail.data.principal_type === "Role" && detail.data.trust_policy != null && (
              <Card size="small" title={t("inventory.drawer.trustPolicy")}>
                {renderDocument(detail.data.trust_policy)}
              </Card>
            )}
            <Card size="small" title={t("inventory.drawer.attachedPolicies")}>
              <List
                size="small"
                dataSource={detail.data.policies}
                locale={{ emptyText: t("inventory.empty.none") }}
                renderItem={(p) => (
                  <List.Item>
                    <Space direction="vertical" size={0} style={{ width: "100%" }}>
                      <Text strong>{p.policy_name ?? p.policy_id}</Text>
                      <Text type="secondary" className="mono">
                        {p.policy_arn ?? p.policy_type ?? ""}
                      </Text>
                      <div style={{ marginTop: 4 }}>
                        {renderPolicyActions(
                          detail.data.principal_type,
                          detail.data.principal_name,
                          p,
                          detail.data.account_db_id,
                        )}
                      </div>
                    </Space>
                  </List.Item>
                )}
              />
            </Card>
            <Card size="small" title={t("inventory.drawer.groups")}>
              <List
                size="small"
                dataSource={detail.data.groups}
                locale={{ emptyText: t("inventory.empty.none") }}
                renderItem={(g) => (
                  <List.Item>
                    <Text>{g.group_name}</Text>
                  </List.Item>
                )}
              />
            </Card>
          </Space>
        ) : detail?.kind === "group" ? (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text type="secondary" className="mono">
              {detail.data.arn}
            </Text>
            <div>
              {t("inventory.drawer.memberCountLabel")}
              <b>{detail.data.member_count}</b>
            </div>
            <Card size="small" title={t("inventory.drawer.groupMembers")}>
              <List
                size="small"
                dataSource={detail.data.members}
                locale={{ emptyText: t("inventory.empty.noMembers") }}
                renderItem={(m) => (
                  <List.Item>
                    <Text>{m.principal_name}</Text>
                  </List.Item>
                )}
              />
            </Card>
            <Card size="small" title={t("inventory.drawer.groupPolicies")}>
              <List
                size="small"
                dataSource={detail.data.policies}
                locale={{ emptyText: t("inventory.empty.none") }}
                renderItem={(p) => (
                  <List.Item>
                    <Space direction="vertical" size={0} style={{ width: "100%" }}>
                      <Text strong>{p.policy_name ?? p.policy_id}</Text>
                      <Text type="secondary" className="mono">
                        {p.policy_arn ?? p.policy_type ?? ""}
                      </Text>
                      <div style={{ marginTop: 4 }}>
                        {renderPolicyActions("Group", detail.data.group_name, p, detail.data.account_db_id)}
                      </div>
                    </Space>
                  </List.Item>
                )}
              />
            </Card>
          </Space>
        ) : detail?.kind === "policy" ? (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text type="secondary" className="mono">
              {detail.data.policy_arn}
            </Text>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label={t("inventory.column.awsAccount")}>
                {/* 官方托管策略无账号（arn:aws:iam::aws:policy/）；自管策略从 ARN 取 */}
                {(detail.data.policy_arn ?? "").match(/^arn:aws:iam::(\d{12}):/)?.[1] ??
                  t("inventory.officialTag")}
              </Descriptions.Item>
              <Descriptions.Item label={t("inventory.drawer.attachedPrincipals")}>
                {detail.data.attached_principals}
              </Descriptions.Item>
              <Descriptions.Item label={t("inventory.drawer.attachedGroups")}>
                {detail.data.attached_groups}
              </Descriptions.Item>
            </Descriptions>
            {(detail.data.policy_arn ?? "").startsWith("arn:aws:iam::aws:policy/") ? null : (
              <Button
                size="small"
                icon={<EditOutlined />}
                onClick={() =>
                  gotoUpdatePolicy(detail.data.id, detail.data.policy_arn, detail.data.policy_name)
                }
              >
                {t("inventory.action.editManagedPolicy")}
              </Button>
            )}
            <Card size="small" title={t("inventory.drawer.policyDocument")}>
              {detail.data.policy_document != null
                ? renderDocument(detail.data.policy_document)
                : t("inventory.empty.documentNotFetched")}
            </Card>
          </Space>
        ) : detail?.kind === "inline" ? (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text type="secondary" className="mono">
              {detail.data.owner_arn}
            </Text>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label={t("inventory.column.owner")}>
                <Space size={6}>
                  <Tag color={detail.data.owner_kind === "group" ? "cyan" : "geekblue"}>
                    {detail.data.owner_kind.toUpperCase()}
                  </Tag>
                  <Text>{detail.data.owner_name}</Text>
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label={t("inventory.column.awsAccount")}>
                {detail.data.aws_account_id}
              </Descriptions.Item>
            </Descriptions>
            {detail.data.aws_managed ? null : (
              <Button
                size="small"
                icon={<EditOutlined />}
                onClick={() =>
                  gotoUpdateInlinePolicy(
                    detail.data.owner_kind === "role"
                      ? "Role"
                      : detail.data.owner_kind === "user"
                        ? "User"
                        : "Group",
                    detail.data.owner_name,
                    detail.data.policy_id,
                    detail.data.policy_name,
                    detail.data.account_db_id,
                  )
                }
              >
                {t("inventory.action.editInlinePolicy")}
              </Button>
            )}
            <Card size="small" title={t("inventory.drawer.policyDocument")}>
              {detail.data.policy_document != null
                ? renderDocument(detail.data.policy_document)
                : t("inventory.empty.none")}
            </Card>
          </Space>
        ) : detail?.kind === "profile" ? (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Text type="secondary" className="mono">
              {detail.data.arn}
            </Text>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label={t("inventory.column.awsAccount")}>
                {detail.data.aws_account_id}
              </Descriptions.Item>
              <Descriptions.Item label={t("inventory.column.boundRole")}>
                {detail.data.role_arn ? (
                  <Text className="mono" copyable={{ text: detail.data.role_arn }}>
                    {detail.data.role_name || detail.data.role_arn}
                  </Text>
                ) : (
                  t("inventory.empty.none")
                )}
              </Descriptions.Item>
              <Descriptions.Item label={t("inventory.column.path")}>
                {detail.data.path}
              </Descriptions.Item>
              <Descriptions.Item label={t("inventory.column.lastSynced")}>
                {detail.data.last_seen_at}
              </Descriptions.Item>
            </Descriptions>
            {detail.data.eks_managed && <Tag color="orange">EKS</Tag>}
            {detail.data.tags && Object.keys(detail.data.tags).length > 0 && (
              <Card size="small" title={t("inventory.drawer.tags")}>
                {Object.entries(detail.data.tags).map(([key, value]) => (
                  <div key={key}>
                    <Text strong>{key}</Text>：{value}
                  </div>
                ))}
              </Card>
            )}
          </Space>
        ) : null}
      </Drawer>
    </div>
  );
}
