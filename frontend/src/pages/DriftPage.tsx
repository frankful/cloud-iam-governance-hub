import {
  Alert,
  Button,
  Empty,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import { ReloadOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type {
  DriftAccountSummary,
  DriftFinding,
  DriftFindingPage,
  DriftRemediationRoute,
  DriftSeverity,
  DriftStatus,
} from "../api/types";
import { hasRole, useAuth } from "../auth";

const { Title, Paragraph, Text } = Typography;

// 超过这个时长没有检测记录就显式告警：判定频率等于同步频率，页面上的
// 「0 条发现」在检测停摆时同样成立，两者必须在视觉上分开（台账 C7）。
const HEALTHY_CHECK_HOURS = 48;

// 摘要由服务端拼中文；带 summary_code 时按当前语言渲染（C16），没有码的
// 历史行、以及 CI 自带 summary 的上报，退回服务端原文。
function driftSummaryText(finding: DriftFinding, t: TFunction): string {
  const code = finding.summary_code;
  if (!code) return finding.summary ?? "";
  const params = finding.summary_params ?? {};
  if (code === "undeclared_extra" && params.child) {
    return t(`drift.summary.${code}`, {
      ...params,
      child: t(`drift.child.${params.child}`, { defaultValue: params.child }),
      defaultValue: finding.summary ?? "",
    });
  }
  return t(`drift.summary.${code}`, { ...params, defaultValue: finding.summary ?? "" });
}

const SEVERITY_COLOR: Record<DriftSeverity, string> = {
  CRITICAL: "magenta",
  HIGH: "red",
  MEDIUM: "orange",
  LOW: "default",
};

// 来源配色：CI 计划是「外部真实跑过 plan」，发布冲突是「归属没谈拢」，
// 与库存判定的可信度不同，用颜色区分比加一段说明更省阅读成本。
const SOURCE_COLOR: Record<string, string> = {
  inventory: "blue",
  ci: "purple",
  publish: "orange",
};

const STATUS_COLOR: Record<DriftStatus, string> = {
  SUSPECT: "gold",
  OPEN: "red",
  PENDING: "blue",
  PENDING_REBASELINE: "cyan",
  IGNORED: "default",
};

function formatTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function renderFieldValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export default function DriftPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const navigate = useNavigate();
  const isAdmin = hasRole(user, "platform_admin");

  const [accounts, setAccounts] = useState<DriftAccountSummary[]>([]);
  const [page, setPage] = useState<DriftFindingPage>({ items: [], total: 0, page: 1, page_size: 20 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  // 正在收敛的发现 id：按钮 loading 与防连点，避免一次点击开两张草稿。
  const [remediating, setRemediating] = useState<number | null>(null);

  const [accountFilter, setAccountFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [severityFilter, setSeverityFilter] = useState<string | undefined>();
  const [includeResolved, setIncludeResolved] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [accountSummaries, findings] = await Promise.all([
        api.driftAccounts(),
        api.listDriftFindings({
          account_id: accountFilter,
          status: statusFilter,
          severity: severityFilter,
          include_resolved: includeResolved,
          page: currentPage,
          page_size: page.page_size,
        }),
      ]);
      setAccounts(accountSummaries);
      setPage(findings);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("drift.error.load", { message: String(err) }),
      );
    } finally {
      setLoading(false);
    }
  }, [accountFilter, statusFilter, severityFilter, includeResolved, currentPage, page.page_size, t]);

  useEffect(() => {
    void load();
    // load 已包含全部筛选依赖；page_size 变化不应额外触发一次请求。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountFilter, statusFilter, severityFilter, includeResolved, currentPage]);

  // 检测按钮作用于筛选行选中的账号；未选账号或账号未纳管时置灰并提示。
  const selectedAccount = useMemo(
    () => accounts.find((account) => account.aws_account_id === accountFilter),
    [accounts, accountFilter],
  );
  const selectedManaged = !!selectedAccount && selectedAccount.declarations > 0;

  const checkDisabled = !selectedAccount || !selectedManaged;
  const checkHint = !selectedAccount
    ? t("drift.action.checkNeedAccount")
    : selectedManaged
      ? undefined
      : t("drift.unmanaged");

  // 心跳判读（C7）：检测跟随同步执行，停摆时页面只会显示 0 条发现。48 小时
  // 是「一个工作日 + 一次夜间同步」的宽限，超过就当成异常而不是安静。
  const neverCheckedCount = useMemo(
    () => accounts.filter((account) => account.declarations > 0 && !account.last_check_at).length,
    [accounts],
  );
  const staleCheckAccounts = useMemo(() => {
    const now = Date.now();
    return accounts.filter(
      (account) =>
        account.declarations > 0 &&
        !!account.last_check_at &&
        now - new Date(account.last_check_at).getTime() > HEALTHY_CHECK_HOURS * 3600000,
    );
  }, [accounts]);
  const selectedHoursSinceCheck = selectedAccount?.last_check_at
    ? (Date.now() - new Date(selectedAccount.last_check_at).getTime()) / 3600000
    : undefined;

  const formatAge = (iso: string) => {
    const minutes = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
    if (minutes < 1) return t("drift.health.justNow");
    if (minutes < 60) return t("drift.health.minutesAgo", { count: minutes });
    const hours = Math.floor(minutes / 60);
    if (hours < HEALTHY_CHECK_HOURS) return t("drift.health.hoursAgo", { count: hours });
    return t("drift.health.daysAgo", { count: Math.floor(hours / 24) });
  };

  const runCheck = async () => {
    if (!selectedAccount) return;
    setChecking(true);
    try {
      const result = await api.checkDrift(selectedAccount.account_id);
      if (result.unmanaged) {
        message.warning(t("drift.unmanaged"));
      } else {
        message.success(
          t("drift.action.checkDone", {
            declarations: result.declarations,
            surfaced: result.surfaced,
            promoted: result.promoted,
            resolved: result.resolved,
          }),
        );
      }
      setCurrentPage(1);
      await load();
    } catch (err) {
      message.error(
        err instanceof ApiError ? t(err.message, { defaultValue: err.message }) : t("drift.error.check"),
      );
    } finally {
      setChecking(false);
    }
  };

  const applyAction = async (id: number, action: "ignore" | "reopen" | "resolve") => {
    try {
      await api.driftAction(id, action);
      await load();
    } catch (err) {
      message.error(
        err instanceof ApiError ? t(err.message, { defaultValue: err.message }) : t("drift.error.action"),
      );
    }
  };

  // 收敛双路：两条路都只"发起"，不替人做决定——追认把现状写成代码，
  // 回滚只生成待审批的草稿。后端把不可行的原因写在 reason 里，按解释展示。
  const remediate = async (record: DriftFinding, route: DriftRemediationRoute) => {
    setRemediating(record.id);
    try {
      const plan = await api.remediateDrift(record.id, route);
      if (plan.reason) {
        Modal.warning({
          title: t(`drift.remediate.${route}`),
          content: plan.reason,
          okText: t("common.confirm"),
        });
      } else if (route === "rollback" && plan.ticket_no) {
        message.success(t("drift.remediate.draftCreated", { ticketNo: plan.ticket_no }));
        navigate(`/tickets/${plan.ticket_no}`);
      } else if (plan.publication) {
        if (plan.in_flight) {
          message.info(t("drift.remediate.inFlight"));
        } else {
          message.success(
            plan.already_published
              ? t("drift.remediate.alreadyPublished")
              : t("drift.remediate.publicationStarted"),
          );
        }
      }
      await load();
    } catch (err) {
      message.error(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("drift.error.remediate"),
      );
    } finally {
      setRemediating(null);
    }
  };

  const columns = [
    {
      title: t("drift.column.severity"),
      dataIndex: "severity",
      width: 100,
      render: (value: DriftSeverity) => (
        <Tag color={SEVERITY_COLOR[value]}>{t(`drift.severity.${value}`)}</Tag>
      ),
    },
    {
      title: t("drift.column.account"),
      dataIndex: "aws_account_id",
      width: 150,
    },
    {
      title: t("drift.column.resource"),
      dataIndex: "resource_key",
      render: (value: string | undefined, record: DriftFinding) => (
        <Space direction="vertical" size={0}>
          <Text strong>{value || record.kind || "—"}</Text>
          {record.resource_address ? <Text type="secondary">{record.resource_address}</Text> : null}
        </Space>
      ),
    },
    {
      title: t("drift.column.source"),
      dataIndex: "source",
      width: 120,
      render: (value: string) => (
        <Tag color={SOURCE_COLOR[value] ?? "default"}>{t(`drift.source.${value}`)}</Tag>
      ),
    },
    {
      title: t("drift.column.changeType"),
      dataIndex: "change_type",
      width: 140,
      render: (value: string) => t(`drift.changeType.${value}`),
    },
    {
      title: t("drift.column.status"),
      dataIndex: "status",
      width: 130,
      render: (value: DriftStatus) => <Tag color={STATUS_COLOR[value]}>{t(`drift.status.${value}`)}</Tag>,
    },
    {
      title: t("drift.column.summary"),
      dataIndex: "summary",
      render: (value: string | undefined, record: DriftFinding) => (
        <Text>{driftSummaryText(record, t) || value || "—"}</Text>
      ),
    },
    {
      title: t("drift.column.occurrences"),
      dataIndex: "occurrences",
      width: 90,
    },
    {
      title: t("drift.column.lastSeen"),
      dataIndex: "last_seen_at",
      width: 170,
      render: (value: string) => formatTime(value),
    },
    {
      title: t("drift.column.actions"),
      width: 320,
      render: (_: unknown, record: DriftFinding) => {
        if (!isAdmin) return null;
        if (record.resolved_at) {
          return (
            <Button size="small" onClick={() => void applyAction(record.id, "reopen")}>
              {t("drift.action.reopen")}
            </Button>
          );
        }
        const busy = remediating === record.id;
        return (
          <Space wrap size={4}>
            <Popconfirm
              title={t("drift.remediate.acknowledge")}
              description={t("drift.remediate.acknowledgeConfirm")}
              okText={t("common.confirm")}
              cancelText={t("common.cancel")}
              onConfirm={() => void remediate(record, "acknowledge")}
            >
              <Button size="small" loading={busy}>
                {t("drift.remediate.acknowledge")}
              </Button>
            </Popconfirm>
            <Popconfirm
              title={t("drift.remediate.rollback")}
              description={t("drift.remediate.rollbackConfirm")}
              okText={t("common.confirm")}
              cancelText={t("common.cancel")}
              onConfirm={() => void remediate(record, "rollback")}
            >
              <Button size="small" type="primary" ghost loading={busy}>
                {t("drift.remediate.rollback")}
              </Button>
            </Popconfirm>
            <Popconfirm
              title={t("drift.action.resolve")}
              onConfirm={() => void applyAction(record.id, "resolve")}
            >
              <Button size="small">{t("drift.action.resolve")}</Button>
            </Popconfirm>
            <Popconfirm
              title={t("drift.action.ignore")}
              onConfirm={() => void applyAction(record.id, "ignore")}
            >
              <Button size="small" type="text">
                {t("drift.action.ignore")}
              </Button>
            </Popconfirm>
          </Space>
        );
      },
    },
  ];

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("drift.title")}
        </Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>
          {t("drift.action.refresh")}
        </Button>
      </Space>
      <Paragraph type="secondary">{t("drift.subtitle")}</Paragraph>
      {error && <Alert style={{ marginBottom: 16 }} type="error" message={error} />}
      <Alert style={{ marginBottom: 16 }} type="info" showIcon message={t("drift.coverageNotice")} />

      {/* 心跳告警（C7）：先按账号集汇总，未选账号也能看到整体停摆；选中账号
          后再给出具体时间与原因，避免「0 条发现」被读成「一切正常」。 */}
      {neverCheckedCount + staleCheckAccounts.length > 0 && (
        <Alert
          style={{ marginBottom: 16 }}
          type="warning"
          showIcon
          message={t("drift.health.overdueSummary", {
            count: neverCheckedCount + staleCheckAccounts.length,
          })}
          description={t("drift.health.overdueSummaryHint")}
        />
      )}

      {selectedAccount && selectedManaged && !selectedAccount.last_check_at && (
        <Alert
          style={{ marginBottom: 16 }}
          type="warning"
          showIcon
          message={`${selectedAccount.aws_account_id} · ${t("drift.health.neverChecked")}`}
          description={t("drift.health.neverCheckedHint")}
        />
      )}

      {selectedAccount &&
        selectedManaged &&
        selectedAccount.last_check_at &&
        (selectedHoursSinceCheck ?? 0) > HEALTHY_CHECK_HOURS && (
          <Alert
            style={{ marginBottom: 16 }}
            type="warning"
            showIcon
            message={t("drift.health.overdue", {
              time: formatAge(selectedAccount.last_check_at),
            })}
            description={t("drift.health.overdueHint")}
          />
        )}

      {/* 覆盖缺口（C13）：在途 PR / 未关单的工单会占住文件，这一轮不参与比对。
          跳过的文件必须有数可查，否则「在途期间看起来干净」正是最危险的误读。 */}
      {selectedAccount && selectedAccount.last_skipped_files > 0 && (
        <Alert
          style={{ marginBottom: 16 }}
          type="info"
          showIcon
          message={t("drift.health.skipped", { files: selectedAccount.last_skipped_files })}
          description={t("drift.health.skippedHint")}
        />
      )}

      {selectedAccount && selectedAccount.last_stale_files > 0 && (
        <Alert
          style={{ marginBottom: 16 }}
          type="warning"
          showIcon
          message={t("drift.health.staleFiles", { files: selectedAccount.last_stale_files })}
          description={t("drift.health.staleHint")}
        />
      )}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 8,
          marginBottom: 16,
        }}
      >
        <Space wrap>
          <Select
            allowClear
            style={{ width: 220 }}
            placeholder={t("drift.filter.account")}
            value={accountFilter}
            onChange={(value) => {
              setAccountFilter(value);
              setCurrentPage(1);
            }}
            options={accounts.map((account) => ({
              value: account.aws_account_id,
              label: `${account.display_name || account.aws_account_id} (${account.aws_account_id})`,
            }))}
          />
          {selectedAccount &&
            (selectedAccount.declarations === 0 ? (
              <Tag color="warning">{t("drift.unmanaged")}</Tag>
            ) : (
              <Tag color="success">
                {t("drift.filter.managed", { declarations: selectedAccount.declarations })}
              </Tag>
            ))}
          {selectedAccount && selectedAccount.declarations > 0 && (
            <Tag color={selectedAccount.last_check_at ? "default" : "error"}>
              {selectedAccount.last_check_at
                ? t("drift.health.lastCheck", { time: formatAge(selectedAccount.last_check_at) })
                : t("drift.health.neverChecked")}
            </Tag>
          )}
          <Select
            allowClear
            style={{ width: 160 }}
            placeholder={t("drift.filter.status")}
            value={statusFilter}
            onChange={(value) => {
              setStatusFilter(value);
              setCurrentPage(1);
            }}
            options={Object.keys(STATUS_COLOR).map((status) => ({
              value: status,
              label: t(`drift.status.${status}`),
            }))}
          />
          <Select
            allowClear
            style={{ width: 140 }}
            placeholder={t("drift.filter.severity")}
            value={severityFilter}
            onChange={(value) => {
              setSeverityFilter(value);
              setCurrentPage(1);
            }}
            options={Object.keys(SEVERITY_COLOR).map((severity) => ({
              value: severity,
              label: t(`drift.severity.${severity}`),
            }))}
          />
          <Space>
            <Switch
              checked={includeResolved}
              onChange={(checked) => {
                setIncludeResolved(checked);
                setCurrentPage(1);
              }}
            />
            <Text>{t("drift.filter.includeResolved")}</Text>
          </Space>
        </Space>
        {isAdmin && (
          <Tooltip title={checkHint}>
            <Popconfirm
              title={t("drift.action.checkConfirmTitle")}
              description={t("drift.action.checkConfirmContent")}
              disabled={checkDisabled}
              onConfirm={() => void runCheck()}
            >
              <Button
                icon={<SafetyCertificateOutlined />}
                loading={checking}
                disabled={checkDisabled}
              >
                {t("drift.action.check")}
              </Button>
            </Popconfirm>
          </Tooltip>
        )}
      </div>

      <Table<DriftFinding>
        rowKey="id"
        loading={loading}
        columns={columns}
        dataSource={page.items}
        locale={{ emptyText: <Empty description={t("drift.empty")} /> }}
        expandable={{
          rowExpandable: (record) => record.fields.length > 0,
          expandedRowRender: (record) => (
            <Table
              size="small"
              rowKey="field"
              pagination={false}
              dataSource={record.fields}
              columns={[
                { title: t("drift.field.name"), dataIndex: "field", width: 160 },
                {
                  title: t("drift.field.declared"),
                  dataIndex: "declared",
                  render: (value: unknown) => (
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{renderFieldValue(value)}</pre>
                  ),
                },
                {
                  title: t("drift.field.live"),
                  dataIndex: "live",
                  render: (value: unknown) => (
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{renderFieldValue(value)}</pre>
                  ),
                },
              ]}
            />
          ),
        }}
        pagination={{
          current: currentPage,
          pageSize: page.page_size,
          total: page.total,
          showSizeChanger: false,
          onChange: setCurrentPage,
        }}
      />
    </div>
  );
}
