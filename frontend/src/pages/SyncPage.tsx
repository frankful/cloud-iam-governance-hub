import {
  Alert,
  Button,
  Card,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import {
  CloudSyncOutlined,
  DownloadOutlined,
  ReloadOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type {
  AWSAccountConfig,
  AWSSyncRun,
  AWSSyncWorkerStatus,
} from "../api/types";
import AccountApproverModal from "../components/AccountApproverModal";

const { Title, Text } = Typography;

const RUN_STATUS_COLOR: Record<string, string> = {
  PENDING: "default",
  RUNNING: "processing",
  SUCCEEDED: "success",
  FAILED: "error",
  // 被更高优先级触发抢占的 PENDING run（同步优先级设计）。
  SUPERSEDED: "warning",
};

// MANUAL = 手动触发；TICKET_CLOSED = 工单自动关闭（merged + CI 成功）后联动。
const TRIGGER_SOURCE_KEY: Record<string, string> = {
  MANUAL: "sync.trigger.manual",
  TICKET_CLOSED: "sync.trigger.ticketClosed",
};

export default function SyncPage() {
  const { t } = useTranslation();
  const [configs, setConfigs] = useState<AWSAccountConfig[]>([]);
  // 账号下拉：一次只看一个账号（配置动作 + 该账号的同步记录），
  // 避免账号多了之后平铺卡片既长又难找。
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [runs, setRuns] = useState<AWSSyncRun[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [triggering, setTriggering] = useState<number | null>(null);
  const [downloading, setDownloading] = useState<number | null>(null);
  const [workerStatus, setWorkerStatus] = useState<AWSSyncWorkerStatus | null>(null);
  // 审批人配置弹窗（A9）：AUTO 审批解析 aws_account_approver 绑定，之前没有
  // 管理入口，新账号永远进不了审批流。候选加载与保存在共享弹窗里完成。
  const [approverConfig, setApproverConfig] = useState<AWSAccountConfig | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // 选中账号：优先 selectedId；首次加载或被删时回退到第一个。
  const selected = configs.find((c) => c.id === selectedId) ?? configs[0] ?? null;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [c, w] = await Promise.all([
        api.listAccountConfigs(),
        // 状态读取失败不影响列表展示。
        api.getSyncWorkerStatus().catch(() => null),
      ]);
      setConfigs(c);
      setWorkerStatus(w);
      const current = c.find((x) => x.id === selectedId) ?? c[0] ?? null;
      if (current) {
        const r = await api.listSyncRuns({ limit: 20, account_id: current.aws_account_id });
        setRuns(r.sync_runs);
      } else {
        setRuns([]);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [selectedId]);

  useEffect(() => {
    void load();
  }, [load]);

  // 有运行中/待处理的行时每 5s 轮询
  useEffect(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (runs.some((r) => r.status === "RUNNING" || r.status === "PENDING")) {
      pollRef.current = setInterval(() => void load(), 5000);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [runs, load]);

  const trigger = async (configId: number) => {
    setTriggering(configId);
    try {
      await api.triggerSync(configId);
      message.success(t("sync.toast.triggered"));
      void load();
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setTriggering(null);
    }
  };

  const toggleSync = async (config: AWSAccountConfig, enabled: boolean) => {
    try {
      await api.setSyncEnabled(config.id, enabled);
      message.success(enabled ? t("sync.toast.enabled") : t("sync.toast.disabled"));
      void load();
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    }
  };

  const downloadChanges = async (runId: number) => {
    setDownloading(runId);
    try {
      await api.downloadSyncChanges(runId);
      message.success(t("sync.toast.downloading"));
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setDownloading(null);
    }
  };

  const openApprovers = (config: AWSAccountConfig) => {
    setApproverConfig(config);
  };

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("sync.title")}
        </Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>
          {t("common.refresh")}
        </Button>
      </Space>
      {error && <Card size="small">{error}</Card>}
      {workerStatus && !workerStatus.online && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message={t("sync.workerOffline")}
          description={t("sync.workerOfflineHint", { count: workerStatus.pending_runs })}
        />
      )}

      <Card size="small" title={t("sync.accountConfigs")} style={{ marginBottom: 16 }}>
        {configs.length === 0 && !loading ? (
          <Text type="secondary">{t("sync.noAccountConfigs")}</Text>
        ) : (
          <>
            <Space wrap style={{ marginBottom: 12 }}>
              <Select
                style={{ minWidth: 320 }}
                placeholder={t("sync.selectAccount")}
                loading={loading}
                value={selected?.id ?? undefined}
                onChange={(id: number) => setSelectedId(id)}
                options={configs.map((c) => ({
                  value: c.id,
                  label: `${c.display_name}（${c.aws_account_id}）`,
                }))}
              />
              {selected && (
                <>
                  <Switch
                    checked={selected.sync_enabled}
                    onChange={(enabled) => void toggleSync(selected, enabled)}
                  />
                  <Button icon={<TeamOutlined />} onClick={() => openApprovers(selected)}>
                    {t("sync.action.approvers")}
                  </Button>
                  <Button
                    type="primary"
                    icon={<ThunderboltOutlined />}
                    loading={triggering === selected.id}
                    disabled={!selected.sync_enabled}
                    onClick={() => void trigger(selected.id)}
                  >
                    {t("sync.action.syncNow")}
                  </Button>
                </>
              )}
            </Space>
            {selected && (
              <Space size="large" wrap>
                <span>{t("sync.mode", { mode: selected.sync_mode })}</span>
                <span>
                  {t("sync.state")}：
                  <Tag color={RUN_STATUS_COLOR[selected.sync_status] ?? "default"}>
                    {selected.sync_status}
                  </Tag>
                </span>
                <Tag color={selected.sync_enabled ? "green" : "default"}>
                  {selected.sync_enabled ? t("common.enabled") : t("common.disabled")}
                </Tag>
                {selected.last_successful_sync_at && (
                  <span>{t("sync.lastSuccess", { time: selected.last_successful_sync_at })}</span>
                )}
                {selected.last_sync_attempt_at && (
                  <span>{t("sync.lastAttempt", { time: selected.last_sync_attempt_at })}</span>
                )}
              </Space>
            )}
          </>
        )}
      </Card>

      <Card size="small" title={t("sync.runHistory")}>
        <Table<AWSSyncRun>
          rowKey="id"
          dataSource={runs}
          pagination={false}
          columns={[
            { title: "ID", dataIndex: "id", width: 70 },
            { title: t("sync.column.account"), dataIndex: "aws_account_id", width: 140 },
            {
              title: t("sync.column.trigger"),
              dataIndex: "trigger_source",
              width: 110,
              render: (s: string) => (TRIGGER_SOURCE_KEY[s] ? t(TRIGGER_SOURCE_KEY[s]) : s),
            },
            { title: t("sync.column.actor"), dataIndex: "triggered_by", width: 120 },
            {
              title: t("sync.column.status"),
              dataIndex: "status",
              width: 110,
              render: (s: string) => <Tag color={RUN_STATUS_COLOR[s] ?? "default"}>{s}</Tag>,
            },
            {
              title: t("sync.column.started"),
              dataIndex: "started_at",
              width: 170,
              render: (v) => v ?? "-",
            },
            {
              title: t("sync.column.finished"),
              dataIndex: "finished_at",
              width: 170,
              render: (v) => v ?? "-",
            },
            {
              title: t("sync.column.changes"),
              dataIndex: "has_changes",
              width: 90,
              render: (_: boolean, run: AWSSyncRun) =>
                run.has_changes ? (
                  <Tooltip title={t("sync.downloadHint")}>
                    <Button
                      size="small"
                      icon={<DownloadOutlined />}
                      loading={downloading === run.id}
                      onClick={() => void downloadChanges(run.id)}
                    >
                      {t("common.download")}
                    </Button>
                  </Tooltip>
                ) : (
                  <Text type="secondary">{t("common.none")}</Text>
                ),
            },
            {
              title: t("sync.column.error"),
              dataIndex: "last_error",
              ellipsis: true,
              render: (v) => (v ? <Text type="danger">{v}</Text> : "-"),
            },
          ]}
        />
      </Card>

      <Card size="small" style={{ marginTop: 16 }}>
        <Space>
          <CloudSyncOutlined />
          <Text type="secondary">{t("sync.footer")}</Text>
        </Space>
      </Card>

      <AccountApproverModal
        accountDbId={approverConfig?.aws_account_db_id ?? null}
        accountLabel={approverConfig?.display_name ?? approverConfig?.aws_account_id ?? ""}
        open={approverConfig !== null}
        onClose={() => setApproverConfig(null)}
      />
    </div>
  );
}
