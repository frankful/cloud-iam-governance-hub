import {
  Alert,
  Button,
  Card,
  Col,
  Drawer,
  Empty,
  Modal,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { FileAddOutlined, ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { AWSAccountRef, BaselineBundleFile, BaselinePreviewJob } from "../api/types";
import { BaselineIssueTable } from "../components/BaselineIssueTable";

const { Title, Text, Paragraph } = Typography;

const STATUS_COLORS: Record<string, string> = {
  PENDING: "default",
  RUNNING: "processing",
  COMPLETED: "success",
  FAILED: "error",
};

/**
 * 基线预览：从库存生成整账号 Terraform bundle 的只读审查页。
 *
 * job 是异步的（创建后后台构建），所以列表在 PENDING/RUNNING 期间轮询；
 * 内容指纹（sha256）是「同库存同结果」的确定性证据，放在列表里一眼可对比。
 */
export default function BaselinePreviewPage() {
  const { t } = useTranslation();
  const [accounts, setAccounts] = useState<AWSAccountRef[]>([]);
  const [accountId, setAccountId] = useState<number | undefined>();
  const [jobs, setJobs] = useState<BaselinePreviewJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<BaselinePreviewJob | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    void api
      .listAccounts()
      .then((list) => {
        setAccounts(list);
        if (list.length > 0) setAccountId(list[0].id);
      })
      .catch(() => setError(t("baseline.error.accounts")));
  }, [t]);

  const load = useCallback(async () => {
    if (!accountId) return;
    setLoading(true);
    try {
      const list = await api.listBaselineJobs(accountId, 20);
      setJobs(list);
      setError(null);
      // 有进行中的 job 时继续轮询；全部终态则停。
      if (list.some((job) => job.status === "PENDING" || job.status === "RUNNING")) {
        if (pollRef.current) clearTimeout(pollRef.current);
        pollRef.current = setTimeout(() => void load(), 3000);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountId]);

  useEffect(() => {
    void load();
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, [load]);

  const create = useCallback(async () => {
    if (!accountId) return;
    setCreating(true);
    try {
      const job = await api.createBaselineJob(accountId);
      Modal.success({
        title: t("baseline.createConfirmTitle"),
        content: t("baseline.created", { id: job.id }),
      });
      void load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setCreating(false);
    }
  }, [accountId, load, t]);

  const openDetail = useCallback(async (job: BaselinePreviewJob) => {
    setDetail(job);
    try {
      setDetail(await api.getBaselineJob(job.id));
    } catch {
      // 保留列表行数据作为兜底展示。
    }
  }, []);

  const statusLabel = (status: string) => t(`baseline.status.${status}`, { defaultValue: status });

  const report = detail?.result;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Title level={4} style={{ marginBottom: 4 }}>
          {t("baseline.title")}
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: 0 }}>
          {t("baseline.subtitle")}
        </Paragraph>
      </div>

      <Space wrap>
        <Select
          style={{ minWidth: 260 }}
          value={accountId}
          onChange={setAccountId}
          options={accounts.map((account) => ({
            value: account.id,
            label: account.account_name
              ? `${account.aws_account_id}（${account.account_name}）`
              : account.aws_account_id,
          }))}
          placeholder={t("baseline.filter.account")}
        />
        <Button
          type="primary"
          icon={<FileAddOutlined />}
          onClick={() => void create()}
          loading={creating}
          disabled={!accountId}
        >
          {t("baseline.create")}
        </Button>
        <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>
          {t("common.refresh")}
        </Button>
      </Space>

      {error ? <Alert type="error" showIcon message={error} /> : null}

      <Table<BaselinePreviewJob>
        rowKey="id"
        loading={loading}
        dataSource={jobs}
        pagination={false}
        size="middle"
        locale={{ emptyText: <Empty description={t("baseline.empty")} /> }}
        onRow={(job) => ({
          onClick: () => void openDetail(job),
          style: { cursor: "pointer" },
        })}
        columns={[
          { title: t("baseline.column.id"), dataIndex: "id", width: 70 },
          {
            title: t("baseline.column.status"),
            dataIndex: "status",
            width: 110,
            render: (status: string) => (
              <Tag color={STATUS_COLORS[status] ?? "default"}>{statusLabel(status)}</Tag>
            ),
          },
          {
            title: t("baseline.column.files"),
            width: 90,
            render: (_: unknown, job) => job.result?.counts?.files ?? "—",
          },
          {
            title: t("baseline.column.issues"),
            width: 90,
            render: (_: unknown, job) => {
              const count = job.result?.issues?.length;
              if (count === undefined) return "—";
              return count > 0 ? <Tag color="orange">{count}</Tag> : <Tag color="green">0</Tag>;
            },
          },
          {
            title: t("baseline.column.hash"),
            dataIndex: "content_sha256",
            width: 160,
            render: (hash: string) =>
              hash ? <Text code copyable={{ text: hash }}>{hash.slice(0, 12)}…</Text> : "—",
          },
          {
            title: t("baseline.column.requestedBy"),
            dataIndex: "requested_by",
            width: 120,
            render: (value: string) => value || "—",
          },
          {
            title: t("baseline.column.createdAt"),
            dataIndex: "created_at",
            width: 180,
            render: (value: string) => new Date(value).toLocaleString(),
          },
          {
            title: t("baseline.column.error"),
            dataIndex: "error",
            render: (value: string) =>
              value ? <Text type="danger">{value}</Text> : null,
          },
        ]}
      />

      <Drawer
        width="72%"
        open={detail !== null}
        title={detail ? t("baseline.detail.title", { id: detail.id }) : ""}
        onClose={() => setDetail(null)}
        destroyOnClose
      >
        {detail ? (
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            {detail.status === "FAILED" ? (
              <Alert type="error" showIcon message={detail.error || t("baseline.error.detail")} />
            ) : null}
            {detail.status === "PENDING" || detail.status === "RUNNING" ? (
              <Alert type="info" showIcon message={statusLabel(detail.status)} />
            ) : null}

            {report ? (
              <>
                <Row gutter={16}>
                  {(Object.keys(report.counts) as Array<keyof typeof report.counts>)
                    .filter((key) => key !== "already-declared" || report.counts[key] > 0)
                    .map((key) => (
                      <Col key={key} xs={12} md={4}>
                        <Card size="small">
                          <Statistic
                            title={t(`baseline.detail.counts.${key}`, { defaultValue: key })}
                            value={report.counts[key]}
                          />
                        </Card>
                      </Col>
                    ))}
                </Row>

                {report.repo_directory ? (
                  <Space size={4}>
                    <Text type="secondary">{t("baseline.detail.repoDir")}:</Text>
                    <Text code copyable>
                      {report.repo_directory}
                    </Text>
                  </Space>
                ) : null}
                <Tooltip title={t("baseline.detail.hashHint")}>
                  <Space size={4}>
                    <Text type="secondary">{t("baseline.detail.hash")}:</Text>
                    <Text code copyable>
                      {report.content_sha256}
                    </Text>
                  </Space>
                </Tooltip>

                <Card size="small" title={t("baseline.detail.issuesTitle")}>
                  {report.issues.length === 0 ? (
                    <Text type="secondary">{t("baseline.detail.noIssues")}</Text>
                  ) : (
                    <BaselineIssueTable issues={report.issues} />
                  )}
                </Card>

                <Card size="small" title={t("baseline.detail.filesTitle")}>
                  <Table<BaselineBundleFile>
                    rowKey="key"
                    dataSource={report.files}
                    pagination={false}
                    size="small"
                    expandable={{
                      expandedRowRender: (file) => (
                        <pre
                          style={{
                            margin: 0,
                            padding: "8px 12px",
                            background: "rgba(127,127,127,0.12)",
                            borderRadius: 6,
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-word",
                            maxHeight: 480,
                            overflow: "auto",
                          }}
                        >
                          {file.content}
                        </pre>
                      ),
                    }}
                    columns={[
                      {
                        title: t("baseline.detail.column.fileName"),
                        dataIndex: "file_name",
                        render: (name: string, file) => (
                          <Space size={4}>
                            <Text code copyable={{ text: name }}>
                              {name}
                            </Text>
                            {file.relationship ? (
                              <Tag>{t("baseline.detail.relationship")}</Tag>
                            ) : null}
                          </Space>
                        ),
                      },
                      {
                        title: t("baseline.detail.column.sources"),
                        dataIndex: "sources",
                        render: (sources: string[]) => (
                          <Text type="secondary">{sources.join(", ")}</Text>
                        ),
                      },
                      {
                        title: t("baseline.detail.column.exists"),
                        dataIndex: "exists_in_repo",
                        width: 110,
                        render: (value?: boolean) => {
                          if (value === undefined) return t("baseline.detail.existsUnknown");
                          return value ? (
                            <Tag color="gold">{t("baseline.detail.existsYes")}</Tag>
                          ) : (
                            <Tag color="green">{t("baseline.detail.existsNo")}</Tag>
                          );
                        },
                      },
                      {
                        title: t("baseline.detail.column.addresses"),
                        dataIndex: "addresses",
                        render: (addresses?: string[]) =>
                          addresses?.length ? (
                            <Text type="secondary" code>
                              {addresses.join(" / ")}
                            </Text>
                          ) : null,
                      },
                    ]}
                  />
                </Card>
              </>
            ) : null}
          </Space>
        ) : null}
      </Drawer>
    </Space>
  );
}
