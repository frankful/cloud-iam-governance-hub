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
import {
  CloudUploadOutlined,
  ExportOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type {
  AWSAccountRef,
  BaselinePublishPreview,
  BaselinePublication,
} from "../api/types";
import { BaselineIssueTable } from "../components/BaselineIssueTable";

const { Title, Text, Paragraph } = Typography;

const STATUS_COLORS: Record<string, string> = {
  PUBLISHING: "processing",
  PUBLISHED: "success",
  FAILED: "error",
  MERGED: "purple",
  CLOSED: "default",
};

/**
 * 基线发布：把整账号 Terraform bundle 推成仓库分支并开 PR（B3）。
 *
 * 发布是异步的：先构建 bundle 与 main 逐文件比对，再把有差异的文件打进
 * 一个 commit（GitHub 侧整树核对 + Git Data API，无差异时 2 秒内结束）；
 * 台账在 PUBLISHING 期间 5 秒轮询。确认框里的差异数是点发布前现算的
 * （GET baseline-preview，与发布同一套分类逻辑，台账 C10），不再凭猜测
 * 告诉用户「大约 10 分钟」。
 * 幂等键 = 账号 + 库存快照 run（同 run 不重发），后端返回
 * already_published=true 时只是把既有 PR 展示一遍，不开新分支。
 */
export default function BaselinePublishPage() {
  const { t } = useTranslation();
  const [accounts, setAccounts] = useState<AWSAccountRef[]>([]);
  const [accountId, setAccountId] = useState<number | undefined>();
  const [publications, setPublications] = useState<BaselinePublication[]>([]);
  const [loading, setLoading] = useState(false);
  // 预检（构建 + 比对 main）在点确认前跑，期间按钮转圈：不能让用户以为
  // 点了没反应，也不能先弹「将推送 N 个文件」再改口。
  const [previewing, setPreviewing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<BaselinePublication | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    void api
      .listAccounts()
      .then((list) => {
        setAccounts(list);
        if (list.length > 0) setAccountId(list[0].id);
      })
      .catch(() => setError(t("baseline.publish.error.accounts")));
  }, [t]);

  const load = useCallback(async () => {
    if (!accountId) return;
    setLoading(true);
    try {
      const list = await api.listBaselinePublications(accountId, 20);
      setPublications(list);
      setError(null);
      if (list.some((publication) => publication.status === "PUBLISHING")) {
        if (pollRef.current) clearTimeout(pollRef.current);
        pollRef.current = setTimeout(() => void load(), 5000);
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

  const publish = useCallback(async () => {
    if (!accountId) return;
    // 先算差异再弹确认框：数与真实发布会算的完全一致（同一套分类函数）。
    // 预检失败不挡发布——它是只读增值信息，真实发布时还会再比对一次；
    // 但必须把失败原因说清楚，不能让用户以为「0 个差异」。
    setPreviewing(true);
    let preview: BaselinePublishPreview | undefined;
    let previewError: string | undefined;
    try {
      preview = await api.previewBaselinePublication(accountId);
    } catch (err) {
      previewError =
        err instanceof ApiError ? t(err.message, { defaultValue: err.message }) : String(err);
    } finally {
      setPreviewing(false);
    }
    Modal.confirm({
      title: t("baseline.publish.confirmTitle"),
      width: 560,
      // 逐条写清真实行为：默认路径是「比对后无差异、不开 PR」，不是「几百个文件推十分钟」。
      content: (
        <Space direction="vertical" size={6} style={{ marginTop: 8 }}>
          {preview && (
            <Alert
              type={preview.conflicts.length > 0 ? "warning" : "info"}
              showIcon
              message={
                preview.to_publish === 0
                  ? t("baseline.publish.previewAllSame", { files: preview.files })
                  : t("baseline.publish.previewCounts", {
                      files: preview.files,
                      unchanged: preview.unchanged,
                      toPublish: preview.to_publish,
                    })
              }
              description={
                preview.conflicts.length > 0
                  ? t("baseline.publish.previewConflicts", {
                      count: preview.conflicts.length,
                      files: preview.conflicts.slice(0, 5).join("、"),
                    })
                  : undefined
              }
            />
          )}
          {previewError && (
            <Alert
              type="warning"
              showIcon
              message={t("baseline.publish.previewFailed", { message: previewError })}
            />
          )}
          {["confirmLine1", "confirmLine2", "confirmLine3", "confirmLine4"].map((key) => (
            <div key={key} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <Text type="secondary">·</Text>
              <Text>{t(`baseline.publish.${key}`)}</Text>
            </div>
          ))}
        </Space>
      ),
      okText: t("baseline.publish.confirmOk"),
      onOk: async () => {
        setCreating(true);
        try {
          const { publication, already_published } =
            await api.createBaselinePublication(accountId);
          if (already_published) {
            Modal.info({
              title: t("baseline.publish.alreadyTitle"),
              content: t("baseline.publish.alreadyContent", { id: publication.id }),
            });
          } else {
            Modal.success({
              title: t("baseline.publish.createdTitle"),
              content: t("baseline.publish.createdContent", {
                id: publication.id,
                branch: publication.branch,
              }),
            });
          }
          void load();
        } catch (err) {
          setError(err instanceof ApiError ? err.message : String(err));
        } finally {
          setCreating(false);
        }
      },
    });
  }, [accountId, load, t]);

  const openDetail = useCallback(async (publication: BaselinePublication) => {
    setDetail(publication);
    try {
      setDetail(await api.getBaselinePublication(publication.id));
    } catch {
      // 保留列表行数据作为兜底展示。
    }
  }, []);

  const statusLabel = (status: string) =>
    t(`baseline.publish.status.${status}`, { defaultValue: status });

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Title level={4} style={{ marginBottom: 4 }}>
          {t("baseline.publish.title")}
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: 0 }}>
          {t("baseline.publish.subtitle")}
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
          placeholder={t("baseline.publish.filter.account")}
        />
        <Button
          type="primary"
          icon={<CloudUploadOutlined />}
          onClick={() => void publish()}
          loading={creating || previewing}
          disabled={!accountId}
        >
          {t("baseline.publish.action")}
        </Button>
        <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>
          {t("common.refresh")}
        </Button>
      </Space>

      <Alert
        type="warning"
        showIcon
        message={t("baseline.publish.hint")}
        description={t("baseline.publish.hintDetail")}
      />

      {error ? <Alert type="error" showIcon message={error} /> : null}

      <Table<BaselinePublication>
        rowKey="id"
        loading={loading}
        dataSource={publications}
        pagination={false}
        size="middle"
        locale={{
          emptyText: <Empty description={t("baseline.publish.empty")} />,
        }}
        onRow={(publication) => ({
          onClick: () => void openDetail(publication),
          style: { cursor: "pointer" },
        })}
        columns={[
          { title: t("baseline.publish.column.id"), dataIndex: "id", width: 70 },
          {
            title: t("baseline.publish.column.status"),
            dataIndex: "status",
            width: 110,
            render: (status: string) => (
              <Tag color={STATUS_COLORS[status] ?? "default"}>{statusLabel(status)}</Tag>
            ),
          },
          {
            title: t("baseline.publish.column.branch"),
            dataIndex: "branch",
            width: 220,
            render: (branch: string) => <Text code copyable={{ text: branch }}>{branch}</Text>,
          },
          {
            title: t("baseline.publish.column.pullRequest"),
            dataIndex: "pull_request_url",
            render: (url: string, publication) =>
              url ? (
                <a
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(event) => event.stopPropagation()}
                >
                  #{publication.remote_request_number || url} <ExportOutlined />
                </a>
              ) : (
                "—"
              ),
          },
          {
            title: t("baseline.publish.column.files"),
            dataIndex: "file_count",
            width: 90,
            render: (value: number) => (value > 0 ? value : "—"),
          },
          {
            title: t("baseline.publish.column.hash"),
            dataIndex: "content_sha256",
            width: 160,
            render: (hash: string) =>
              hash ? (
                <Text code copyable={{ text: hash }}>
                  {hash.slice(0, 12)}…
                </Text>
              ) : (
                "—"
              ),
          },
          {
            title: t("baseline.publish.column.requestedBy"),
            dataIndex: "requested_by",
            width: 120,
            render: (value: string) => value || "—",
          },
          {
            title: t("baseline.publish.column.createdAt"),
            dataIndex: "created_at",
            width: 180,
            render: (value: string) => new Date(value).toLocaleString(),
          },
          {
            title: t("baseline.publish.column.error"),
            dataIndex: "error",
            render: (value: string) => (value ? <Text type="danger">{value}</Text> : null),
          },
        ]}
      />

      <Drawer
        width="60%"
        open={detail !== null}
        title={detail ? t("baseline.publish.detail.title", { id: detail.id }) : ""}
        onClose={() => setDetail(null)}
        destroyOnClose
      >
        {detail ? (
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            {detail.status === "FAILED" ? (
              <Alert type="error" showIcon message={detail.error} />
            ) : null}
            {detail.status === "PUBLISHING" ? (
              <Alert type="info" showIcon message={t("baseline.publish.publishingHint")} />
            ) : null}
            {detail.pull_request_url ? (
              <Alert
                type="success"
                showIcon
                message={
                  <a href={detail.pull_request_url} target="_blank" rel="noreferrer">
                    {t("baseline.publish.detail.openPullRequest", {
                      number: detail.remote_request_number,
                    })}{" "}
                    <ExportOutlined />
                  </a>
                }
                description={t("baseline.publish.detail.mergeHint")}
              />
            ) : null}
            {detail.superseded && detail.superseded.length > 0 ? (
              <Card size="small" title={t("baseline.publish.detail.supersededTitle")}>
                <Table
                  rowKey={(record) => record.remote_request_number}
                  dataSource={detail.superseded}
                  pagination={false}
                  size="small"
                  columns={[
                    {
                      title: "PR",
                      dataIndex: "remote_request_number",
                      width: 90,
                      render: (number: string, record) => (
                        <a href={record.pull_request_url} target="_blank" rel="noreferrer">
                          #{number}
                        </a>
                      ),
                    },
                    {
                      title: t("common.status"),
                      dataIndex: "status",
                      width: 120,
                      render: (status: string) => (
                        <Tag color={STATUS_COLORS[status] ?? "default"}>
                          {t(`baseline.publish.status.${status}`, { defaultValue: status })}
                        </Tag>
                      ),
                    },
                    {
                      title: t("baseline.publish.column.createdAt"),
                      dataIndex: "published_at",
                      render: (value?: string) => (value ? new Date(value).toLocaleString() : "—"),
                    },
                    {
                      title: t("baseline.publish.detail.supersededAt"),
                      dataIndex: "superseded_at",
                      render: (value: string) => new Date(value).toLocaleString(),
                    },
                  ]}
                />
              </Card>
            ) : null}

            <Space direction="vertical" size={4}>
              <Space size={4}>
                <Text type="secondary">{t("baseline.publish.detail.branch")}:</Text>
                <Text code copyable>
                  {detail.branch}
                </Text>
              </Space>
              <Space size={4}>
                <Text type="secondary">{t("baseline.publish.detail.syncRun")}:</Text>
                <Text code>#{detail.sync_run_id}</Text>
              </Space>
              {detail.repo_directory ? (
                <Space size={4}>
                  <Text type="secondary">{t("baseline.publish.detail.repoDir")}:</Text>
                  <Text code copyable>
                    {detail.repo_directory}
                  </Text>
                </Space>
              ) : null}
              {detail.content_sha256 ? (
                <Tooltip title={t("baseline.detail.hashHint")}>
                  <Space size={4}>
                    <Text type="secondary">{t("baseline.detail.hash")}:</Text>
                    <Text code copyable>
                      {detail.content_sha256}
                    </Text>
                  </Space>
                </Tooltip>
              ) : null}
            </Space>

            {detail.counts ? (
              <Row gutter={16}>
                {(Object.keys(detail.counts) as Array<keyof typeof detail.counts>)
                  .filter((key) => key !== "already-declared" || detail.counts?.[key]! > 0)
                  .map((key) => (
                    <Col key={key} xs={12} md={4}>
                      <Card size="small">
                        <Statistic
                          title={t(`baseline.detail.counts.${key}`, { defaultValue: key })}
                          value={detail.counts?.[key] ?? 0}
                        />
                      </Card>
                    </Col>
                  ))}
              </Row>
            ) : null}

            {detail.issues ? (
              <Card size="small" title={t("baseline.detail.issuesTitle")}>
                {detail.issues.length === 0 ? (
                  <Text type="secondary">{t("baseline.detail.noIssues")}</Text>
                ) : (
                  <BaselineIssueTable issues={detail.issues} />
                )}
              </Card>
            ) : null}
          </Space>
        ) : null}
      </Drawer>
    </Space>
  );
}
