import { Alert, Button, Card, Col, Empty, Row, Select, Space, Statistic, Table, Tag, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type {
  AWSAccountRef,
  CleanupEvidence,
  CleanupItem,
  CleanupReport,
} from "../api/types";

const { Title, Text, Paragraph } = Typography;

/**
 * 待清理清单：平台声明错的、AWS 侧留下没用的。
 *
 * 页面刻意只读——删除动作一条在 IaC 仓库、一条在 AWS 控制台，平台替用户执行
 * 反而是风险。所以这里给的是「凭什么删」和「删哪一条」，不是按钮。
 */
export default function CleanupPage() {
  const { t } = useTranslation();
  const [accounts, setAccounts] = useState<AWSAccountRef[]>([]);
  const [accountId, setAccountId] = useState<number | undefined>();
  const [report, setReport] = useState<CleanupReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .listAccounts()
      .then((list) => {
        setAccounts(list);
        if (list.length > 0) setAccountId(list[0].id);
      })
      .catch(() => setError(t("cleanup.error.accounts")));
  }, [t]);

  const load = useCallback(async () => {
    if (!accountId) return;
    setLoading(true);
    setError(null);
    try {
      setReport(await api.getCleanupSuggestions(accountId));
    } catch (err) {
      const message = err instanceof ApiError ? err.message : String(err);
      setError(message);
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [accountId]);

  useEffect(() => {
    void load();
  }, [load]);

  const items = report?.items ?? [];
  const platformFiles = report?.category_counts?.["platform-file"] ?? 0;
  const awsResources = report?.category_counts?.["aws-resource"] ?? 0;
  const high = report?.confidence_counts?.high ?? 0;
  const review = report?.confidence_counts?.review ?? 0;

  const kindLabel = (kind: string) => {
    const key = `cleanup.kind.${kind}`;
    const label = t(key);
    return label === key ? kind : label;
  };

  // 服务端同时下发 code + 原文：code 命中语言包就按语言翻译，否则退回原文。
  // 这样服务端新增规则时不会因为翻译缺失而显示 key 本身。
  const translated = (key: string, fallback: string, params?: Record<string, string>) =>
    key ? t(key, { ...(params ?? {}), defaultValue: fallback }) : fallback;

  const reasonText = (item: CleanupItem) =>
    translated(
      item.reason_code ? `cleanup.reason.${item.reason_code}` : "",
      item.reason,
      item.params,
    );

  const actionText = (item: CleanupItem) =>
    translated(
      item.action_code ? `cleanup.action.${item.action_code}` : "",
      item.action,
      item.params,
    );

  const evidenceText = (line: CleanupEvidence) =>
    translated(
      line.code ? `cleanup.evidence.${line.code}` : "",
      line.text,
      line.params,
    );

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Title level={4} style={{ marginBottom: 4 }}>
          {t("cleanup.title")}
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: 0 }}>
          {t("cleanup.subtitle")}
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
          placeholder={t("cleanup.filter.account")}
        />
        <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>
          {t("common.refresh")}
        </Button>
        {report?.latest_sync_run_id ? (
          <Text type="secondary">
            {t("cleanup.snapshot", { run: report.latest_sync_run_id })}
          </Text>
        ) : null}
      </Space>

      {error ? <Alert type="error" showIcon message={error} /> : null}

      <Row gutter={16}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title={t("cleanup.stat.platformFile")} value={platformFiles} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title={t("cleanup.stat.awsResource")} value={awsResources} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title={t("cleanup.stat.high")} value={high} valueStyle={{ color: "#cf1322" }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title={t("cleanup.stat.review")} value={review} valueStyle={{ color: "#d46b08" }} />
          </Card>
        </Col>
      </Row>

      <Table<CleanupItem>
        rowKey={(item) => `${item.category}:${item.kind}:${item.name}`}
        loading={loading}
        dataSource={items}
        pagination={false}
        size="middle"
        locale={{ emptyText: <Empty description={t("cleanup.empty")} /> }}
        expandable={{
          expandedRowRender: (item) => (
            <Space direction="vertical" size={8} style={{ width: "100%" }}>
              <div>
                <Text strong>{t("cleanup.detail.evidence")}</Text>
                <ul style={{ margin: "4px 0 0 20px", padding: 0 }}>
                  {item.evidence.map((line, index) => (
                    <li key={index}>
                      <Text type="secondary">{evidenceText(line)}</Text>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <Text strong>{t("cleanup.detail.action")}</Text>
                <pre
                  style={{
                    margin: "4px 0 0",
                    padding: "8px 12px",
                    background: "rgba(127,127,127,0.12)",
                    borderRadius: 6,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {actionText(item)}
                </pre>
              </div>
              {item.pull_request_url ? (
                <Text type="secondary">
                  {t("cleanup.detail.pr")}:{" "}
                  <a href={item.pull_request_url} target="_blank" rel="noreferrer">
                    {item.pull_request_url}
                  </a>
                </Text>
              ) : null}
            </Space>
          ),
        }}
        columns={[
          {
            title: t("cleanup.column.category"),
            dataIndex: "category",
            width: 130,
            filters: [
              { text: t("cleanup.category.platform-file"), value: "platform-file" },
              { text: t("cleanup.category.aws-resource"), value: "aws-resource" },
            ],
            onFilter: (value, item) => item.category === value,
            render: (category: CleanupItem["category"]) => (
              <Tag color={category === "platform-file" ? "blue" : "volcano"}>
                {t(`cleanup.category.${category}`)}
              </Tag>
            ),
          },
          {
            title: t("cleanup.column.confidence"),
            dataIndex: "confidence",
            width: 120,
            filters: [
              { text: t("cleanup.confidence.high"), value: "high" },
              { text: t("cleanup.confidence.review"), value: "review" },
            ],
            onFilter: (value, item) => item.confidence === value,
            render: (confidence: CleanupItem["confidence"]) => (
              <Tag color={confidence === "high" ? "green" : "gold"}>
                {t(`cleanup.confidence.${confidence}`)}
              </Tag>
            ),
          },
          {
            title: t("cleanup.column.kind"),
            dataIndex: "kind",
            width: 120,
            render: (kind: string) => kindLabel(kind),
          },
          {
            title: t("cleanup.column.name"),
            dataIndex: "name",
            width: 280,
            render: (name: string, item) => (
              <Space direction="vertical" size={0}>
                <Text code copyable={{ text: name }}>
                  {name}
                </Text>
                {item.file_key ? <Text type="secondary">{item.file_key}</Text> : null}
              </Space>
            ),
          },
          {
            title: t("cleanup.column.reason"),
            dataIndex: "reason",
            render: (_reason: string, item: CleanupItem) => <Text>{reasonText(item)}</Text>,
          },
        ]}
      />

      {report?.rule_gaps?.length ? (
        <Alert
          type="info"
          showIcon
          message={t("cleanup.gaps.title")}
          description={
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {report.rule_gaps.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          }
        />
      ) : null}
    </Space>
  );
}
