import { Alert, Button, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { DashboardSummary } from "../api/types";

const { Title } = Typography;

function byStatusRows(summary: DashboardSummary) {
  return Object.entries(summary.tickets.by_status).map(([status, count]) => ({
    key: status,
    status,
    count,
  }));
}

export default function DashboardPage() {
  const { t } = useTranslation();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setSummary(await api.dashboardSummary());
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("dashboard.error.loadFailed", { message: String(err) }),
      );
    }
  }, [t]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("dashboard.title")}
        </Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>
          {t("dashboard.action.refresh")}
        </Button>
      </Space>
      {error && <Alert style={{ marginBottom: 16 }} type="error" message={error} />}
      {summary && (
        <>
          <Row gutter={16}>
            <Col span={6}>
              <Card>
                <Statistic title={t("dashboard.stat.totalTickets")} value={summary.tickets.total} />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title={t("dashboard.stat.openRisks")}
                  value={summary.risks.open}
                  valueStyle={{ color: summary.risks.open > 0 ? "#cf1322" : undefined }}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title={t("dashboard.stat.iamPrincipals")}
                  value={`${summary.inventory.users} / ${summary.inventory.roles}`}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic title={t("dashboard.stat.groups")} value={summary.inventory.groups} />
              </Card>
            </Col>
          </Row>
          <Row gutter={16} style={{ marginTop: 16 }}>
            <Col span={12}>
              <Card title={t("dashboard.card.ticketStatus")} size="small">
                <Table
                  size="small"
                  rowKey="key"
                  pagination={false}
                  dataSource={byStatusRows(summary)}
                  columns={[
                    {
                      title: t("dashboard.column.status"),
                      dataIndex: "status",
                      render: (s: string) => <Tag>{s}</Tag>,
                    },
                    { title: t("dashboard.column.count"), dataIndex: "count", width: 120 },
                  ]}
                />
              </Card>
            </Col>
            <Col span={12}>
              <Card title={t("dashboard.card.syncOverview")} size="small">
                <Space direction="vertical" style={{ width: "100%" }}>
                  <div>
                    {t("dashboard.sync.configuredAccounts")}
                    <b>{summary.sync.configs_total}</b>
                    {t("dashboard.sync.enabledCount", { count: summary.sync.configs_enabled })}
                  </div>
                  <div>
                    {t("dashboard.sync.runsLast24h")}
                    {Object.entries(summary.sync.runs_last_24h_by_status)
                      .map(([s, c]) => `${s} × ${c}`)
                      .join(t("dashboard.listSeparator")) || t("dashboard.empty.none")}
                  </div>
                  <div>
                    {t("dashboard.drift.unresolved")}
                    <b
                      style={{
                        color: (summary.drift?.unresolved ?? 0) > 0 ? "#cf1322" : undefined,
                      }}
                    >
                      {summary.drift?.unresolved ?? 0}
                    </b>
                  </div>
                  <div>
                    {t("dashboard.sync.riskLevels")}
                    {Object.entries(summary.risks.open_by_level)
                      .map(([l, c]) => `${l} × ${c}`)
                      .join(t("dashboard.listSeparator")) || t("dashboard.empty.none")}
                  </div>
                </Space>
              </Card>
            </Col>
          </Row>
        </>
      )}
    </div>
  );
}
