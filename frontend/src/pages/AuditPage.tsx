import {
  Button,
  Card,
  DatePicker,
  Input,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { DownloadOutlined, ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, authHeaders } from "../api/client";
import type { AuditEventView } from "../api/types";

const { Title, Text } = Typography;
const { RangePicker } = DatePicker;

export default function AuditPage() {
  const { t } = useTranslation();
  const [events, setEvents] = useState<AuditEventView[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    actor_id: "",
    action: "",
    outcome: "",
    range: null as [string, string] | null,
  });
  const [page, setPage] = useState({ limit: 50, offset: 0 });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listAuditEvents({
        actor_id: filters.actor_id || undefined,
        action: filters.action || undefined,
        outcome: filters.outcome || undefined,
        from: filters.range?.[0],
        to: filters.range?.[1],
        limit: page.limit,
        offset: page.offset,
      });
      setEvents(res.events);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    void load();
  }, [load]);

  const exportEvents = async () => {
    try {
      const params = new URLSearchParams();
      if (filters.actor_id) params.set("actor_id", filters.actor_id);
      if (filters.action) params.set("action", filters.action);
      if (filters.outcome) params.set("outcome", filters.outcome);
      if (filters.range) {
        params.set("from", filters.range[0]);
        params.set("to", filters.range[1]);
      }
      const res = await fetch(`/api/v1/audit/events/export?${params.toString()}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message ?? `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "audit-events.json";
      a.click();
      URL.revokeObjectURL(url);
      message.success(t("audit.toast.exported"));
    } catch (err) {
      message.error(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("audit.title")}
        </Title>
        <Space>
          <Button icon={<DownloadOutlined />} onClick={() => void exportEvents()}>
            {t("audit.action.export")}
          </Button>
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>
      <Card size="small" style={{ marginBottom: 16 }}>
        <Space wrap>
          <Input.Search
            style={{ width: 180 }}
            placeholder={t("audit.filter.actor")}
            allowClear
            onSearch={(v) => {
              setFilters({ ...filters, actor_id: v });
              setPage({ ...page, offset: 0 });
            }}
          />
          <Input.Search
            style={{ width: 220 }}
            placeholder={t("audit.filter.action", { example: "TICKET_CREATED" })}
            allowClear
            onSearch={(v) => {
              setFilters({ ...filters, action: v });
              setPage({ ...page, offset: 0 });
            }}
          />
          <Select
            style={{ width: 130 }}
            placeholder={t("audit.filter.outcome")}
            allowClear
            value={filters.outcome || undefined}
            onChange={(v) => {
              setFilters({ ...filters, outcome: v ?? "" });
              setPage({ ...page, offset: 0 });
            }}
            options={[
              { value: "SUCCESS", label: t("audit.outcome.success") },
              { value: "FAILURE", label: t("audit.outcome.failure") },
            ]}
          />
          <RangePicker
            showTime
            value={filters.range ? (filters.range as never) : null}
            onChange={(_, dateStrings) => {
              setFilters({ ...filters, range: dateStrings[0] ? (dateStrings as [string, string]) : null });
              setPage({ ...page, offset: 0 });
            }}
          />
        </Space>
      </Card>
      {error && <Card size="small">{error}</Card>}
      <Table<AuditEventView>
        rowKey="id"
        loading={loading}
        dataSource={events}
        pagination={{
          current: Math.floor(page.offset / page.limit) + 1,
          pageSize: page.limit,
          total,
          showSizeChanger: false,
          onChange: (p, size) => setPage({ limit: size, offset: (p - 1) * size }),
        }}
        columns={[
          { title: "ID", dataIndex: "id", width: 80 },
          { title: t("audit.column.time"), dataIndex: "occurred_at", width: 180 },
          { title: t("audit.column.actor"), dataIndex: "actor_id", width: 130, render: (v) => v ?? "-" },
          { title: t("audit.column.action"), dataIndex: "action", width: 260, className: "mono" },
          { title: t("audit.column.resource"), dataIndex: "resource_type", width: 160 },
          {
            title: t("audit.column.resourceId"),
            dataIndex: "resource_id",
            width: 140,
            render: (v) => v ?? "-",
          },
          {
            title: t("audit.column.outcome"),
            dataIndex: "outcome",
            width: 90,
            render: (v) => <Tag color={v === "SUCCESS" ? "green" : "red"}>{v}</Tag>,
          },
          { title: "HTTP", dataIndex: "http_status", width: 80, render: (v) => v ?? "-" },
        ]}
      />
      <Text type="secondary" style={{ fontSize: 12 }}>
        {t("audit.footer")}
      </Text>
    </div>
  );
}
