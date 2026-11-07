import {
  Button,
  Card,
  Input,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type { Ticket } from "../api/types";
import { StatusTag } from "../status";

const { Title, Link } = Typography;

/** 工单状态下拉项的文案 key（配合 STATUS_OPTIONS 使用）。 */
type StatusOptionKey =
  | "tickets.status.DRAFT"
  | "tickets.status.APPROVING"
  | "tickets.status.APPROVED"
  | "tickets.status.PUBLISHING"
  | "tickets.status.PUBLISH_FAILED"
  | "tickets.status.REJECTED"
  | "tickets.status.MERGED"
  | "tickets.status.CLOSED";

/** 工单类型下拉项的文案 key（配合 TYPE_OPTIONS 使用）。 */
type TypeOptionKey =
  | "tickets.type.CREATE_ROLE"
  | "tickets.type.CREATE_MANAGED_POLICY"
  | "tickets.type.CREATE_USER"
  | "tickets.type.CREATE_GROUP"
  | "tickets.type.UPDATE_ROLE"
  | "tickets.type.ATTACH_USER_POLICY"
  | "tickets.type.UPDATE_MANAGED_POLICY"
  | "tickets.type.UPDATE_GROUP_INLINE_POLICY"
  | "tickets.type.ADOPT_ROLE_INLINE_POLICIES"
  | "tickets.type.ROLLBACK";

// 下拉项的 value 是后端枚举值（提交给后端的取值），只有界面文案走 i18n。
const STATUS_OPTIONS: { value: string; labelKey: StatusOptionKey }[] = [
  { value: "DRAFT", labelKey: "tickets.status.DRAFT" },
  { value: "APPROVING", labelKey: "tickets.status.APPROVING" },
  { value: "APPROVED", labelKey: "tickets.status.APPROVED" },
  { value: "PUBLISHING", labelKey: "tickets.status.PUBLISHING" },
  { value: "PUBLISH_FAILED", labelKey: "tickets.status.PUBLISH_FAILED" },
  { value: "REJECTED", labelKey: "tickets.status.REJECTED" },
  { value: "MERGED", labelKey: "tickets.status.MERGED" },
  { value: "CLOSED", labelKey: "tickets.status.CLOSED" },
];

const TYPE_OPTIONS: { value: string; labelKey: TypeOptionKey }[] = [
  { value: "CREATE_ROLE", labelKey: "tickets.type.CREATE_ROLE" },
  { value: "CREATE_MANAGED_POLICY", labelKey: "tickets.type.CREATE_MANAGED_POLICY" },
  { value: "CREATE_USER", labelKey: "tickets.type.CREATE_USER" },
  { value: "CREATE_GROUP", labelKey: "tickets.type.CREATE_GROUP" },
  { value: "UPDATE_ROLE", labelKey: "tickets.type.UPDATE_ROLE" },
  { value: "ATTACH_USER_POLICY", labelKey: "tickets.type.ATTACH_USER_POLICY" },
  { value: "UPDATE_MANAGED_POLICY", labelKey: "tickets.type.UPDATE_MANAGED_POLICY" },
  { value: "UPDATE_GROUP_INLINE_POLICY", labelKey: "tickets.type.UPDATE_GROUP_INLINE_POLICY" },
  { value: "ADOPT_ROLE_INLINE_POLICIES", labelKey: "tickets.type.ADOPT_ROLE_INLINE_POLICIES" },
  { value: "ROLLBACK", labelKey: "tickets.type.ROLLBACK" },
];

export default function TicketsPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({ status: "", ticket_type: "", submitter: "", q: "" });
  const [page, setPage] = useState({ limit: 20, offset: 0 });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listTickets({
        status: filters.status || undefined,
        ticket_type: filters.ticket_type || undefined,
        submitter: filters.submitter || undefined,
        q: filters.q || undefined,
        limit: page.limit,
        offset: page.offset,
      });
      setTickets(res.tickets);
      setTotal(res.total);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? t(err.message, { defaultValue: err.message })
          : t("tickets.error.loadFailed", { message: String(err) }),
      );
    } finally {
      setLoading(false);
    }
  }, [filters, page, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const statusOptions = STATUS_OPTIONS.map((option) => ({
    value: option.value,
    label: t(option.labelKey),
  }));
  const typeOptions = TYPE_OPTIONS.map((option) => ({
    value: option.value,
    label: t(option.labelKey),
  }));

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("tickets.title")}
        </Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate("/tickets/new")}>
          {t("tickets.action.create")}
        </Button>
      </Space>
      <Card size="small" style={{ marginBottom: 16 }}>
        <Space wrap>
          <Select
            style={{ width: 140 }}
            placeholder={t("tickets.filter.status")}
            allowClear
            options={statusOptions}
            value={filters.status || undefined}
            onChange={(v) => {
              setFilters({ ...filters, status: v ?? "" });
              setPage({ ...page, offset: 0 });
            }}
          />
          <Select
            style={{ width: 160 }}
            placeholder={t("tickets.filter.type")}
            allowClear
            options={typeOptions}
            value={filters.ticket_type || undefined}
            onChange={(v) => {
              setFilters({ ...filters, ticket_type: v ?? "" });
              setPage({ ...page, offset: 0 });
            }}
          />
          <Input.Search
            style={{ width: 220 }}
            placeholder={t("tickets.filter.keyword")}
            allowClear
            onSearch={(v) => {
              setFilters({ ...filters, q: v });
              setPage({ ...page, offset: 0 });
            }}
          />
          <Input.Search
            style={{ width: 180 }}
            placeholder={t("tickets.filter.submitter")}
            allowClear
            onSearch={(v) => {
              setFilters({ ...filters, submitter: v });
              setPage({ ...page, offset: 0 });
            }}
          />
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>
            {t("tickets.action.refresh")}
          </Button>
        </Space>
      </Card>
      {error && <Card size="small">{error}</Card>}
      <Table<Ticket>
        rowKey={(row) => row.id}
        loading={loading}
        dataSource={tickets}
        scroll={{ x: 1100 }}
        pagination={{
          current: Math.floor(page.offset / page.limit) + 1,
          pageSize: page.limit,
          total,
          showSizeChanger: false,
          onChange: (p, size) => setPage({ limit: size, offset: (p - 1) * size }),
        }}
        columns={[
          {
            title: t("tickets.column.ticketNo"),
            dataIndex: "ticket_no",
            width: 230,
            render: (no: string) => (
              <Link onClick={() => navigate(`/tickets/${no}`)}>{no}</Link>
            ),
          },
          {
            title: t("tickets.column.status"),
            dataIndex: "status",
            width: 130,
            render: (_: string, record) => <StatusTag ticket={record} />,
          },
          {
            title: t("tickets.column.type"),
            dataIndex: "ticket_type",
            width: 130,
            render: (v: string) => t(`tickets.type.${v}`, { defaultValue: v ?? "-" }),
          },
          { title: t("tickets.column.principal"), dataIndex: "principal_name", width: 200, ellipsis: true },
          { title: t("tickets.column.submitter"), dataIndex: "submitter", width: 120 },
          {
            title: t("tickets.column.approvalMode"),
            dataIndex: "approval_mode",
            width: 100,
            render: (v) => <Tag>{v === "AUTO" ? t("tickets.approvalMode.auto") : t("tickets.approvalMode.manual")}</Tag>,
          },
          { title: t("tickets.column.createdAt"), dataIndex: "created_at", width: 170 },
        ]}
      />
    </div>
  );
}
