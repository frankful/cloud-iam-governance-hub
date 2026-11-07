import {
  Alert,
  App,
  Button,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from "antd";
import {
  ApiOutlined,
  PlusOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { AWSAccountConfig, AWSAccountConfigInput } from "../api/types";

const { Title, Text } = Typography;

const RUN_STATUS_COLOR: Record<string, string> = {
  SUCCEEDED: "green",
  FAILED: "red",
  RUNNING: "blue",
  PENDING: "orange",
  SUPERSEDED: "gold",
};

interface AccountFormValues {
  aws_account_id: string;
  display_name: string;
  sync_mode: "CURRENT_CREDENTIALS" | "ASSUME_ROLE";
  read_only_role_arn?: string;
  sync_enabled: boolean;
}

/**
 * 账号管理：录入/编辑/停用云账号接入配置。
 *
 * 安全边界：本页只管理「怎么连」，不管理「用什么密钥」——平台永不存储
 * 目标账号的 AK/SK。凭证只有两个来源：收集者自身身份（CURRENT_CREDENTIALS，
 * 适合单收集号直连的场景）或跨账只读角色（ASSUME_ROLE，多账号推荐）。
 * 因此表单里没有也不允许出现任何密钥输入框。
 */
export default function AccountAdminPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [configs, setConfigs] = useState<AWSAccountConfig[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<AWSAccountConfig | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<number | null>(null);
  const [form] = Form.useForm<AccountFormValues>();
  const syncMode = Form.useWatch("sync_mode", form);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setConfigs(await api.listAccountConfigs());
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void load();
  }, [load]);

  const openCreate = () => {
    setEditing(null);
    setFormError(null);
    form.setFieldsValue({
      aws_account_id: "",
      display_name: "",
      sync_mode: "ASSUME_ROLE",
      read_only_role_arn: "",
      sync_enabled: true,
    });
    setModalOpen(true);
  };

  const openEdit = (config: AWSAccountConfig) => {
    setEditing(config);
    setFormError(null);
    form.setFieldsValue({
      aws_account_id: config.aws_account_id,
      display_name: config.display_name,
      sync_mode: config.sync_mode === "ASSUME_ROLE" ? "ASSUME_ROLE" : "CURRENT_CREDENTIALS",
      read_only_role_arn: config.read_only_role_arn ?? "",
      sync_enabled: config.sync_enabled,
    });
    setModalOpen(true);
  };

  const submit = async () => {
    const values = await form.validateFields();
    const payload: AWSAccountConfigInput = {
      aws_account_id: values.aws_account_id.trim(),
      display_name: values.display_name.trim(),
      sync_mode: values.sync_mode,
      read_only_role_arn:
        values.sync_mode === "ASSUME_ROLE" ? values.read_only_role_arn?.trim() : undefined,
      sync_enabled: values.sync_enabled,
    };
    setSubmitting(true);
    setFormError(null);
    try {
      if (editing) {
        await api.updateAccountConfig(editing.id, payload);
        message.success(t("accounts.saved"));
      } else {
        await api.createAccountConfig(payload);
        message.success(t("accounts.created"));
      }
      setModalOpen(false);
      void load();
    } catch (err) {
      // 保存前服务端会做 STS 连通性校验，400/502 大多是角色/凭证配置问题，
      // 把原文展示出来便于排查（与 NewTicketPage 的 4xx 面板同款策略）。
      setFormError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const testConnection = async (config: AWSAccountConfig) => {
    setTestingId(config.id);
    try {
      const identity = await api.testAccountConnection(config.id);
      message.success(
        t("accounts.testOk", { account: identity.AccountID ?? "?", arn: identity.ARN ?? "?" }),
        6,
      );
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err), 8);
    } finally {
      setTestingId(null);
    }
  };

  const toggleEnabled = async (config: AWSAccountConfig, enabled: boolean) => {
    try {
      await api.setSyncEnabled(config.id, enabled);
      setConfigs((prev) =>
        prev.map((c) => (c.id === config.id ? { ...c, sync_enabled: enabled } : c)),
      );
      message.success(enabled ? t("accounts.enabledMsg") : t("accounts.disabledMsg"));
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    }
  };

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Title level={4} className="page-title">
          {t("accounts.title")}
        </Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>
            {t("common.refresh")}
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            {t("accounts.create")}
          </Button>
        </Space>
      </Space>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t("accounts.securityTitle")}
        description={t("accounts.securityHint")}
      />

      <Table<AWSAccountConfig>
        rowKey="id"
        loading={loading}
        dataSource={configs}
        pagination={false}
        locale={{ emptyText: t("accounts.empty") }}
        columns={[
          {
            title: t("accounts.column.account"),
            width: 260,
            render: (_: unknown, c: AWSAccountConfig) => (
              <Space direction="vertical" size={0}>
                <Text strong>{c.display_name}</Text>
                <Text type="secondary" className="mono">
                  {c.aws_account_id}
                </Text>
              </Space>
            ),
          },
          {
            title: t("accounts.column.mode"),
            width: 180,
            render: (_: unknown, c: AWSAccountConfig) => (
              <Tag color={c.sync_mode === "ASSUME_ROLE" ? "blue" : "default"}>{c.sync_mode}</Tag>
            ),
          },
          {
            title: t("accounts.column.roleArn"),
            render: (_: unknown, c: AWSAccountConfig) =>
              c.read_only_role_arn ? (
                <Text className="mono" style={{ fontSize: 12 }} ellipsis>
                  {c.read_only_role_arn}
                </Text>
              ) : (
                <Text type="secondary">-</Text>
              ),
          },
          {
            title: t("accounts.column.enabled"),
            width: 100,
            render: (_: unknown, c: AWSAccountConfig) => (
              <Switch
                checked={c.sync_enabled}
                onChange={(enabled) => void toggleEnabled(c, enabled)}
              />
            ),
          },
          {
            title: t("accounts.column.syncState"),
            width: 200,
            render: (_: unknown, c: AWSAccountConfig) => (
              <Space direction="vertical" size={0}>
                <Tag color={RUN_STATUS_COLOR[c.sync_status] ?? "default"}>{c.sync_status}</Tag>
                {c.last_successful_sync_at && (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {t("accounts.lastSuccess", { time: c.last_successful_sync_at })}
                  </Text>
                )}
              </Space>
            ),
          },
          {
            title: t("common.actions"),
            width: 210,
            render: (_: unknown, c: AWSAccountConfig) => (
              <Space>
                <Button
                  size="small"
                  icon={<ApiOutlined />}
                  loading={testingId === c.id}
                  onClick={() => void testConnection(c)}
                >
                  {t("accounts.action.test")}
                </Button>
                <Button size="small" onClick={() => openEdit(c)}>
                  {t("common.edit")}
                </Button>
              </Space>
            ),
          },
        ]}
      />

      <Modal
        title={editing ? t("accounts.editTitle") : t("accounts.createTitle")}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => void submit()}
        confirmLoading={submitting}
        okText={t("common.save")}
        width={560}
      >
        {formError && (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
            message={t("accounts.saveFailed")}
            description={<pre className="mono" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{formError}</pre>}
          />
        )}
        <Form form={form} layout="vertical">
          <Form.Item
            name="aws_account_id"
            label={t("accounts.field.accountId")}
            rules={[
              { required: true },
              { pattern: /^\d{12}$/, message: t("accounts.field.accountIdPattern") },
            ]}
            extra={editing ? t("accounts.field.accountIdFixed") : undefined}
          >
            <Input disabled={!!editing} placeholder="123456789012" className="mono" />
          </Form.Item>
          <Form.Item
            name="display_name"
            label={t("accounts.field.displayName")}
            rules={[{ required: true }, { max: 256 }]}
          >
            <Input placeholder={t("accounts.field.displayNamePlaceholder")} />
          </Form.Item>
          <Form.Item name="sync_mode" label={t("accounts.field.syncMode")} required>
            <Select
              options={[
                { value: "ASSUME_ROLE", label: t("accounts.mode.assumeRole") },
                { value: "CURRENT_CREDENTIALS", label: t("accounts.mode.currentCredentials") },
              ]}
            />
          </Form.Item>
          {syncMode === "ASSUME_ROLE" && (
            <Form.Item
              name="read_only_role_arn"
              label={t("accounts.field.roleArn")}
              rules={[{ required: true }]}
              extra={t("accounts.field.roleArnHint")}
            >
              <Input
                placeholder="arn:aws:iam::123456789012:role/cloud-iam-governance-readonly"
                className="mono"
              />
            </Form.Item>
          )}
          <Form.Item
            name="sync_enabled"
            label={t("accounts.field.syncEnabled")}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          <Alert type="warning" showIcon message={t("accounts.noSecretHint")} />
        </Form>
      </Modal>
    </div>
  );
}
