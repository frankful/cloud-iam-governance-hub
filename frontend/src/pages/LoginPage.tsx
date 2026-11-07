import { Alert, Button, Card, Form, Input, Spin, Typography, message } from "antd";
import { LockOutlined, UserOutlined } from "@ant-design/icons";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useNavigate } from "react-router-dom";
import { getDevUser } from "../api/client";
import { landingPath, useAuth } from "../auth";
import { LanguageSwitcher } from "../i18n/LanguageSwitcher";

const { Title, Text } = Typography;

export default function LoginPage() {
  const { mode, user, loading, error, login, loginDev } = useAuth();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: 120 }}>
        <Spin size="large" />
      </div>
    );
  }
  if (user) return <Navigate to={landingPath(user)} replace />;

  const submit = async (values: { token?: string; user_id?: string }) => {
    setSubmitting(true);
    setFormError(null);
    try {
      const identity =
        mode === "development"
          ? await loginDev(values.user_id ?? "")
          : await login(values.token ?? "");
      message.success(t("login.success", { user: identity.user_id }));
      navigate(landingPath(identity), { replace: true });
    } catch (err) {
      setFormError(err instanceof Error ? err.message : t("login.failed"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#f5f7fa",
        padding: 24,
      }}
    >
      <Card style={{ width: 420 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <Title level={3} style={{ marginBottom: 4 }}>
              {t("app.name")}
            </Title>
            <Text type="secondary">{t("app.subtitle")}</Text>
          </div>
          <LanguageSwitcher />
        </div>
        <div style={{ height: 20 }} />
        {error && (
          <Alert
            type="error"
            showIcon
            message={t("login.configError")}
            description={error}
            style={{ marginBottom: 16 }}
          />
        )}
        {formError && (
          <Alert type="error" showIcon message={formError} style={{ marginBottom: 16 }} />
        )}
        {mode === "development" ? (
          <Form layout="vertical" onFinish={(values) => void submit(values)}>
            <Alert
              type="warning"
              showIcon
              message={t("login.devMode")}
              description={t("login.devModeHint")}
              style={{ marginBottom: 16 }}
            />
            <Form.Item
              name="user_id"
              label={t("login.devUserId")}
              initialValue={getDevUser() || "admin"}
              rules={[{ required: true, message: t("login.devUserIdRequired") }]}
            >
              <Input prefix={<UserOutlined />} autoComplete="username" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={submitting}>
              {t("login.enterDev")}
            </Button>
          </Form>
        ) : mode === "api-token" ? (
          <Form layout="vertical" onFinish={(values) => void submit(values)}>
            <Form.Item
              name="token"
              label={t("login.tokenLabel")}
              rules={[{ required: true, message: t("login.tokenRequired") }]}
            >
              <Input.Password
                prefix={<LockOutlined />}
                placeholder="iamg_..."
                autoComplete="current-password"
              />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={submitting}>
              {t("login.signIn")}
            </Button>
            <Text type="secondary" style={{ display: "block", marginTop: 12, fontSize: 12 }}>
              {t("login.tokenHint")}
            </Text>
          </Form>
        ) : (
          <Alert
            type="error"
            showIcon
            message={t("login.unknownMode")}
            description={t("login.unknownModeHint")}
          />
        )}
      </Card>
    </div>
  );
}
