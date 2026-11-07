import { Layout as AntLayout, Button, Menu, Select, Space, Tag, Typography } from "antd";
import {
  AuditOutlined,
  ClearOutlined,
  CloudServerOutlined,
  ToolOutlined,
  CloudSyncOutlined,
  DashboardOutlined,
  DiffOutlined,
  FileDoneOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  UnorderedListOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { api, getDevUser } from "../api/client";
import { hasRole, useAuth } from "../auth";
import { LanguageSwitcher } from "../i18n/LanguageSwitcher";

const { Header, Sider, Content } = AntLayout;

interface MenuEntry {
  key: string;
  icon: React.ReactNode;
  labelKey: string;
  roles?: string[];
  children?: { key: string; labelKey: string; icon?: React.ReactNode; roles?: string[] }[];
}

// 「同步管理」分组：基线与同步是同一条数据链路（同步产出库存 → 基线从库存
// 生成 bundle，发布还强依赖一次成功的同步 run），导航上放在一起；
// 「维护中心」只留低频高危动作（待清理、后续风险扫描），与日常导航分开。
const MENU: MenuEntry[] = [
  { key: "/", icon: <DashboardOutlined />, labelKey: "nav.dashboard", roles: ["platform_admin", "approval_admin"] },
  { key: "/tickets", icon: <UnorderedListOutlined />, labelKey: "nav.tickets" },
  { key: "/inventory", icon: <SafetyCertificateOutlined />, labelKey: "nav.inventory" },
  {
    key: "sync",
    icon: <CloudSyncOutlined />,
    labelKey: "nav.sync",
    children: [
      { key: "/accounts", labelKey: "nav.accountAdmin", icon: <CloudServerOutlined />, roles: ["platform_admin"] },
      { key: "/sync", labelKey: "nav.syncAccounts", icon: <CloudSyncOutlined /> },
      { key: "/baseline", labelKey: "nav.baseline", icon: <FileDoneOutlined />, roles: ["platform_admin"] },
      { key: "/drift", labelKey: "nav.drift", icon: <DiffOutlined /> },
    ],
  },
  { key: "/audit", icon: <AuditOutlined />, labelKey: "nav.audit", roles: ["platform_admin"] },
  {
    key: "maintenance",
    icon: <ToolOutlined />,
    labelKey: "nav.maintenance",
    roles: ["platform_admin"],
    children: [{ key: "/cleanup", labelKey: "nav.cleanup", icon: <ClearOutlined /> }],
  },
  { key: "/users", icon: <TeamOutlined />, labelKey: "nav.users", roles: ["platform_admin"] },
];

const LEAF_KEYS = MENU.flatMap((entry) => entry.children?.map((child) => child.key) ?? [entry.key]);

export default function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { mode, user, loginDev, logout } = useAuth();
  const { t } = useTranslation();
  const visibleMenu = MENU.filter((item) => !item.roles || hasRole(user, ...item.roles)).map((item) => ({
    ...item,
    children: item.children?.filter((child) => !child.roles || hasRole(user, ...child.roles)),
  }));
  const selected = [LEAF_KEYS.find((key) => key === location.pathname)
    ?? LEAF_KEYS.find((key) => key !== "/" && location.pathname.startsWith(key))
    ?? visibleMenu.find((m) => !m.children && location.pathname.startsWith(m.key))?.key
    ?? "/tickets"];

  const [devUsers, setDevUsers] = useState<string[]>([]);
  const currentDevUser = getDevUser() || user?.user_id || "";

  // Development-only user switcher. In api-token mode the identity comes from
  // the bearer token and cannot be changed from the browser.
  useEffect(() => {
    if (mode !== "development") return;
    let cancelled = false;
    api
      .listApprovers()
      .then((approvers) => {
        if (cancelled) return;
        const ids = approvers.map((a) => a.user_id);
        if (currentDevUser && !ids.includes(currentDevUser)) ids.unshift(currentDevUser);
        setDevUsers(ids);
      })
      .catch(() => {
        if (currentDevUser) setDevUsers([currentDevUser]);
      });
    return () => {
      cancelled = true;
    };
  }, [mode, currentDevUser]);

  return (
    <AntLayout style={{ minHeight: "100vh" }}>
      <Sider theme="dark" width={220}>
        <div
          style={{
            color: "#fff",
            fontSize: 16,
            fontWeight: 600,
            padding: "16px 20px",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
          title={t("app.name")}
        >
          {t("app.name")}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={selected}
          defaultOpenKeys={["sync", "maintenance"]}
          items={visibleMenu.map(({ key, icon, labelKey, children }) => ({
            key,
            icon,
            label: t(labelKey),
            children: children?.map(({ key: childKey, labelKey: childLabelKey, icon: childIcon }) => ({
              key: childKey,
              icon: childIcon,
              label: t(childLabelKey),
            })),
          }))}
          onClick={({ key }) => {
            // 分组 key（如 maintenance）没有路由，只有叶子路径才导航。
            if (key.startsWith("/")) navigate(key);
          }}
        />
      </Sider>
      <AntLayout>
        <Header
          style={{
            background: "#fff",
            paddingInline: 24,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            borderBottom: "1px solid #f0f0f0",
          }}
        >
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {mode === "development" ? t("app.devHint") : t("app.bearerHint")}
          </Typography.Text>
          <Space>
            <LanguageSwitcher />
            <UserOutlined />
            {mode === "development" ? (
              <Select
                style={{ width: 220 }}
                showSearch
                value={currentDevUser}
                options={devUsers.map((u) => ({ value: u, label: u }))}
                onChange={(value) => {
                  void loginDev(value).then(() => navigate(0));
                }}
              />
            ) : (
              <Typography.Text>{user?.user_id}</Typography.Text>
            )}
            {user?.roles.map((role) => (
              <Tag key={role} color={role === "platform_admin" ? "blue" : role === "approval_admin" ? "gold" : "default"}>
                {role}
              </Tag>
            ))}
            {mode !== "development" && (
              <Button
                size="small"
                icon={<LogoutOutlined />}
                onClick={() => {
                  logout();
                  navigate("/login", { replace: true });
                }}
              >
                {t("app.logout")}
              </Button>
            )}
          </Space>
        </Header>
        <Content style={{ background: "#fff", minHeight: "calc(100vh - 64px)" }}>
          <Outlet />
        </Content>
      </AntLayout>
    </AntLayout>
  );
}
