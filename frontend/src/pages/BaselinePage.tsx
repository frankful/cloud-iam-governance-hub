import { Tabs } from "antd";
import { useTranslation } from "react-i18next";
import { lazy, Suspense } from "react";
import { Spin } from "antd";

// 与兄弟页面一样按 code-split 拆分：容器只负责把「预览」和「发布」
// 两个能力挂在同一入口（/baseline）下，避免菜单再长一层。
const BaselinePreviewPage = lazy(() => import("./BaselinePreviewPage"));
const BaselinePublishPage = lazy(() => import("./BaselinePublishPage"));

function TabLoading() {
  return (
    <div style={{ display: "flex", justifyContent: "center", padding: 64 }}>
      <Spin />
    </div>
  );
}

export default function BaselinePage() {
  const { t } = useTranslation();
  return (
    <Tabs
      defaultActiveKey="preview"
      items={[
        {
          key: "preview",
          label: t("baseline.tabs.preview"),
          children: (
            <Suspense fallback={<TabLoading />}>
              <BaselinePreviewPage />
            </Suspense>
          ),
        },
        {
          key: "publish",
          label: t("baseline.tabs.publish"),
          children: (
            <Suspense fallback={<TabLoading />}>
              <BaselinePublishPage />
            </Suspense>
          ),
        },
      ]}
    />
  );
}
