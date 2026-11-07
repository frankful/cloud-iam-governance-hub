import { Table, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import type { BaselineBundleIssue } from "../api/types";

const { Text } = Typography;

const ISSUE_COLORS: Record<string, string> = {
  "file-exists": "gold",
  "already-declared": "blue",
  "file-key": "volcano",
  address: "volcano",
  "generation-error": "red",
  deferred: "purple",
};

/**
 * 基线 issue 表：预览详情与发布台账详情共用。
 *
 * 「说明」列不直接渲染服务端的 detail —— 那是中文原文，切到英文界面后这一列
 * 还是中文（界面语言由 i18n 决定，服务端不该承担用户可见措辞）。按 detail_code
 * 取本地化文案；没有码的旧记录才退回原文。
 */
export function BaselineIssueTable({ issues }: { issues: BaselineBundleIssue[] }) {
  const { t } = useTranslation();

  const detailText = (issue: BaselineBundleIssue) => {
    if (!issue.detail_code) {
      return issue.detail ?? "";
    }
    return t(`baseline.detail.issueDetail.${issue.detail_code}`, {
      ...issue.detail_params,
      defaultValue: issue.detail ?? issue.detail_code,
    });
  };

  return (
    <Table<BaselineBundleIssue>
      rowKey={(issue) => `${issue.kind}:${issue.value}`}
      dataSource={issues}
      pagination={false}
      size="small"
      columns={[
        {
          title: t("baseline.detail.column.kind"),
          dataIndex: "kind",
          width: 170,
          render: (kind: string) => (
            <Tag color={ISSUE_COLORS[kind] ?? "default"}>
              {t(`baseline.detail.issueKind.${kind}`, { defaultValue: kind })}
            </Tag>
          ),
        },
        {
          title: "ID",
          dataIndex: "value",
          render: (value: string) => <Text code>{value}</Text>,
        },
        {
          title: t("baseline.detail.column.detail"),
          dataIndex: "detail",
          render: (_: unknown, issue) => detailText(issue),
        },
      ]}
    />
  );
}
