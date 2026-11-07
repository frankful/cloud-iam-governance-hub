import { Alert, List, Space, Tag } from "antd";
import { useTranslation } from "react-i18next";
import type { ApiError } from "../api/client";

interface Violation {
  code: string;
  statement_index: number;
  action?: string;
  resource?: string;
  condition_key?: string;
  description: string;
}

interface Finding {
  risk_type: string;
  risk_level: string;
  description: string;
}

/** 渲染 422 结构化 details：基线违规 / 风险发现 */
export default function ValidationErrors({ error }: { error: ApiError }) {
  const { t } = useTranslation();
  const details = (error.details ?? {}) as Record<string, unknown>;
  const violations = details.violations as Violation[] | undefined;
  const findings = details.findings as Finding[] | undefined;

  if (!violations && !findings) {
    return <Alert type="error" message={error.message} />;
  }
  return (
    <Alert
      type="error"
      message={error.message}
      description={
        <List
          size="small"
          dataSource={[...(violations ?? []), ...(findings ?? [])]}
          renderItem={(item) => {
            const v = item as Violation;
            const f = item as Finding;
            return (
              <List.Item style={{ padding: "4px 0" }}>
                <Space size={8} wrap>
                  {v.code && <Tag color="red">{v.code}</Tag>}
                  {f.risk_type && <Tag color="orange">{f.risk_type}</Tag>}
                  {f.risk_level && <Tag color="volcano">{f.risk_level}</Tag>}
                  {v.statement_index !== undefined && (
                    <Tag>{t("validation.statement", { index: v.statement_index })}</Tag>
                  )}
                  {v.action && <span className="mono">{v.action}</span>}
                  {v.resource && <span className="mono">{v.resource}</span>}
                  {v.condition_key && <span className="mono">{v.condition_key}</span>}
                </Space>
                <div>{v.description ?? f.description}</div>
              </List.Item>
            );
          }}
        />
      }
    />
  );
}
