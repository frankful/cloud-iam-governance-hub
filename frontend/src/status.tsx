import { Tag } from "antd";
import { useTranslation } from "react-i18next";
import type { Ticket } from "./api/types";
import i18n from "./i18n";

/**
 * 轮询预算：与后端 service.MaxPollAttempts 保持一致。
 * 线性退避（首次 5 分钟，每轮 +5 分钟）下 63 次恰好覆盖 7 天。
 * 超出后轮询停止，工单保持已发布，需平台管理员「重新轮询」续期。
 */
export const POLL_BUDGET_MAX = 63;

/** 轮询已停止：已发布且预算耗尽（7 天未合并） */
export function pollBudgetExhausted(ticket: Ticket): boolean {
  return (
    ticket.status === "APPROVED" &&
    !!ticket.remote_request_number &&
    ticket.poll_attempt_count >= POLL_BUDGET_MAX
  );
}

/**
 * PRD 决策1：状态模型在前端映射，后端状态机不动。
 * 后端 iam_ticket.status → 前端展示状态：
 *   DRAFT                → 草稿
 *   APPROVING            → 审批中（PRD 的 SUBMITTED）
 *   APPROVED（无 PR）    → 已批准
 *   PUBLISHING           → 发布中
 *   APPROVED（有 PR 号） → 已发布（PRD 的 PUBLISHED）
 *   PUBLISH_FAILED       → 发布失败
 *   REJECTED             → 已拒绝
 *   MERGED               → 已合入
 *   CLOSED + APPLIED     → 已生效关闭（PRD 的 CLOSED_APPLIED）
 *   CLOSED + ABANDONED   → 已废弃关闭
 */
export type DisplayStatus =
  | "DRAFT"
  | "APPROVING"
  | "APPROVED"
  | "PUBLISHING"
  | "PUBLISHED"
  | "PUBLISH_FAILED"
  | "REJECTED"
  | "MERGED"
  | "CLOSED_APPLIED"
  | "CLOSED_ABANDONED";

export function displayStatus(ticket: Ticket): DisplayStatus {
  switch (ticket.status) {
    case "DRAFT":
      return "DRAFT";
    case "APPROVING":
      return "APPROVING";
    case "APPROVED":
      return ticket.remote_request_number ? "PUBLISHED" : "APPROVED";
    case "PUBLISHING":
      return "PUBLISHING";
    case "PUBLISH_FAILED":
      return "PUBLISH_FAILED";
    case "REJECTED":
      return "REJECTED";
    case "MERGED":
      return "MERGED";
    case "CLOSED":
      return ticket.closure_reason === "APPLIED" ? "CLOSED_APPLIED" : "CLOSED_ABANDONED";
    default:
      return "DRAFT";
  }
}

const STATUS_COLOR: Record<DisplayStatus, string> = {
  DRAFT: "default",
  APPROVING: "processing",
  APPROVED: "cyan",
  PUBLISHING: "geekblue",
  PUBLISHED: "green",
  PUBLISH_FAILED: "red",
  REJECTED: "volcano",
  MERGED: "purple",
  CLOSED_APPLIED: "success",
  CLOSED_ABANDONED: "warning",
};

export function StatusTag({ ticket }: { ticket: Ticket }) {
  const { t } = useTranslation();
  const status = displayStatus(ticket);
  return (
    <>
      <Tag color={STATUS_COLOR[status]}>{statusLabel(status)}</Tag>
      {pollBudgetExhausted(ticket) && <Tag color="warning">{t("status.pollExpired")}</Tag>}
    </>
  );
}

export function statusLabel(status: DisplayStatus): string {
  return i18n.t(`status.display.${status}`);
}

/** 工单类型标签 */
export function ticketTypeLabel(type?: string): string {
  if (!type) return "-";
  return i18n.t(`status.ticketType.${type}`, { defaultValue: type });
}
