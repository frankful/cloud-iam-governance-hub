import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  List,
  Modal,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import { ArrowLeftOutlined, CheckOutlined, CloseOutlined, CopyOutlined, RollbackOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { api, ApiError, currentUser } from "../api/client";
import type { ExecutionRecord, Ticket, TicketApprovalInfo } from "../api/types";
import { StatusTag, pollBudgetExhausted, ticketTypeLabel } from "../status";

const { Title, Link, Text } = Typography;

// 回滚只对「反向操作能落到目标工单自己写过的文件」的类型有意义，与后端
// service.RollbackSupportedTargetType 一一对应。批量纳管（ADOPT_ROLE_INLINE_POLICIES）
// 的声明按策略拆成多份文件、挂载工单的反向操作是另开解绑单——这两类后端会明确
// 拒绝（400），入口在这里先收掉，别让用户填完表单才被拒。
const ROLLBACK_SUPPORTED_TYPES = [
  "CREATE_ROLE",
  "CREATE_USER",
  "CREATE_GROUP",
  "CREATE_MANAGED_POLICY",
  "UPDATE_ROLE",
  "UPDATE_MANAGED_POLICY",
  "UPDATE_GROUP_INLINE_POLICY",
  "UPDATE_GROUP_MEMBERSHIP",
  "ATTACH_USER_POLICY",
];

// rollbackBlockReason 返回「这张工单为什么不能回滚」的说明，空表示可以。
// 只有 ATTACH_USER_POLICY 需要看请求内容：只有「解绑」工单能回滚（重新挂载），
// 「挂载」工单没有对应的反向链路。
function rollbackBlockReason(ticket: Ticket, t: TFunction): string | null {
  const type = ticket.ticket_type ?? "";
  if (!ROLLBACK_SUPPORTED_TYPES.includes(type)) {
    return t("ticketDetail.rollbackUnsupported.type");
  }
  if (type === "ATTACH_USER_POLICY") {
    const stored = (ticket.request_policy as StoredRequest) ?? null;
    if (stored?.operation !== "detach") {
      return t("ticketDetail.rollbackUnsupported.attach");
    }
  }
  return null;
}

function mergeStateLabel(state: string, t: TFunction): string {
  const map: Record<string, string> = {
    OPEN: t("ticketDetail.mergeState.open"),
    MERGED: t("ticketDetail.mergeState.merged"),
    CLOSED: t("ticketDetail.mergeState.closed"),
    LOCKED: t("ticketDetail.mergeState.locked"),
    UNKNOWN: t("ticketDetail.mergeState.unknown"),
  };
  return map[state] ?? state;
}

function mergeStateColor(state: string): string {
  const map: Record<string, string> = {
    OPEN: "blue",
    MERGED: "green",
    CLOSED: "red",
    LOCKED: "orange",
  };
  return map[state] ?? "default";
}

function applyResultLabel(result: string, t: TFunction): string {
  const map: Record<string, string> = {
    PENDING: t("ticketDetail.applyResult.pending"),
    SUCCEEDED: t("ticketDetail.applyResult.succeeded"),
    FAILED: t("ticketDetail.applyResult.failed"),
    UNKNOWN: t("ticketDetail.applyResult.unknown"),
  };
  return map[result] ?? result;
}

interface StoredRequest {
  operation?: string;
  source_ticket_no?: string;
  target_ticket_no?: string;
  managed_policy_arn?: string;
  principal_type?: string;
  role_inline_policies?: { name?: string }[];
  update_policy?: {
    policy_arn?: string;
    policy_name?: string;
    group_name?: string;
    inline_policy_name?: string;
    document?: unknown;
  };
}

/**
 * 请求详情卡片：展示 ATTACH 工单的操作类型（挂载/解绑）与源工单，
 * 以及策略更新工单的目标策略身份。策略文档只展示行数，完整内容见 Terraform。
 */
function RequestPolicyCard({ ticket }: { ticket: Ticket }) {
  const { t } = useTranslation();
  let stored: StoredRequest | null = null;
  try {
    stored = (ticket.request_policy as StoredRequest) ?? null;
  } catch {
    stored = null;
  }
  if (!stored) return null;
  const updatePolicy = stored.update_policy;
  const isAttach = ticket.ticket_type === "ATTACH_USER_POLICY";
  const isPolicyUpdate =
    ticket.ticket_type === "UPDATE_MANAGED_POLICY" ||
    ticket.ticket_type === "UPDATE_GROUP_INLINE_POLICY";
  const isRolePolicyBatch = ticket.ticket_type === "ADOPT_ROLE_INLINE_POLICIES";
  if (!isAttach && !isPolicyUpdate && !isRolePolicyBatch && !stored.target_ticket_no) return null;

  const operationLabel =
    stored.operation === "detach"
      ? t("ticketDetail.request.operation.detach")
      : stored.operation === "attach"
        ? t("ticketDetail.request.operation.attach")
        : null;

  const documentLines = (() => {
    if (!updatePolicy?.document) return null;
    try {
      return JSON.stringify(updatePolicy.document).length;
    } catch {
      return null;
    }
  })();

  return (
    <Card size="small" style={{ marginTop: 16 }} title={t("ticketDetail.request.title")}>
      <Descriptions column={2} size="small">
        {operationLabel && (
          <Descriptions.Item label={t("ticketDetail.request.label.operationType")}>
            {operationLabel}
          </Descriptions.Item>
        )}
        {stored.target_ticket_no && (
          <Descriptions.Item label={t("ticketDetail.request.label.targetTicket")}>
            <Text className="mono">{stored.target_ticket_no}</Text>
          </Descriptions.Item>
        )}
        {isRolePolicyBatch && (
          <Descriptions.Item label={t("ticketDetail.request.label.roleInlinePolicies")} span={2}>
            {(stored.role_inline_policies ?? []).map((policy) => policy.name).filter(Boolean).join(", ")}
          </Descriptions.Item>
        )}
        {stored.source_ticket_no && (
          <Descriptions.Item label={t("ticketDetail.request.label.sourceTicket")}>
            <Text className="mono">{stored.source_ticket_no}</Text>
          </Descriptions.Item>
        )}
        {stored.managed_policy_arn && (
          <Descriptions.Item label={t("ticketDetail.request.label.managedPolicy")} span={2}>
            <Text className="mono">{stored.managed_policy_arn}</Text>
          </Descriptions.Item>
        )}
        {updatePolicy?.policy_arn && (
          <Descriptions.Item label={t("ticketDetail.request.label.targetPolicy")} span={2}>
            <Text className="mono">{updatePolicy.policy_arn}</Text>
          </Descriptions.Item>
        )}
        {updatePolicy?.group_name && (
          <Descriptions.Item label={t("ticketDetail.request.label.targetGroup")}>
            {updatePolicy.group_name}
          </Descriptions.Item>
        )}
        {updatePolicy?.inline_policy_name && (
          <Descriptions.Item label={t("ticketDetail.request.label.inlinePolicyName")}>
            {updatePolicy.inline_policy_name}
          </Descriptions.Item>
        )}
        {documentLines !== null && (
          <Descriptions.Item label={t("ticketDetail.request.label.policyDocument")}>
            {t("ticketDetail.request.policyDocumentSize", { bytes: documentLines })}
          </Descriptions.Item>
        )}
      </Descriptions>
      {stored.operation === "detach" && (
        <Alert
          style={{ marginTop: 8 }}
          type="info"
          showIcon
          message={t("ticketDetail.request.detachWarning")}
        />
      )}
    </Card>
  );
}

export default function TicketDetailPage() {
  const { t } = useTranslation();
  const { ticketNo = "" } = useParams();
  const navigate = useNavigate();
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [approval, setApproval] = useState<TicketApprovalInfo | null>(null);
  const [records, setRecords] = useState<ExecutionRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [decisionOpen, setDecisionOpen] = useState<"APPROVE" | "REJECT" | null>(null);
  const [comment, setComment] = useState("");
  const [acting, setActing] = useState(false);
  const [rearming, setRearming] = useState(false);
  const [abandonOpen, setAbandonOpen] = useState(false);
  const [abandonComment, setAbandonComment] = useState("");
  const [appliedOpen, setAppliedOpen] = useState(false);
  const [appliedComment, setAppliedComment] = useState("");
  const [appliedTriggerSync, setAppliedTriggerSync] = useState(true);
  const [terraformPreview, setTerraformPreview] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setError(null);
    try {
      const [t, a, r] = await Promise.all([
        api.getTicket(ticketNo),
        api.getApprovalInfo(ticketNo),
        api.getExecutionRecords(ticketNo, 5),
      ]);
      setTicket(t);
      setApproval(a);
      setRecords(r);
      // 未发布的工单没有 terraform_code，按需取回将要发布的预览。
      if (t.terraform_code) {
        setTerraformPreview(null);
        setPreviewError(null);
      } else {
        api
          .getTerraformPreview(ticketNo)
          .then((code) => {
            setTerraformPreview(code);
            setPreviewError(null);
          })
          .catch((err) => {
            setTerraformPreview(null);
            setPreviewError(err instanceof ApiError ? err.message : String(err));
          });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }, [ticketNo]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<Ticket>, success: string) => {
    setActing(true);
    try {
      setTicket(await fn());
      message.success(success);
      setDecisionOpen(null);
      setComment("");
      void load();
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setActing(false);
    }
  };

  const rearm = async () => {
    setRearming(true);
    try {
      await api.rearmPoll(ticketNo);
      message.success(t("ticketDetail.success.rearm"));
      void load();
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setRearming(false);
    }
  };

  if (error) {
    return (
      <div className="page">
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/tickets")}>
          {t("ticketDetail.action.back")}
        </Button>
        <Alert style={{ marginTop: 16 }} type="error" message={error} />
      </div>
    );
  }
  if (!ticket) return <div className="page">{t("ticketDetail.loading")}</div>;
  // 已发布工单用存库原文；未发布用工单将要发布的按需预览。
  const displayCode = ticket.terraform_code ?? terraformPreview;

  const status = ticket.status ?? "";
  const canSubmit = status === "DRAFT";
  // MANUAL 模式需要全部指定审批人表态。当前登录人已表过态时按钮必须停用：
  // 再点一次后端会返回「审批决定已记录」，看起来像没刷新，实则重复提交。
  const myDecision = (approval?.approvals ?? []).find(
    (entry) => entry.approver_id === currentUser(),
  )?.result;
  const canDecide = status === "APPROVING" && !myDecision;
  const waitingApprovers = (approval?.approvals ?? [])
    .filter((entry) => !entry.result)
    .map((entry) => entry.display_name || entry.approver_id);
  // 多人列表的分隔符随语言变化（中文顿号 / 英文逗号）。
  const listSeparator = t("ticketDetail.listSeparator");
  const waitingApproverList = waitingApprovers.join(listSeparator);
  const canRetryPublish = status === "PUBLISH_FAILED";
  const rollbackEligible = status === "CLOSED" && ticket.closure_reason === "APPLIED";
  const rollbackBlocked = rollbackEligible ? rollbackBlockReason(ticket, t) : null;
  const canRollback = rollbackEligible && !rollbackBlocked;
  // 与后端 CloseTicket 的可关闭状态保持一致。
  const canAbandon = ["DRAFT", "APPROVING", "APPROVED", "PUBLISHING", "PUBLISH_FAILED"].includes(
    status,
  );
  // 人工关单（已应用）：CI 暂缓阶段在 main 工作副本手工 apply 后使用。
  // 只对已发布（APPROVED）的工单开放——草稿/审批中谈不上"已应用"。
  const canMarkApplied = status === "APPROVED";

  // A12②：PR 已合并但 CI apply 失败——资源没在 AWS 落地，工单停在 APPROVED。
  // 这种情况必须显式提示，否则操作者只会看到"一张没人处理的工单"。
  const applyFailed = ticket.git_apply_result === "FAILED" && status !== "CLOSED";
  const failedRecord = records.find((record) => record.apply_result === "FAILED");
  const failedCommit = (failedRecord?.commit_sha || ticket.git_commit_sha || "").slice(0, 8);
  const ciRunURL = failedRecord?.remote_url || "";

  const abandon = () => {
    setAbandonComment("");
    setAbandonOpen(true);
  };

  const abandonConfirm = () => {
    setAbandonOpen(false);
    act(() => api.closeTicket(ticketNo, "ABANDONED", abandonComment.trim()), t("ticketDetail.success.abandoned"));
  };

  const markApplied = () => {
    setAppliedComment("");
    setAppliedTriggerSync(true);
    setAppliedOpen(true);
  };

  const markAppliedConfirm = () => {
    setAppliedOpen(false);
    act(
      () =>
        api.closeTicket(
          ticketNo,
          "APPLIED",
          appliedComment.trim(),
          appliedTriggerSync,
        ),
      t("ticketDetail.success.applied"),
    );
  };

  return (
    <div className="page">
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/tickets")}>
            {t("ticketDetail.action.back")}
          </Button>
          <Title level={4} className="page-title" style={{ margin: 0 }}>
            {ticket.ticket_no}
          </Title>
          <StatusTag ticket={ticket} />
        </Space>
        <Space>
          {canSubmit && (
            <Button
              type="primary"
              loading={acting}
              onClick={() => void act(() => api.submitTicket(ticketNo), t("ticketDetail.success.submitted"))}
            >
              {t("ticketDetail.action.submit")}
            </Button>
          )}
          {canDecide && (
            <>
              <Button
                type="primary"
                icon={<CheckOutlined />}
                loading={acting}
                onClick={() => setDecisionOpen("APPROVE")}
              >
                {t("ticketDetail.action.approve")}
              </Button>
              <Button
                danger
                icon={<CloseOutlined />}
                loading={acting}
                onClick={() => setDecisionOpen("REJECT")}
              >
                {t("ticketDetail.action.reject")}
              </Button>
            </>
          )}
          {canRetryPublish && (
            <Button
              type="primary"
              loading={acting}
              onClick={() =>
                void act(() => api.retryPublish(ticketNo), t("ticketDetail.success.publishRetried"))
              }
            >
              {t("ticketDetail.action.retryPublish")}
            </Button>
          )}
          {canRollback && (
            <Button
              icon={<RollbackOutlined />}
              onClick={() =>
                navigate("/tickets/new", {
                  state: { ticket_type: "ROLLBACK", target_ticket_no: ticket.ticket_no },
                })
              }
            >
              {t("ticketDetail.action.rollback")}
            </Button>
          )}
          {/* 不支持回滚的工单类型：按钮留在原位但禁用，tooltip 说明原因和替代路径
              （直接隐藏会让人以为「这张单和别人不一样」是数据问题）。 */}
          {rollbackEligible && rollbackBlocked && (
            <Tooltip title={rollbackBlocked}>
              <span style={{ cursor: "not-allowed" }}>
                <Button disabled icon={<RollbackOutlined />}>
                  {t("ticketDetail.action.rollback")}
                </Button>
              </span>
            </Tooltip>
          )}
          {canMarkApplied && (
            <Button type="primary" loading={acting} onClick={markApplied}>
              {t("ticketDetail.modal.appliedTitle")}
            </Button>
          )}
          {canAbandon && (
            <Button danger loading={acting} onClick={abandon}>
              {t("ticketDetail.action.abandon")}
            </Button>
          )}
        </Space>
      </Space>

      {status === "APPROVING" && (
        <Alert
          style={{ marginTop: 16 }}
          type={myDecision ? "success" : "info"}
          showIcon
          message={
            myDecision
              ? waitingApprovers.length > 0
                ? t("ticketDetail.approval.decidedWaiting", {
                    decision: t(
                      myDecision === "APPROVE"
                        ? "ticketDetail.approval.decision.approve"
                        : "ticketDetail.approval.decision.reject",
                    ),
                    approvers: waitingApproverList,
                  })
                : t("ticketDetail.approval.allDecided")
              : waitingApprovers.length > 0
                ? t("ticketDetail.approval.waitingApprovers", { approvers: waitingApproverList })
                : t("ticketDetail.approval.waiting")
          }
          description={
            myDecision ? t("ticketDetail.approval.noRepeatHint") : undefined
          }
        />
      )}

      <Card size="small" style={{ marginTop: 16 }}>
        <Descriptions column={2} size="small">
          <Descriptions.Item label={t("ticketDetail.field.type")}>
            {ticketTypeLabel(ticket.ticket_type)}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.principal")}>
            {ticket.principal_name ?? "-"}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.submitter")}>
            {ticket.submitter ?? "-"}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.approvalMode")}>
            <Tag>
              {ticket.approval_mode === "AUTO"
                ? t("ticketDetail.field.approvalModeAuto")
                : t("ticketDetail.field.approvalModeManual")}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.approvers")}>
            {(ticket.approver_ids ?? []).join(listSeparator) || "-"}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.pollCount")}>
            {ticket.poll_attempt_count}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.gitRepository")}>
            {ticket.git_repository ?? "-"}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.pr")}>
            {ticket.git_pr_url ? (
              <Link href={ticket.git_pr_url} target="_blank">
                {ticket.remote_request_number ?? ticket.git_pr_url}
              </Link>
            ) : (
              "-"
            )}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.closureReason")}>
            {ticket.closure_reason ?? "-"}
          </Descriptions.Item>
          {ticket.closure_comment && (
            <Descriptions.Item label={t("ticketDetail.field.closureComment")} span={2}>
              {ticket.closure_comment}
            </Descriptions.Item>
          )}
          <Descriptions.Item label={t("ticketDetail.field.createdAt")}>
            {ticket.created_at}
          </Descriptions.Item>
          <Descriptions.Item label={t("ticketDetail.field.updatedAt")}>
            {ticket.updated_at}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <RequestPolicyCard ticket={ticket} />

      <Card
        size="small"
        style={{ marginTop: 16 }}
        title={t("ticketDetail.terraform.title")}
        extra={
          displayCode ? (
            <Button
              size="small"
              icon={<CopyOutlined />}
              onClick={() => {
                void navigator.clipboard
                  ?.writeText(displayCode ?? "")
                  .then(
                    () => message.success(t("ticketDetail.success.copied")),
                    () => message.error(t("ticketDetail.error.copyFailed")),
                  );
              }}
            >
              {t("ticketDetail.action.copy")}
            </Button>
          ) : undefined
        }
      >
        {ticket.terraform_code ? (
          <pre className="mono terraform-code">{ticket.terraform_code}</pre>
        ) : displayCode ? (
          <>
            <Alert
              style={{ marginBottom: 8 }}
              type="info"
              showIcon
              message={t("ticketDetail.terraform.previewBadge")}
              description={t("ticketDetail.terraform.previewDesc")}
            />
            <pre className="mono terraform-code">{displayCode}</pre>
          </>
        ) : previewError ? (
          <Text type="secondary">
            {t("ticketDetail.terraform.previewFailed", { error: previewError })}
          </Text>
        ) : (
          <Text type="secondary">{t("ticketDetail.terraform.empty")}</Text>
        )}
      </Card>

      {applyFailed && (
        <Alert
          style={{ marginTop: 16 }}
          type="error"
          showIcon
          message={t("ticketDetail.applyFailed.title")}
          description={t("ticketDetail.applyFailed.desc", {
            commit: failedCommit || t("ticketDetail.applyFailed.noCommit"),
          })}
          action={
            ciRunURL ? (
              <Button
                size="small"
                danger
                type="primary"
                href={ciRunURL}
                target="_blank"
                rel="noreferrer"
              >
                {t("ticketDetail.applyFailed.viewCI")}
              </Button>
            ) : undefined
          }
        />
      )}

      {pollBudgetExhausted(ticket) && (
        <Alert
          style={{ marginTop: 16 }}
          type="warning"
          showIcon
          message={t("ticketDetail.poll.stopped")}
          description={t("ticketDetail.poll.stoppedDesc")}
          action={
            <Button size="small" type="primary" loading={rearming} onClick={() => void rearm()}>
              {t("ticketDetail.action.rearm")}
            </Button>
          }
        />
      )}

      <Card size="small" style={{ marginTop: 16 }} title={t("ticketDetail.approvalRecords.title")}>
        <List
          size="small"
          dataSource={approval?.approvals ?? []}
          locale={{ emptyText: t("ticketDetail.approvalRecords.empty") }}
          renderItem={(item) => (
            <List.Item>
              <Space>
                <Text strong>
                  {item.display_name}
                  {item.approver_id === currentUser() && (
                    <Text type="secondary">{t("ticketDetail.approvalRecords.you")}</Text>
                  )}
                </Text>
                <Tag color={item.result === "APPROVE" ? "green" : item.result === "REJECT" ? "red" : "default"}>
                  {item.result === "APPROVE"
                    ? t("ticketDetail.approval.approved")
                    : item.result === "REJECT"
                      ? t("ticketDetail.approval.rejected")
                      : t("ticketDetail.approval.pending")}
                </Tag>
                <Text type="secondary">{item.created_at}</Text>
              </Space>
              {item.comment && <div className="mono">{item.comment}</div>}
            </List.Item>
          )}
        />
      </Card>

      <Card size="small" style={{ marginTop: 16 }} title={t("ticketDetail.pollStatus.title")}>
        <List
          size="small"
          dataSource={records}
          locale={{ emptyText: t("ticketDetail.pollStatus.empty") }}
          renderItem={(item) => (
            <List.Item>
              <Space size="large" wrap>
                <Space>
                  <Text type="secondary">{t("ticketDetail.pollStatus.mergeState")}</Text>
                  <Tag color={mergeStateColor(item.merge_state)}>
                    {mergeStateLabel(item.merge_state, t)}
                  </Tag>
                </Space>
                <Space>
                  <Text type="secondary">{t("ticketDetail.pollStatus.ci")}</Text>
                  <Tag color={item.ci_state === "SUCCEEDED" ? "green" : item.ci_state === "FAILED" ? "red" : "default"}>
                    {item.ci_state}
                  </Tag>
                </Space>
                <Space>
                  <Text type="secondary">{t("ticketDetail.pollStatus.applyResult")}</Text>
                  <Tag color={item.apply_result === "SUCCEEDED" ? "green" : item.apply_result === "FAILED" ? "red" : "default"}>
                    {applyResultLabel(item.apply_result, t)}
                  </Tag>
                </Space>
                <Text type="secondary">
                  {t("ticketDetail.pollStatus.attempt", { attempt: item.attempt })}
                </Text>
                <Text type="secondary">{item.observed_at}</Text>
              </Space>
            </List.Item>
          )}
        />
      </Card>

      <Modal
        title={
          decisionOpen === "APPROVE"
            ? t("ticketDetail.modal.approveTitle")
            : t("ticketDetail.modal.rejectTitle")
        }
        open={decisionOpen !== null}
        onCancel={() => setDecisionOpen(null)}
        onOk={() => {
          if (!decisionOpen) return;
          void act(
            () => api.decideTicket(ticketNo, decisionOpen, comment),
            decisionOpen === "APPROVE"
              ? t("ticketDetail.approval.approved")
              : t("ticketDetail.approval.rejected"),
          );
        }}
        confirmLoading={acting}
        okText={
          decisionOpen === "APPROVE"
            ? t("ticketDetail.action.approve")
            : t("ticketDetail.action.reject")
        }
        okButtonProps={{ danger: decisionOpen === "REJECT" }}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="comment" label={t("ticketDetail.modal.commentLabel")}>
            <Input.TextArea
              rows={3}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder={t("ticketDetail.modal.commentPlaceholder")}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t("ticketDetail.modal.abandonTitle")}
        open={abandonOpen}
        onCancel={() => setAbandonOpen(false)}
        onOk={abandonConfirm}
        confirmLoading={acting}
        okText={t("ticketDetail.action.abandon")}
        okButtonProps={{ danger: true }}
        cancelText={t("ticketDetail.action.cancel")}
      >
        <Alert
          style={{ marginBottom: 12 }}
          type="warning"
          showIcon
          message={
            ticket.git_pr_url
              ? t("ticketDetail.modal.abandonWarningWithPr")
              : t("ticketDetail.modal.abandonWarning")
          }
        />
        <Input.TextArea
          rows={3}
          value={abandonComment}
          onChange={(e) => setAbandonComment(e.target.value)}
          placeholder={t("ticketDetail.modal.abandonCommentPlaceholder")}
        />
      </Modal>

      <Modal
        title={t("ticketDetail.modal.appliedTitle")}
        open={appliedOpen}
        onCancel={() => setAppliedOpen(false)}
        onOk={markAppliedConfirm}
        confirmLoading={acting}
        okText={t("ticketDetail.modal.appliedTitle")}
        cancelText={t("ticketDetail.action.cancel")}
      >
        <Alert
          style={{ marginBottom: 12 }}
          type="info"
          showIcon
          message={t("ticketDetail.modal.appliedWarning")}
        />
        <div style={{ marginBottom: 4 }}>
          <Switch
            checked={appliedTriggerSync}
            onChange={setAppliedTriggerSync}
          />
          <span style={{ marginLeft: 8 }}>{t("ticketDetail.modal.appliedTriggerSync")}</span>
        </div>
        <Typography.Text type="secondary" style={{ display: "block", marginBottom: 12, fontSize: 12 }}>
          {t("ticketDetail.modal.appliedTriggerSyncHint")}
        </Typography.Text>
        <Input.TextArea
          rows={3}
          value={appliedComment}
          onChange={(e) => setAppliedComment(e.target.value)}
          placeholder={t("ticketDetail.modal.appliedCommentPlaceholder")}
        />
      </Modal>
    </div>
  );
}
