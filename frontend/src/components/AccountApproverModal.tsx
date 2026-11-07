import { Alert, Modal, Select, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { AccountApproverBinding, AccountApproverCandidate } from "../api/types";

interface AccountApproverModalProps {
  /** 账号的数据库 ID（不是 12 位账号号）；null 表示未选择账号。 */
  accountDbId: number | null;
  /** 弹窗标题里的账号展示名。 */
  accountLabel?: string;
  open: boolean;
  onClose: () => void;
  /** 保存成功后回调，调用方可据此刷新本地审批人列表。 */
  onSaved?: () => void;
}

/**
 * 账号审批人的唯一编辑弹窗：同步管理（账号视角）和新建工单（AUTO 缺审批人
 * 时就地配置）共用。抽出来是因为同一份「候选 + 已绑定 + 失效绑定」逻辑出现
 * 在第三处就会各自漂移。
 */
export default function AccountApproverModal({
  accountDbId,
  accountLabel,
  open,
  onClose,
  onSaved,
}: AccountApproverModalProps) {
  const { t } = useTranslation();
  const [candidates, setCandidates] = useState<AccountApproverCandidate[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  // 已绑定但当前不合格（停用/降级）的用户：候选列表按实时 JOIN 过滤，看不到
  // 他们，但绑定行还在——整体替换保存会顺手清掉，必须先让操作者看见。
  const [stale, setStale] = useState<AccountApproverBinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || !accountDbId) return;
    let cancelled = false;
    setLoading(true);
    Promise.all([
      api.listAccountApproverCandidates(accountDbId),
      api.getAccountApprovers(accountDbId),
    ])
      .then(([candidateList, bindings]) => {
        if (cancelled) return;
        setCandidates(candidateList);
        setSelected(candidateList.filter((candidate) => candidate.bound).map((candidate) => candidate.user_id));
        const qualified = new Set(["platform_admin", "approval_admin"]);
        setStale(bindings.filter((binding) => !binding.is_active || !binding.roles.some((role) => qualified.has(role))));
      })
      .catch((err) => {
        if (cancelled) return;
        message.error(err instanceof ApiError ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, accountDbId]);

  const save = async () => {
    if (!accountDbId) return;
    setSaving(true);
    try {
      await api.replaceAccountApprovers(accountDbId, selected);
      message.success(t("approver.saved"));
      onSaved?.();
      onClose();
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={t("approver.title", { name: accountLabel ?? "" })}
      open={open}
      onOk={() => void save()}
      onCancel={onClose}
      confirmLoading={saving}
      okText={t("common.save")}
      cancelText={t("common.cancel")}
      destroyOnClose
    >
      <Alert type="info" showIcon style={{ marginBottom: 12 }} message={t("approver.hint")} />
      {stale.length > 0 && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message={t("approver.staleTitle")}
          description={
            <>
              {stale.map((binding) => `${binding.display_name}（${binding.user_id}）`).join("、")}
              <div style={{ marginTop: 4 }}>{t("approver.staleHint")}</div>
            </>
          }
        />
      )}
      <Select
        mode="multiple"
        style={{ width: "100%" }}
        placeholder={t("approver.empty")}
        value={selected}
        loading={loading}
        onChange={setSelected}
        options={candidates.map((candidate) => ({
          value: candidate.user_id,
          label: `${candidate.display_name}（${candidate.user_id}）`,
        }))}
        notFoundContent={t("approver.empty")}
      />
      <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
        {selected.length > 0
          ? t("approver.bound", { count: selected.length })
          : t("approver.noBinding")}
      </Typography.Paragraph>
    </Modal>
  );
}
