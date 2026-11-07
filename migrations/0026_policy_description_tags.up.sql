-- 0026: 基线缺失属性采集（description / tags）。
-- aws_iam_policy 的 description 是 ForceNew：基线声明漏写会让首次 apply
-- 销毁重建全部 managed policy（实测 8 个 replace 的唯一 FORCE 原因）。
-- tags 同理：声明缺 tags 会把实态 tag 整体清空（含 AKIA* 等标记 tag）。
-- iam_policy 是按 policy_arn 全局去重的表，无 account_id 列。

ALTER TABLE iam_policy
    ADD COLUMN description TEXT NOT NULL DEFAULT '',
    ADD COLUMN tags JSONB;

