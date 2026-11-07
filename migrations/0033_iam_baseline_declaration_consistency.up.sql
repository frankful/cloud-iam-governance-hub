-- 0033: 声明快照的一致性维护（phase4-drift-design.md §4.6 / §6）。
--
-- 0032 只解决了「声明要落库」，还剩三种让基准本身不可信的情况：
--
-- 1) 一次没落地的发布把有效声明盖掉了。基线 PR 被关闭未合并、工单被废弃，
--    都意味着这次发布从未进 main，main 上还是上一个声明对应的内容。只作废
--    不恢复，这些资源就变成「有实态、无基准」的覆盖空洞。为了能恢复，
--    必须区分历史行是「被新声明取代」（REPLACED，可恢复）还是「被作废」
--    （VOIDED，恢复它等于复活一个幽灵基准）。
--
-- 2) 有人绕过平台直接改 main 上的 tf 文件。此时文件内容与声明不一致，
--    差异不是漂移（是 baseline_stale），判定必须跳过而不是误报。stale_at /
--    stale_reason 由新鲜度核对写入，P3 判定读它。
--
-- 3) 恢复时按 (account_id, resource_key) 找「最近一条可恢复的历史行」，
--    局部索引把这次倒序扫变成索引扫描。
--
-- 回填：0032/0033 之前的行没有 superseded_reason。它们都是「被后一条声明
-- 取代」的正常历史（P2b 的作废逻辑上线时间很短），统一记 REPLACED——否则
-- 恢复逻辑会把它们当幽灵排除在外，已有的覆盖空洞永远补不回来。
ALTER TABLE iam_baseline_declaration
    ADD COLUMN superseded_reason TEXT,
    ADD COLUMN stale_at TIMESTAMPTZ,
    ADD COLUMN stale_reason TEXT;

UPDATE iam_baseline_declaration
SET superseded_reason = 'REPLACED'
WHERE superseded_at IS NOT NULL AND superseded_reason IS NULL;

-- 「当前声明」必须没有作废标记；「历史声明」必须说明为什么退场。
ALTER TABLE iam_baseline_declaration
    ADD CONSTRAINT iam_baseline_declaration_supersede_check
    CHECK ((superseded_at IS NULL) = (superseded_reason IS NULL)),
    ADD CONSTRAINT iam_baseline_declaration_supersede_reason_check
    CHECK (superseded_reason IS NULL OR superseded_reason IN ('REPLACED', 'VOIDED')),
    -- 过期标记是成对的：要么不算过期，要么给出原因。
    ADD CONSTRAINT iam_baseline_declaration_stale_check
    CHECK ((stale_at IS NULL) = (stale_reason IS NULL));

CREATE INDEX iam_baseline_declaration_restore_idx
    ON iam_baseline_declaration (account_id, resource_key, superseded_at DESC)
    WHERE superseded_at IS NOT NULL;
