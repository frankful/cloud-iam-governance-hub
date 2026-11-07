-- 0035: 基线发布的「已 apply」确认（phase4-drift-design.md §3 第 5 层）。
-- 合并 ≠ 生效：PR 合并只说明文件进了 main，terraform apply 是否跑过、跑的
-- 是哪个 commit，平台此前无从知道。CI 在 apply 后回调时带上 publication_id，
-- 这三列就是那条回调的落点，用来区分「已合并」与「已应用」。
ALTER TABLE iam_baseline_publication
    ADD COLUMN applied_at         TIMESTAMPTZ,
    ADD COLUMN applied_commit_sha TEXT,
    ADD COLUMN applied_ci_url     TEXT;
