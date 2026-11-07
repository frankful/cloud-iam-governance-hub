-- 0029: 重发同 run 时保留被覆盖的旧 PR 记录（审计）。
-- 台账行以 (account_id, sync_run_id) 为唯一键，重发 MERGED/CLOSED 行是
-- 原地 UPDATE；此前旧 PR 的编号、URL、终态会被直接覆盖丢失。superseded
-- 数组把每次被重发替代的 PR 记录追加归档在行内。
ALTER TABLE iam_baseline_publication
    ADD COLUMN superseded JSONB NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(superseded) = 'array');
