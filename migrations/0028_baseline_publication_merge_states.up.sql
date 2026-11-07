-- PR 合并感知（B3 收尾）：发布台账记录远端 PR 终态。
-- MERGED = PR 已合并；CLOSED = PR 被关闭且未合并（发布被拒，error 列记原因）。
ALTER TABLE iam_baseline_publication
    DROP CONSTRAINT iam_baseline_publication_status_check;

ALTER TABLE iam_baseline_publication
    ADD CONSTRAINT iam_baseline_publication_status_check
    CHECK (status IN ('PUBLISHING', 'PUBLISHED', 'FAILED', 'MERGED', 'CLOSED'));
