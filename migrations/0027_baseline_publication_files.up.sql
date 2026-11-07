-- 0027: 基线归属感知的更新门禁。
-- PR 合并进 main 后，基线自己的文件就常驻 main 了：原「存在即拒绝」门禁
-- 会让同账号的任何再次发布必然失败。升级为：
--   内容与 main 相同        -> 跳过（无变化）
--   内容不同但在既往发布清单 -> 允许更新（基线拥有的文件走基线更新）
--   内容不同且不在清单      -> 拒绝（保护工单/手工文件归属）
-- files 记录每次成功发布覆盖的文件清单（归属证据）；既往无清单的发布
-- 由运维从其 PR 的 changed files 回填。

ALTER TABLE iam_baseline_publication
    ADD COLUMN files JSONB CHECK (files IS NULL OR jsonb_typeof(files) = 'array');

-- 全部文件与 main 相同时不开 PR 也算发布成功（基线已是最新）。
ALTER TABLE iam_baseline_publication
    DROP CONSTRAINT iam_baseline_publication_published_identity;
ALTER TABLE iam_baseline_publication
    ADD CONSTRAINT iam_baseline_publication_published_identity CHECK (
        status <> 'PUBLISHED' OR (
            published_at IS NOT NULL
            AND (pull_request_url <> '' OR files IS NOT NULL)
        )
    );
