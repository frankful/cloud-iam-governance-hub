-- 漂移发现的 summary 也是服务端拼中文（台账 C16）：Drift 页「说明」列直接
-- 渲染它，界面切英文后整列仍是中文。和基线 issue（0037）同样的处理：新增
-- summary_code + summary_params，前端按码取词条，summary 退化为兜底
-- （webhook、CLI 等外部消费者继续读它）。
--
-- 回填只做确定性映射，全部取自这一行已有的列（change_type / resource_key /
-- file_key / kind / fields），不解析旧文案——文案改过一个字，正则就会猜错。

ALTER TABLE iam_drift_finding ADD COLUMN IF NOT EXISTS summary_code VARCHAR(64);
ALTER TABLE iam_drift_finding ADD COLUMN IF NOT EXISTS summary_params JSONB;

COMMENT ON COLUMN iam_drift_finding.summary_code IS
    '摘要的语义码（declared_missing / undeclared_extra / baseline_stale / attribute / attribute_fields / file_conflict）；前端按界面语言渲染，summary 为兜底';
COMMENT ON COLUMN iam_drift_finding.summary_params IS
    '摘要插值参数：resource / child / file / fields';

UPDATE iam_drift_finding
SET summary_code = CASE
        WHEN change_type IN ('declared_missing', 'undeclared_extra',
                             'baseline_stale', 'file_conflict') THEN change_type
        WHEN COALESCE(JSONB_ARRAY_LENGTH(fields), 0) > 0 THEN 'attribute_fields'
        ELSE 'attribute'
    END,
    summary_params = CASE
        -- 基准过期按文件说事：summary 里的 X.tf 就是这个文件。
        WHEN change_type = 'baseline_stale'
            THEN JSONB_BUILD_OBJECT('file', COALESCE(file_key, '') || '.tf')
        -- 发布冲突的资源键形如 file:<key>。
        WHEN change_type = 'file_conflict'
            THEN JSONB_BUILD_OBJECT(
                'file', REGEXP_REPLACE(COALESCE(resource_key, ''), '^file:', '') || '.tf')
        WHEN change_type = 'undeclared_extra'
            THEN JSONB_BUILD_OBJECT(
                'resource', COALESCE(NULLIF(resource_key, ''), COALESCE(kind, '')),
                'child', CASE kind
                    WHEN 'attachment' THEN 'attachment'
                    WHEN 'membership' THEN 'membership'
                    WHEN 'inline-policy' THEN 'inline_policy'
                    ELSE 'resource'
                END)
        WHEN COALESCE(JSONB_ARRAY_LENGTH(fields), 0) > 0
            THEN JSONB_BUILD_OBJECT(
                'resource', COALESCE(NULLIF(resource_key, ''), COALESCE(kind, '')),
                'fields', (
                    SELECT STRING_AGG(entry->>'field', ', ' ORDER BY ordinality)
                    FROM JSONB_ARRAY_ELEMENTS(fields) WITH ORDINALITY AS t(entry, ordinality)
                ))
        ELSE JSONB_BUILD_OBJECT(
            'resource', COALESCE(NULLIF(resource_key, ''), COALESCE(kind, '')))
    END
WHERE summary_code IS NULL;
