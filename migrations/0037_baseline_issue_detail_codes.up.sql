-- 历史 baseline issue 只有中文 detail，界面切到英文后「说明」列仍是中文
-- （台账 C15）。新记录自带 detail_code，这里把旧记录补上：detail 是当时
-- 服务端的常量文案，按「kind + 原文」映射回语义码；匹配不到语义码的保持
-- 原样（前端退回原文显示，不猜）。
--
-- detail_params 只补需要插值的三类：仓库检查失败（error）、生成失败
-- （error）、让路（holder）。

CREATE FUNCTION _mig0037_issue_detail_code(issue JSONB) RETURNS JSONB AS $$
  SELECT CASE
    WHEN issue->>'detail_code' IS NOT NULL THEN issue
    WHEN issue->>'kind' = 'already-declared'
      THEN issue || '{"detail_code":"already-declared"}'::JSONB
    WHEN issue->>'kind' = 'file-exists'
      AND COALESCE(issue->>'detail', '') LIKE '仓库检查失败：%'
      THEN issue || JSONB_BUILD_OBJECT(
        'detail_code', 'repo-check-failed',
        'detail_params', JSONB_BUILD_OBJECT(
          'error', SUBSTR(issue->>'detail', LENGTH('仓库检查失败：') + 1)))
    WHEN issue->>'kind' = 'file-exists'
      THEN issue || '{"detail_code":"file-exists"}'::JSONB
    WHEN issue->>'kind' = 'file-key'
      THEN issue || JSONB_BUILD_OBJECT(
        'detail_code',
        CASE WHEN COALESCE(issue->>'detail', '') = ''
          THEN 'file-key-conflict' ELSE 'file-key-merged' END)
    WHEN issue->>'kind' = 'address'
      THEN issue || '{"detail_code":"address-conflict"}'::JSONB
    WHEN issue->>'kind' = 'generation-error'
      AND COALESCE(issue->>'detail', '') = '生成器未实现'
      THEN issue || '{"detail_code":"generator-missing"}'::JSONB
    WHEN issue->>'kind' = 'generation-error'
      THEN issue || JSONB_BUILD_OBJECT(
        'detail_code', 'generator-error',
        'detail_params', JSONB_BUILD_OBJECT('error', COALESCE(issue->>'detail', '')))
    WHEN issue->>'kind' = 'deferred'
      THEN issue || JSONB_BUILD_OBJECT(
        'detail_code', 'deferred',
        'detail_params', JSONB_BUILD_OBJECT(
          'holder',
          SUBSTR(COALESCE(issue->>'detail', ''),
            STRPOS(COALESCE(issue->>'detail', ''), '：') + 1)))
    ELSE issue
  END
$$ LANGUAGE SQL IMMUTABLE;

-- 发布台账：issues 是独立列。
UPDATE iam_baseline_publication publication
SET issues = COALESCE((
  SELECT JSONB_AGG(_mig0037_issue_detail_code(entry) ORDER BY ordinality)
  FROM JSONB_ARRAY_ELEMENTS(publication.issues) WITH ORDINALITY AS entries(entry, ordinality)
), '[]'::JSONB)
WHERE JSONB_TYPEOF(publication.issues) = 'array';

-- 预览 job：issues 嵌在 result 里。
UPDATE iam_baseline_job job
SET result = JSONB_SET(job.result, '{issues}', COALESCE((
  SELECT JSONB_AGG(_mig0037_issue_detail_code(entry) ORDER BY ordinality)
  FROM JSONB_ARRAY_ELEMENTS(job.result->'issues') WITH ORDINALITY AS entries(entry, ordinality)
), '[]'::JSONB))
WHERE JSONB_TYPEOF(job.result->'issues') = 'array';

DROP FUNCTION _mig0037_issue_detail_code(JSONB);
