-- 回滚：去掉 0037 补上的 detail_code / detail_params，回到「只有中文原文」
-- 的状态。升级后新写入的 issue 也带码，回滚同样会把它们去掉——那是旧版本
-- 前端本来就忽略的字段，重新发布会再次写入。

UPDATE iam_baseline_publication publication
SET issues = COALESCE((
  SELECT JSONB_AGG(entry - 'detail_code' - 'detail_params' ORDER BY ordinality)
  FROM JSONB_ARRAY_ELEMENTS(publication.issues) WITH ORDINALITY AS entries(entry, ordinality)
), '[]'::JSONB)
WHERE JSONB_TYPEOF(publication.issues) = 'array';

UPDATE iam_baseline_job job
SET result = JSONB_SET(job.result, '{issues}', COALESCE((
  SELECT JSONB_AGG(entry - 'detail_code' - 'detail_params' ORDER BY ordinality)
  FROM JSONB_ARRAY_ELEMENTS(job.result->'issues') WITH ORDINALITY AS entries(entry, ordinality)
), '[]'::JSONB))
WHERE JSONB_TYPEOF(job.result->'issues') = 'array';
