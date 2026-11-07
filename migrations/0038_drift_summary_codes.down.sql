-- 回滚：去掉 0038 新增的两列，回到「只有中文 summary」的状态。
-- 升级后新写入的发现也带码，回滚会把它们一起丢掉——旧版前端本来就忽略这
-- 两个字段，下一轮检测会重新写入。
ALTER TABLE iam_drift_finding DROP COLUMN IF EXISTS summary_params;
ALTER TABLE iam_drift_finding DROP COLUMN IF EXISTS summary_code;
