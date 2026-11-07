-- 0017: UPDATE_ROLE 收窄与块级 patch 前置：角色属性采集扩展。
-- max_session_duration / tags 此前未采集（collector 只取 Description），
-- 导致回滚无法还原这两项属性。采集器从 GetRole 同响应直接落库，成本很小。
ALTER TABLE iam_principal ADD COLUMN max_session_duration INTEGER;
ALTER TABLE iam_principal ADD COLUMN tags JSONB;
