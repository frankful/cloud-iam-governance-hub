-- 0019: 纳管归属标记。
--
-- 全量纳管（接入账号后由平台把该账号的 IAM 资产全部纳入 Terraform 声明）
-- 需要知道每个资源归谁管：platform = 平台纳管（Terraform 声明它），
-- external = 别的系统管（CloudFormation / eksctl / 其他团队的 Terraform），
-- unknown = 还没标注（阶段 0 的差异清单里会列出来等管理员拍板）。
--
-- 采集器不写这一列：同步只刷新资源内容，归属是管理员的决定，同步不能覆盖。
-- 默认 unknown，现有存量行在加列时自动落到 unknown。
ALTER TABLE iam_principal ADD COLUMN managed_by VARCHAR(16) NOT NULL DEFAULT 'unknown';
ALTER TABLE iam_principal ADD CONSTRAINT iam_principal_managed_by_check
    CHECK (managed_by IN ('platform', 'external', 'unknown'));

ALTER TABLE iam_group ADD COLUMN managed_by VARCHAR(16) NOT NULL DEFAULT 'unknown';
ALTER TABLE iam_group ADD CONSTRAINT iam_group_managed_by_check
    CHECK (managed_by IN ('platform', 'external', 'unknown'));

ALTER TABLE iam_policy ADD COLUMN managed_by VARCHAR(16) NOT NULL DEFAULT 'unknown';
ALTER TABLE iam_policy ADD CONSTRAINT iam_policy_managed_by_check
    CHECK (managed_by IN ('platform', 'external', 'unknown'));

CREATE INDEX iam_principal_managed_by_idx ON iam_principal (account_id, managed_by);
CREATE INDEX iam_policy_managed_by_idx ON iam_policy (managed_by);
