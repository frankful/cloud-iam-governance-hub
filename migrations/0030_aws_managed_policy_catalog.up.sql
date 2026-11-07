-- 0030: AWS 托管策略目录（C2）。
--
-- 采集器原先只拉 Scope=Local，官方策略（arn:aws:iam::aws:policy/*）只在被
-- 挂载到某个 role/user 时才按需抓取。结果是：策略搜索、资产页和工单下拉里
-- 看不到 AdministratorAccess 这类策略，管理员无法通过平台给主体挂载它们。
--
-- 目录行只存元数据（ARN / 名称 / 类型），不存文档：
-- policy_document 为 NULL 表示“已知存在、尚未拉取文档”。不用空文档占位，
-- 否则详情页会把“没有任何权限”当成真实策略内容展示，比缺文档更危险。
-- 文档仍由挂载时的按需抓取（fetchManagedPolicy）补齐。
ALTER TABLE iam_policy ALTER COLUMN policy_document DROP NOT NULL;

-- 目录行的 ARN 前缀固定，部分索引让「只看官方策略」的查询走索引。
CREATE INDEX iam_policy_aws_managed_idx ON iam_policy (policy_arn)
    WHERE policy_arn LIKE 'arn:aws:iam::aws:policy/%';
