-- 0021: iam_policy 补账号维度 + 归属标注审计。
--
-- 0019 给归属标注留了一个洞：iam_policy 表没有 account_id 列（policy_arn 全局
-- 唯一，模型上把不同账号的行放在同一张表里），SetOwnership 的策略分支只能按
-- policy_name 匹配——改一个账号的归属，会把**所有账号**同名策略一起改掉。
-- 这里把模型理正：customer-managed 策略属于某个账号（ARN 里就带着 12 位账号
-- ID），AWS 托管策略不属于任何账号（account_id 保持 NULL）。
--
-- 同时给三张表的归属标注加审计：谁在什么时候标的。归属决定全量基线能不能动
-- 这个资源，是高危决定，必须可追溯。

ALTER TABLE iam_policy ADD COLUMN account_id BIGINT REFERENCES aws_account(id);

-- 回填：customer-managed 策略按 ARN 里的账号 ID 关联到 aws_account。
-- AWS 托管策略（arn:aws:iam::aws:policy/...）不属于任何账号，保持 NULL。
UPDATE iam_policy
SET account_id = aws_account.id
FROM aws_account
WHERE iam_policy.account_id IS NULL
  AND iam_policy.policy_arn LIKE 'arn:aws:iam::_______%:policy/%'
  AND substring(iam_policy.policy_arn FROM 'arn:aws:iam::([0-9]{12}):') = aws_account.account_id;

CREATE INDEX iam_policy_account_idx ON iam_policy (account_id);

-- 归属标注审计：reviewed_at/by 只在标注时写入，采集器不碰。
ALTER TABLE iam_principal ADD COLUMN managed_by_reviewed_at TIMESTAMPTZ;
ALTER TABLE iam_principal ADD COLUMN managed_by_reviewed_by VARCHAR(128);
ALTER TABLE iam_group ADD COLUMN managed_by_reviewed_at TIMESTAMPTZ;
ALTER TABLE iam_group ADD COLUMN managed_by_reviewed_by VARCHAR(128);
ALTER TABLE iam_policy ADD COLUMN managed_by_reviewed_at TIMESTAMPTZ;
ALTER TABLE iam_policy ADD COLUMN managed_by_reviewed_by VARCHAR(128);
