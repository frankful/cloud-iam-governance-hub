-- 目录行没有文档，恢复 NOT NULL 前必须先清掉它们。
DELETE FROM iam_policy WHERE policy_document IS NULL;

DROP INDEX IF EXISTS iam_policy_aws_managed_idx;

ALTER TABLE iam_policy ALTER COLUMN policy_document SET NOT NULL;
