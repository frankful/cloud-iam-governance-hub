ALTER TABLE iam_policy
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS description;
