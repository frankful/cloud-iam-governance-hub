-- 0015: pre-update role configuration snapshot for UPDATE_ROLE tickets.
-- Captured at publication time; ROLLBACK of an UPDATE_ROLE ticket reads this
-- snapshot to generate reverse Terraform restoring the original state.
ALTER TABLE iam_ticket ADD COLUMN role_snapshot JSONB;
