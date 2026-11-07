-- 0024: 在用性证据补充「EKS 侧不可用」标记。
-- EKS 只读权限（eks:List*/Describe*）需要单独授予；缺权限时解析器仍能给出
-- EC2 launch template 侧的完整证据，但要记录「EKS 侧未检查」，让待清理清单
-- 给出权限提示、且理由文本不再声称「角色没有节点组在用」。
-- 结构化布尔列而不是从 warnings 文本反推：提示文案可以随时改，语义不能变。

ALTER TABLE iam_profile_usage_evidence
    ADD COLUMN eks_unavailable BOOLEAN NOT NULL DEFAULT FALSE;
