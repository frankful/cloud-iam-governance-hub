package migrations

import (
	"io/fs"
	"sort"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreContiguousThroughCurrentPhase1(t *testing.T) {
	names, err := fs.Glob(Files, "*.up.sql")
	if err != nil {
		t.Fatalf("fs.Glob() error = %v", err)
	}
	sort.Strings(names)
	want := []string{
		"0001_initial_schema.up.sql",
		"0002_ticket_approval.up.sql",
		"0003_iam_groups.up.sql",
		"0004_platform_audit.up.sql",
		"0005_inventory_snapshot.up.sql",
		"0006_platform_rbac_tokens.up.sql",
		"0007_aws_account_config.up.sql",
		"0008_iam_baselines_and_validation.up.sql",
		"0009_iac_execution_records.up.sql",
		"0010_ticket_phase1_status.up.sql",
		"0011_immutable_ticket_snapshots.up.sql",
		"0012_ticket_git_poll_state.up.sql",
		"0013_aws_sync_runs.up.sql",
		"0014_sync_run_changes.up.sql",
		"0015_ticket_role_snapshot.up.sql",
		"0016_ticket_closure_comment.up.sql",
		"0017_iam_role_extra_attrs.up.sql",
		"0018_aws_sync_run_trigger_source_ticket_closed.up.sql",
		"0019_iam_resource_ownership.up.sql",
		"0020_iam_baseline_collection_fields.up.sql",
		"0021_policy_account_and_ownership_audit.up.sql",
		"0022_iam_baseline_job.up.sql",
		"0023_profile_usage_evidence.up.sql",
		"0024_profile_usage_eks_unavailable.up.sql",
		"0025_baseline_publication.up.sql",
		"0026_policy_description_tags.up.sql",
		"0027_baseline_publication_files.up.sql",
		"0028_baseline_publication_merge_states.up.sql",
		"0029_baseline_publication_superseded.up.sql",
		"0030_aws_managed_policy_catalog.up.sql",
		"0031_publish_reservation.up.sql",
		"0032_iam_baseline_declaration.up.sql",
		"0033_iam_baseline_declaration_consistency.up.sql",
		"0034_iam_drift_finding.up.sql",
		"0035_iam_baseline_publication_apply.up.sql",
		"0036_drift_skip_counts.up.sql",
		"0037_baseline_issue_detail_codes.up.sql",
		"0038_drift_summary_codes.up.sql",
		"0039_sync_run_superseded.up.sql",
	}
	if len(names) != len(want) {
		t.Fatalf("embedded migrations = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Errorf("migration %d = %q, want %q", index, names[index], want[index])
		}
	}
}

func TestPhase1MigrationsContainSecurityAndAppendOnlyGuards(t *testing.T) {
	checks := map[string][]string{
		"0006_platform_rbac_tokens.up.sql": {
			"token_hash BYTEA NOT NULL UNIQUE",
			"octet_length(token_hash) = 32",
			"platform_role_code_check",
		},
		"0007_aws_account_config.up.sql": {
			"aws_account_config_role_check",
			"CURRENT_CREDENTIALS",
			"sync_enabled BOOLEAN NOT NULL DEFAULT FALSE",
		},
		"0008_iam_baselines_and_validation.up.sql": {
			"iam_baseline_content_immutable",
			"ticket_validation_request_hash_length_check",
			"ticket_validation_record_append_only",
		},
		"0009_iac_execution_records.up.sql": {
			"iac_execution_record_append_only",
			"idempotency_key VARCHAR(256) NOT NULL UNIQUE",
		},
		"0010_ticket_phase1_status.up.sql": {
			"'PUBLISH_FAILED'",
			"'CLOSED'",
			"iam_ticket_closed_state_reason_check",
		},
		"0011_immutable_ticket_snapshots.up.sql": {
			"iam_ticket_snapshot_immutable",
			"request_policy IS DISTINCT FROM NEW.request_policy",
			"approver_ids IS DISTINCT FROM NEW.approver_ids",
		},
		"0019_iam_resource_ownership.up.sql": {
			"ADD COLUMN managed_by VARCHAR(16) NOT NULL DEFAULT 'unknown'",
			"iam_principal_managed_by_check",
		},
		// path / permissions_boundary 是 AWS provider 的 ForceNew 属性，
		// 这两列一旦缺失，存量基线首次 apply 就会重建角色或用户。
		"0020_iam_baseline_collection_fields.up.sql": {
			"ADD COLUMN path VARCHAR(512) NOT NULL DEFAULT '/'",
			"ADD COLUMN permissions_boundary_arn VARCHAR(512)",
			"CREATE TABLE iam_instance_profile",
			"role_arn VARCHAR(512)",
			"CREATE TABLE iam_identity_provider",
			"provider_type IN ('OIDC', 'SAML')",
		},
		// iam_policy 没有账号维度时，SetOwnership 按名字匹配会把所有账号的
		// 同名策略一起改掉；审计列保证归属决定可追溯到人。
		"0021_policy_account_and_ownership_audit.up.sql": {
			"ADD COLUMN account_id BIGINT REFERENCES aws_account(id)",
			"substring(iam_policy.policy_arn FROM 'arn:aws:iam::([0-9]{12}):')",
			"CREATE INDEX iam_policy_account_idx",
			"ADD COLUMN managed_by_reviewed_at TIMESTAMPTZ",
			"ADD COLUMN managed_by_reviewed_by VARCHAR(128)",
		},
		// 预览 job 的结果与哈希只在终态写入；归属列由触发器保护，
		// 防止把 job 挂到别的账号或事后改经办人。
		"0022_iam_baseline_job.up.sql": {
			"CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED'))",
			"iam_baseline_job_result_object_check",
			"octet_length(content_sha256) = 32",
			"iam_baseline_job_identity_immutable",
		},
		// 一账号一行的在用性证据：NOT NULL 的 JSONB 结构校验挡住半截写入。
		"0023_profile_usage_evidence.up.sql": {
			"aws_account_id VARCHAR(20) NOT NULL UNIQUE REFERENCES aws_account(account_id) ON DELETE CASCADE",
			"iam_profile_usage_evidence_object_check",
			"jsonb_typeof(used_profiles) = 'object'",
			"jsonb_typeof(role_nodegroups) = 'object'",
		},
		// EKS 权限需单独授予：缺权限时 EC2 证据照常可用，但必须记录
		// 「EKS 侧未检查」，让清理页给出提示而不是编造角色级结论。
		"0024_profile_usage_eks_unavailable.up.sql": {
			"ADD COLUMN eks_unavailable BOOLEAN NOT NULL DEFAULT FALSE",
		},
		// B3 发布台账：幂等键唯一约束 + 已发布行的完整性（必须有 PR 与时间）。
		"0025_baseline_publication.up.sql": {
			"CONSTRAINT iam_baseline_publication_account_run_key UNIQUE (account_id, sync_run_id)",
			"iam_baseline_publication_published_identity",
			"octet_length(content_sha256) = 32",
		},
		// 策略基线缺失属性：description 是 ForceNew（漏写 = 首次 apply 销毁
		// 重建 managed policy），tags 漏写会清空实态 tag。
		"0026_policy_description_tags.up.sql": {
			"ADD COLUMN description TEXT NOT NULL DEFAULT ''",
			"ADD COLUMN tags JSONB",
		},
		// 归属感知门禁：files 清单是基线拥有文件的证据；全部无变化时
		// PUBLISHED 不再强制要求 PR（GitHub 拒绝空 diff）。
		"0027_baseline_publication_files.up.sql": {
			"ADD COLUMN files JSONB",
			"pull_request_url <> '' OR files IS NOT NULL",
		},
		// PR 合并感知：台账记录远端 PR 终态。
		"0028_baseline_publication_merge_states.up.sql": {
			"'PUBLISHING', 'PUBLISHED', 'FAILED', 'MERGED', 'CLOSED'",
		},
	}
	for name, fragments := range checks {
		t.Run(name, func(t *testing.T) {
			contents, err := Files.ReadFile(name)
			if err != nil {
				t.Fatalf("read migration: %v", err)
			}
			for _, fragment := range fragments {
				if !strings.Contains(string(contents), fragment) {
					t.Errorf("%s does not contain %q", name, fragment)
				}
			}
		})
	}
}
