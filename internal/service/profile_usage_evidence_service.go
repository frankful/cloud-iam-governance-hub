package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// ErrProfileUsageEvidenceNotFound 表示该账号还没有落库的在用性证据。
var ErrProfileUsageEvidenceNotFound = errors.New("profile usage evidence not found")

// ProfileUsageEvidenceStore 读写「实例配置文件在用性证据」的数据库快照。
//
// 这份证据（EC2 launch template 引用 + EKS 节点组角色）变化频率是部署级的，
// 同步时顺带采集落库后，待清理清单直接读库即可，不必每次打开页面都实时调
// AWS。一账号一行，UPSERT 覆盖：证据只关心「当前谁在用」，不保留版本史。
type ProfileUsageEvidenceStore struct {
	db *sql.DB
}

// NewProfileUsageEvidenceStore 创建证据存取服务。
func NewProfileUsageEvidenceStore(database *sql.DB) (*ProfileUsageEvidenceStore, error) {
	if database == nil {
		return nil, errors.New("database handle must not be nil")
	}
	return &ProfileUsageEvidenceStore{db: database}, nil
}

// Save 覆盖式写入一个账号的证据快照。调用方保证 result 可用（解析成功）；
// 失败的解析没有「证据」可言，不该污染库里已有的快照。
func (store *ProfileUsageEvidenceStore) Save(
	ctx context.Context,
	awsAccountID string,
	result profileUsageResult,
) error {
	if result.UsedProfiles == nil {
		result.UsedProfiles = map[string][]string{}
	}
	if result.RoleNodegroups == nil {
		result.RoleNodegroups = map[string][]string{}
	}
	usedProfiles, err := json.Marshal(result.UsedProfiles)
	if err != nil {
		return fmt.Errorf("encode used profiles: %w", err)
	}
	roleNodegroups, err := json.Marshal(result.RoleNodegroups)
	if err != nil {
		return fmt.Errorf("encode role nodegroups: %w", err)
	}
	warnings, err := json.Marshal(result.Warnings)
	if err != nil {
		return fmt.Errorf("encode warnings: %w", err)
	}
	// nil 切片会被编码成 JSON null，而约束要求 array；空切片才是 []。
	if len(result.Warnings) == 0 {
		warnings = []byte("[]")
	}
	_, err = store.db.ExecContext(ctx, `
		INSERT INTO iam_profile_usage_evidence
		       (aws_account_id, used_profiles, role_nodegroups, warnings, eks_unavailable, collected_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (aws_account_id) DO UPDATE SET
		       used_profiles = EXCLUDED.used_profiles,
		       role_nodegroups = EXCLUDED.role_nodegroups,
		       warnings = EXCLUDED.warnings,
		       eks_unavailable = EXCLUDED.eks_unavailable,
		       collected_at = NOW()`,
		awsAccountID, string(usedProfiles), string(roleNodegroups), string(warnings), result.EKSUnavailable)
	if err != nil {
		return fmt.Errorf("save profile usage evidence: %w", err)
	}
	return nil
}

// Load 读取一个账号的证据快照。没有行时返回 ErrProfileUsageEvidenceNotFound；
// collectedAt 让上层判断证据的新鲜度。
func (store *ProfileUsageEvidenceStore) Load(
	ctx context.Context,
	awsAccountID string,
) (profileUsageResult, time.Time, error) {
	var usedProfiles, roleNodegroups, warnings []byte
	var collectedAt time.Time
	var eksUnavailable bool
	err := store.db.QueryRowContext(ctx, `
		SELECT used_profiles, role_nodegroups, warnings, eks_unavailable, collected_at
		FROM iam_profile_usage_evidence
		WHERE aws_account_id = $1`, awsAccountID,
	).Scan(&usedProfiles, &roleNodegroups, &warnings, &eksUnavailable, &collectedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return profileUsageResult{}, time.Time{}, ErrProfileUsageEvidenceNotFound
	}
	if err != nil {
		return profileUsageResult{}, time.Time{}, fmt.Errorf("load profile usage evidence: %w", err)
	}
	result := profileUsageResult{
		UsedProfiles:   map[string][]string{},
		RoleNodegroups: map[string][]string{},
		EKSUnavailable: eksUnavailable,
	}
	if err := json.Unmarshal(usedProfiles, &result.UsedProfiles); err != nil {
		return profileUsageResult{}, time.Time{}, fmt.Errorf("decode used profiles: %w", err)
	}
	if err := json.Unmarshal(roleNodegroups, &result.RoleNodegroups); err != nil {
		return profileUsageResult{}, time.Time{}, fmt.Errorf("decode role nodegroups: %w", err)
	}
	// warnings 允许为空数组；解码失败只降级成无警告，不让整条证据作废。
	if len(warnings) > 0 {
		_ = json.Unmarshal(warnings, &result.Warnings)
	}
	return result, collectedAt, nil
}

// StoredProfileUsageResolver 让待清理清单优先读数据库快照，快照不存在时
// 实时回源（并顺手把结果落库，下次就不用再等 AWS 了）。
//
// 命中快照时追加一条「证据来自数据库」的警告——它会流进清理报告的 rule_gaps，
// 提醒操作者证据的新鲜度取决于最近一次同步，真正删除前仍应按证据复核。
type StoredProfileUsageResolver struct {
	store  *ProfileUsageEvidenceStore
	live   ProfileUsageResolver
	logger *slog.Logger
}

// NewStoredProfileUsageResolver 组合数据库快照与实时解析器；两者都必须非空。
// logger 可为 nil（退回 slog.Default）。
func NewStoredProfileUsageResolver(
	store *ProfileUsageEvidenceStore,
	live ProfileUsageResolver,
	logger *slog.Logger,
) (*StoredProfileUsageResolver, error) {
	if store == nil {
		return nil, errors.New("profile usage evidence store must not be nil")
	}
	if live == nil {
		return nil, errors.New("live profile usage resolver must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &StoredProfileUsageResolver{store: store, live: live, logger: logger}, nil
}

// ResolveUsedProfiles 实现 ProfileUsageResolver。
func (resolver *StoredProfileUsageResolver) ResolveUsedProfiles(
	ctx context.Context,
	awsAccountID string,
) (profileUsageResult, error) {
	stored, collectedAt, err := resolver.store.Load(ctx, awsAccountID)
	if err == nil {
		age := time.Since(collectedAt).Round(time.Minute)
		resolver.logger.Info("profile usage evidence served from database snapshot",
			"aws_account_id", awsAccountID, "age", age.String())
		stored.Warnings = append(stored.Warnings, fmt.Sprintf(
			"EKS/EC2 在用性证据来自数据库快照（%s 前同步采集）；执行删除前请按证据复核，重新同步后证据会更新。", age))
		return stored, nil
	}
	if !errors.Is(err, ErrProfileUsageEvidenceNotFound) {
		resolver.logger.Warn("load profile usage evidence failed; falling back to live resolution",
			"aws_account_id", awsAccountID, "error", err)
	}
	result, liveErr := resolver.live.ResolveUsedProfiles(ctx, awsAccountID)
	if liveErr == nil {
		// 回源成功就落库，作为缓存穿透的回写；失败只记日志，不影响本次返回。
		if saveErr := resolver.store.Save(ctx, awsAccountID, result); saveErr != nil {
			resolver.logger.Warn("persist profile usage evidence after live resolve failed",
				"aws_account_id", awsAccountID, "error", saveErr)
		} else {
			resolver.logger.Info("profile usage evidence persisted after live resolve",
				"aws_account_id", awsAccountID)
		}
	} else {
		resolver.logger.Warn("live profile usage resolution failed",
			"aws_account_id", awsAccountID, "error", liveErr)
	}
	return result, liveErr
}
