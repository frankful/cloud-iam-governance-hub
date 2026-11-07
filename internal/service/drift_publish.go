package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// 发布冲突升级为独立发现（phase4-drift-design.md §6 场景 B）。
//
// 归属门禁拒绝覆盖一份「别人拥有」的文件时，过去只把文件名塞进台账的 error
// 字符串——那是一个字符串，不是一条待办。冲突本身是有人必须处理的事实：「这
// 个文件归谁」。因此把它写成 source=publish 的 file_conflict 发现，与 inventory
// / ci 共用同一张表、同一个页面、同一套处置。
//
// 生命周期：发布因冲突失败 → 记录（同一文件重复冲突只增 occurrences）；该账号
// 任一次发布成功 → 关闭全部 publish 类发现（成功即证明没有冲突）。

// BaselinePublishDriftRecorder 是发布服务对漂移台账的最小依赖。用接口而不是
// 具体类型，是为了让发布测试不必拉起整套判定依赖。
type BaselinePublishDriftRecorder interface {
	// RecordPublishConflicts 记录一次因归属冲突导致的发布失败。
	RecordPublishConflicts(ctx context.Context, publicationID int64, files []string, detail string) error
	// ResolvePublishConflicts 在发布成功后关闭该账号的 publish 类发现。
	ResolvePublishConflicts(ctx context.Context, publicationID int64) error
}

// SetDriftRecorder 装配漂移台账。未装配时发布行为不变（只记 error 字符串）。
func (service *BaselinePublishService) SetDriftRecorder(recorder BaselinePublishDriftRecorder) {
	service.drift = recorder
}

// RecordPublishConflicts 把冲突文件写成发现。files 是 bundle 内的 file key
// （不含 .tf），与预约表、声明表同一口径——三张表必须能按同一个键对上。
func (service *DriftService) RecordPublishConflicts(
	ctx context.Context, publicationID int64, files []string, detail string,
) error {
	keys := make([]string, 0, len(files))
	seen := map[string]bool{}
	for _, file := range files {
		file = strings.TrimSpace(strings.TrimSuffix(file, ".tf"))
		if file == "" || seen[file] {
			continue
		}
		seen[file] = true
		keys = append(keys, file)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)

	var accountDBID int64
	var awsAccountID string
	err := service.db.QueryRowContext(ctx, `
		SELECT account_id, aws_account_id FROM iam_baseline_publication WHERE id = $1`,
		publicationID).Scan(&accountDBID, &awsAccountID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %d", ErrBaselinePublicationNotFound, publicationID)
	}
	if err != nil {
		return fmt.Errorf("load publication %d for publish conflicts: %w", publicationID, err)
	}

	existing, err := service.loadOpenFindings(ctx, accountDBID, DriftSourcePublish)
	if err != nil {
		return err
	}
	publication := publicationID
	recorded := make([]DriftFinding, 0, len(keys))
	for _, fileKey := range keys {
		finding := DriftFinding{
			AccountDBID:           accountDBID,
			AWSAccountID:          awsAccountID,
			Source:                DriftSourcePublish,
			ResourceKey:           "file:" + fileKey,
			Kind:                  "file",
			FileKey:               fileKey,
			ChangeType:            DriftChangeFileConflict,
			Severity:              DriftSeverityMedium,
			Fields:                []DriftFieldDiff{{Field: "owner", Declared: "baseline", Live: "another publisher"}},
			Summary:               strings.TrimSpace(detail),
			SummaryCode:           DriftSummaryFileConflict,
			SummaryParams:         map[string]string{"file": fileKey + ".tf"},
			BaselinePublicationID: &publication,
		}
		if previous, ok := existing[finding.driftKey()]; ok {
			if err := service.updateFinding(ctx, previous.ID, finding, DriftStatusOpen); err != nil {
				return err
			}
			continue
		}
		id, err := service.insertFinding(ctx, finding, DriftStatusOpen)
		if err != nil {
			return err
		}
		finding.ID = id
		recorded = append(recorded, finding)
	}
	service.logger.Info("publish conflicts recorded as drift findings",
		"publication_id", publicationID, "account_id", accountDBID,
		"conflicts", len(keys), "surfaced", len(recorded))
	if len(recorded) > 0 {
		service.notify("drift.publish_conflict", recorded)
	}
	return nil
}

// ResolvePublishConflicts 关闭该账号的 publish 类发现。发布成功说明归属门禁
// 已经通过：要么文件已经归基线，要么不再冲突。
func (service *DriftService) ResolvePublishConflicts(
	ctx context.Context, publicationID int64,
) error {
	result, err := service.db.ExecContext(ctx, `
		UPDATE iam_drift_finding
		SET resolved_at = NOW(), resolved_by = 'auto', updated_at = NOW()
		WHERE source = $2 AND resolved_at IS NULL
		  AND account_id = (SELECT account_id FROM iam_baseline_publication WHERE id = $1)`,
		publicationID, DriftSourcePublish)
	if err != nil {
		return fmt.Errorf("resolve publish conflicts for publication %d: %w", publicationID, err)
	}
	if affected, _ := result.RowsAffected(); affected > 0 {
		service.logger.Info("publish conflicts auto-resolved after successful publication",
			"publication_id", publicationID, "resolved", affected)
	}
	return nil
}
