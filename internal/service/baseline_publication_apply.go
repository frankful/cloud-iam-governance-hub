package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
)

// 基线发布的 apply 回调（phase4-drift-design.md §3 第 5 层、§8）。
//
// 「PR 合并」只证明文件进了 main；「apply 成功」才证明线上真的变了。没有这
// 条确认，平台只能靠「合并后一段时间没新差异」去猜，猜错就把 apply 失败记成
// 干净。CI 在 apply 后带上 publication_id 回调，这三列就是落点。
//
// 语义刻意保守：
//   - 只有 PUBLISHED / MERGED 的发布可以标记已应用（PUBLISHING 还没开完 PR，
//     FAILED 没有可应用的东西）；
//   - 首次写入生效（`applied_at IS NULL`），重复回调幂等——CI 重试不该改
//     已有证据；
//   - failed 只记日志，不动状态：apply 失败不改变「文件已合并」这个事实。

// BaselineApplyResult 是 CI 对一次基线发布 apply 的回报。
type BaselineApplyResult struct {
	// Status 只接受 succeeded / failed。
	Status string
	// CommitSHA 是实际应用的 commit（通常是 main 上的合并提交）。
	CommitSHA string
	// CIURL 指向流水线，供排障。
	CIURL string
	// Note 是自由文本备注。
	Note string
}

const (
	BaselineApplyStatusSucceeded = "succeeded"
	BaselineApplyStatusFailed    = "failed"
)

// RecordApplyResult 处理一次 apply 回调。返回最新的发布行（含 applied_*）。
func (service *BaselinePublishService) RecordApplyResult(
	ctx context.Context, publicationID int64, actor string, result BaselineApplyResult,
) (*BaselinePublication, error) {
	if publicationID <= 0 {
		return nil, apperr.Validation("publication id must be a positive integer")
	}
	if result.Status != BaselineApplyStatusSucceeded && result.Status != BaselineApplyStatusFailed {
		return nil, apperr.Validationf(
			"status must be %s or %s", BaselineApplyStatusSucceeded, BaselineApplyStatusFailed)
	}
	publication, err := service.Get(ctx, publicationID)
	if err != nil {
		return nil, err
	}
	repositoryURL := strings.TrimSpace(publication.PullRequestURL)
	if result.Status == BaselineApplyStatusFailed {
		service.logger.Warn("baseline apply reported failure; publication state unchanged",
			"publication_id", publicationID,
			"actor", actor,
			"commit_sha", result.CommitSHA,
			"ci_url", result.CIURL,
			"note", result.Note,
			"pull_request", repositoryURL,
		)
		return publication, nil
	}
	switch publication.Status {
	case BaselinePublicationStatusPublished, BaselinePublicationStatusMerged:
	default:
		return nil, apperr.Validationf(
			"publication %d is %s; only a published or merged baseline can be marked applied",
			publicationID, publication.Status)
	}

	if _, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET applied_at = COALESCE(applied_at, NOW()),
		    applied_commit_sha = COALESCE(applied_commit_sha, NULLIF($2, '')),
		    applied_ci_url = COALESCE(applied_ci_url, NULLIF($3, '')),
		    updated_at = NOW()
		WHERE id = $1`,
		publicationID, strings.TrimSpace(result.CommitSHA), strings.TrimSpace(result.CIURL),
	); err != nil {
		return nil, fmt.Errorf("record apply result for publication %d: %w", publicationID, err)
	}
	applied, err := service.Get(ctx, publicationID)
	if err != nil {
		return nil, err
	}
	service.logger.Info("baseline publication marked applied by CI callback",
		"publication_id", publicationID,
		"actor", actor,
		"commit_sha", result.CommitSHA,
		"ci_url", result.CIURL)
	return applied, nil
}
