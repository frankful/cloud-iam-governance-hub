package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
)

// PR 合并感知：发布台账停在 PUBLISHED 只说明分支/PR 已开出，PR 是否被合并
// 平台不知道，远端 baseline/* 分支也无人清理（GitHub 没有 RemoveSourceBranch
// 等价物）。合并感知服务周期性查询开放过的 PR：MERGED → 台账记 MERGED 并按
// keep_branch 决定是否删远端分支；CLOSED（未合并被拒）→ 记 CLOSED 留审计；
// 仍 OPEN / 查不到 → 跳过等下一轮。查询走 githost 中立接口，GitHub 与 GitLab
// 共用一套逻辑。

// BaselinePublicationStatusMerged 表示发布 PR 已合并进目标分支。
const BaselinePublicationStatusMerged = "MERGED"

// BaselinePublicationStatusClosed 表示发布 PR 被关闭且未合并（发布被拒绝）。
const BaselinePublicationStatusClosed = "CLOSED"

// BaselineMergeStatusClient 查询远端 PR/MR 状态。githost.GitHost 满足它，
// 测试用 fake。
type BaselineMergeStatusClient interface {
	FetchMergeRequest(ctx context.Context, project string, number string) (*githost.MergeRequestStatus, error)
}

// BaselineBranchCleaner 删除远端分支。GitHubPublisher 与 GitLabSDKPublisher
// 都实现它；为 nil 时（发布器不可用）只更新台账不删分支。
type BaselineBranchCleaner interface {
	DeleteBranch(ctx context.Context, branch string) error
}

// BaselinePublicationMergeService 把远端 PR 终态同步回发布台账。
type BaselinePublicationMergeService struct {
	db      *sql.DB
	host    BaselineMergeStatusClient
	project string
	cleaner BaselineBranchCleaner
	logger  *slog.Logger
	// reservations 是文件级发布预约（phase4 §4.2）：PR 合并转 MERGED 态
	// 等同步确认，PR 关闭未合并直接释放。nil 安全。
	reservations *PublishReservationService
	// declarations 是声明快照（phase4 §4.6）：PR 关闭未合并说明这次发布
	// 从未进 main，声明必须作废。nil 安全。
	declarations *BaselineDeclarationService
}

func NewBaselinePublicationMergeService(
	db *sql.DB,
	host BaselineMergeStatusClient,
	project string,
	cleaner BaselineBranchCleaner,
	logger *slog.Logger,
) *BaselinePublicationMergeService {
	if logger == nil {
		logger = slog.Default()
	}
	reservations, reservationErr := NewPublishReservationService(db, logger)
	if reservationErr != nil {
		reservations = nil
	}
	declarations, declarationErr := NewBaselineDeclarationService(db, logger)
	if declarationErr != nil {
		declarations = nil
	}
	return &BaselinePublicationMergeService{
		db: db, host: host, project: project, cleaner: cleaner, logger: logger,
		reservations: reservations, declarations: declarations,
	}
}

// ReconcileMerged 同步一轮。返回值：进入 MERGED 的条数、删除的分支数。
// 单条失败记录日志继续，不让一条 PR 查询失败拖垮整轮。
func (service *BaselinePublicationMergeService) ReconcileMerged(
	ctx context.Context,
) (merged int, deleted int, err error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT id, branch, remote_request_number, keep_branch
		FROM iam_baseline_publication
		WHERE status = $1 AND COALESCE(remote_request_number, '') <> ''`,
		BaselinePublicationStatusPublished,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("list published baseline publications: %w", err)
	}
	type candidate struct {
		id     int64
		branch string
		number string
		keep   bool
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.branch, &item.number, &item.keep); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("scan baseline publication for merge check: %w", err)
		}
		candidates = append(candidates, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate baseline publications for merge check: %w", err)
	}

	for _, item := range candidates {
		status, fetchErr := service.host.FetchMergeRequest(ctx, service.project, item.number)
		if fetchErr != nil {
			service.logger.Warn("failed to fetch baseline publication PR state",
				"publication_id", item.id, "number", item.number, "error", fetchErr)
			continue
		}
		if status == nil {
			continue // PR 已被远端删除，无从判断；保留台账原状
		}
		switch status.State {
		case githost.MergeStateMerged:
			if err := service.markMerged(ctx, item.id, status.MergeCommit); err != nil {
				service.logger.Error("failed to mark baseline publication merged",
					"publication_id", item.id, "error", err)
				continue
			}
			merged++
			if item.keep {
				continue
			}
			if service.cleaner == nil {
				continue
			}
			if err := service.cleaner.DeleteBranch(ctx, item.branch); err != nil {
				service.logger.Warn("failed to delete merged baseline branch",
					"publication_id", item.id, "branch", item.branch, "error", err)
				continue
			}
			deleted++
			service.logger.Info("deleted merged baseline branch",
				"publication_id", item.id, "branch", item.branch)
		case githost.MergeStateClosed:
			if err := service.markClosed(ctx, item.id); err != nil {
				service.logger.Warn("failed to mark baseline publication closed",
					"publication_id", item.id, "error", err)
				continue
			}
			service.logger.Info("baseline publication PR closed without merge",
				"publication_id", item.id, "branch", item.branch)
		}
		// MergeStateOpen / MergeStateUnknown：等下一轮。
	}
	return merged, deleted, nil
}

func (service *BaselinePublicationMergeService) markMerged(
	ctx context.Context, publicationID int64, mergeCommit string,
) error {
	result, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET status = $2, updated_at = NOW()
		WHERE id = $1 AND status = $3`,
		publicationID, BaselinePublicationStatusMerged, BaselinePublicationStatusPublished,
	)
	if err != nil {
		return fmt.Errorf("mark baseline publication %d merged: %w", publicationID, err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return errors.New("publication already left PUBLISHED state")
	}
	// 基线 PR 合并：预约转 MERGED 态（phase4 §4.2），等该账号下一次成功
	// 同步确认清单已反映变更后再释放。失败只记日志。
	if service.reservations != nil {
		if err := service.reservations.MarkPublicationMerged(ctx, publicationID); err != nil {
			service.logger.Warn("failed to mark baseline reservations merged",
				"publication_id", publicationID, "error", err)
		}
	}
	return nil
}

func (service *BaselinePublicationMergeService) markClosed(
	ctx context.Context, publicationID int64,
) error {
	// 先撤声明再改状态（phase4 §4.8）：这次发布从未进 main，main 上还是上
	// 一个声明对应的内容，不撤就会拿一份没落地的意图当漂移基准，把线上正确
	// 的资源全报成被改坏。作废顺手恢复被它取代的上一条有效声明，不留空洞。
	//
	// 顺序不能反：状态一旦改成 CLOSED，reconcile 下一轮就不再扫这条记录了，
	// 撤声明失败会变成永久的幽灵基准。先撤后改，失败就让下次轮询整体重试
	// ——作废是幂等的（第二次查不到当前声明，什么都不做）。
	if service.declarations != nil {
		if err := service.declarations.VoidForPublication(ctx, publicationID); err != nil {
			return fmt.Errorf("void declarations of closed baseline publication %d: %w",
				publicationID, err)
		}
	}
	result, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET status = $2, error = $3, updated_at = NOW()
		WHERE id = $1 AND status = $4`,
		publicationID, BaselinePublicationStatusClosed,
		"pull request closed without merging", BaselinePublicationStatusPublished,
	)
	if err != nil {
		return fmt.Errorf("mark baseline publication %d closed: %w", publicationID, err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return errors.New("publication already left PUBLISHED state")
	}
	// 预约同步释放，防止「基线以为归它管、main 上根本没有」的幽灵归属。
	if service.reservations != nil {
		if err := service.reservations.ReleasePublication(ctx, publicationID); err != nil {
			service.logger.Warn("failed to release closed baseline reservations",
				"publication_id", publicationID, "error", err)
		}
	}
	return nil
}

// BaselineMergeReconcileInterval 合并感知的默认轮询间隔。PR 从合并到台账
// 反映有至多一个周期的延迟，发布不是时效敏感操作，5 分钟足够。
const BaselineMergeReconcileInterval = 5 * time.Minute

// StartMergeReconcileLoop 周期执行 ReconcileMerged，直到 ctx 取消。挂在
// sync-worker（后台进程）而不是 API：合并感知依赖远端查询，放 worker 与
// 采集同生命周期，重启互不影响。首次延迟一个周期，避开启动高峰。
func StartMergeReconcileLoop(
	ctx context.Context,
	service *BaselinePublicationMergeService,
	interval time.Duration,
	logger *slog.Logger,
) {
	if interval <= 0 {
		interval = BaselineMergeReconcileInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconcileCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				merged, deleted, err := service.ReconcileMerged(reconcileCtx)
				cancel()
				if err != nil {
					logger.Warn("baseline merge reconcile failed", "error", err)
					continue
				}
				if merged > 0 || deleted > 0 {
					logger.Info("baseline merge reconcile completed",
						"merged", merged, "branches_deleted", deleted)
				}
			}
		}
	}()
}
