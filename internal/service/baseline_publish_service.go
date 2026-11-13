package service

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 基线发布（B3，D4/D7 拍板口径）：
//   - 幂等键 = 账号 + 库存快照 run（aws_sync_run.id）：同 run 不重复发布，
//     新 run 才允许再发，不允许人工重跑覆盖旧分支；
//   - 方案 A：一账号一短分支一 PR（baseline/<aws账号>/<run>），代码合入 main、
//     apply 只在 main；同一 run 的多账号可显式聚合成一个 PR（批量选项）；
//   - 分支保留是配置开关（keepBranch），默认合并即删由仓库侧维护，开启则保留
//     分支作审计痕迹（保留模式需配套清理策略）；
//   - 归属感知的更新门禁在发布侧落实（0027）：目标文件在 main 上已存在时，
//     内容与 main 相同则跳过；内容不同但在本账号既往发布的文件清单里（基线
//     拥有）允许更新；否则拒绝——基线永远不覆盖别人的文件。分支内容 upsert
//     幂等，重试安全。
const (
	BaselinePublicationStatusPublishing = "PUBLISHING"
	BaselinePublicationStatusPublished  = "PUBLISHED"
	BaselinePublicationStatusFailed     = "FAILED"

	// BaselinePublishTimeout 覆盖构建（分钟级）+ 一次整树文件核对 + 一次
	// 批量提交 + 开 PR。文件数不再线性放大请求数（见 commitBranchFiles），
	// 但保留宽上限兜住大仓库与网络抖动。
	BaselinePublishTimeout = 30 * time.Minute

	// BaselinePublicationStaleAfter 超过该时长仍处于 PUBLISHING 的发布视为被
	// 中断（进程重启、panic），由 SweepStale 收尾成 FAILED。
	BaselinePublicationStaleAfter = time.Hour
)

var (
	// ErrBaselinePublicationNotFound 表示发布记录不存在，handler 返回 404。
	ErrBaselinePublicationNotFound = errors.New("baseline publication not found")

	// ErrBaselineNoSyncRun 表示账号没有成功的库存同步，无法确定幂等键；
	// 发布前必须先同步。
	ErrBaselineNoSyncRun = errors.New("no successful inventory sync run for account")

	// ErrBaselineFilesExistInRepo 表示 bundle 里有文件已存在于 main——基线
	// 不覆盖已有文件，需先处理归属（纳管/工单）再发布。
	ErrBaselineFilesExistInRepo = errors.New("baseline files already exist on the target branch")

	// ErrBaselineSnapshotMoved 表示台账钉住的库存快照与 Build 实际读取的
	// 最新成功同步不是同一个 run（Create → Run 之间又跑了一次同步）。此时
	// 声明的审计键会指向旧快照、内容却来自新快照，事后回溯对不上，因此
	// 拒绝继续，让操作者重发以钉住新快照。
	ErrBaselineSnapshotMoved = errors.New("inventory snapshot moved between publication and build")
)

// ensureSnapshotPinned 校验「台账钉住的 sync run」与「bundle 实际构建所用
// 的 run」一致。Build 内部自取最新成功 run（见 baseline_candidate_service
// 的 refreshLatestSyncRun），与 Create 时刻可能差一次同步。
// report.LatestSyncRunID 为 0 表示构建未查询到快照信息（兼容路径），不阻断。
func ensureSnapshotPinned(pinnedRunID int64, report *BaselineBundleReport) error {
	if report == nil || report.LatestSyncRunID == 0 || pinnedRunID == 0 {
		return nil
	}
	if report.LatestSyncRunID != pinnedRunID {
		return fmt.Errorf("%w: pinned run %d, build used %d; retry the publish to pin the new snapshot",
			ErrBaselineSnapshotMoved, pinnedRunID, report.LatestSyncRunID)
	}
	return nil
}

// BaselinePublicationSupersede 是重发时归档的被替代 PR 记录：同 run 重发
// 是原地 UPDATE，旧 PR 的编号、URL、终态若不归档就彻底丢失。
type BaselinePublicationSupersede struct {
	RemoteRequestNumber string     `json:"remote_request_number"`
	PullRequestURL      string     `json:"pull_request_url"`
	Status              string     `json:"status"`
	PublishedAt         *time.Time `json:"published_at,omitempty"`
	SupersededAt        time.Time  `json:"superseded_at"`
}

// BaselinePublication 是 iam_baseline_publication 的一行：逐账号的幂等与
// 审计单位。聚合模式下多行共享同一分支与 PR。
type BaselinePublication struct {
	ID                  int64      `json:"id"`
	AccountDBID         int64      `json:"account_db_id"`
	AWSAccountID        string     `json:"aws_account_id"`
	SyncRunID           int64      `json:"sync_run_id"`
	Status              string     `json:"status"`
	Branch              string     `json:"branch"`
	PullRequestURL      string     `json:"pull_request_url,omitempty"`
	RemoteRequestNumber string     `json:"remote_request_number,omitempty"`
	RepoDirectory       string     `json:"repo_directory,omitempty"`
	FileCount           int        `json:"file_count"`
	ContentSHA256       string     `json:"content_sha256,omitempty"`
	KeepBranch          bool       `json:"keep_branch"`
	Error               string     `json:"error,omitempty"`
	RequestedBy         string     `json:"requested_by,omitempty"`
	PublishedAt         *time.Time `json:"published_at,omitempty"`
	// AppliedAt 非空表示 CI 回调确认过 terraform apply 成功。合并 ≠ 生效，
	// 这一列是「已应用」的唯一证据。
	AppliedAt        *time.Time            `json:"applied_at,omitempty"`
	AppliedCommitSHA string                `json:"applied_commit_sha,omitempty"`
	AppliedCIURL     string                `json:"applied_ci_url,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
	Counts           map[string]int        `json:"counts,omitempty"`
	Issues           []BaselineBundleIssue `json:"issues,omitempty"`
	// Superseded 是本行历史上被重发替代的 PR 记录（新在前）。
	Superseded []BaselinePublicationSupersede `json:"superseded,omitempty"`
	// InFlight 表示这条记录是「已经有人在跑的发布」而不是刚创建的台账。
	// 幂等命中时 Create 返回既有行，调用方不能据此再 spawn 一个 Run——
	// Run 的领取不是原子的，重复驱动会让同一个 PR 被提交两次。不落库。
	InFlight bool `json:"in_flight,omitempty"`
}

// BaselineBranchPublisher 是发布服务对代码托管侧的最小依赖；GitHubPublisher
// 实现它，测试用 fake。
type BaselineBranchPublisher interface {
	PublishBranch(ctx context.Context, req BranchPublishRequest) (*TicketPublishResult, error)
}

// BaselineBundleBuilder 抽象 bundle 构建，测试可替换。
type BaselineBundleBuilder interface {
	Build(ctx context.Context, accountRef string) (*BaselineBundleReport, error)
}

// batchItem 是聚合发布时的中间装载结构：台账行 + 构建产物。
type batchItem struct {
	id          int64
	accountDBID int64
	awsAccount  string
	syncRunID   int64
	report      *BaselineBundleReport
	// publish 是通过门禁后真正要提交的文件子集（无变化的跳过）。
	publish []BaselineBundleFile
	// unchanged 是与 main 内容相同而跳过的文件数。
	unchanged int
	// deferred 是被在途变更占用、本轮让路的文件（PR 描述里可见）。
	deferred []PublishReservationConflict
}

// BaselinePublishService 把一次基线 bundle 发布成分支 + PR，并落台账。
type BaselinePublishService struct {
	db         *sql.DB
	bundles    BaselineBundleBuilder
	publisher  BaselineBranchPublisher
	keepBranch bool
	logger     *slog.Logger
	// reservations 是文件级发布预约（phase4 §4）：基线对被工单占用的
	// 文件让路（deferred），其余照发。失败/supersede 时释放。
	reservations *PublishReservationService
	// declarations 落声明快照（phase4 §5）：发布成功即更新漂移基准。
	declarations *BaselineDeclarationService
	// drift 把归属冲突写成 source=publish 的发现（phase4 §6 场景 B）。未装配
	// 时冲突仍只落在台账 error 里，行为与之前一致。
	drift BaselinePublishDriftRecorder
}

func NewBaselinePublishService(
	db *sql.DB,
	bundles BaselineBundleBuilder,
	publisher BaselineBranchPublisher,
	keepBranch bool,
	logger *slog.Logger,
) *BaselinePublishService {
	if logger == nil {
		logger = slog.Default()
	}
	reservations, reservationErr := NewPublishReservationService(db, logger)
	if reservationErr != nil {
		// db 已由调用方保证非 nil，这里只为满足构造函数约定。
		reservations = nil
	}
	declarations, declarationErr := NewBaselineDeclarationService(db, logger)
	if declarationErr != nil {
		declarations = nil
	}
	return &BaselinePublishService{
		db:           db,
		bundles:      bundles,
		publisher:    publisher,
		keepBranch:   keepBranch,
		logger:       logger,
		reservations: reservations,
		declarations: declarations,
	}
}

// BaselineBatchOutcome 是批量发布里单个账号的结果。
type BaselineBatchOutcome struct {
	AccountRef       string               `json:"account_ref"`
	Publication      *BaselinePublication `json:"publication,omitempty"`
	AlreadyPublished bool                 `json:"already_published,omitempty"`
	Error            string               `json:"error,omitempty"`
}

// Create 解析账号与最新成功快照 run，做幂等检查后落一条 PUBLISHING 台账。
// alreadyPublished=true 表示同 run 已发布过，直接返回既有记录（幂等跳过）；
// inFlight=true 表示同 run 已有发布在进行中。执行由调用方用 Run 驱动。
func (service *BaselinePublishService) Create(
	ctx context.Context,
	accountRef string,
	requestedBy string,
) (publication *BaselinePublication, alreadyPublished bool, err error) {
	ref := strings.TrimSpace(accountRef)
	if ref == "" {
		return nil, false, errors.New("account reference must not be empty")
	}
	var accountDBID int64
	var awsAccountID string
	if err := service.db.QueryRowContext(ctx, `
		SELECT id, account_id FROM aws_account
		WHERE account_id = $1 OR id::text = $1
		LIMIT 1`, ref,
	).Scan(&accountDBID, &awsAccountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, fmt.Errorf("%w: %q", ErrBaselineAccountNotFound, ref)
		}
		return nil, false, fmt.Errorf("load AWS account %q: %w", ref, err)
	}

	var syncRunID int64
	if err := service.db.QueryRowContext(ctx, `
		SELECT id FROM aws_sync_run
		WHERE aws_account_id = $1 AND status = 'SUCCEEDED'
		ORDER BY id DESC
		LIMIT 1`, awsAccountID,
	).Scan(&syncRunID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, fmt.Errorf(
				"%w %s: publish pins the baseline to an inventory snapshot run; sync first",
				ErrBaselineNoSyncRun, awsAccountID)
		}
		return nil, false, fmt.Errorf("load latest sync run for %s: %w", awsAccountID, err)
	}

	existing, err := service.loadByAccountRun(ctx, accountDBID, syncRunID)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		switch existing.Status {
		case BaselinePublicationStatusPublished:
			// 幂等键命中：同 run 已发布（PR 仍开放），不重发、不覆盖旧分支（D4）。
			// PR 合并后台账由合并感知改为 MERGED，走到下面的重发分支。
			return existing, true, nil
		case BaselinePublicationStatusPublishing:
			// 已有发布在进行，返回它让前端继续轮询。InFlight 告诉调用方
			// 「别再 spawn 一次 Run」——这条不是新建的台账。
			existing.InFlight = true
			return existing, false, nil
		}
		// FAILED / MERGED / CLOSED：允许同 run 重发。MERGED 重发是合法运维动作
		// （纳管逻辑修复后重发同一快照，增量 PR 只带新文件）；CLOSED 同 FAILED
		// 可重试。行是 (账号, run) 唯一键，重发原地覆盖当前 PR 记录——但旧 PR
		// 先归档进 superseded，审计链不丢。
		if _, err := service.db.ExecContext(ctx, `
			UPDATE iam_baseline_publication
			SET status = $2, error = '', requested_by = $3, keep_branch = $4,
			    superseded = superseded || $5::jsonb,
			    updated_at = NOW()
			WHERE id = $1`,
			existing.ID, BaselinePublicationStatusPublishing,
			strings.TrimSpace(requestedBy), service.keepBranch,
			supersedeArchive(existing),
		); err != nil {
			return nil, false, fmt.Errorf("reset failed baseline publication %d: %w", existing.ID, err)
		}
		// 旧 PR 的归属预约随归档一并释放：重发会重新预约，别让旧记录占着。
		if service.reservations != nil {
			if err := service.reservations.ReleasePublication(ctx, existing.ID); err != nil {
				service.logger.Warn("failed to release superseded baseline reservations",
					"publication_id", existing.ID, "error", err)
			}
		}
		existing.Status = BaselinePublicationStatusPublishing
		existing.Error = ""
		existing.RequestedBy = strings.TrimSpace(requestedBy)
		existing.KeepBranch = service.keepBranch
		return existing, false, nil
	}

	publication = &BaselinePublication{
		AccountDBID:  accountDBID,
		AWSAccountID: awsAccountID,
		SyncRunID:    syncRunID,
		Status:       BaselinePublicationStatusPublishing,
		Branch:       fmt.Sprintf("baseline/%s/%d", awsAccountID, syncRunID),
		KeepBranch:   service.keepBranch,
		RequestedBy:  strings.TrimSpace(requestedBy),
	}
	if err := service.db.QueryRowContext(ctx, `
		INSERT INTO iam_baseline_publication
		       (account_id, aws_account_id, sync_run_id, status, branch,
		        keep_branch, requested_by)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
		RETURNING id, created_at, updated_at`,
		accountDBID, awsAccountID, syncRunID, publication.Status,
		publication.Branch, publication.KeepBranch, publication.RequestedBy,
	).Scan(&publication.ID, &publication.CreatedAt, &publication.UpdatedAt); err != nil {
		// 并发同账号发布：唯一约束兜底，重新读既有行。
		if existing, loadErr := service.loadByAccountRun(ctx, accountDBID, syncRunID); loadErr == nil && existing != nil {
			return existing, existing.Status == BaselinePublicationStatusPublished, nil
		}
		return nil, false, fmt.Errorf("create baseline publication: %w", err)
	}
	return publication, false, nil
}

// CreateBatch 批量创建台账：逐账号走 Create（含幂等检查），单账号失败记入
// outcome 不中断整批。聚合分支名在 RunBatch 阶段才确定——创建阶段每个账号
// 仍按各自的「账号 + run」幂等键落行。
func (service *BaselinePublishService) CreateBatch(
	ctx context.Context,
	accountRefs []string,
	requestedBy string,
) ([]BaselineBatchOutcome, error) {
	outcomes := make([]BaselineBatchOutcome, 0, len(accountRefs))
	for _, ref := range accountRefs {
		publication, alreadyPublished, err := service.Create(ctx, ref, requestedBy)
		outcome := BaselineBatchOutcome{
			AccountRef:       strings.TrimSpace(ref),
			Publication:      publication,
			AlreadyPublished: alreadyPublished,
		}
		if err != nil {
			outcome.Error = sanitizeErrorMessage(err.Error())
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// Run 领取一条 PUBLISHING 台账并完成「构建 → 发布 → 记账」。与调用方上下文
// 解耦（后台 goroutine 传入 Background），自带超时。
func (service *BaselinePublishService) Run(ctx context.Context, publicationID int64) error {
	runCtx, cancel := context.WithTimeout(context.Background(), BaselinePublishTimeout)
	defer cancel()

	var accountDBID int64
	var awsAccountID, branch string
	var syncRunID int64
	err := service.db.QueryRowContext(runCtx, `
		UPDATE iam_baseline_publication
		SET updated_at = NOW()
		WHERE id = $1 AND status = $2
		RETURNING account_id, aws_account_id, sync_run_id, branch`,
		publicationID, BaselinePublicationStatusPublishing,
	).Scan(&accountDBID, &awsAccountID, &syncRunID, &branch)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %d", ErrBaselinePublicationNotFound, publicationID)
	}
	if err != nil {
		return fmt.Errorf("claim baseline publication %d: %w", publicationID, err)
	}

	report, err := service.bundles.Build(runCtx, fmt.Sprintf("%d", accountDBID))
	if err != nil {
		return service.finishFailed(runCtx, publicationID, err)
	}
	if report.AWSAccountID != awsAccountID {
		return service.finishFailed(runCtx, publicationID, fmt.Errorf(
			"bundle account %s does not match publication account %s",
			report.AWSAccountID, awsAccountID))
	}
	if report.RepoDirectory == "" {
		return service.finishFailed(runCtx, publicationID, errors.New(
			"terraform path is not configured; cannot compute repository file names"))
	}
	if err := ensureSnapshotPinned(syncRunID, report); err != nil {
		return service.finishFailed(runCtx, publicationID, err)
	}
	// 归属感知门禁（0027）：PR 合并后基线文件常驻 main，「存在即拒绝」会让
	// 同账号的再次发布必然失败。按内容与归属分三类处置：
	//   与 main 内容相同                 -> 跳过（无变化，不重复提交）
	//   内容不同但在既往发布的文件清单里 -> 允许更新（基线拥有的文件）
	//   内容不同且不在清单               -> 拒绝（保护工单/手工文件归属）
	owned, err := service.baselineOwnedFiles(runCtx, accountDBID, publicationID)
	if err != nil {
		return service.finishFailed(runCtx, publicationID, err)
	}
	plan := classifyBaselineFiles(report, owned)
	conflicts, unchanged, publishFiles := plan.Conflicts, plan.Unchanged, plan.Publish
	if len(conflicts) > 0 {
		cause := fmt.Errorf(
			"%w: %d file(s) not owned by baseline: %s", ErrBaselineFilesExistInRepo,
			len(conflicts), strings.Join(conflicts, ", "))
		// 冲突文件同时也是「归谁」这个待办：先写进发现表，再记发布失败。
		service.recordConflictFindings(runCtx, publicationID, conflicts, cause)
		return service.finishFailed(runCtx, publicationID, cause)
	}
	report.Counts["files-unchanged"] = unchanged
	report.Counts["files-to-publish"] = len(publishFiles)

	if len(publishFiles) == 0 {
		// 基线与 main 完全一致：GitHub 不接受无 diff 的 PR，直接记 PUBLISHED。
		// files 清单照记，作为归属证据。
		return service.finishUnchanged(runCtx, publicationID, accountDBID, syncRunID, awsAccountID, report, unchanged)
	}

	files := make([]BranchPublishFile, 0, len(publishFiles))
	for _, file := range publishFiles {
		files = append(files, BranchPublishFile{
			FileName: path.Join(report.RepoDirectory, file.FileName),
			Content:  file.Content,
		})
	}

	// 文件级发布预约（phase4 §4.1）：基线只被文件相交的在途发布源挡住，
	// 相交文件让路（deferred，PR 描述与台账都可见），其余照发——不做
	// 账号级冻结。nil 安全：未装配时跳过（与 phase4 之前行为一致）。
	publishFiles, deferredConflicts, err := service.reserveBaselineFiles(
		runCtx, report, accountDBID, publicationID, publishFiles)
	if err != nil {
		return service.finishFailed(runCtx, publicationID, err)
	}
	if len(deferredConflicts) > 0 {
		files = files[:0]
		for _, file := range publishFiles {
			files = append(files, BranchPublishFile{
				FileName: path.Join(report.RepoDirectory, file.FileName),
				Content:  file.Content,
			})
		}
		service.logger.Info("baseline publication deferred conflicting files",
			"publication_id", publicationID,
			"deferred", len(deferredConflicts),
			"publishing", len(publishFiles),
		)
	}

	// 让路后无文件可发：不开 PR（GitHub 不接受空 diff），记 PUBLISHED 并
	// 把 deferred 原因写进台账，让「为什么没发」可见。
	if len(files) == 0 {
		if len(deferredConflicts) > 0 {
			return service.finishFullyDeferred(runCtx, publicationID, report, unchanged)
		}
		// 基线与 main 完全一致：GitHub 不接受无 diff 的 PR，直接记 PUBLISHED。
		// files 清单照记，作为归属证据。
		return service.finishUnchanged(runCtx, publicationID, accountDBID, syncRunID, awsAccountID, report, unchanged)
	}

	body := fmt.Sprintf("Generated baseline bundle for AWS account %s.\n\n"+
		"Idempotency key: account %s + inventory run %d.\n"+
		"Content SHA-256: %s\nFiles: %d (resources + relationships, with import blocks).\n\n"+
		"Merge to main, then run terraform plan/apply on main only.",
		awsAccountID, awsAccountID, syncRunID, report.ContentSHA256, len(files))
	body = appendDeferredSection(body, deferredConflicts)
	result, err := service.publisher.PublishBranch(runCtx, BranchPublishRequest{
		Branch: branch,
		// Baseline-Publications trailer（phase4 §8）：CI 合并后从 commit
		// message 解析 publication id，回调 apply-result 记账 applied_at。
		// 放标题而不是描述：GitLab 默认 merge commit 只带 MR 标题，描述不进
		// commit message，push pipeline 里读不到。
		Title: fmt.Sprintf("IAM baseline for account %s (inventory run %d) — Baseline-Publications: %d",
			awsAccountID, syncRunID, publicationID),
		Body:  body,
		Files: files,
	})
	if err != nil {
		return service.finishFailed(runCtx, publicationID, err)
	}

	hash, err := hex.DecodeString(report.ContentSHA256)
	if err != nil || len(hash) != 32 {
		return service.finishFailed(runCtx, publicationID, fmt.Errorf(
			"bundle content hash %q is not a 32-byte hex digest", report.ContentSHA256))
	}
	counts, _ := encodeBaselineCounts(report.Counts)
	issues, _ := encodeBaselineIssues(report.Issues)
	manifest, err := encodeBaselineFiles(report.Files)
	if err != nil {
		return service.finishFailed(runCtx, publicationID, err)
	}
	if _, err := service.db.ExecContext(runCtx, `
		UPDATE iam_baseline_publication
		SET status = $2, pull_request_url = $3, remote_request_number = $4,
		    repo_directory = $5, file_count = $6, content_sha256 = $7,
		    counts = $8::jsonb, issues = $9::jsonb, files = $10::jsonb,
		    published_at = NOW(), updated_at = NOW()
		WHERE id = $1`,
		publicationID, BaselinePublicationStatusPublished,
		result.URL, result.RemoteRequestNumber, report.RepoDirectory,
		len(files), hash, counts, issues, manifest,
	); err != nil {
		return fmt.Errorf("complete baseline publication %d: %w", publicationID, err)
	}
	service.logger.Info("baseline publication published",
		"publication_id", publicationID,
		"account", awsAccountID,
		"sync_run", syncRunID,
		"branch", branch,
		"pull_request", result.URL,
		"files", len(files),
		"content_sha256", report.ContentSHA256,
	)
	service.resolveConflictFindings(runCtx, publicationID)
	service.recordDeclarations(runCtx, publicationID, accountDBID, syncRunID, awsAccountID, report)
	return nil
}

// RunBatch 驱动一批台账。aggregate=false 时逐账号独立发布（各自分支与 PR）；
// aggregate=true 时全部文件进同一分支（baseline/batch/<时间戳>）开一个 PR，
// 各行共享分支与 PR。单账号失败不拖垮其他账号，各自落 FAILED。
func (service *BaselinePublishService) RunBatch(
	ctx context.Context,
	publicationIDs []int64,
	aggregate bool,
) error {
	runCtx, cancel := context.WithTimeout(context.Background(), BaselinePublishTimeout)
	defer cancel()

	if !aggregate {
		var firstErr error
		for _, id := range publicationIDs {
			if err := service.Run(context.Background(), id); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	branch := fmt.Sprintf("baseline/batch/%s", time.Now().UTC().Format("20060102-150405"))
	items := make([]batchItem, 0, len(publicationIDs))
	// settled 记录「已收尾但没有文件进 PR」的行（无变化 / 全部让路 / 已被
	// 并发处理），failed 记录失败行。全部落空时据此给出准确原因：没有可
	// 发布的账号不等于发布失败。
	settled, failed := 0, 0
	for _, id := range publicationIDs {
		item := batchItem{id: id}
		err := service.db.QueryRowContext(runCtx, `
			UPDATE iam_baseline_publication
			SET branch = $2, updated_at = NOW()
			WHERE id = $1 AND status = $3
			RETURNING account_id, aws_account_id, sync_run_id`,
			id, branch, BaselinePublicationStatusPublishing,
		).Scan(&item.accountDBID, &item.awsAccount, &item.syncRunID)
		if errors.Is(err, sql.ErrNoRows) {
			settled++
			continue // 已被并发处理或不存在
		}
		if err != nil {
			return fmt.Errorf("claim baseline publication %d for batch: %w", id, err)
		}
		report, buildErr := service.bundles.Build(runCtx, fmt.Sprintf("%d", item.accountDBID))
		if buildErr != nil {
			_ = service.finishFailed(runCtx, id, buildErr)
			failed++
			continue
		}
		if report.RepoDirectory == "" {
			_ = service.finishFailed(runCtx, id, errors.New(
				"terraform path is not configured; cannot compute repository file names"))
			failed++
			continue
		}
		if pinnedErr := ensureSnapshotPinned(item.syncRunID, report); pinnedErr != nil {
			_ = service.finishFailed(runCtx, id, pinnedErr)
			failed++
			continue
		}
		owned, ownedErr := service.baselineOwnedFiles(runCtx, item.accountDBID, id)
		if ownedErr != nil {
			_ = service.finishFailed(runCtx, id, ownedErr)
			failed++
			continue
		}
		plan := classifyBaselineFiles(report, owned)
		conflicts := plan.Conflicts
		item.publish = plan.Publish
		item.unchanged = plan.Unchanged
		if len(conflicts) > 0 {
			cause := fmt.Errorf(
				"%w: %d file(s) not owned by baseline: %s", ErrBaselineFilesExistInRepo,
				len(conflicts), strings.Join(conflicts, ", "))
			service.recordConflictFindings(runCtx, id, conflicts, cause)
			_ = service.finishFailed(runCtx, id, cause)
			failed++
			continue
		}
		// 批量发布同样走文件级预约（phase4 §4.1）：聚合 PR 不能绕过预约，
		// 被在途变更占用的文件逐账号让路，其余文件照常进批量 PR。
		var deferred []PublishReservationConflict
		item.publish, deferred, buildErr = service.reserveBaselineFiles(
			runCtx, report, item.accountDBID, id, item.publish)
		if buildErr != nil {
			_ = service.finishFailed(runCtx, id, buildErr)
			failed++
			continue
		}
		item.deferred = deferred
		if len(item.publish) == 0 {
			if len(deferred) > 0 {
				// 全部让路：单独记 PUBLISHED + file_count=0，不进批量 PR。
				_ = service.finishFullyDeferred(runCtx, id, report, item.unchanged)
				settled++
				continue
			}
			// 该账号基线与 main 完全一致：单独记 PUBLISHED，不进批量 PR。
			_ = service.finishUnchanged(runCtx, id, item.accountDBID, item.syncRunID, item.awsAccount, report, item.unchanged)
			settled++
			continue
		}
		report.Counts["files-unchanged"] = item.unchanged
		report.Counts["files-to-publish"] = len(item.publish)
		item.report = report
		items = append(items, item)
	}
	if len(items) == 0 {
		// 没有任何账号需要进 PR。若各行都已收尾（无变化 / 全部让路 / 已被
		// 并发处理），这不是失败，只是「本轮无可发布内容」；只有全部失败
		// 或什么都没查到才向上报错——错误信息与台账保持一致的口径。
		if settled > 0 {
			service.logger.Info("baseline batch had nothing to publish",
				"settled", settled, "failed", failed)
			return nil
		}
		if failed > 0 {
			return fmt.Errorf("batch baseline publication failed for %d account(s)", failed)
		}
		return errors.New("batch baseline publication has no publishable accounts")
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].awsAccount < items[j].awsAccount
	})

	files := make([]BranchPublishFile, 0, 256)
	for _, item := range items {
		for _, file := range item.publish {
			files = append(files, BranchPublishFile{
				FileName: path.Join(item.report.RepoDirectory, file.FileName),
				Content:  file.Content,
			})
		}
	}
	result, err := service.publisher.PublishBranch(runCtx, BranchPublishRequest{
		// 与单账号发布同一 trailer 约定：批量 PR 对应多个 publication id，
		// CI 逐个回调 apply-result（幂等）。
		Branch: branch,
		Title: fmt.Sprintf("IAM baseline batch: %d accounts — Baseline-Publications: %s",
			len(items), baselinePublicationIDs(items)),
		Body: appendDeferredSection(fmt.Sprintf(
			"Generated baseline bundles for %d AWS accounts in one batch.\n\n"+
				"Accounts: %s\nFiles: %d (resources + relationships, with import blocks).\n\n"+
				"Merge to main, then run terraform plan/apply on main only.",
			len(items), accountList(items), len(files)),
			collectBatchDeferred(items)),
		Files: files,
	})
	if err != nil {
		// 整批共享一个 PR：发布失败把所有未完成行落 FAILED。
		for _, item := range items {
			_ = service.finishFailed(runCtx, item.id, fmt.Errorf("batch publish: %w", err))
		}
		return err
	}
	for _, item := range items {
		hash, hashErr := hex.DecodeString(item.report.ContentSHA256)
		if hashErr != nil || len(hash) != 32 {
			_ = service.finishFailed(runCtx, item.id, fmt.Errorf(
				"bundle content hash %q is not a 32-byte hex digest", item.report.ContentSHA256))
			continue
		}
		counts, _ := encodeBaselineCounts(item.report.Counts)
		issues, _ := encodeBaselineIssues(item.report.Issues)
		manifest, manifestErr := encodeBaselineFiles(item.report.Files)
		if manifestErr != nil {
			service.logger.Error("failed to encode baseline manifest",
				"publication_id", item.id, "error", manifestErr)
		}
		if _, err := service.db.ExecContext(runCtx, `
			UPDATE iam_baseline_publication
			SET status = $2, pull_request_url = $3, remote_request_number = $4,
			    repo_directory = $5, file_count = $6, content_sha256 = $7,
			    counts = $8::jsonb, issues = $9::jsonb, files = $10::jsonb,
			    published_at = NOW(), updated_at = NOW()
			WHERE id = $1`,
			item.id, BaselinePublicationStatusPublished,
			result.URL, result.RemoteRequestNumber, item.report.RepoDirectory,
			len(item.publish), hash, counts, issues, manifest,
		); err != nil {
			service.logger.Error("failed to record baseline batch publication",
				"publication_id", item.id, "error", err)
			continue
		}
		service.resolveConflictFindings(runCtx, item.id)
		service.recordDeclarations(runCtx, item.id, item.accountDBID,
			item.syncRunID, item.awsAccount, item.report)
	}
	service.logger.Info("baseline batch publication published",
		"branch", branch,
		"accounts", len(items),
		"pull_request", result.URL,
		"files", len(files),
	)
	return nil
}

// reserveBaselineFiles 为本次要写的文件预约发布权，并把被其他开放变更
// 占用的文件从待发布集合中剔除（让路，deferred）。让路的文件同时从
// report.Files（归属清单证据）里剔除：它们没写进仓库，记进去会让下次
// 发布误判为「基线拥有」。未装配预约服务（单测/降级部署）时原样返回。
func (service *BaselinePublishService) reserveBaselineFiles(
	ctx context.Context,
	report *BaselineBundleReport,
	accountDBID, publicationID int64,
	publishFiles []BaselineBundleFile,
) ([]BaselineBundleFile, []PublishReservationConflict, error) {
	if service.reservations == nil || len(publishFiles) == 0 {
		return publishFiles, nil, nil
	}
	keys := make([]string, 0, len(publishFiles))
	for _, file := range publishFiles {
		keys = append(keys, strings.TrimSuffix(file.FileName, ".tf"))
	}
	conflicts, err := service.reservations.ReserveForPublication(
		ctx, accountDBID, publicationID, keys)
	if err != nil {
		return nil, nil, err
	}
	if len(conflicts) == 0 {
		return publishFiles, nil, nil
	}
	held := make(map[string]PublishReservationConflict, len(conflicts))
	for _, conflict := range conflicts {
		held[conflict.FileKey] = conflict
	}
	stillPublishable := make([]BaselineBundleFile, 0, len(publishFiles))
	deferred := make([]PublishReservationConflict, 0, len(conflicts))
	for _, file := range publishFiles {
		key := strings.TrimSuffix(file.FileName, ".tf")
		conflict, isHeld := held[key]
		if !isHeld {
			stillPublishable = append(stillPublishable, file)
			continue
		}
		deferred = append(deferred, conflict)
		report.Issues = append(report.Issues, BaselineBundleIssue{
			Kind:      "deferred",
			Value:     key,
			Resources: file.Sources,
			Detail:    "文件被其他开放变更占用，本轮让路：" + conflict.Describe(),
			// 占用说明本身是 Describe() 拼的（含文件 key 与持有方），
			// 措辞留在前端，服务端只给参数。
			DetailCode:   IssueDetailDeferred,
			DetailParams: map[string]string{"holder": conflict.Describe()},
		})
		report.Counts["deferred"]++
	}
	scopedFiles := make([]BaselineBundleFile, 0, len(report.Files))
	for _, bundleFile := range report.Files {
		if _, isHeld := held[strings.TrimSuffix(bundleFile.FileName, ".tf")]; !isHeld {
			scopedFiles = append(scopedFiles, bundleFile)
		}
	}
	report.Files = scopedFiles
	return stillPublishable, deferred, nil
}

// appendDeferredSection 把让路清单写进 PR 描述：让路是文件级的让步，不是
// 静默跳过，评审人必须能看见「这些文件为什么不在这个 PR 里」。
func appendDeferredSection(body string, deferred []PublishReservationConflict) string {
	if len(deferred) == 0 {
		return body
	}
	body += "\n\nDeferred files (held by another open change, not in this PR):"
	for _, conflict := range deferred {
		body += "\n- " + conflict.Describe()
	}
	return body
}

// finishFullyDeferred 记录「全部文件让路」的发布：不开空 PR，台账记
// PUBLISHED + file_count=0 + deferred issue。归属清单为空——本次没写
// 任何文件，不能主张它们归基线。
func (service *BaselinePublishService) finishFullyDeferred(
	ctx context.Context,
	publicationID int64,
	report *BaselineBundleReport,
	unchanged int,
) error {
	manifest, manifestErr := encodeBaselineFiles(nil)
	if manifestErr != nil {
		return service.finishFailed(ctx, publicationID, manifestErr)
	}
	counts, _ := encodeBaselineCounts(report.Counts)
	issues, _ := encodeBaselineIssues(report.Issues)
	hash, hashErr := hex.DecodeString(report.ContentSHA256)
	if hashErr != nil || len(hash) != 32 {
		return service.finishFailed(ctx, publicationID, fmt.Errorf(
			"bundle content hash %q is not a 32-byte hex digest", report.ContentSHA256))
	}
	if _, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET status = $2, repo_directory = $3, file_count = 0, content_sha256 = $4,
		    counts = $5::jsonb, issues = $6::jsonb, files = $7::jsonb,
		    published_at = NOW(), updated_at = NOW()
		WHERE id = $1`,
		publicationID, BaselinePublicationStatusPublished, report.RepoDirectory,
		hash, counts, issues, manifest,
	); err != nil {
		return fmt.Errorf("record fully-deferred baseline publication %d: %w", publicationID, err)
	}
	service.resolveConflictFindings(ctx, publicationID)
	service.logger.Info("baseline publication fully deferred; nothing published",
		"publication_id", publicationID,
		"deferred", report.Counts["deferred"],
		"unchanged", unchanged,
	)
	return nil
}

func (service *BaselinePublishService) finishFailed(
	ctx context.Context,
	publicationID int64,
	cause error,
) error {
	message := sanitizeErrorMessage(cause.Error())
	if _, execErr := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET status = $2, error = $3, updated_at = NOW()
		WHERE id = $1`,
		publicationID, BaselinePublicationStatusFailed, message,
	); execErr != nil {
		service.logger.Error("failed to record baseline publication failure",
			"publication_id", publicationID, "cause", cause, "record_error", execErr)
	}
	// 失败即释放预约（phase4 §4.2）：占着文件不放会挡住工单变更。
	if service.reservations != nil {
		if err := service.reservations.ReleasePublication(ctx, publicationID); err != nil {
			service.logger.Warn("failed to release baseline publish reservations",
				"publication_id", publicationID, "error", err)
		}
	}
	return fmt.Errorf("baseline publication %d failed: %w", publicationID, cause)
}

// baselineFilePlan 是「这份 bundle 与 main、归属台账」比对后的三分结果：
// 无变化（内容已一致）、可发布（新文件或基线拥有的文件）、冲突（内容不同
// 且不在归属清单里，发布必须拒绝）。
type baselineFilePlan struct {
	Unchanged int
	Publish   []BaselineBundleFile
	Conflicts []string
}

// classifyBaselineFiles 被 Run、RunBatch、发布前预览三处共用。预览如果自己
// 抄一遍判定，迟早与真实发布走偏——而预览存在的全部意义就是「说真话」，
// 让用户在点确认前知道这次要推几个文件、几个已经在 main 上了（台账 C10）。
func classifyBaselineFiles(
	report *BaselineBundleReport, owned map[string]struct{},
) baselineFilePlan {
	plan := baselineFilePlan{Publish: make([]BaselineBundleFile, 0, len(report.Files))}
	for _, file := range report.Files {
		if file.ExistsInRepo == nil || !*file.ExistsInRepo {
			plan.Publish = append(plan.Publish, file)
			continue
		}
		if file.RepoBlobSHA != "" && file.RepoBlobSHA == gitBlobSHA(file.Content) {
			plan.Unchanged++
			continue
		}
		if _, isOwned := owned[file.FileName]; isOwned {
			plan.Publish = append(plan.Publish, file)
			continue
		}
		plan.Conflicts = append(plan.Conflicts, file.FileName)
	}
	if len(plan.Conflicts) > 0 {
		// 冲突清单要进错误信息与发现表：顺序稳定才便于比对与人工核对。
		sort.Strings(plan.Conflicts)
	}
	return plan
}

// BaselinePublishPreview 是「点发布之前」的差异概览（台账 C10）。不含预约
// 判定：预约会写入台账，预览不能有副作用，所以 Deferred 只可能在真实发布
// 时出现，页面文案不能承诺「一定会推 N 个」。
type BaselinePublishPreview struct {
	AccountDBID   int64    `json:"account_id"`
	AWSAccountID  string   `json:"aws_account_id"`
	SyncRunID     int64    `json:"sync_run_id"`
	RepoDirectory string   `json:"repo_directory"`
	Files         int      `json:"files"`
	Unchanged     int      `json:"unchanged"`
	ToPublish     int      `json:"to_publish"`
	Conflicts     []string `json:"conflicts"`
}

// Preview 构建 bundle 并与 main 比对，但不落任何台账。构建本身会读库存并
// 生成全部文件（Build 顺带填好 ExistsInRepo/RepoBlobSHA），所以这里不需要
// 额外的远端往返。
func (service *BaselinePublishService) Preview(
	ctx context.Context, accountRef string,
) (BaselinePublishPreview, error) {
	preview := BaselinePublishPreview{Conflicts: []string{}}
	ref := strings.TrimSpace(accountRef)
	if ref == "" {
		return preview, errors.New("account reference must not be empty")
	}
	if err := service.db.QueryRowContext(ctx, `
		SELECT id, account_id FROM aws_account
		WHERE account_id = $1 OR id::text = $1
		LIMIT 1`, ref,
	).Scan(&preview.AccountDBID, &preview.AWSAccountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return preview, fmt.Errorf("%w: %q", ErrBaselineAccountNotFound, ref)
		}
		return preview, fmt.Errorf("load AWS account %q: %w", ref, err)
	}
	if err := service.db.QueryRowContext(ctx, `
		SELECT id FROM aws_sync_run
		WHERE aws_account_id = $1 AND status = 'SUCCEEDED'
		ORDER BY id DESC
		LIMIT 1`, preview.AWSAccountID,
	).Scan(&preview.SyncRunID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return preview, fmt.Errorf(
				"%w %s: preview pins the baseline to an inventory snapshot run; sync first",
				ErrBaselineNoSyncRun, preview.AWSAccountID)
		}
		return preview, fmt.Errorf("load latest sync run for %s: %w", preview.AWSAccountID, err)
	}
	report, err := service.bundles.Build(ctx, fmt.Sprintf("%d", preview.AccountDBID))
	if err != nil {
		return preview, err
	}
	if report.RepoDirectory == "" {
		return preview, errors.New(
			"terraform path is not configured; cannot compute repository file names")
	}
	owned, err := service.baselineOwnedFiles(ctx, preview.AccountDBID, 0)
	if err != nil {
		return preview, err
	}
	plan := classifyBaselineFiles(report, owned)
	preview.RepoDirectory = report.RepoDirectory
	preview.Files = len(report.Files)
	preview.Unchanged = plan.Unchanged
	preview.ToPublish = len(plan.Publish)
	if len(plan.Conflicts) > 0 {
		preview.Conflicts = plan.Conflicts
	}
	return preview, nil
}

// finishUnchanged 把「基线与 main 完全一致」的发布记为 PUBLISHED：没有 diff
// 就没有 PR（GitHub 不接受空 PR），但归属清单照记——下次发布仍可据此更新。
//
// 声明快照同样要落（台账 C9）：无变化发布的语义是「这些文件的内容就是
// main 现在的样子」，正是一次完整的声明确认。早先这里只 UPDATE 台账不写
// 声明，导致「首次全量发布恰好无变化」的账号 publication=PUBLISHED、
// declarations=0，漂移判定按「未纳管」整账号跳过——明明纳管了却永远不被
// 检测，而且页面上看不出来。
func (service *BaselinePublishService) finishUnchanged(
	ctx context.Context,
	publicationID, accountDBID, syncRunID int64,
	awsAccountID string,
	report *BaselineBundleReport,
	unchanged int,
) error {
	hash, err := hex.DecodeString(report.ContentSHA256)
	if err != nil || len(hash) != 32 {
		return service.finishFailed(ctx, publicationID, fmt.Errorf(
			"bundle content hash %q is not a 32-byte hex digest", report.ContentSHA256))
	}
	counts, _ := encodeBaselineCounts(report.Counts)
	issues, _ := encodeBaselineIssues(report.Issues)
	manifest, manifestErr := encodeBaselineFiles(report.Files)
	if manifestErr != nil {
		return service.finishFailed(ctx, publicationID, manifestErr)
	}
	if _, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET status = $2, repo_directory = $3, file_count = $4, content_sha256 = $5,
		    counts = $6::jsonb, issues = $7::jsonb, files = $8::jsonb,
		    published_at = NOW(), updated_at = NOW()
		WHERE id = $1`,
		publicationID, BaselinePublicationStatusPublished, report.RepoDirectory,
		unchanged, hash, counts, issues, manifest,
	); err != nil {
		service.logger.Error("failed to record unchanged baseline publication",
			"publication_id", publicationID, "error", err)
		return fmt.Errorf("complete unchanged baseline publication %d: %w", publicationID, err)
	}
	// 声明必须在 UPDATE 之后落：RecordDeclarations 会按本批文件作废旧声明，
	// 而 finishUnchanged 的权威事实是「台账已 PUBLISHED」，顺序反了会在
	// UPDATE 失败时留下「声明已换、台账还是 PUBLISHING」的错位。
	service.recordDeclarations(ctx, publicationID, accountDBID, syncRunID, awsAccountID, report)
	service.resolveConflictFindings(ctx, publicationID)
	service.logger.Info("baseline publication unchanged; main already up to date",
		"publication_id", publicationID, "files", unchanged)
	return nil
}

// recordConflictFindings 记录归属冲突。失败只告警：冲突本身已经让发布
// 失败了，不能因为写发现表失败把错误信息换成另一个。
func (service *BaselinePublishService) recordConflictFindings(
	ctx context.Context, publicationID int64, files []string, cause error,
) {
	if service.drift == nil {
		return
	}
	if err := service.drift.RecordPublishConflicts(ctx, publicationID, files, cause.Error()); err != nil {
		service.logger.Warn("failed to record publish conflicts as drift findings",
			"publication_id", publicationID, "error", err)
	}
}

// resolveConflictFindings 在发布成功后关闭该账号的 publish 类发现。
func (service *BaselinePublishService) resolveConflictFindings(
	ctx context.Context, publicationID int64,
) {
	if service.drift == nil {
		return
	}
	if err := service.drift.ResolvePublishConflicts(ctx, publicationID); err != nil {
		service.logger.Warn("failed to resolve publish conflict findings",
			"publication_id", publicationID, "error", err)
	}
}

// recordDeclarations 落声明快照（phase4 §5）：只记本次真正声明过的文件
// （让路的文件不在 report.Files 里），发布与「无变化」两条路径都要记——
// 无变化同样是一次声明确认。失败只告警不阻断：发布已经成功，把已合并的
// PR 报成失败更糟；基准滞后会在下一次发布会话里被覆盖。
func (service *BaselinePublishService) recordDeclarations(
	ctx context.Context,
	publicationID, accountDBID, syncRunID int64,
	awsAccountID string,
	report *BaselineBundleReport,
) {
	if service.declarations == nil || len(report.Declarations) == 0 || len(report.Files) == 0 {
		return
	}
	publication := publicationID
	target := DeclarationTarget{
		AccountDBID:   accountDBID,
		AWSAccountID:  awsAccountID,
		SyncRunID:     syncRunID,
		PublicationID: &publication,
		Declarations:  report.Declarations,
	}
	if err := service.declarations.RecordDeclarations(ctx, target, report.Files); err != nil {
		service.logger.Error("failed to record baseline declarations",
			"publication_id", publicationID, "account_id", accountDBID, "error", err)
	}
}

// gitBlobSHA 计算内容的 git blob SHA-1（"blob <len>\0" + content），与
// GitHub contents API 返回的文件 sha 同一算法，无需下载内容即可比对。
func gitBlobSHA(content string) string {
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d", len(content))
	hash.Write([]byte{0})
	io.WriteString(hash, content)
	return hex.EncodeToString(hash.Sum(nil))
}

// baselineOwnedFiles 汇总本账号既往发布记录（PUBLISHED：PR 仍开放；MERGED：
// 已合并进 main，文件同样由基线拥有）的文件清单。清单里的文件是基线拥有的：
// 内容变化时允许基线更新它们；不在清单里的同名文件视为工单/手工归属，拒绝
// 覆盖。CLOSED（PR 被拒未合并）不算——那些文件从未落进 main。
func (service *BaselinePublishService) baselineOwnedFiles(
	ctx context.Context,
	accountDBID int64,
	excludePublicationID int64,
) (map[string]struct{}, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT files FROM iam_baseline_publication
		WHERE account_id = $1 AND status IN ($2, $3) AND id <> $4 AND files IS NOT NULL`,
		accountDBID, BaselinePublicationStatusPublished, BaselinePublicationStatusMerged, excludePublicationID)
	if err != nil {
		return nil, fmt.Errorf("load baseline ownership manifests: %w", err)
	}
	defer rows.Close()
	owned := make(map[string]struct{}, 256)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan baseline ownership manifest: %w", err)
		}
		var manifest []struct {
			File string `json:"file"`
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return nil, fmt.Errorf("decode baseline ownership manifest: %w", err)
		}
		for _, entry := range manifest {
			if entry.File != "" {
				owned[entry.File] = struct{}{}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate baseline ownership manifests: %w", err)
	}
	return owned, nil
}

// encodeBaselineFiles 把 bundle 文件清单编码成归属证据 JSONB：
// [{"file": "...", "sha256": "..."}]。file 是不含仓库目录前缀的 bundle 内
// 文件名，与门禁比对口径一致。
func encodeBaselineFiles(files []BaselineBundleFile) ([]byte, error) {
	manifest := make([]map[string]string, 0, len(files))
	for _, file := range files {
		manifest = append(manifest, map[string]string{
			"file":   file.FileName,
			"sha256": file.SHA256,
		})
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode baseline ownership manifest: %w", err)
	}
	return encoded, nil
}

// SweepStale 把被中断的发布收尾成 FAILED。API 启动时调用一次。
func (service *BaselinePublishService) SweepStale(ctx context.Context) (int, error) {
	result, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_publication
		SET status = $1, error = $2, updated_at = NOW()
		WHERE status = $3 AND created_at < NOW() - $4::interval`,
		BaselinePublicationStatusFailed,
		"interrupted: publication never reached a terminal state (restart or crash)",
		BaselinePublicationStatusPublishing,
		fmt.Sprintf("%d seconds", int(BaselinePublicationStaleAfter.Seconds())),
	)
	if err != nil {
		return 0, fmt.Errorf("sweep stale baseline publications: %w", err)
	}
	affected, _ := result.RowsAffected()
	// 基线预约 TTL 回收（phase4 §4.2）：被遗忘的基线 PR 不应永久挡住该
	// 账号的工单变更。工单侧刻意不扫（挂死的预约需要人看）。
	if service.reservations != nil {
		if _, err := service.reservations.SweepBaselineExpired(ctx); err != nil {
			service.logger.Warn("failed to sweep expired baseline reservations", "error", err)
		}
	}
	return int(affected), nil
}

// List 返回账号的发布记录（新在前）。accountRef 支持 12 位 AWS 账号 ID 或
// 平台内部 ID；limit <= 0 取默认 20。
func (service *BaselinePublishService) List(
	ctx context.Context,
	accountRef string,
	limit int,
) ([]BaselinePublication, error) {
	ref := strings.TrimSpace(accountRef)
	if ref == "" {
		return nil, errors.New("account reference must not be empty")
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := service.db.QueryContext(ctx, `
		SELECT p.id, p.account_id, p.aws_account_id, p.sync_run_id, p.status,
		       p.branch, p.pull_request_url, p.remote_request_number,
		       p.repo_directory, p.file_count,
		       COALESCE(ENCODE(p.content_sha256, 'hex'), ''),
		       p.keep_branch, COALESCE(p.error, ''), COALESCE(p.requested_by, ''),
		       p.published_at, p.applied_at, COALESCE(p.applied_commit_sha, ''),
		       COALESCE(p.applied_ci_url, ''),
		       p.created_at, p.updated_at, p.counts, p.issues,
		       p.superseded
		FROM iam_baseline_publication p
		JOIN aws_account a ON a.id = p.account_id
		WHERE a.account_id = $1 OR a.id::text = $1
		ORDER BY p.id DESC
		LIMIT $2`, ref, limit)
	if err != nil {
		return nil, fmt.Errorf("list baseline publications: %w", err)
	}
	defer rows.Close()
	publications := []BaselinePublication{}
	for rows.Next() {
		publication, scanErr := scanBaselinePublication(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		publications = append(publications, *publication)
	}
	return publications, rows.Err()
}

// Get 返回单条发布记录。
func (service *BaselinePublishService) Get(
	ctx context.Context,
	publicationID int64,
) (*BaselinePublication, error) {
	row := service.db.QueryRowContext(ctx, `
		SELECT p.id, p.account_id, p.aws_account_id, p.sync_run_id, p.status,
		       p.branch, p.pull_request_url, p.remote_request_number,
		       p.repo_directory, p.file_count,
		       COALESCE(ENCODE(p.content_sha256, 'hex'), ''),
		       p.keep_branch, COALESCE(p.error, ''), COALESCE(p.requested_by, ''),
		       p.published_at, p.applied_at, COALESCE(p.applied_commit_sha, ''),
		       COALESCE(p.applied_ci_url, ''),
		       p.created_at, p.updated_at, p.counts, p.issues,
		       p.superseded
		FROM iam_baseline_publication p
		WHERE p.id = $1`, publicationID)
	publication, err := scanBaselinePublication(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBaselinePublicationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load baseline publication %d: %w", publicationID, err)
	}
	return publication, nil
}

// supersedeArchive 把将被重发覆盖的当前 PR 记录序列化成单元素 JSON 数组，
// 追加进行 superseded；从未开过 PR 的行（如发布早期失败）返回空数组。
func supersedeArchive(publication *BaselinePublication) string {
	if publication == nil || strings.TrimSpace(publication.RemoteRequestNumber) == "" {
		return "[]"
	}
	record := BaselinePublicationSupersede{
		RemoteRequestNumber: publication.RemoteRequestNumber,
		PullRequestURL:      publication.PullRequestURL,
		Status:              publication.Status,
		PublishedAt:         publication.PublishedAt,
		SupersededAt:        time.Now(),
	}
	encoded, err := json.Marshal([]BaselinePublicationSupersede{record})
	if err != nil {
		// 编码固定结构不会失败；兜底空数组，归档失败不应阻断重发。
		return "[]"
	}
	return string(encoded)
}

func (service *BaselinePublishService) loadByAccountRun(
	ctx context.Context,
	accountDBID, syncRunID int64,
) (*BaselinePublication, error) {
	row := service.db.QueryRowContext(ctx, `
		SELECT p.id, p.account_id, p.aws_account_id, p.sync_run_id, p.status,
		       p.branch, p.pull_request_url, p.remote_request_number,
		       p.repo_directory, p.file_count,
		       COALESCE(ENCODE(p.content_sha256, 'hex'), ''),
		       p.keep_branch, COALESCE(p.error, ''), COALESCE(p.requested_by, ''),
		       p.published_at, p.applied_at, COALESCE(p.applied_commit_sha, ''),
		       COALESCE(p.applied_ci_url, ''),
		       p.created_at, p.updated_at, p.counts, p.issues,
		       p.superseded
		FROM iam_baseline_publication p
		WHERE p.account_id = $1 AND p.sync_run_id = $2`, accountDBID, syncRunID)
	publication, err := scanBaselinePublication(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load baseline publication by account+run: %w", err)
	}
	return publication, nil
}

func scanBaselinePublication(
	row interface {
		Scan(dest ...interface{}) error
	},
) (*BaselinePublication, error) {
	var publication BaselinePublication
	var contentSHA256 string
	var counts, issues, superseded []byte
	var publishedAt, appliedAt sql.NullTime
	if err := row.Scan(
		&publication.ID, &publication.AccountDBID, &publication.AWSAccountID,
		&publication.SyncRunID, &publication.Status, &publication.Branch,
		&publication.PullRequestURL, &publication.RemoteRequestNumber,
		&publication.RepoDirectory, &publication.FileCount, &contentSHA256,
		&publication.KeepBranch, &publication.Error, &publication.RequestedBy,
		&publishedAt, &appliedAt, &publication.AppliedCommitSHA,
		&publication.AppliedCIURL, &publication.CreatedAt, &publication.UpdatedAt,
		&counts, &issues, &superseded,
	); err != nil {
		return nil, err
	}
	if appliedAt.Valid {
		value := appliedAt.Time
		publication.AppliedAt = &value
	}
	publication.ContentSHA256 = contentSHA256
	if publishedAt.Valid {
		value := publishedAt.Time
		publication.PublishedAt = &value
	}
	if len(counts) > 0 {
		publication.Counts = decodeBaselineCounts(counts)
	}
	if len(issues) > 0 {
		publication.Issues = decodeBaselineIssues(issues)
	}
	if len(superseded) > 0 {
		publication.Superseded = decodeBaselineSuperseded(superseded)
	}
	return &publication, nil
}

// encodeBaselineCounts / encodeBaselineIssues / decodeBaselineCounts /
// decodeBaselineIssues 把 bundle 报告的汇总塞进台账 JSONB 列，供前端在发布
// 记录里直接看统计与冲突，不必再回查预览 job。
func encodeBaselineCounts(counts map[string]int) (string, error) {
	if len(counts) == 0 {
		return "{}", nil
	}
	encoded, err := json.Marshal(counts)
	if err != nil {
		return "{}", err
	}
	return string(encoded), nil
}

func encodeBaselineIssues(issues []BaselineBundleIssue) (string, error) {
	if len(issues) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(issues)
	if err != nil {
		return "[]", err
	}
	return string(encoded), nil
}

func decodeBaselineCounts(raw []byte) map[string]int {
	counts := map[string]int{}
	_ = json.Unmarshal(raw, &counts)
	return counts
}

func decodeBaselineIssues(raw []byte) []BaselineBundleIssue {
	issues := []BaselineBundleIssue{}
	_ = json.Unmarshal(raw, &issues)
	return issues
}

func decodeBaselineSuperseded(raw []byte) []BaselinePublicationSupersede {
	records := []BaselinePublicationSupersede{}
	_ = json.Unmarshal(raw, &records)
	return records
}

// accountList 渲染批量 PR 描述里的账号清单（已排序）。
func accountList(items []batchItem) string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.awsAccount)
	}
	return strings.Join(names, ", ")
}

// baselinePublicationIDs 渲染 MR 标题里的 Baseline-Publications trailer
// 值（逗号分隔的 publication id，顺序与 accountList 一致）。CI 在合并后
// 从 commit message 解析这串 id，逐个回调 apply-result。
func baselinePublicationIDs(items []batchItem) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, strconv.FormatInt(item.id, 10))
	}
	return strings.Join(ids, ",")
}

// collectBatchDeferred 汇总批量发布里各账号的让路文件。文件 key 只在账号
// 内唯一，这里前缀 AWS 账号号，避免跨账号同名文件在同一个 PR 描述里看起来
// 重复或混淆。
func collectBatchDeferred(items []batchItem) []PublishReservationConflict {
	var deferred []PublishReservationConflict
	for _, item := range items {
		for _, conflict := range item.deferred {
			conflict.FileKey = item.awsAccount + "/" + conflict.FileKey
			deferred = append(deferred, conflict)
		}
	}
	return deferred
}
