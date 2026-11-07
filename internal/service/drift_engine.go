package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// DriftService 是漂移判定的执行者（phase4-drift-design.md §3）。
//
// 判定基准是 iam_baseline_declaration（已声明的意图），比对对象是同一次
// 同步结束后的库存——两者之间隔着 apply 与 state 两层，所以不能拿 main
// 上的文件内容直接比。判定在同步成功后按账号执行一次，不做常驻轮询：
// 库存没有变化时重复判定只会得到同样的结论。
type DriftService struct {
	db           *sql.DB
	declarations *BaselineDeclarationService
	notifier     *DriftNotifier
	logger       *slog.Logger
}

// DriftServiceOption 让外围出口（webhook）按需装配：没有配置时判定照跑，
// 只是不往外推。
type DriftServiceOption func(*DriftService)

// WithDriftNotifier 设置漂移出口。nil 视为未配置。
func WithDriftNotifier(notifier *DriftNotifier) DriftServiceOption {
	return func(service *DriftService) {
		service.notifier = notifier
	}
}

func NewDriftService(
	db *sql.DB,
	declarations *BaselineDeclarationService,
	logger *slog.Logger,
	options ...DriftServiceOption,
) (*DriftService, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	if declarations == nil {
		return nil, errors.New("baseline declaration service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	service := &DriftService{db: db, declarations: declarations, logger: logger}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service, nil
}

// DriftPendingWindow 是「工单已合并、apply 结果未确认」的宽限期。
//
// 窗口内的差异记 PENDING（可能只是 apply 还在路上，报出来是噪音）；超出
// 窗口仍存在，说明 apply 大概率没发生、也没人报回来——这时不能再保持沉默，
// 必须让发现继续走稳定窗口（SUSPECT → OPEN）。没有这个上限，无 CI 回调、
// 又没人手工报 apply-result 的账号会永久停在 PENDING——即「PENDING 永久
// 滞留」漏报通道，主循环与子资源分支都必须关掉它。
const DriftPendingWindow = 24 * time.Hour

// notify 把本轮新增/升级的发现推给 webhook。失败不影响判定。
func (service *DriftService) notify(event string, findings []DriftFinding) {
	if service.notifier == nil || len(findings) == 0 {
		return
	}
	now := time.Now().UTC()
	normalized := make([]DriftFinding, len(findings))
	for index, finding := range findings {
		// 候选结构里没有时间与空字段：推出去之前补齐，接收方才能把消息
		// 和库里那条发现对上（Fields 也必须是 [] 而不是 null）。
		if finding.Fields == nil {
			finding.Fields = []DriftFieldDiff{}
		}
		if finding.FirstSeenAt.IsZero() {
			finding.FirstSeenAt = now
		}
		finding.LastSeenAt = now
		normalized[index] = finding
	}
	service.notifier.Notify(event, normalized)
}

// DriftEvaluation 是一次账号判定的结果。Unmanaged 表示账号没有任何声明：
// 检测范围为空，页面必须显式写「未纳管，不检测」——把空结果当干净是最
// 危险的误读。
type DriftEvaluation struct {
	AccountDBID  int64     `json:"account_id"`
	AWSAccountID string    `json:"aws_account_id"`
	Unmanaged    bool      `json:"unmanaged"`
	Declarations int       `json:"declarations"`
	StaleFiles   int       `json:"stale_files"`
	SkippedFiles int       `json:"skipped_files"`
	Surfaced     int       `json:"surfaced"`
	Promoted     int       `json:"promoted"`
	Resolved     int       `json:"resolved"`
	Pending      int       `json:"pending"`
	OpenFindings int       `json:"open_findings"`
	CheckedAt    time.Time `json:"checked_at"`
}

// driftTicketActivity 是某个文件最近一次成功工单的落地情况，用于第 3 层
// 工单豁免与 PENDING 判定。
type driftTicketActivity struct {
	TicketID    int64
	TicketNo    string
	Status      string
	ApplyResult string
	UpdatedAt   time.Time
}

// EvaluateAccount 对一个账号执行完整判定并落库。幂等：同一份库存重复判定
// 只会让 occurrences 递增，不会产生重复发现。
func (service *DriftService) EvaluateAccount(
	ctx context.Context,
	accountDBID int64,
) (DriftEvaluation, error) {
	evaluation := DriftEvaluation{AccountDBID: accountDBID}
	if accountDBID <= 0 {
		return evaluation, errors.New("drift evaluation requires an account id")
	}
	var awsAccountID string
	err := service.db.QueryRowContext(ctx,
		`SELECT account_id FROM aws_account WHERE id = $1`, accountDBID).Scan(&awsAccountID)
	if errors.Is(err, sql.ErrNoRows) {
		return evaluation, fmt.Errorf("account %d not found", accountDBID)
	}
	if err != nil {
		return evaluation, fmt.Errorf("load account %d: %w", accountDBID, err)
	}
	evaluation.AWSAccountID = awsAccountID

	declarations, err := service.declarations.LoadCurrent(ctx, accountDBID)
	if err != nil {
		return evaluation, err
	}
	evaluation.Declarations = len(declarations)
	if len(declarations) == 0 {
		// 场景 E（§6）：账号从未发布基线 = 检测范围为空。只看心跳，不写
		// 任何发现，也不把「没检测」记成「干净」。
		evaluation.Unmanaged = true
		evaluation.CheckedAt = time.Now().UTC()
		if err := service.recordHeartbeat(ctx, accountDBID, false, nil, nil); err != nil {
			return evaluation, err
		}
		service.logger.Info("drift evaluation skipped: account has no declarations",
			"account_id", accountDBID, "aws_account_id", awsAccountID)
		return evaluation, nil
	}

	live, err := loadDriftLiveSnapshot(ctx, service.db, accountDBID, awsAccountID)
	if err != nil {
		return evaluation, err
	}
	inFlight, err := service.loadInFlightFiles(ctx, accountDBID)
	if err != nil {
		return evaluation, err
	}
	activities, err := service.loadTicketActivities(ctx, accountDBID)
	if err != nil {
		return evaluation, err
	}
	existing, err := service.loadOpenFindings(ctx, accountDBID, DriftSourceInventory)
	if err != nil {
		return evaluation, err
	}

	candidates, audit := buildDriftCandidates(declarations, live, inFlight, activities, time.Now().UTC())
	evaluation.StaleFiles = audit.staleFiles
	evaluation.SkippedFiles = audit.skippedFiles

	seen := make(map[string]bool, len(candidates))
	// surfaced/promoted 的发现攒在一起推一次：一条判定通知一条消息，比
	// 每个发现发一条更接近使用方的用法。
	notifiable := make([]DriftFinding, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.AccountDBID = accountDBID
		candidate.AWSAccountID = awsAccountID
		key := candidate.driftKey()
		seen[key] = true
		status := candidate.Status
		if previous, ok := existing[key]; ok {
			status = nextDriftStatus(previous, candidate.Status)
			if status == DriftStatusOpen && previous.Status != DriftStatusOpen {
				evaluation.Promoted++
				candidate.ID = previous.ID
				notifiable = append(notifiable, candidate)
			}
			if err := service.updateFinding(ctx, previous.ID, candidate, status); err != nil {
				return evaluation, err
			}
		} else {
			id, err := service.insertFinding(ctx, candidate, status)
			if err != nil {
				return evaluation, err
			}
			candidate.ID = id
			evaluation.Surfaced++
			notifiable = append(notifiable, candidate)
		}
		if status == DriftStatusPending || status == DriftStatusPendingRebaseline {
			evaluation.Pending++
		}
	}

	// 第 6 层：本轮没再看到的未解决发现 = 实态已与声明一致，自动恢复。
	for key, previous := range existing {
		if seen[key] {
			continue
		}
		if err := service.resolveFinding(ctx, previous.ID); err != nil {
			return evaluation, err
		}
		evaluation.Resolved++
	}

	openCount, err := service.countOpenFindings(ctx, accountDBID)
	if err != nil {
		return evaluation, err
	}
	evaluation.OpenFindings = openCount
	evaluation.CheckedAt = time.Now().UTC()
	if err := service.recordHeartbeat(ctx, accountDBID, openCount == 0,
		&evaluation.SkippedFiles, &evaluation.StaleFiles); err != nil {
		return evaluation, err
	}
	service.notify("drift.detected", notifiable)
	service.logger.Info("drift evaluation completed",
		"account_id", accountDBID, "aws_account_id", awsAccountID,
		"declarations", evaluation.Declarations,
		"stale_files", evaluation.StaleFiles,
		"surfaced", evaluation.Surfaced, "promoted", evaluation.Promoted,
		"resolved", evaluation.Resolved, "open", openCount)
	return evaluation, nil
}

// nextDriftStatus 实现第 5 层的稳定窗口：首轮 SUSPECT，连续两轮仍在才升
// OPEN，避开 IAM 最终一致性与 apply 后同步的抖动。人工忽略是明确决定，
// 不因为再次检测到就翻回 OPEN——只有资源恢复一致才会被自动关闭。
func nextDriftStatus(previous DriftFinding, candidate string) string {
	if previous.Status == DriftStatusIgnored {
		return DriftStatusIgnored
	}
	if candidate == DriftStatusSuspect && previous.Occurrences >= 1 {
		return DriftStatusOpen
	}
	return candidate
}

// driftAudit 记录判定过程中的旁路计数，便于回答「为什么这个账号只判了
// 3 个资源」。
type driftAudit struct {
	staleFiles   int
	skippedFiles int
}

// buildDriftCandidates 是纯函数：输入声明与库存快照，输出本轮应当存在的
// 发现。不碰数据库，便于用表驱动测试覆盖六层过滤。
func buildDriftCandidates(
	declarations []BaselineDeclaration,
	live driftLiveSnapshot,
	inFlight map[string]bool,
	activities map[string]driftTicketActivity,
	now time.Time,
) ([]DriftFinding, driftAudit) {
	audit := driftAudit{}
	candidates := make([]DriftFinding, 0, 16)

	// 第 1 层：过期声明不参与比对，按文件报 baseline_stale。差异本身不是
	// 漂移——是基准已经不能代表 main 上的内容。
	staleFiles := map[string]string{}
	declared := make([]BaselineDeclaration, 0, len(declarations))
	declaredKeys := map[string]bool{}
	declaredAtByKey := map[string]time.Time{}
	declaredTicketByKey := map[string]int64{}
	for _, declaration := range declarations {
		if declaration.StaleAt != nil {
			if _, ok := staleFiles[declaration.FileKey]; !ok {
				staleFiles[declaration.FileKey] = declaration.StaleReason
			}
			continue
		}
		declared = append(declared, declaration)
		declaredKeys[declaration.ResourceKey] = true
		declaredAtByKey[declaration.ResourceKey] = declaration.declaredAt
		if declaration.TicketID != nil {
			declaredTicketByKey[declaration.ResourceKey] = *declaration.TicketID
		}
	}
	audit.staleFiles = len(staleFiles)
	staleFileKeys := make([]string, 0, len(staleFiles))
	for fileKey := range staleFiles {
		staleFileKeys = append(staleFileKeys, fileKey)
	}
	sort.Strings(staleFileKeys)
	for _, fileKey := range staleFileKeys {
		candidates = append(candidates, DriftFinding{
			Source:                DriftSourceInventory,
			ResourceKey:           "file:" + fileKey,
			Kind:                  "file",
			FileKey:               fileKey,
			ChangeType:            DriftChangeBaselineStale,
			Status:                DriftStatusOpen,
			Fields:                []DriftFieldDiff{{Field: "stale_reason", Declared: "fresh", Live: staleFiles[fileKey]}},
			BaselinePublicationID: declarationPublicationID(declarations, fileKey),
		})
	}

	// 第 4 层：文件被在途发布占用（OPEN/MERGED 预约）= 结论随时会变，本轮
	// 跳过，不产生也不升级发现。
	for _, declaration := range declared {
		if inFlight[declaration.FileKey] {
			audit.skippedFiles++
		}
	}

	for _, declaration := range declared {
		if inFlight[declaration.FileKey] {
			continue
		}
		status := DriftStatusSuspect
		if activity, ok := activities[declaration.FileKey]; ok {
			ownTicket := declaration.TicketID != nil && *declaration.TicketID == activity.TicketID
			// 已合并但 apply 尚未确认：差异可能是 apply 在途，不能算漂移。
			// 宽限只在 DriftPendingWindow 内成立；超窗仍未确认说明没有机器
			// 兜底（A12 的 CI 回调是可选项），必须回到稳定窗口里升 OPEN——
			// 否则真实漂移会被 PENDING 永久压住，即「PENDING 永久滞留」
			// 漏报通道（子资源分支同样适用这套规则）。
			applyUnconfirmed := activity.Status == TicketStatusMerged &&
				activity.ApplyResult != "SUCCEEDED"
			switch {
			case applyUnconfirmed && now.Sub(activity.UpdatedAt) < DriftPendingWindow:
				status = DriftStatusPending
			case applyUnconfirmed:
				// 超窗也不落 PENDING_REBASELINE：那是「基线该更新」的软标签，
				// 说的不是同一件事（这里是 apply 没发生），同样不会告警。
				status = DriftStatusSuspect
			case !ownTicket && activity.UpdatedAt.After(declaration.declaredAt):
				// 第 3 层：声明之后又有别的成功工单改了同一文件——这是获批的
				// 变更，不是漂移；基线该更新了。工单不能豁免自己：它的
				// merge/close 必然晚于自己声明的落库时间，否则工单自有文件上
				// 的真实改动会被永久标成「基线该更新」，而 0027 又禁止对这类
				// 文件重发基线——追认被拒，只剩回滚可用。
				status = DriftStatusPendingRebaseline
			}
		}
		resource, ok := live.get(declaration.ResourceKey)
		if !ok {
			candidates = append(candidates, DriftFinding{
				Source:                DriftSourceInventory,
				ResourceKey:           declaration.ResourceKey,
				Kind:                  declaration.Kind,
				FileKey:               declaration.FileKey,
				ChangeType:            DriftChangeDeclaredMissing,
				Status:                status,
				Fields:                []DriftFieldDiff{},
				BaselinePublicationID: declaration.PublicationID,
			})
			continue
		}
		var declaredAttributes map[string]any
		if len(declaration.Attributes) > 0 {
			_ = json.Unmarshal(declaration.Attributes, &declaredAttributes)
		}
		diffs := compareDeclaredAttributes(declaredAttributes, resource.Attributes)
		if len(diffs) == 0 {
			continue
		}
		candidates = append(candidates, DriftFinding{
			Source:                DriftSourceInventory,
			ResourceKey:           declaration.ResourceKey,
			Kind:                  declaration.Kind,
			FileKey:               declaration.FileKey,
			ChangeType:            DriftChangeAttribute,
			Status:                status,
			Fields:                diffs,
			BaselinePublicationID: declaration.PublicationID,
		})
	}

	// 子资源（挂载 / 成员 / 内联策略）的「未声明多余」：只有父资源确实
	// 被声明过才判定。父资源未纳管时，它的子资源属于「未纳管」范围，本页
	// 不负责——否则一个从没建过基线的账号会瞬间刷出几百条噪音。
	childKeys := make([]string, 0, len(live.resources))
	for key := range live.resources {
		childKeys = append(childKeys, key)
	}
	sort.Strings(childKeys)
	for _, key := range childKeys {
		resource := live.resources[key]
		if declaredKeys[key] || inFlight[fileKeyForLiveChild(resource)] {
			continue
		}
		parentKey, childFileKey := driftChildParent(resource)
		if parentKey == "" || !declaredKeys[parentKey] {
			continue
		}
		status := DriftStatusSuspect
		if activity, ok := activities[childFileKey]; ok {
			// 与主循环同一套豁免规则（层 3 + 层 5），只是声明时间/工单
			// 取父声明的：子资源没有自己的声明行。
			ownTicket := declaredTicketByKey[parentKey] != 0 &&
				declaredTicketByKey[parentKey] == activity.TicketID
			applyUnconfirmed := activity.Status == TicketStatusMerged &&
				activity.ApplyResult != "SUCCEEDED"
			switch {
			case applyUnconfirmed && now.Sub(activity.UpdatedAt) < DriftPendingWindow:
				status = DriftStatusPending
			case applyUnconfirmed:
				// 超窗也不落 PENDING_REBASELINE，理由同主循环：那不是
				// 「基线该更新」，同样不会告警。
				status = DriftStatusSuspect
			case !ownTicket && activity.UpdatedAt.After(declaredAtByKey[parentKey]):
				status = DriftStatusPendingRebaseline
			}
		}
		candidates = append(candidates, DriftFinding{
			Source:      DriftSourceInventory,
			ResourceKey: key,
			Kind:        resource.Kind,
			FileKey:     childFileKey,
			ChangeType:  DriftChangeUndeclaredExtra,
			Status:      status,
			Fields:      []DriftFieldDiff{},
		})
	}

	for index := range candidates {
		candidates[index].Severity = driftSeverity(
			candidates[index].ChangeType, candidates[index].Kind, candidates[index].Fields)
		applyDriftSummary(&candidates[index])
	}
	return candidates, audit
}

// driftChildParent 返回子资源的父资源 key，以及它自己的文件 key（用于
// 在途门禁）。非子资源返回空 key。
func driftChildParent(resource driftLiveResource) (parentKey, fileKey string) {
	switch resource.Kind {
	case "attachment":
		principalKind, _ := resource.Attributes["principal_kind"].(string)
		principal, _ := resource.Attributes["principal"].(string)
		policyName := resource.Name
		return principalKind + ":" + principal,
			AttachmentFileKey(principalKind, principal, policyName)
	case "membership":
		group, _ := resource.Attributes["group"].(string)
		return BaselineKindGroup + ":" + group, MembershipFileKey(group)
	case BaselineKindInlinePolicy:
		ownerKind, _ := resource.Attributes["owner_kind"].(string)
		owner, _ := resource.Attributes["owner"].(string)
		policyName, _ := resource.Attributes["policy"].(string)
		return ownerKind + ":" + owner, InlinePolicyFileKey(ownerKind, owner, policyName)
	default:
		return "", ""
	}
}

func fileKeyForLiveChild(resource driftLiveResource) string {
	_, fileKey := driftChildParent(resource)
	return fileKey
}

func declarationPublicationID(declarations []BaselineDeclaration, fileKey string) *int64 {
	for _, declaration := range declarations {
		if declaration.FileKey == fileKey && declaration.PublicationID != nil {
			return declaration.PublicationID
		}
	}
	return nil
}

func (service *DriftService) loadInFlightFiles(
	ctx context.Context, accountDBID int64,
) (map[string]bool, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT file_key FROM publish_reservation
		WHERE account_id = $1 AND status IN ('OPEN', 'MERGED')`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load in-flight reservations: %w", err)
	}
	defer rows.Close()
	files := map[string]bool{}
	for rows.Next() {
		var fileKey string
		if err := rows.Scan(&fileKey); err != nil {
			return nil, fmt.Errorf("scan in-flight reservation: %w", err)
		}
		files[fileKey] = true
	}
	return files, rows.Err()
}

func (service *DriftService) loadTicketActivities(
	ctx context.Context, accountDBID int64,
) (map[string]driftTicketActivity, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT DISTINCT ON (r.file_key)
		       r.file_key, t.id, t.ticket_no, t.status,
		       COALESCE(t.git_apply_result, ''), t.updated_at
		FROM publish_reservation r
		JOIN iam_ticket t ON t.ticket_no = r.ref AND t.account_id = r.account_id
		WHERE r.account_id = $1 AND r.channel = 'ticket'
		  AND (t.status = 'MERGED'
		       OR (t.status = 'CLOSED' AND t.closure_reason = 'APPLIED'))
		ORDER BY r.file_key, t.updated_at DESC`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load successful ticket activity: %w", err)
	}
	defer rows.Close()
	activities := map[string]driftTicketActivity{}
	for rows.Next() {
		var fileKey string
		var activity driftTicketActivity
		if err := rows.Scan(&fileKey, &activity.TicketID, &activity.TicketNo,
			&activity.Status, &activity.ApplyResult, &activity.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan ticket activity: %w", err)
		}
		activities[fileKey] = activity
	}
	return activities, rows.Err()
}

func (service *DriftService) loadOpenFindings(
	ctx context.Context, accountDBID int64, source string,
) (map[string]DriftFinding, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT id, resource_key, resource_address, status, occurrences
		FROM iam_drift_finding
		WHERE account_id = $1 AND source = $2 AND resolved_at IS NULL`,
		accountDBID, source)
	if err != nil {
		return nil, fmt.Errorf("load open drift findings: %w", err)
	}
	defer rows.Close()
	findings := map[string]DriftFinding{}
	for rows.Next() {
		var finding DriftFinding
		if err := rows.Scan(&finding.ID, &finding.ResourceKey,
			&finding.ResourceAddress, &finding.Status, &finding.Occurrences); err != nil {
			return nil, fmt.Errorf("scan open drift finding: %w", err)
		}
		findings[finding.driftKey()] = finding
	}
	return findings, rows.Err()
}

// insertFinding 落一条新发现并返回自增 ID。ID 不只是内部标识：webhook 与
// 页面都用它指认同一条发现，推 0 出去等于让接收方无法回查。
func (service *DriftService) insertFinding(
	ctx context.Context, finding DriftFinding, status string,
) (int64, error) {
	var id int64
	fields, err := json.Marshal(finding.Fields)
	if err != nil {
		return 0, fmt.Errorf("marshal drift fields: %w", err)
	}
	summaryParams, err := marshalDriftSummaryParams(finding.SummaryParams)
	if err != nil {
		return 0, err
	}
	err = service.db.QueryRowContext(ctx, `
		INSERT INTO iam_drift_finding (
			account_id, aws_account_id, source, resource_key, resource_address,
			kind, file_key, change_type, fields, severity, status,
			baseline_publication_id, summary, summary_code, summary_params, ci_url, commit_sha)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15::jsonb, $16, $17)
		RETURNING id`,
		finding.AccountDBID, finding.AWSAccountID, finding.Source,
		finding.ResourceKey, finding.ResourceAddress, finding.Kind, finding.FileKey,
		finding.ChangeType, []byte(fields), finding.Severity, status,
		finding.BaselinePublicationID, finding.Summary, finding.SummaryCode,
		[]byte(summaryParams), strings.TrimSpace(finding.CIURL),
		strings.TrimSpace(finding.CommitSHA)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert drift finding %s: %w", finding.ResourceKey, err)
	}
	return id, nil
}

// marshalDriftSummaryParams 统一把参数写成 JSON 文本；nil 落成空对象，
// 让列永远是合法 jsonb（前端按 code 取参时不会遇到 NULL）。
func marshalDriftSummaryParams(params map[string]string) ([]byte, error) {
	if len(params) == 0 {
		return []byte("{}"), nil
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal drift summary params: %w", err)
	}
	return encoded, nil
}

func (service *DriftService) updateFinding(
	ctx context.Context, id int64, finding DriftFinding, status string,
) error {
	fields, err := json.Marshal(finding.Fields)
	if err != nil {
		return fmt.Errorf("marshal drift fields: %w", err)
	}
	summaryParams, err := marshalDriftSummaryParams(finding.SummaryParams)
	if err != nil {
		return err
	}
	_, err = service.db.ExecContext(ctx, `
		UPDATE iam_drift_finding
		SET fields = $2::jsonb, severity = $3, status = $4, summary = $5,
		    summary_code = $6, summary_params = $7::jsonb,
		    kind = $8, file_key = $9, baseline_publication_id = $10,
		    ci_url = COALESCE(NULLIF($11, ''), ci_url),
		    commit_sha = COALESCE(NULLIF($12, ''), commit_sha),
		    last_seen_at = NOW(), occurrences = occurrences + 1, updated_at = NOW()
		WHERE id = $1`,
		id, []byte(fields), finding.Severity, status, finding.Summary,
		finding.SummaryCode, []byte(summaryParams),
		finding.Kind, finding.FileKey, finding.BaselinePublicationID,
		finding.CIURL, finding.CommitSHA)
	if err != nil {
		return fmt.Errorf("update drift finding %d: %w", id, err)
	}
	return nil
}

func (service *DriftService) resolveFinding(ctx context.Context, id int64) error {
	if _, err := service.db.ExecContext(ctx, `
		UPDATE iam_drift_finding
		SET resolved_at = NOW(), resolved_by = 'auto', updated_at = NOW()
		WHERE id = $1 AND resolved_at IS NULL`, id); err != nil {
		return fmt.Errorf("resolve drift finding %d: %w", id, err)
	}
	return nil
}

func (service *DriftService) countOpenFindings(
	ctx context.Context, accountDBID int64,
) (int, error) {
	var count int
	if err := service.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM iam_drift_finding
		WHERE account_id = $1 AND resolved_at IS NULL AND status <> 'IGNORED'`,
		accountDBID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count open drift findings: %w", err)
	}
	return count, nil
}

// recordHeartbeat 记录「检测确实跑过」。last_drift_clean_at 只在干净时前移：
// 它回答的是「上次全绿是什么时候」，不能每轮都刷新。
//
// skipped/stale 传指针：库存判定两样都算得出来，CI 上报（drift_report）只
// 能算发现数、算不出「跳过了多少文件」，传 nil 保持上一轮的值——用 0 覆盖
// 会让页面把「这次没统计」读成「这次一个都没跳过」。
func (service *DriftService) recordHeartbeat(
	ctx context.Context, accountDBID int64, clean bool,
	skipped, stale *int,
) error {
	_, err := service.db.ExecContext(ctx, `
		UPDATE aws_account_config
		SET last_drift_check_at = NOW(),
		    last_drift_clean_at = CASE WHEN $2 THEN NOW() ELSE last_drift_clean_at END,
		    last_drift_skipped_files = COALESCE($3, last_drift_skipped_files),
		    last_drift_stale_files = COALESCE($4, last_drift_stale_files),
		    updated_at = NOW()
		WHERE aws_account_db_id = $1`, accountDBID, clean, skipped, stale)
	if err != nil {
		return fmt.Errorf("record drift heartbeat: %w", err)
	}
	return nil
}
