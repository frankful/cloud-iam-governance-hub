package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// BaselineDeclaration 是一条「已声明的资源意图」：资源标识、它落在哪个
// 文件、以及归一化后的属性快照。漂移判定拿它当基准（declared）与库存
// （live）逐字段比对——不是拿「上次库存」比（会把已批准的变更算成漂移），
// 也不是拿仓库文件比（隔着 state 与 apply 两层）。
type BaselineDeclaration struct {
	// AWSAccountID 是声明所属的 AWS 账号（运维排查时按它对话，而不是内部
	// 数据库主键）。
	AWSAccountID string `json:"aws_account_id,omitempty"`
	// ResourceKey 是资源级标识：role:foo / role:foo:inline:baz /
	// attachment:role:foo:arn:... / membership:group:g。
	ResourceKey string `json:"resource_key"`
	// FileKey 是不含 .tf 的 bundle 文件名，与 publish_reservation 同源。
	FileKey string `json:"file_key"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	// Attributes 是归一化属性 JSON（键序固定、策略文档语义归一）。
	Attributes json.RawMessage `json:"attributes"`
	// ContentBlobSHA 是声明时该文件的 git blob SHA：检测时与 main 现文件
	// 比对，不一致说明有人绕过基线改了 tf 文件（baseline_stale），
	// 这时差异不该报成漂移。
	ContentBlobSHA string `json:"content_blob_sha,omitempty"`

	// StaleAt / StaleReason 是新鲜度核对（phase4 §4.6）的结论：声明所依据
	// 的文件已与 main 不一致。非空表示这条声明不能当基准用——P3 判定要跳过
	// 它并报 baseline_stale，而不是把「有人手改 tf」算成漂移。
	StaleAt     *time.Time `json:"stale_at,omitempty"`
	StaleReason string     `json:"stale_reason,omitempty"`

	DeclaredAt    string `json:"declared_at,omitempty"`
	PublicationID *int64 `json:"publication_id,omitempty"`
	TicketID      *int64 `json:"ticket_id,omitempty"`

	// declaredAt 是 DeclaredAt 的时间形态，供判定比较「声明之后有没有
	// 成功工单改过同一文件」。不导出：对外只暴露 RFC3339 字符串。
	declaredAt time.Time
}

// DeclarationTarget 是一次声明落库的目标：哪次发布/哪张工单、为哪个账号
// 写入了哪些声明。
type DeclarationTarget struct {
	AccountDBID  int64
	AWSAccountID string
	SyncRunID    int64
	// PublicationID 与 TicketID 二选一：基线发布或工单产出。
	PublicationID *int64
	TicketID      *int64
	Declarations  []BaselineDeclaration
	// TouchedFiles 是本次真正写进仓库的文件。即使一个声明都没反解出来也要
	// 按它作废旧声明：回滚把文件清空、移除最后一名成员把 membership 文件
	// 清空，这类「零声明」的发布本身就是「这个文件不再声明任何资源」。
	// 反解失败（gap）的文件不要列进来——那是不确定，不是清空。
	TouchedFiles []string
}

// BaselineDeclarationService 维护声明快照表（0032）。
type BaselineDeclarationService struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewBaselineDeclarationService(db *sql.DB, logger *slog.Logger) (*BaselineDeclarationService, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BaselineDeclarationService{db: db, logger: logger}, nil
}

// Save 用本次发布/工单的声明替换「这批文件」上的旧声明：旧行打上
// superseded_at 保留追溯，新行插入。空声明不替换——「本轮没发布任何
// 文件」不等于「什么都没声明」，抹掉基准会让漂移检测失去依据。
//
// 作废范围是文件级 + 资源级，不是账号级：基线与工单共同构成声明集合
// （范围 = baseline ∪ 成功工单），账号级作废会让一次基线发布抹掉所有
// 工单声明，反之亦然。同一资源换了文件也要作废旧行——(account_id,
// resource_key) 的当前行唯一，否则插入会撞唯一索引。
func (service *BaselineDeclarationService) Save(
	ctx context.Context,
	target DeclarationTarget,
) error {
	if target.AccountDBID <= 0 {
		return errors.New("declaration target must carry an account id")
	}
	if len(target.Declarations) == 0 && len(target.TouchedFiles) == 0 {
		return nil
	}
	awsAccountID := target.AWSAccountID
	fileKeys := make([]string, 0, len(target.Declarations)+len(target.TouchedFiles))
	resourceKeys := make([]string, 0, len(target.Declarations))
	seenFiles := make(map[string]bool, len(target.Declarations)+len(target.TouchedFiles))
	for _, fileKey := range target.TouchedFiles {
		if seenFiles[fileKey] {
			continue
		}
		seenFiles[fileKey] = true
		fileKeys = append(fileKeys, fileKey)
	}
	for _, declaration := range target.Declarations {
		if !seenFiles[declaration.FileKey] {
			seenFiles[declaration.FileKey] = true
			fileKeys = append(fileKeys, declaration.FileKey)
		}
		resourceKeys = append(resourceKeys, declaration.ResourceKey)
	}
	// 0 不是合法的 sync run：工单发布没有同步批次，落 NULL 而不是伪造一个
	// 不存在的 run id。
	var syncRunID any
	if target.SyncRunID > 0 {
		syncRunID = target.SyncRunID
	}

	transaction, err := service.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin baseline declaration: %w", err)
	}
	defer transaction.Rollback()

	if _, err := transaction.ExecContext(ctx, `
		UPDATE iam_baseline_declaration
		SET superseded_at = NOW(), superseded_reason = 'REPLACED'
		WHERE account_id = $1 AND superseded_at IS NULL
		  AND (file_key = ANY($2::text[]) OR resource_key = ANY($3::text[]))`,
		target.AccountDBID, fileKeys, resourceKeys); err != nil {
		return fmt.Errorf("supersede previous baseline declarations: %w", err)
	}
	for _, declaration := range target.Declarations {
		attributes := declaration.Attributes
		if len(bytes.TrimSpace(attributes)) == 0 {
			attributes = json.RawMessage(`{}`)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO iam_baseline_declaration (
				account_id, aws_account_id, publication_id, ticket_id, sync_run_id,
				resource_key, file_key, kind, name, attributes, content_blob_sha)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)`,
			target.AccountDBID, awsAccountID, target.PublicationID, target.TicketID,
			syncRunID, declaration.ResourceKey, declaration.FileKey,
			declaration.Kind, declaration.Name, []byte(attributes),
			declaration.ContentBlobSHA,
		); err != nil {
			return fmt.Errorf("insert baseline declaration %s: %w", declaration.ResourceKey, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit baseline declarations: %w", err)
	}
	service.logger.Info("baseline declarations recorded",
		"account_id", target.AccountDBID,
		"declarations", len(target.Declarations),
		"publication_id", target.PublicationID,
		"ticket_id", target.TicketID,
	)
	return nil
}

// VoidForTicket 作废某张工单落下的「当前」声明。工单发布时就把声明写进
// 基准（PR 一开，声明就确定），但 PR 被关闭未合并等于什么都没声明——必须
// 撤回，否则漂移检测会拿一份从未进 main 的意图当基准，把实态里正确的
// 资源全报成「被改回去了」。
//
// 只动这张工单自己那几行：如果它写过的文件已被后续基线发布重新声明，
// 那些行早已 superseded，这里不会误伤。
func (service *BaselineDeclarationService) VoidForTicket(ctx context.Context, ticketID int64) error {
	if ticketID <= 0 {
		return nil
	}
	return service.voidDeclarations(ctx, "ticket_id", ticketID)
}

// VoidForPublication 作废某次基线发布落下的「当前」声明：PR 关闭未合并
// 与工单废弃是同一件事——这次发布从未进 main（phase4 §6 场景 C）。
func (service *BaselineDeclarationService) VoidForPublication(
	ctx context.Context, publicationID int64,
) error {
	if publicationID <= 0 {
		return nil
	}
	return service.voidDeclarations(ctx, "publication_id", publicationID)
}

// voidDeclarations 作废某次发布/某张工单落下且仍然生效的声明，并把「被它
// 取代的上一条有效声明」恢复回来。
//
// 为什么要恢复：PR 关闭未合并、工单废弃都意味着这次发布从未进 main，main
// 上还是上一个声明对应的内容。只作废不恢复，这些资源就变成「有实态、无
// 基准」的覆盖空洞——看起来像从未纳管，其实有基准，只是被一次没落地的
// 发布盖住了。
//
// 恢复只认 superseded_reason = 'REPLACED' 的历史行：'VOIDED' 的那条本身
// 也是一次没落地的发布，恢复它等于复活一个幽灵基准。同一资源优先恢复同
// 一个文件里的上一条（资源可能换过文件），按退场时间倒序取最近一条。
//
// scopeColumn 只接受本文件里的字面量（ticket_id / publication_id），
// 不做任何外部拼接。
func (service *BaselineDeclarationService) voidDeclarations(
	ctx context.Context, scopeColumn string, scopeID int64,
) error {
	switch scopeColumn {
	case "ticket_id", "publication_id":
	default:
		return fmt.Errorf("unsupported declaration void scope %q", scopeColumn)
	}
	transaction, err := service.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin declaration void: %w", err)
	}
	defer transaction.Rollback()

	type voidedDeclaration struct {
		id          int64
		accountID   int64
		resourceKey string
		fileKey     string
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT id, account_id, resource_key, file_key
		FROM iam_baseline_declaration
		WHERE `+scopeColumn+` = $1 AND superseded_at IS NULL
		FOR UPDATE`, scopeID)
	if err != nil {
		return fmt.Errorf("load declarations to void: %w", err)
	}
	var voided []voidedDeclaration
	for rows.Next() {
		var item voidedDeclaration
		if err := rows.Scan(&item.id, &item.accountID, &item.resourceKey, &item.fileKey); err != nil {
			rows.Close()
			return fmt.Errorf("scan declaration to void: %w", err)
		}
		voided = append(voided, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate declarations to void: %w", err)
	}
	if len(voided) == 0 {
		return nil
	}

	// 先逐条打上 VOIDED，再恢复：恢复查询只看 REPLACED，已经 void 的行
	// 不会被自己捡回来。
	for _, item := range voided {
		if _, err := transaction.ExecContext(ctx, `
			UPDATE iam_baseline_declaration
			SET superseded_at = NOW(), superseded_reason = 'VOIDED'
			WHERE id = $1`, item.id); err != nil {
			return fmt.Errorf("void declaration %d: %w", item.id, err)
		}
	}
	restored := 0
	for _, item := range voided {
		var previousID int64
		err := transaction.QueryRowContext(ctx, `
			SELECT id FROM iam_baseline_declaration
			WHERE account_id = $1 AND resource_key = $2
			  AND superseded_reason = 'REPLACED'
			ORDER BY (file_key = $3) DESC, superseded_at DESC, id DESC
			LIMIT 1`, item.accountID, item.resourceKey, item.fileKey).Scan(&previousID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("find previous declaration for %s: %w", item.resourceKey, err)
		}
		// 恢复同时清掉过期标记：上一版声明对应的文件内容还在 main 上，
		// 新不新鲜由下一轮核对重新算。
		if _, err := transaction.ExecContext(ctx, `
			UPDATE iam_baseline_declaration
			SET superseded_at = NULL, superseded_reason = NULL,
			    stale_at = NULL, stale_reason = NULL
			WHERE id = $1`, previousID); err != nil {
			return fmt.Errorf("restore previous declaration %d: %w", previousID, err)
		}
		restored++
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit declaration void: %w", err)
	}
	service.logger.Info("voided declarations for unpublished change",
		"scope", scopeColumn, "scope_id", scopeID,
		"voided", len(voided), "restored", restored)
	return nil
}

// LoadCurrent 返回账号当前生效的声明，供漂移判定（P3）、「基准过期」核对
// 与运维排查使用。已过期的行带 stale_at / stale_reason 一起返回：判定要
// 跳过它们，运维要知道为什么跳过。
func (service *BaselineDeclarationService) LoadCurrent(
	ctx context.Context,
	accountDBID int64,
) ([]BaselineDeclaration, error) {
	rows, err := service.db.QueryContext(ctx, `
		SELECT aws_account_id, resource_key, file_key, kind, name, attributes::text,
		       COALESCE(content_blob_sha, ''), publication_id, ticket_id,
		       stale_at, stale_reason, declared_at
		FROM iam_baseline_declaration
		WHERE account_id = $1 AND superseded_at IS NULL
		ORDER BY resource_key`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load baseline declarations: %w", err)
	}
	defer rows.Close()

	declarations := make([]BaselineDeclaration, 0, 256)
	for rows.Next() {
		var declaration BaselineDeclaration
		var attributes string
		var staleAt sql.NullTime
		var staleReason sql.NullString
		var declaredAt time.Time
		if err := rows.Scan(&declaration.AWSAccountID, &declaration.ResourceKey,
			&declaration.FileKey, &declaration.Kind, &declaration.Name, &attributes,
			&declaration.ContentBlobSHA, &declaration.PublicationID,
			&declaration.TicketID, &staleAt, &staleReason, &declaredAt); err != nil {
			return nil, fmt.Errorf("scan baseline declaration: %w", err)
		}
		declaration.Attributes = json.RawMessage(attributes)
		declaration.declaredAt = declaredAt
		declaration.DeclaredAt = declaredAt.UTC().Format(time.RFC3339)
		if staleAt.Valid {
			at := staleAt.Time
			declaration.StaleAt = &at
		}
		declaration.StaleReason = staleReason.String
		declarations = append(declarations, declaration)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate baseline declarations: %w", err)
	}
	return declarations, nil
}

// RecordDeclarations 是发布侧的便捷入口：把声明按「真正写进仓库的文件」
// 过滤（让路的文件、本轮没写的文件都不算声明），并补上文件的 blob SHA。
// 失败只记日志不阻断发布——发布本身已经成功，声明落库失败会让漂移基准
// 停在上一版（可见、可重发），把已合并的 PR 报成失败反而更糟。
//
// 呼叫方若连个声明都没反解出来但要作废旧声明（回滚清空文件、移除最后
// 一名成员），把文件放进 DeclarationTarget.TouchedFiles：Save 会按文件
// 作废而不插入任何行。
func (service *BaselineDeclarationService) RecordDeclarations(
	ctx context.Context,
	target DeclarationTarget,
	files []BaselineBundleFile,
) error {
	blobSHAs := make(map[string]string, len(files))
	for _, file := range files {
		blobSHAs[file.Key] = gitBlobSHA(file.Content)
	}
	declarations := make([]BaselineDeclaration, 0, len(target.Declarations))
	for _, declaration := range target.Declarations {
		if _, published := blobSHAs[declaration.FileKey]; !published {
			continue
		}
		declaration.ContentBlobSHA = blobSHAs[declaration.FileKey]
		declarations = append(declarations, declaration)
	}
	target.Declarations = declarations
	return service.Save(ctx, target)
}

// canonicalJSON 把任意值编码成键序固定的 JSON（encoding/json 对 map 键
// 排序），供声明属性与漂移比对共用：同一语义必须得到同一字节。
func canonicalJSON(value any) (json.RawMessage, error) {
	if value == nil {
		return json.RawMessage(`{}`), nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize JSON: %w", err)
	}
	return json.RawMessage(encoded), nil
}

// canonicalPolicy 把策略文档归一化成可比较的值：键序与空白无关，但数组
// 顺序（Statement / Action / Resource）仍然敏感——这是刻意的，语义级
// 集合比较留给漂移判定按需处理，声明快照只保证「同文档同字节」。
// 空文档返回 nil（不写入属性），避免把「没有文档」写成 {}。
func canonicalPolicy(raw json.RawMessage) any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		// 文档损坏时保留原文，至少让差异可见，而不是静默丢字段。
		return string(raw)
	}
	return value
}
