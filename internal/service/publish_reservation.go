package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// PublishReservationService 是文件级发布预约（phase4-drift-design.md §4）：
// 同一账号同一文件至多一个开放 PR 源。发布方在写仓库前预约本次要写的
// 文件集合，唯一索引兜住并发；冲突方带渠道与持有者返回，让「为什么我
// 发不了布」在错误信息里自解释。
//
// 释放规则（拍板）：
//   - 工单：REJECTED / CLOSED（未合并）/ PUBLISH_FAILED 直接释放；MERGED
//     转 MERGED 态等下一次成功同步释放（工单侧无 TTL，挂死走管理员干预）。
//   - 基线：FAILED / CLOSED / 被 supersede 时释放；PR 合并转 MERGED 态；
//     OPEN 态由 SweepStale 按 TTL 回收（基线是巡检通道，不能无限占文件）。
type PublishReservationService struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPublishReservationService(db *sql.DB, logger *slog.Logger) (*PublishReservationService, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PublishReservationService{db: db, logger: logger}, nil
}

// PublishReservationConflict 描述一次预约尝试中被别人持有的文件。
type PublishReservationConflict struct {
	AccountDBID int64  `json:"account_id"`
	FileKey     string `json:"file_key"`
	Channel     string `json:"channel"`
	Ref         string `json:"ref"`
}

// Describe 渲染成人可读的占用说明（进错误信息与台账 issue）。
func (conflict PublishReservationConflict) Describe() string {
	switch conflict.Channel {
	case PublishChannelTicket:
		return fmt.Sprintf("%s (held by ticket %s)", conflict.FileKey, conflict.Ref)
	case PublishChannelBaseline:
		return fmt.Sprintf("%s (held by baseline publication %s)", conflict.FileKey, conflict.Ref)
	default:
		return fmt.Sprintf("%s (held by %s %s)", conflict.FileKey, conflict.Channel, conflict.Ref)
	}
}

const (
	PublishChannelTicket   = "ticket"
	PublishChannelBaseline = "baseline"
)

// ReserveForTicket 为工单发布预约文件集合。先释放该工单自己遗留的开放
// 预约（发布重试时文件集合可能变化），再原子插入新集合；被其他发布方
// 持有的文件原样返回冲突。要么全部预约成功、要么一个都不插：带冲突时
// 回滚，避免半套预约卡住后续发布。
func (service *PublishReservationService) ReserveForTicket(
	ctx context.Context,
	accountDBID int64,
	ticketNo string,
	fileKeys []string,
) ([]PublishReservationConflict, error) {
	return service.reserve(ctx, accountDBID, PublishChannelTicket, ticketNo, fileKeys, true)
}

// ReserveForPublication 为基线发布预约文件集合。基线对冲突采取让路语义：
// 冲突文件不预约也不发布（deferred），其余文件照发，所以这里允许部分
// 成功并返回冲突清单。
func (service *PublishReservationService) ReserveForPublication(
	ctx context.Context,
	accountDBID int64,
	publicationID int64,
	fileKeys []string,
) ([]PublishReservationConflict, error) {
	return service.reserve(ctx, accountDBID, PublishChannelBaseline,
		fmt.Sprintf("%d", publicationID), fileKeys, false)
}

// releaseOwn 释放同渠道同持有者的全部开放预约（重试时文件集合可能变化）。
func (service *PublishReservationService) releaseOwn(
	ctx context.Context,
	tx *sql.Tx,
	channel, ref string,
) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE publish_reservation
		SET status = 'RELEASED', released_at = NOW()
		WHERE channel = $1 AND ref = $2 AND status = 'OPEN'`, channel, ref)
	if err != nil {
		return fmt.Errorf("release previous %s reservations for %s: %w", channel, ref, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		service.logger.Info("released previous publish reservations",
			"channel", channel, "ref", ref, "count", affected)
	}
	return nil
}

func (service *PublishReservationService) reserve(
	ctx context.Context,
	accountDBID int64,
	channel, ref string,
	fileKeys []string,
	allOrNothing bool,
) ([]PublishReservationConflict, error) {
	if len(fileKeys) == 0 {
		return nil, nil
	}
	cleaned := make([]string, 0, len(fileKeys))
	seen := make(map[string]bool, len(fileKeys))
	for _, key := range fileKeys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		cleaned = append(cleaned, key)
	}
	if len(cleaned) == 0 {
		return nil, nil
	}

	transaction, err := service.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin publish reservation: %w", err)
	}
	defer transaction.Rollback()

	if err := service.releaseOwn(ctx, transaction, channel, ref); err != nil {
		return nil, err
	}
	for _, key := range cleaned {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO publish_reservation (account_id, file_key, channel, ref)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (account_id, file_key) WHERE status = 'OPEN' DO NOTHING`,
			accountDBID, key, channel, ref); err != nil {
			return nil, fmt.Errorf("reserve publish file %s: %w", key, err)
		}
	}
	conflicts, err := service.openConflicts(ctx, transaction, accountDBID, channel, ref, cleaned)
	if err != nil {
		return nil, err
	}
	if allOrNothing && len(conflicts) > 0 {
		return conflicts, fmt.Errorf("%w: %s", ErrPublishFileReserved, describeConflicts(conflicts))
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit publish reservation: %w", err)
	}
	return conflicts, nil
}

func (service *PublishReservationService) openConflicts(
	ctx context.Context,
	tx *sql.Tx,
	accountDBID int64,
	channel, ref string,
	fileKeys []string,
) ([]PublishReservationConflict, error) {
	conflicts := []PublishReservationConflict{}
	for _, key := range fileKeys {
		rows, err := tx.QueryContext(ctx, `
			SELECT channel, ref FROM publish_reservation
			WHERE account_id = $1 AND status = 'OPEN'
			  AND file_key = $2
			  AND NOT (channel = $3 AND ref = $4)`,
			accountDBID, key, channel, ref)
		if err != nil {
			return nil, fmt.Errorf("load conflicting publish reservations: %w", err)
		}
		for rows.Next() {
			var conflict PublishReservationConflict
			conflict.AccountDBID = accountDBID
			conflict.FileKey = key
			if err := rows.Scan(&conflict.Channel, &conflict.Ref); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan conflicting publish reservation: %w", err)
			}
			conflicts = append(conflicts, conflict)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("iterate conflicting publish reservations: %w", err)
		}
		rows.Close()
	}
	sort.Slice(conflicts, func(i, j int) bool {
		return conflicts[i].FileKey < conflicts[j].FileKey
	})
	return conflicts, nil
}

// ErrPublishFileReserved 表示要写的文件已被另一个开放 PR 源占用。
var ErrPublishFileReserved = errors.New("publish file reserved by another open change")

func describeConflicts(conflicts []PublishReservationConflict) string {
	descriptions := make([]string, 0, len(conflicts))
	for _, conflict := range conflicts {
		descriptions = append(descriptions, conflict.Describe())
	}
	return strings.Join(descriptions, ", ")
}

// ReleaseTicket 释放工单的全部开放预约：REJECTED / CLOSED（未合并）/
// PUBLISH_FAILED 时调用。
func (service *PublishReservationService) ReleaseTicket(ctx context.Context, ticketNo string) error {
	return service.release(ctx, PublishChannelTicket, ticketNo)
}

// ReleasePublication 释放基线台账的全部开放预约：FAILED / CLOSED /
// supersede 时调用。
func (service *PublishReservationService) ReleasePublication(ctx context.Context, publicationID int64) error {
	return service.release(ctx, PublishChannelBaseline, fmt.Sprintf("%d", publicationID))
}

func (service *PublishReservationService) release(ctx context.Context, channel, ref string) error {
	result, err := service.db.ExecContext(ctx, `
		UPDATE publish_reservation
		SET status = 'RELEASED', released_at = NOW()
		WHERE channel = $1 AND ref = $2 AND status = 'OPEN'`, channel, ref)
	if err != nil {
		return fmt.Errorf("release %s reservations for %s: %w", channel, ref, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		service.logger.Info("released publish reservations",
			"channel", channel, "ref", ref, "count", affected)
	}
	return nil
}

// MarkTicketMerged 在工单 PR 合并时把开放预约转 MERGED 态：不立即释放，
// 等该账号下一次成功同步确认清单已反映变更后再释放（merge→apply 窗口
// 的文件级表现）。
func (service *PublishReservationService) MarkTicketMerged(ctx context.Context, ticketNo string) error {
	return service.markMerged(ctx, PublishChannelTicket, ticketNo)
}

// MarkPublicationMerged 在基线 PR 合并时把开放预约转 MERGED 态。
func (service *PublishReservationService) MarkPublicationMerged(ctx context.Context, publicationID int64) error {
	return service.markMerged(ctx, PublishChannelBaseline, fmt.Sprintf("%d", publicationID))
}

func (service *PublishReservationService) markMerged(ctx context.Context, channel, ref string) error {
	result, err := service.db.ExecContext(ctx, `
		UPDATE publish_reservation
		SET status = 'MERGED', released_at = NULL
		WHERE channel = $1 AND ref = $2 AND status = 'OPEN'`, channel, ref)
	if err != nil {
		return fmt.Errorf("mark %s reservations merged for %s: %w", channel, ref, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		service.logger.Info("publish reservations awaiting sync confirmation",
			"channel", channel, "ref", ref, "count", affected)
	}
	return nil
}

// ReleaseMergedForAccount 在账号同步成功后释放其全部 MERGED 预约：清单
// 已确认反映合并后的状态，merge→apply 窗口关闭。
func (service *PublishReservationService) ReleaseMergedForAccount(ctx context.Context, accountDBID int64) error {
	result, err := service.db.ExecContext(ctx, `
		UPDATE publish_reservation
		SET status = 'RELEASED', released_at = NOW()
		WHERE account_id = $1 AND status = 'MERGED'`, accountDBID)
	if err != nil {
		return fmt.Errorf("release merged reservations for account %d: %w", accountDBID, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		service.logger.Info("released merged publish reservations after sync",
			"account_id", accountDBID, "count", affected)
	}
	return nil
}

// BaselineReservationTTL 是基线开放预约的回收时限（拍板：基线侧有 TTL，
// 工单侧没有）。基线 PR 通常当天合并或关闭；72h 覆盖周末挂起的场景。
const BaselineReservationTTL = 72 * time.Hour

// SweepBaselineExpired 回收超过 TTL 仍 OPEN 的基线预约。基线是巡检通道，
// 一条被遗忘的基线 PR 不应永久挡住该账号的工单变更。工单侧刻意不扫：
// 挂死的工单预约需要人看（管理员手动释放），静默回收会掩盖问题。
func (service *PublishReservationService) SweepBaselineExpired(ctx context.Context) (int, error) {
	result, err := service.db.ExecContext(ctx, `
		UPDATE publish_reservation
		SET status = 'RELEASED', released_at = NOW()
		WHERE channel = 'baseline' AND status = 'OPEN'
		  AND created_at < NOW() - $1::interval`,
		fmt.Sprintf("%d seconds", int(BaselineReservationTTL.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("sweep expired baseline reservations: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		service.logger.Info("swept expired baseline publish reservations", "count", affected)
	}
	return int(affected), nil
}

// ReleaseExpiredForAdmin 是管理员手动释放入口的底层：无条件释放指定
// 工单的全部开放与 MERGED 预约。调用方（handler）负责权限校验与审计。
func (service *PublishReservationService) ReleaseExpiredForAdmin(ctx context.Context, channel, ref string) (int, error) {
	result, err := service.db.ExecContext(ctx, `
		UPDATE publish_reservation
		SET status = 'RELEASED', released_at = NOW()
		WHERE channel = $1 AND ref = $2 AND status IN ('OPEN', 'MERGED')`, channel, ref)
	if err != nil {
		return 0, fmt.Errorf("admin release %s reservations for %s: %w", channel, ref, err)
	}
	affected, _ := result.RowsAffected()
	service.logger.Warn("admin released publish reservations",
		"channel", channel, "ref", ref, "count", affected)
	return int(affected), nil
}

// 预约状态。OPEN = 有开放 PR 占着文件；MERGED = PR 已合并、等同步确认；
// RELEASED = 已释放（终态，仅留痕）。
const (
	PublishReservationStatusOpen     = "OPEN"
	PublishReservationStatusMerged   = "MERGED"
	PublishReservationStatusReleased = "RELEASED"
)

// PublishReservation 是预约表的只读投影，供运维回答「这个文件为什么
// 发不了」：谁占着（channel + ref）、占多久了（created_at）。
type PublishReservation struct {
	ID          int64      `json:"id"`
	AccountDBID int64      `json:"account_id"`
	FileKey     string     `json:"file_key"`
	Channel     string     `json:"channel"`
	Ref         string     `json:"ref"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ReleasedAt  *time.Time `json:"released_at,omitempty"`
}

// PublishReservationFilter 收窄列表范围。零值 = 不限（status 默认只查
// OPEN + MERGED，因为 RELEASED 是历史痕迹，通常不需要看）。
type PublishReservationFilter struct {
	AccountDBID int64
	Channel     string
	Status      string
	Limit       int
}

const (
	publishReservationDefaultLimit = 100
	publishReservationMaxLimit     = 500
)

// List 返回预约记录，按状态与账号过滤。默认只返回仍在生效的预约
// （OPEN + MERGED）——RELEASED 行只是审计痕迹，默认视图不该被它淹没。
func (service *PublishReservationService) List(
	ctx context.Context,
	filter PublishReservationFilter,
) ([]PublishReservation, error) {
	conditions := make([]string, 0, 4)
	arguments := make([]any, 0, 4)
	addCondition := func(column string, value any) {
		arguments = append(arguments, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(arguments)))
	}
	if filter.AccountDBID > 0 {
		addCondition("account_id", filter.AccountDBID)
	}
	if channel := strings.TrimSpace(filter.Channel); channel != "" {
		addCondition("channel", channel)
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		addCondition("status", status)
	} else {
		conditions = append(conditions, "status IN ('OPEN', 'MERGED')")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = publishReservationDefaultLimit
	}
	if limit > publishReservationMaxLimit {
		limit = publishReservationMaxLimit
	}
	arguments = append(arguments, limit)

	query := `SELECT id, account_id, file_key, channel, ref, status, created_at, released_at
		FROM publish_reservation`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(arguments))

	rows, err := service.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list publish reservations: %w", err)
	}
	defer rows.Close()
	reservations := make([]PublishReservation, 0, limit)
	for rows.Next() {
		var reservation PublishReservation
		if err := rows.Scan(&reservation.ID, &reservation.AccountDBID, &reservation.FileKey,
			&reservation.Channel, &reservation.Ref, &reservation.Status,
			&reservation.CreatedAt, &reservation.ReleasedAt); err != nil {
			return nil, fmt.Errorf("scan publish reservation: %w", err)
		}
		reservations = append(reservations, reservation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate publish reservations: %w", err)
	}
	return reservations, nil
}
