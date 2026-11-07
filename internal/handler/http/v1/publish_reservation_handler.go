package v1

import (
	stdcontext "context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

// publishReservationService 是文件级发布预约的运维面：列出「谁占着哪个
// 文件」，以及管理员手动释放挂死的预约（工单侧刻意没有 TTL，异常必须
// 人来处理）。
type publishReservationService interface {
	List(ctx stdcontext.Context, filter service.PublishReservationFilter) ([]service.PublishReservation, error)
	ReleaseExpiredForAdmin(ctx stdcontext.Context, channel, ref string) (int, error)
}

// PublishReservationHandler 暴露预约表。写操作（释放）收敛在平台管理员：
// 释放会让两个开放 PR 源同时写同一文件，属于运维兜底而非日常操作。
type PublishReservationHandler struct {
	service publishReservationService
	logger  *slog.Logger
}

func NewPublishReservationHandler(
	reservations publishReservationService,
	logger *slog.Logger,
) (*PublishReservationHandler, error) {
	if reservations == nil {
		return nil, errors.New("publish reservation service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PublishReservationHandler{service: reservations, logger: logger}, nil
}

func RegisterPublishReservationRoutes(router gin.IRoutes, handler *PublishReservationHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodGet, "/publish-reservations", append(admin, handler.List)...)
	router.Handle(http.MethodPost, "/publish-reservations/release", append(admin, handler.Release)...)
}

// List handles GET /publish-reservations?account_id=&channel=&status=&limit=
// 默认只返回仍在生效的预约（OPEN + MERGED）。
func (handler *PublishReservationHandler) List(context *gin.Context) {
	filter := service.PublishReservationFilter{
		Channel: strings.TrimSpace(context.Query("channel")),
		Status:  strings.TrimSpace(context.Query("status")),
	}
	if raw := strings.TrimSpace(context.Query("account_id")); raw != "" {
		accountID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || accountID <= 0 {
			writeError(context, http.StatusBadRequest, "account_id must be a positive integer")
			return
		}
		filter.AccountDBID = accountID
	}
	if raw := strings.TrimSpace(context.Query("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			writeError(context, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		filter.Limit = limit
	}
	if filter.Channel != "" && !isPublishChannel(filter.Channel) {
		writeError(context, http.StatusBadRequest, "channel must be one of: ticket, baseline")
		return
	}
	if filter.Status != "" && !isPublishReservationStatus(filter.Status) {
		writeError(context, http.StatusBadRequest, "status must be one of: OPEN, MERGED, RELEASED")
		return
	}

	reservations, err := handler.service.List(context.Request.Context(), filter)
	if err != nil {
		handler.logger.Error("failed to list publish reservations", "error", err)
		writeError(context, http.StatusInternalServerError, "failed to list publish reservations")
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"reservations": reservations,
		"total":        len(reservations),
	})
}

// releaseRequest 是管理员手动释放的入参：按渠道 + 持有者定位预约。
// 用 (channel, ref) 而不是预约 id，是因为运维看到的是「这张工单/这次
// 发布卡住了」，一次释放它的全部文件。
type releaseRequest struct {
	Channel string `json:"channel"`
	Ref     string `json:"ref"`
}

// Release handles POST /publish-reservations/release
// body: {"channel":"ticket","ref":"IAM-20261104-0001"}
func (handler *PublishReservationHandler) Release(context *gin.Context) {
	var request releaseRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	request.Channel = strings.TrimSpace(request.Channel)
	request.Ref = strings.TrimSpace(request.Ref)
	if !isPublishChannel(request.Channel) {
		writeError(context, http.StatusBadRequest, "channel must be one of: ticket, baseline")
		return
	}
	if request.Ref == "" {
		writeError(context, http.StatusBadRequest, "ref must not be empty")
		return
	}

	released, err := handler.service.ReleaseExpiredForAdmin(
		context.Request.Context(), request.Channel, request.Ref)
	if err != nil {
		handler.logger.Error("failed to release publish reservations",
			"channel", request.Channel, "ref", request.Ref, "error", err)
		writeError(context, http.StatusInternalServerError, "failed to release publish reservations")
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"channel":  request.Channel,
		"ref":      request.Ref,
		"released": released,
	})
}

func isPublishChannel(channel string) bool {
	return channel == service.PublishChannelTicket || channel == service.PublishChannelBaseline
}

func isPublishReservationStatus(status string) bool {
	switch status {
	case service.PublishReservationStatusOpen,
		service.PublishReservationStatusMerged,
		service.PublishReservationStatusReleased:
		return true
	default:
		return false
	}
}
