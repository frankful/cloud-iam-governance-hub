package v1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type awsSyncRunService interface {
	TriggerManualSync(context.Context, int64, string) (service.AWSSyncRun, error)
	ListSyncRuns(context.Context, service.AWSSyncRunFilter) ([]service.AWSSyncRun, int, error)
	GetSyncRun(context.Context, int64) (service.AWSSyncRun, error)
	GetSyncRunChanges(context.Context, int64) (*service.AWSSyncChanges, error)
}

// syncWorkerStatusReader reports whether a sync worker is consuming the queue.
type syncWorkerStatusReader interface {
	WorkerStatus(context.Context) (service.AWSSyncWorkerStatus, error)
}

// AWSSyncRunHandler triggers manual AWS sync runs and exposes run history.
type AWSSyncRunHandler struct {
	service      awsSyncRunService
	workerStatus syncWorkerStatusReader
}

// NewAWSSyncRunHandler creates an AWSSyncRunHandler. The worker-status reader
// may be nil; the status endpoint then reports it as unconfigured.
func NewAWSSyncRunHandler(syncRunService awsSyncRunService, workerStatus syncWorkerStatusReader) (*AWSSyncRunHandler, error) {
	if syncRunService == nil {
		return nil, errors.New("AWS sync run service must not be nil")
	}
	return &AWSSyncRunHandler{service: syncRunService, workerStatus: workerStatus}, nil
}

// RegisterAWSSyncRunRoutes registers the manual sync trigger and run history
// endpoints under the account-config route family.
func RegisterAWSSyncRunRoutes(router gin.IRoutes, handler *AWSSyncRunHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodPost, "/aws/account-configs/:configID/sync", append(admin, handler.Trigger)...)
	router.Handle(http.MethodGet, "/aws/sync-runs", append(admin, handler.List)...)
	router.Handle(http.MethodGet, "/aws/sync-runs/:runID", append(admin, handler.Get)...)
	router.Handle(http.MethodGet, "/aws/sync-runs/:runID/changes.csv", append(admin, handler.DownloadChanges)...)
	router.Handle(http.MethodGet, "/aws/sync/worker-status", append(admin, handler.GetWorkerStatus)...)
}

// GetWorkerStatus handles GET /aws/sync/worker-status: heartbeat presence plus
// the pending queue depth, so stuck PENDING runs are explainable instead of
// silent.
func (handler *AWSSyncRunHandler) GetWorkerStatus(context *gin.Context) {
	if handler.workerStatus == nil {
		writeError(context, http.StatusServiceUnavailable, "sync worker status is not configured")
		return
	}
	status, err := handler.workerStatus.WorkerStatus(context.Request.Context())
	if err != nil {
		writeError(context, http.StatusServiceUnavailable, err.Error())
		return
	}
	context.JSON(http.StatusOK, gin.H{"worker": status})
}

// Trigger handles POST /aws/account-configs/:configID/sync. The AWS call runs
// in the sync worker; this only records and enqueues the run.
func (handler *AWSSyncRunHandler) Trigger(context *gin.Context) {
	actorID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	configID, ok := parseAWSAccountConfigID(context)
	if !ok {
		return
	}
	run, err := handler.service.TriggerManualSync(context.Request.Context(), configID, actorID)
	if err != nil {
		writeAWSSyncRunError(context, err)
		return
	}
	context.JSON(http.StatusAccepted, gin.H{"sync_run": run})
}

// List handles GET /aws/sync-runs.
func (handler *AWSSyncRunHandler) List(context *gin.Context) {
	filter := service.AWSSyncRunFilter{
		ConfigID:     parseOptionalPositiveInt64(context, "config_id"),
		AWSAccountID: strings.TrimSpace(context.Query("account_id")),
		Status:       strings.TrimSpace(context.Query("status")),
		Limit:        20,
		Offset:       0,
	}
	if filter.ConfigID == -1 {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	runs, total, err := handler.service.ListSyncRuns(context.Request.Context(), filter)
	if err != nil {
		writeAWSSyncRunError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"sync_runs": runs, "total": total, "limit": limit, "offset": offset,
	})
}

// Get handles GET /aws/sync-runs/:runID.
func (handler *AWSSyncRunHandler) Get(context *gin.Context) {
	runID, ok := parsePolicyDerivedID(context, "runID")
	if !ok {
		return
	}
	run, err := handler.service.GetSyncRun(context.Request.Context(), runID)
	if err != nil {
		writeAWSSyncRunError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"sync_run": run})
}

// DownloadChanges handles GET /aws/sync-runs/:runID/changes.csv: the inventory
// diff of one sync run (newly discovered and disappeared principals/groups)
// as a CSV attachment for offline comparison.
func (handler *AWSSyncRunHandler) DownloadChanges(context *gin.Context) {
	runID, ok := parsePolicyDerivedID(context, "runID")
	if !ok {
		return
	}
	changes, err := handler.service.GetSyncRunChanges(context.Request.Context(), runID)
	if err != nil {
		writeAWSSyncRunError(context, err)
		return
	}
	if changes == nil {
		writeError(context, http.StatusNotFound, "no change record for this sync run")
		return
	}

	context.Header("Content-Type", "text/csv; charset=utf-8")
	context.Header("Content-Disposition",
		fmt.Sprintf(`attachment; filename="sync-run-%d-changes.csv"`, runID))
	context.String(http.StatusOK, renderSyncChangesCSV(changes))
}

// renderSyncChangesCSV flattens the diff into one row per changed asset.
func renderSyncChangesCSV(changes *service.AWSSyncChanges) string {
	var builder strings.Builder
	builder.WriteString("category,action,name,type,arn\n")
	writeRows := func(category, action string, rows []service.AWSSyncAssetChange) {
		for _, row := range rows {
			fmt.Fprintf(&builder, "%s,%s,%s,%s,%s\n",
				category, action, csvField(row.Name), csvField(row.Type), csvField(row.ARN))
		}
	}
	writeRows("principal", "ADDED", changes.PrincipalsAdded)
	writeRows("principal", "REMOVED", changes.PrincipalsRemoved)
	writeRows("group", "ADDED", changes.GroupsAdded)
	writeRows("group", "REMOVED", changes.GroupsRemoved)
	return builder.String()
}

// csvField quotes a CSV cell when it contains a comma, quote, or newline.
func csvField(value string) string {
	if !strings.ContainsAny(value, ",\"\n\r") {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func writeAWSSyncRunError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrAWSAccountConfigNotFound):
		writeError(context, http.StatusNotFound, "AWS account configuration not found")
	case errors.Is(err, service.ErrSyncRunNotFound):
		writeError(context, http.StatusNotFound, "AWS sync run not found")
	case errors.Is(err, service.ErrSyncRunAlreadyActive):
		// RUNNING 不抢占（正在写库存）；同优先级 PENDING 维持去重。
		// 提示操作员稍候或在同步记录里查看在途 run。
		writeError(context, http.StatusConflict,
			"an AWS sync run is already pending or running for this account; it usually finishes within a few minutes — check the sync history")
	case errors.Is(err, service.ErrSyncDisabled):
		writeError(context, http.StatusConflict, "AWS account sync is disabled; enable it before triggering a sync")
	case errors.Is(err, service.ErrInvalidSyncRunStatus):
		writeError(context, http.StatusBadRequest, err.Error())
	case errors.Is(err, service.ErrSyncEnqueueFailed):
		writeError(context, http.StatusInternalServerError, "failed to enqueue AWS sync run")
	default:
		var validationError *service.AWSAccountConfigValidationError
		if errors.As(err, &validationError) {
			writeError(context, http.StatusBadRequest, validationError.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to trigger AWS sync run")
	}
}
