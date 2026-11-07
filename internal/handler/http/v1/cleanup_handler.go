package v1

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type cleanupService interface {
	Build(context.Context, string) (*service.CleanupReport, error)
}

// CleanupHandler 暴露「待清理清单」：平台自己声明错的、以及 AWS 侧留下没用的资源。
// 只读——真正的删除动作在 IaC 仓库和 AWS 控制台，平台只负责指出来。
type CleanupHandler struct {
	service cleanupService
}

func NewCleanupHandler(cleanupService cleanupService) (*CleanupHandler, error) {
	if cleanupService == nil {
		return nil, errors.New("cleanup service must not be nil")
	}
	return &CleanupHandler{service: cleanupService}, nil
}

func RegisterCleanupRoutes(router gin.IRoutes, handler *CleanupHandler) {
	// 清单里带删除命令，收在平台管理员里；普通用户只需要看到资产清单。
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(
		http.MethodGet,
		"/aws/accounts/:accountID/cleanup-suggestions",
		append(admin, handler.List)...,
	)
}

func (handler *CleanupHandler) List(context *gin.Context) {
	ref := strings.TrimSpace(context.Param("accountID"))
	if ref == "" {
		writeError(context, http.StatusBadRequest, "accountID must not be empty")
		return
	}
	report, err := handler.service.Build(context.Request.Context(), ref)
	if err != nil {
		if errors.Is(err, service.ErrBaselineAccountNotFound) {
			writeError(context, http.StatusNotFound, err.Error())
			return
		}
		writeError(context, http.StatusInternalServerError, "failed to build cleanup suggestions")
		return
	}
	context.JSON(http.StatusOK, gin.H{"cleanup": report})
}
