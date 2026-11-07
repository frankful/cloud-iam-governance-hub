package v1

import (
	stdcontext "context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

// baselineDeclarationService 是声明快照的运维面（phase4 §4.6）：看清「这个
// 账号的漂移基准由哪些声明构成」，以及手动触发一次新鲜度核对。
type baselineDeclarationService interface {
	LoadCurrent(ctx stdcontext.Context, accountDBID int64) ([]service.BaselineDeclaration, error)
	ReconcileFreshness(
		ctx stdcontext.Context,
		accountDBID int64,
		repoDirectory string,
		reader service.DeclarationFileMetaReader,
	) (*service.DeclarationFreshnessReport, error)
}

// BaselineDeclarationHandler 暴露声明快照。只读 + 一次显式的核对触发：
// 声明由发布链路写、由作废链路撤，人工不该直接改（那会让基准与仓库脱节，
// 正是这一期要消灭的东西）。
type BaselineDeclarationHandler struct {
	service       baselineDeclarationService
	reader        service.DeclarationFileMetaReader
	terraformPath string
	logger        *slog.Logger
}

func NewBaselineDeclarationHandler(
	declarations baselineDeclarationService,
	reader service.DeclarationFileMetaReader,
	terraformPath string,
	logger *slog.Logger,
) (*BaselineDeclarationHandler, error) {
	if declarations == nil {
		return nil, errors.New("baseline declaration service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BaselineDeclarationHandler{
		service:       declarations,
		reader:        reader,
		terraformPath: strings.TrimSpace(terraformPath),
		logger:        logger,
	}, nil
}

func RegisterBaselineDeclarationRoutes(router gin.IRoutes, handler *BaselineDeclarationHandler) {
	admin := []gin.HandlerFunc{RequireRoles("platform_admin")}
	router.Handle(http.MethodGet, "/baseline-declarations", append(admin, handler.List)...)
	router.Handle(http.MethodPost, "/baseline-declarations/refresh", append(admin, handler.Refresh)...)
}

// declarationFileSummary 按文件汇总：运维关心「哪个文件的声明不新鲜」，
// 而不是逐条资源。
type declarationFileSummary struct {
	FileKey        string `json:"file_key"`
	Declarations   int    `json:"declarations"`
	Stale          int    `json:"stale"`
	ContentBlobSHA string `json:"content_blob_sha,omitempty"`
}

// List handles GET /baseline-declarations?account_id=<db id>
// 返回该账号当前生效的声明（含过期标记）与按文件的汇总。
func (handler *BaselineDeclarationHandler) List(context *gin.Context) {
	accountID, ok := accountIDQuery(context)
	if !ok {
		return
	}
	declarations, err := handler.service.LoadCurrent(context.Request.Context(), accountID)
	if err != nil {
		handler.logger.Error("failed to load baseline declarations",
			"account_id", accountID, "error", err)
		writeError(context, http.StatusInternalServerError, "failed to load baseline declarations")
		return
	}

	summaries := make(map[string]*declarationFileSummary, len(declarations))
	staleDeclarations := 0
	awsAccountID := ""
	for index := range declarations {
		declaration := declarations[index]
		if awsAccountID == "" {
			awsAccountID = declaration.AWSAccountID
		}
		summary, exists := summaries[declaration.FileKey]
		if !exists {
			summary = &declarationFileSummary{
				FileKey:        declaration.FileKey,
				ContentBlobSHA: declaration.ContentBlobSHA,
			}
			summaries[declaration.FileKey] = summary
		}
		summary.Declarations++
		if declaration.StaleAt != nil {
			summary.Stale++
			staleDeclarations++
		}
	}
	files := make([]declarationFileSummary, 0, len(summaries))
	for _, summary := range summaries {
		files = append(files, *summary)
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].FileKey < files[right].FileKey
	})

	context.JSON(http.StatusOK, gin.H{
		"account_id":     accountID,
		"aws_account_id": awsAccountID,
		"total":          len(declarations),
		"stale":          staleDeclarations,
		"files":          files,
		"declarations":   declarations,
	})
}

// Refresh handles POST /baseline-declarations/refresh {"account_id": 7}
// 触发一次新鲜度核对：比对声明记的 blob SHA 与 main 现文件，写回
// baseline_stale 标记。声明为空时直接返回空报告（没有基准可比）。
func (handler *BaselineDeclarationHandler) Refresh(context *gin.Context) {
	var request struct {
		AccountID int64 `json:"account_id"`
	}
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if request.AccountID <= 0 {
		writeError(context, http.StatusBadRequest, "account_id must be a positive integer")
		return
	}
	if handler.reader == nil {
		// 没配发布器就没有仓库可读：显式说明，而不是返回一份「全部新鲜」
		// 的假报告——那会让人以为基准是可信的。
		writeError(context, http.StatusConflict,
			"git publisher is not configured; declaration freshness cannot be verified")
		return
	}
	declarations, err := handler.service.LoadCurrent(context.Request.Context(), request.AccountID)
	if err != nil {
		handler.logger.Error("failed to load baseline declarations",
			"account_id", request.AccountID, "error", err)
		writeError(context, http.StatusInternalServerError, "failed to load baseline declarations")
		return
	}
	if len(declarations) == 0 {
		context.JSON(http.StatusOK, service.DeclarationFreshnessReport{
			AccountDBID: request.AccountID,
			Files:       []service.DeclarationFreshnessFile{},
		})
		return
	}
	report, err := handler.service.ReconcileFreshness(
		context.Request.Context(),
		request.AccountID,
		service.BaselineRepoDirectory(handler.terraformPath, declarations[0].AWSAccountID),
		handler.reader,
	)
	if err != nil {
		handler.logger.Error("failed to reconcile declaration freshness",
			"account_id", request.AccountID, "error", err)
		writeError(context, http.StatusInternalServerError, "failed to reconcile declaration freshness")
		return
	}
	context.JSON(http.StatusOK, report)
}

// accountIDQuery 解析 ?account_id=（数据库主键，与预约表同一口径）。
func accountIDQuery(context *gin.Context) (int64, bool) {
	raw := strings.TrimSpace(context.Query("account_id"))
	if raw == "" {
		writeError(context, http.StatusBadRequest, "account_id is required")
		return 0, false
	}
	accountID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || accountID <= 0 {
		writeError(context, http.StatusBadRequest, "account_id must be a positive integer")
		return 0, false
	}
	return accountID, true
}
