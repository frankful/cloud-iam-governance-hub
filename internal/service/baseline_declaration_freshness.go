package service

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

// 声明新鲜度核对（phase4-drift-design.md §4.6「baseline_stale」）。
//
// 声明快照记的是「我们以为 main 上是什么」（content_blob_sha）。如果有人
// 绕过平台直接改 main 上的 tf 文件，文件内容就与声明不一致——这时库存与
// 声明的差异不是漂移，是「基准过期」：拿一份过期基准去判「线上被改坏了」
// 会天天误报，最后所有人学会忽略告警。所以判定前先核对文件，过期的声明
// 打标记并跳过（P3 报 baseline_stale 这条独立发现，而不是漂移）。
//
// 核对只读仓库（GitHub/GitLab contents API 的 blob SHA），不下载文件体。

// 过期原因。用常量而不是自由文本：P3 与页面按原因分流处置
// （FILE_MISSING 要看是不是文件被删/改名，CONTENT_CHANGED 要查是谁改的）。
const (
	// DeclarationStaleFileMissing 表示声明所在的文件在 main 上已经不存在。
	DeclarationStaleFileMissing = "FILE_MISSING"
	// DeclarationStaleContentChanged 表示文件还在，但内容已不是声明时的版本。
	DeclarationStaleContentChanged = "CONTENT_CHANGED"
	// DeclarationStaleNoContentHash 表示声明没记 blob SHA（历史数据），无从核对。
	DeclarationStaleNoContentHash = "NO_CONTENT_HASH"
)

// DeclarationFileMetaReader 读目标分支上文件的 blob SHA。实现方是发布器
// （GitHubPublisher / GitLabSDKPublisher），与基线预览的存在性检查同源。
type DeclarationFileMetaReader interface {
	TerraformFileMeta(ctx context.Context, fileName string) (blobSHA string, exists bool, err error)
}

// DeclarationFreshnessFile 是一个文件（同一份内容的全部声明）的核对结论。
type DeclarationFreshnessFile struct {
	FileKey        string `json:"file_key"`
	ContentBlobSHA string `json:"content_blob_sha,omitempty"`
	// LiveBlobSHA 是 main 上现文件的 blob SHA，文件不存在时为空。
	LiveBlobSHA  string `json:"live_blob_sha,omitempty"`
	Declarations int    `json:"declarations"`
	// Verified 为 false 表示这次没读到远端（网络/权限），状态保持原样：
	// 一次读失败绝不能把整个账号的声明判成过期，那会静默关掉漂移检测。
	Verified bool   `json:"verified"`
	Stale    bool   `json:"stale"`
	Reason   string `json:"reason,omitempty"`
}

// DeclarationFreshnessReport 是一次核对的结果。
type DeclarationFreshnessReport struct {
	AccountDBID int64 `json:"account_id"`
	// Files 逐文件（逐内容版本）列出结论，按文件名字典序。
	Files []DeclarationFreshnessFile `json:"files"`
	// FilesChecked / FilesUnverified / FilesStale 是文件级计数。
	FilesChecked    int `json:"files_checked"`
	FilesUnverified int `json:"files_unverified"`
	FilesStale      int `json:"files_stale"`
	// StaleDeclarations 是受影响的声明条数（漂移判定会跳过它们）。
	StaleDeclarations int `json:"stale_declarations"`
}

// BaselineRepoDirectory 是一个账号的 Terraform 目录：<terraformPath>/
// account-<AWS账号ID>。与发布器写文件、基线 bundle 的路径检查完全同源。
func BaselineRepoDirectory(terraformPath, awsAccountID string) string {
	terraformPath = strings.TrimSpace(terraformPath)
	if terraformPath == "" {
		terraformPath = "iam"
	}
	return path.Join(terraformPath, "account-"+strings.TrimSpace(awsAccountID))
}

// ReconcileFreshness 核对一个账号的全部当前声明与 main 的差异，并把结论
// 写回 stale_at / stale_reason。repoDirectory 是该账号的 Terraform 目录
// （见 BaselineRepoDirectory）。
//
// 写回是「只在状态变化时更新」：核对会被周期性调用，绝大多数轮次什么都不
// 变，不该每次都刷新 stale_at（时间戳一抖，页面上「多久之前过期」就失真）。
func (service *BaselineDeclarationService) ReconcileFreshness(
	ctx context.Context,
	accountDBID int64,
	repoDirectory string,
	reader DeclarationFileMetaReader,
) (*DeclarationFreshnessReport, error) {
	if accountDBID <= 0 {
		return nil, errors.New("declaration freshness requires an account id")
	}
	if reader == nil {
		return nil, errors.New("declaration freshness requires a repository reader")
	}
	if strings.TrimSpace(repoDirectory) == "" {
		return nil, errors.New("declaration freshness requires a repository directory")
	}

	rows, err := service.db.QueryContext(ctx, `
		SELECT file_key, content_blob_sha, COUNT(*), COUNT(stale_at)
		FROM iam_baseline_declaration
		WHERE account_id = $1 AND superseded_at IS NULL
		GROUP BY file_key, content_blob_sha
		ORDER BY file_key, content_blob_sha`, accountDBID)
	if err != nil {
		return nil, fmt.Errorf("load declaration files: %w", err)
	}
	type declarationFile struct {
		fileKey      string
		contentSHA   string
		declarations int
		staleRows    int
	}
	var files []declarationFile
	for rows.Next() {
		var item declarationFile
		if err := rows.Scan(&item.fileKey, &item.contentSHA,
			&item.declarations, &item.staleRows); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan declaration file: %w", err)
		}
		files = append(files, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate declaration files: %w", err)
	}

	report := &DeclarationFreshnessReport{
		AccountDBID: accountDBID,
		Files:       make([]DeclarationFreshnessFile, 0, len(files)),
	}
	// 与 bundle 构建同一优化：一次整树清单（1 次请求）替代逐文件 contents
	// 查询；拿不到时才退回逐文件（读取器没有批量能力/网络失败/清单截断）。
	tree := loadRepoTerraformTree(ctx, reader)
	for index := 0; index < len(files); {
		fileKey := files[index].fileKey
		// 同一文件可能有多份内容版本：作废恢复会把上一条声明的内容带回来，
		// 这时文件里同时存在两代 blob SHA，必须逐版本核对。
		end := index
		for end < len(files) && files[end].fileKey == fileKey {
			end++
		}
		var liveSHA string
		var exists bool
		var metaErr error
		if tree != nil {
			liveSHA, exists = tree[path.Join(repoDirectory, fileKey+".tf")]
		} else {
			liveSHA, exists, metaErr = reader.TerraformFileMeta(
				ctx, path.Join(repoDirectory, fileKey+".tf"))
		}
		report.FilesChecked++
		for _, item := range files[index:end] {
			entry := DeclarationFreshnessFile{
				FileKey:        item.fileKey,
				ContentBlobSHA: item.contentSHA,
				Declarations:   item.declarations,
			}
			if metaErr != nil {
				report.FilesUnverified++
				entry.Verified = false
				report.Files = append(report.Files, entry)
				continue
			}
			entry.Verified = true
			entry.LiveBlobSHA = liveSHA
			switch {
			case !exists:
				entry.Stale = true
				entry.Reason = DeclarationStaleFileMissing
			case item.contentSHA == "":
				entry.Stale = true
				entry.Reason = DeclarationStaleNoContentHash
			case item.contentSHA != liveSHA:
				entry.Stale = true
				entry.Reason = DeclarationStaleContentChanged
			}
			if entry.Stale {
				report.FilesStale++
				report.StaleDeclarations += item.declarations
			}
			// 只在状态翻转时写：已经是 stale 的再标一次没有意义，还会让
			// 「过期多久了」这个时间戳失真。
			if entry.Stale && item.staleRows < item.declarations {
				if err := service.markFileStale(ctx, accountDBID, item.fileKey,
					item.contentSHA, entry.Reason); err != nil {
					return nil, err
				}
			}
			if !entry.Stale && item.staleRows > 0 {
				if err := service.clearFileStale(ctx, accountDBID, item.fileKey,
					item.contentSHA); err != nil {
					return nil, err
				}
			}
			report.Files = append(report.Files, entry)
		}
		index = end
	}
	if report.FilesChecked > 0 {
		service.logger.Info("baseline declaration freshness reconciled",
			"account_id", accountDBID,
			"files", report.FilesChecked,
			"stale_files", report.FilesStale,
			"unverified_files", report.FilesUnverified,
			"stale_declarations", report.StaleDeclarations,
		)
	}
	return report, nil
}

// markFileStale 给「同一文件 + 同一内容版本」的当前声明打过期标记。按内容
// 版本而不是按文件整批标记：恢复回来的上一代声明仍然对应 main 上的旧内容
// （如果 main 真是旧内容，它们其实是新鲜的）。
func (service *BaselineDeclarationService) markFileStale(
	ctx context.Context, accountDBID int64, fileKey, contentSHA, reason string,
) error {
	if _, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_declaration
		SET stale_at = NOW(), stale_reason = $4
		WHERE account_id = $1 AND file_key = $2 AND content_blob_sha = $3
		  AND superseded_at IS NULL`, accountDBID, fileKey, contentSHA, reason); err != nil {
		return fmt.Errorf("mark declarations of %s stale: %w", fileKey, err)
	}
	return nil
}

func (service *BaselineDeclarationService) clearFileStale(
	ctx context.Context, accountDBID int64, fileKey, contentSHA string,
) error {
	if _, err := service.db.ExecContext(ctx, `
		UPDATE iam_baseline_declaration
		SET stale_at = NULL, stale_reason = NULL
		WHERE account_id = $1 AND file_key = $2 AND content_blob_sha = $3
		  AND superseded_at IS NULL AND stale_at IS NOT NULL`,
		accountDBID, fileKey, contentSHA); err != nil {
		return fmt.Errorf("clear stale declarations of %s: %w", fileKey, err)
	}
	return nil
}

// StaleDeclarationFiles 返回账号里已过期声明的文件名集合：判定侧据此跳过
// 比对（这些资源的差异是「基准过期」，不是漂移）。返回 nil 表示全部新鲜。
func StaleDeclarationFiles(declarations []BaselineDeclaration) map[string]bool {
	if len(declarations) == 0 {
		return nil
	}
	stale := make(map[string]bool)
	for _, declaration := range declarations {
		if declaration.StaleAt != nil {
			stale[declaration.FileKey] = true
		}
	}
	return stale
}
