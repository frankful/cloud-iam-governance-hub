package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/xanzy/go-gitlab"
)

// GitLab 分支发布与文件元数据（B3）：与 GitHubPublisher.PublishBranch 同一
// 语义——确保分支 → 一次 commit 写入整批文件（已存在则更新，内容相同跳过）
// → 开/复用开放 MR。GitLab 的 blob_id 与 git blob SHA 同一算法，
// TerraformFileMeta 返回它即可与本地 gitBlobSHA 无下载比对。
//
// 为什么是「一次 commit」：逐文件 PUT 是 2N 次请求 + N 个提交（每次先 GET
// 比对内容再写），单账号 300+ 文件要十几分钟，PR 里还堆着几百个提交没法审。
// commits API 的 actions 一次写完，请求数与文件数无关。批量能力不是正确性的
// 前提：树读不到、动作数超限或提交报错都退回逐文件 upsert（幂等，慢但稳）。

// maxGitLabTreePages 给「整树分页」封顶：100 页 × 100 条 = 1 万个文件。超过
// 就当作读不到（退回逐文件），而不是无限翻页把发布卡死。
const maxGitLabTreePages = 100

// TerraformFileTree 一次拉取目标分支上 Terraform 目录的 blob 清单（仓库相对
// 路径 → blob id），实现 BundleRepoTreeLister：基线发布核对数百个文件时不必
// 逐文件走 files API。目录不存在（首次发布）返回空清单而不是错误——「一个文件
// 都没有」是合法状态，调用方会按新建处理。
func (publisher *GitLabSDKPublisher) TerraformFileTree(
	ctx context.Context,
) (map[string]string, error) {
	return publisher.terraformFileTreeAt(ctx, publisher.config.TargetBranch)
}

func (publisher *GitLabSDKPublisher) terraformFileTreeAt(
	ctx context.Context,
	ref string,
) (map[string]string, error) {
	blobs := make(map[string]string, 512)
	page := 1
	for pages := 0; pages < maxGitLabTreePages; pages++ {
		entries, response, err := publisher.client.Repositories.ListTree(
			publisher.config.ProjectID,
			&gitlab.ListTreeOptions{
				ListOptions: gitlab.ListOptions{PerPage: 100, Page: page},
				Path:        gitlab.String(publisher.config.TerraformPath),
				Ref:         gitlab.String(ref),
				Recursive:   gitlab.Bool(true),
			},
			gitlab.WithContext(ctx),
		)
		if err != nil {
			if response != nil && response.StatusCode == http.StatusNotFound {
				// 目录还不存在（首次发布）或分支刚建好：空清单，不是故障。
				return blobs, nil
			}
			return nil, fmt.Errorf("list GitLab tree %s@%s: %w",
				publisher.config.TerraformPath, ref, err)
		}
		for _, entry := range entries {
			if entry == nil || entry.Type != "blob" || entry.Path == "" {
				continue
			}
			blobs[entry.Path] = entry.ID
		}
		if response == nil || response.NextPage == 0 || len(entries) == 0 {
			break
		}
		page = response.NextPage
	}
	return blobs, nil
}

// TerraformFileMeta reports whether fileName exists on the target branch and,
// when it does, its git blob SHA. Implements BundleRepoChecker so the baseline
// bundle conflict check and the ownership-aware publish gate work on GitLab.
func (publisher *GitLabSDKPublisher) TerraformFileMeta(
	ctx context.Context,
	fileName string,
) (blobSHA string, exists bool, err error) {
	if strings.TrimSpace(fileName) == "" {
		return "", false, errors.New("file name must not be empty")
	}
	file, response, err := publisher.client.RepositoryFiles.GetFile(
		publisher.config.ProjectID,
		fileName,
		&gitlab.GetFileOptions{Ref: gitlab.String(publisher.config.TargetBranch)},
		gitlab.WithContext(ctx),
	)
	if err != nil {
		if response != nil && response.StatusCode == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, fmt.Errorf("fetch GitLab file meta %s: %w", fileName, err)
	}
	if file == nil {
		return "", false, fmt.Errorf("GitLab API returned no file for %s", fileName)
	}
	return file.BlobID, true, nil
}

// PublishBranch 执行分支发布（基线 B3 与工单共用语义）。
func (publisher *GitLabSDKPublisher) PublishBranch(
	ctx context.Context,
	req BranchPublishRequest,
) (*TicketPublishResult, error) {
	if strings.TrimSpace(req.Branch) == "" {
		return nil, errors.New("branch name is required for publication")
	}
	if strings.TrimSpace(req.Title) == "" {
		return nil, errors.New("commit title is required for publication")
	}
	if len(req.Files) == 0 {
		return nil, errors.New("at least one Terraform file is required for publication")
	}
	for _, file := range req.Files {
		// FileName 是完整仓库相对路径（含目录），只拒绝空、绝对路径与目录穿越。
		if strings.TrimSpace(file.FileName) == "" || path.IsAbs(file.FileName) ||
			strings.Contains(file.FileName, "..") {
			return nil, fmt.Errorf("invalid Terraform file name %q", file.FileName)
		}
	}

	if err := publisher.ensureBranch(ctx, req.Branch); err != nil {
		return nil, fmt.Errorf("prepare GitLab branch %s: %w", req.Branch, err)
	}
	if err := publisher.commitBranchFiles(ctx, req.Branch, req.Title, req.Files); err != nil {
		return nil, err
	}
	if mergeRequestURL, iid, found, err := publisher.findOpenMergeRequest(ctx, req.Branch); err != nil {
		return nil, fmt.Errorf("find existing GitLab Merge Request: %w", err)
	} else if found {
		return &TicketPublishResult{
			URL:                 mergeRequestURL,
			Provider:            "gitlab",
			Project:             publisher.config.ProjectID,
			RemoteRequestNumber: fmt.Sprintf("%d", iid),
		}, nil
	}

	mergeRequest, _, err := publisher.client.MergeRequests.CreateMergeRequest(
		publisher.config.ProjectID,
		&gitlab.CreateMergeRequestOptions{
			Title:        gitlab.String(req.Title),
			Description:  gitlab.String(req.Body),
			SourceBranch: gitlab.String(req.Branch),
			TargetBranch: gitlab.String(publisher.config.TargetBranch),
			// 分支删除归合并感知服务（BaselinePublicationMergeService）统一
			// 管：keep_branch 开启时保留分支作审计痕迹，GitLab 自动删除会
			// 绕过这个开关，所以这里不设 RemoveSourceBranch。
			RemoveSourceBranch: gitlab.Bool(false),
		},
		gitlab.WithContext(ctx),
	)
	if err != nil {
		// 与 GitHub 相同的重试安全网：上一次调用可能已建 MR 但没来得及落 URL。
		if existingURL, iid, found, lookupErr := publisher.findOpenMergeRequest(ctx, req.Branch); lookupErr == nil && found {
			return &TicketPublishResult{
				URL:                 existingURL,
				Provider:            "gitlab",
				Project:             publisher.config.ProjectID,
				RemoteRequestNumber: fmt.Sprintf("%d", iid),
			}, nil
		}
		return nil, fmt.Errorf("create GitLab Merge Request: %w", err)
	}
	if mergeRequest == nil || mergeRequest.WebURL == "" {
		return nil, errors.New("GitLab API returned a Merge Request without a web URL")
	}
	return &TicketPublishResult{
		URL:                 mergeRequest.WebURL,
		Provider:            "gitlab",
		Project:             publisher.config.ProjectID,
		RemoteRequestNumber: fmt.Sprintf("%d", mergeRequest.IID),
		CommitSHA:           mergeRequest.SHA,
	}, nil
}

// DeleteBranch 删除远端分支。分支不存在（已删/未建）不是错误——重试安全。
func (publisher *GitLabSDKPublisher) DeleteBranch(ctx context.Context, branch string) error {
	if strings.TrimSpace(branch) == "" {
		return errors.New("branch name must not be empty")
	}
	response, err := publisher.client.Branches.DeleteBranch(
		publisher.config.ProjectID,
		branch,
		nil,
		gitlab.WithContext(ctx),
	)
	if err != nil {
		if response != nil && response.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("delete GitLab branch %s: %w", branch, err)
	}
	return nil
}

func (publisher *GitLabSDKPublisher) ensureBranch(ctx context.Context, branch string) error {
	if _, _, err := publisher.client.Branches.GetBranch(
		publisher.config.ProjectID, branch, gitlab.WithContext(ctx),
	); err == nil {
		return nil
	}
	_, _, createErr := publisher.client.Branches.CreateBranch(
		publisher.config.ProjectID,
		&gitlab.CreateBranchOptions{
			Branch: gitlab.String(branch),
			Ref:    gitlab.String(publisher.config.TargetBranch),
		},
		gitlab.WithContext(ctx),
	)
	if createErr == nil {
		return nil
	}
	// 并发重试可能同时观察到分支缺失；对方已建成即接受竞态。
	if _, _, lookupErr := publisher.client.Branches.GetBranch(
		publisher.config.ProjectID, branch, gitlab.WithContext(ctx),
	); lookupErr == nil {
		return nil
	}
	return createErr
}

// commitBranchFiles 把整批文件作为一次提交写到分支上（commits API 的
// actions）。先读一次分支的树：既决定每个文件用 create 还是 update，也用来
// 跳过内容逐字节相同的文件（重试幂等，且不会产生空提交）。
//
// 任何一步不成立都退回逐文件 upsert：批量只是加速，不是正确性的前提。
func (publisher *GitLabSDKPublisher) commitBranchFiles(
	ctx context.Context,
	branch, commitMessage string,
	files []BranchPublishFile,
) error {
	if len(files) == 0 {
		return errors.New("at least one Terraform file is required to commit")
	}
	total := 0
	for _, file := range files {
		total += len(file.Content)
	}
	if len(files) > maxBatchCommitFiles || total > maxBatchCommitBytes {
		return publisher.upsertBranchFiles(ctx, branch, commitMessage, files)
	}
	existing, err := publisher.terraformFileTreeAt(ctx, branch)
	if err != nil {
		return publisher.upsertBranchFiles(ctx, branch, commitMessage, files)
	}

	actions := make([]*gitlab.CommitActionOptions, 0, len(files))
	for _, file := range files {
		if blob, ok := existing[file.FileName]; ok {
			if blob != "" && blob == gitBlobSHA(file.Content) {
				continue
			}
			// GitLab 的 create 在文件已存在时会整批失败，update 在文件不存在
			// 时同样失败——动作类型必须按树的实际内容选。
			actions = append(actions, &gitlab.CommitActionOptions{
				Action:   gitlab.FileAction(gitlab.FileUpdate),
				FilePath: gitlab.String(file.FileName),
				Content:  gitlab.String(file.Content),
			})
			continue
		}
		actions = append(actions, &gitlab.CommitActionOptions{
			Action:   gitlab.FileAction(gitlab.FileCreate),
			FilePath: gitlab.String(file.FileName),
			Content:  gitlab.String(file.Content),
		})
	}
	if len(actions) == 0 {
		// 全部与分支上一致：不提交（与逐文件 upsert 的「相同则跳过」等价）。
		return nil
	}
	if _, _, err := publisher.client.Commits.CreateCommit(
		publisher.config.ProjectID,
		&gitlab.CreateCommitOptions{
			Branch:        gitlab.String(branch),
			CommitMessage: gitlab.String(commitMessage),
			Actions:       actions,
		},
		gitlab.WithContext(ctx),
	); err != nil {
		// 竞态（树读完到提交之间文件被创建）、动作数上限、瞬时网络错误：
		// 逐文件 upsert 幂等且会重新比对内容，能把这批文件补齐。
		if fallbackErr := publisher.upsertBranchFiles(
			ctx, branch, commitMessage, files,
		); fallbackErr != nil {
			return fmt.Errorf("create GitLab commit: %w (per-file fallback: %v)", err, fallbackErr)
		}
	}
	return nil
}

func (publisher *GitLabSDKPublisher) upsertBranchFiles(
	ctx context.Context,
	branch, commitMessage string,
	files []BranchPublishFile,
) error {
	for _, file := range files {
		if err := publisher.upsertBranchFile(ctx, file.FileName, branch, commitMessage, file.Content); err != nil {
			return fmt.Errorf("commit Terraform file %s: %w", file.FileName, err)
		}
	}
	return nil
}

func (publisher *GitLabSDKPublisher) upsertBranchFile(
	ctx context.Context,
	fileName, branch, commitMessage, content string,
) error {
	// 先读现文件：内容相同直接跳过（幂等重试、减少 MR 噪音），存在则更新。
	file, _, err := publisher.client.RepositoryFiles.GetFile(
		publisher.config.ProjectID,
		fileName,
		&gitlab.GetFileOptions{Ref: gitlab.String(branch)},
		gitlab.WithContext(ctx),
	)
	if err == nil && file != nil {
		// GitLab contents API 的 content 恒为 base64（与 FetchTerraformFile
		// 同一约定）：先解码再比对。拿编码后的 blob 与明文比较，「内容相同
		// 跳过」永不命中，每次重试都会重复提交同一个文件。
		if decoded, decodeErr := base64.StdEncoding.DecodeString(
			strings.Join(strings.Fields(file.Content), ""),
		); decodeErr == nil && string(decoded) == content {
			return nil
		}
	}
	updateOptions := &gitlab.UpdateFileOptions{
		Branch:        gitlab.String(branch),
		Content:       gitlab.String(content),
		CommitMessage: gitlab.String(commitMessage),
	}
	if err == nil && file != nil {
		updateOptions.LastCommitID = gitlab.String(file.LastCommitID)
		if _, _, updateErr := publisher.client.RepositoryFiles.UpdateFile(
			publisher.config.ProjectID, fileName, updateOptions, gitlab.WithContext(ctx),
		); updateErr == nil {
			return nil
		} else {
			return updateErr
		}
	}
	if _, _, createErr := publisher.client.RepositoryFiles.CreateFile(
		publisher.config.ProjectID,
		fileName,
		&gitlab.CreateFileOptions{
			Branch:        gitlab.String(branch),
			Content:       gitlab.String(content),
			CommitMessage: gitlab.String(commitMessage),
		},
		gitlab.WithContext(ctx),
	); createErr != nil {
		// 竞态兜底：读时不存在、写时已被并发创建 → 改走更新。
		if _, _, updateErr := publisher.client.RepositoryFiles.UpdateFile(
			publisher.config.ProjectID, fileName, updateOptions, gitlab.WithContext(ctx),
		); updateErr == nil {
			return nil
		}
		return createErr
	}
	return nil
}

func (publisher *GitLabSDKPublisher) findOpenMergeRequest(
	ctx context.Context,
	branch string,
) (string, int, bool, error) {
	mergeRequests, _, err := publisher.client.MergeRequests.ListProjectMergeRequests(
		publisher.config.ProjectID,
		&gitlab.ListProjectMergeRequestsOptions{
			State:        gitlab.String("opened"),
			SourceBranch: gitlab.String(branch),
			TargetBranch: gitlab.String(publisher.config.TargetBranch),
		},
		gitlab.WithContext(ctx),
	)
	if err != nil {
		return "", 0, false, err
	}
	for _, mergeRequest := range mergeRequests {
		if mergeRequest != nil && mergeRequest.WebURL != "" {
			return mergeRequest.WebURL, mergeRequest.IID, true, nil
		}
	}
	return "", 0, false, nil
}

var (
	_ BaselineBranchPublisher = (*GitLabSDKPublisher)(nil)
	_ BundleRepoChecker       = (*GitLabSDKPublisher)(nil)
	_ BundleRepoTreeLister    = (*GitLabSDKPublisher)(nil)
	_ BaselineBranchCleaner   = (*GitLabSDKPublisher)(nil)
)
