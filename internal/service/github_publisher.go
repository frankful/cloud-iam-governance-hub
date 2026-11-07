package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	defaultGitHubAPIURL = "https://api.github.com"
	gitHubAPIVersion    = "2022-11-28"
	maxGitHubBodySize   = 1 << 20
	// maxGitHubTreeBodySize 是 git/trees 响应的读取上限：整个仓库的文件清单
	// 远比单个文件大（一次基线发布要查数百个路径）。
	maxGitHubTreeBodySize = 8 << 20
	// Git Data API 单次建树的上限（GitHub 侧为 100,000 条目 / 7 MB）。超过
	// 就退回逐文件 upsert——慢，但不会被一次超限请求卡死。
	maxBatchCommitFiles = 5000
	maxBatchCommitBytes = 6 << 20
)

// GitHubConfig configures publishing Terraform changes as a GitHub Pull Request.
// Repository must be in owner/name form. BaseURL may point to a GitHub Enterprise
// API endpoint, for example https://github.example.com/api/v3.
type GitHubConfig struct {
	BaseURL       string
	Token         string
	Repository    string
	TargetBranch  string
	TerraformPath string
}

// GitHubPublisher implements TicketPublisher without changing the GitLab path.
type GitHubPublisher struct {
	client *http.Client
	config GitHubConfig
	apiURL string
}

func NewGitHubPublisher(config GitHubConfig) (*GitHubPublisher, error) {
	config.Token = strings.TrimSpace(config.Token)
	if config.Token == "" {
		return nil, errors.New("GitHub token must not be empty")
	}
	owner, repository, ok := strings.Cut(strings.TrimSpace(config.Repository), "/")
	if !ok || owner == "" || repository == "" || strings.Contains(repository, "/") {
		return nil, errors.New("GitHub repository must be in owner/name form")
	}
	config.Repository = owner + "/" + repository
	if strings.TrimSpace(config.TargetBranch) == "" {
		config.TargetBranch = "main"
	}
	if strings.TrimSpace(config.TerraformPath) == "" {
		config.TerraformPath = "iam"
	}

	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultGitHubAPIURL
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || (parsedURL.Scheme != "https" && parsedURL.Hostname() != "127.0.0.1" && parsedURL.Hostname() != "localhost") {
		return nil, errors.New("GitHub API URL must be HTTPS (HTTP is allowed only for localhost)")
	}
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, errors.New("GitHub API URL must not contain a query or fragment")
	}

	return &GitHubPublisher{
		client: &http.Client{
			Timeout: maxCodeHostRequestDuration,
			// otelhttp creates one span per GitHub API call; no-op without a provider.
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
		config: config,
		apiURL: baseURL,
	}, nil
}

func (publisher *GitHubPublisher) Publish(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	terraformCode string,
) (*TicketPublishResult, error) {
	if ticket.TicketNo == nil {
		return nil, errors.New("ticket number is required for GitHub publication")
	}
	fileKey := strings.ToLower(request.terraformFileTicketNo(*ticket.TicketNo))
	return publisher.publishFiles(ctx, ticket, request, []TerraformBundleFile{{Key: fileKey, Content: terraformCode}})
}

func (publisher *GitHubPublisher) PublishBundle(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	files []TerraformBundleFile,
) (*TicketPublishResult, error) {
	return publisher.publishFiles(ctx, ticket, request, files)
}

// BranchPublishFile 是提交到一个分支的单个文件：完整仓库相对路径 + 内容。
type BranchPublishFile struct {
	FileName string
	Content  string
}

// BranchPublishRequest 描述一次「确保分支 → 整批提交 → 开/复用 PR」的发布。
// 工单链路与基线发布（B3）共用：分支名、标题、描述、文件清单由调用方决定，
// 本方法只负责幂等地落到仓库。已有同 head 的开放 PR 时直接复用，不重复创建。
type BranchPublishRequest struct {
	Branch string
	Title  string
	Body   string
	Files  []BranchPublishFile
}

// PublishBranch 执行分支发布。调用方负责给 ctx 设超时（工单链路 5 倍单请求
// 上限；基线一次可达数百文件，由发布服务自己给更长的上限）。
func (publisher *GitHubPublisher) PublishBranch(
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
		return nil, fmt.Errorf("prepare GitHub branch %s: %w", req.Branch, err)
	}
	if err := publisher.commitBranchFiles(ctx, req.Branch, req.Title, req.Files); err != nil {
		return nil, err
	}
	if pullRequestURL, prNumber, found, err := publisher.findOpenPullRequest(ctx, req.Branch); err != nil {
		return nil, fmt.Errorf("find existing GitHub Pull Request: %w", err)
	} else if found {
		return &TicketPublishResult{
			URL:                 pullRequestURL,
			Provider:            "github",
			Project:             publisher.config.Repository,
			RemoteRequestNumber: fmt.Sprintf("%d", prNumber),
		}, nil
	}

	var pullRequest struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	err := publisher.requestJSON(
		ctx,
		http.MethodPost,
		publisher.repositoryURL("/pulls"),
		map[string]string{
			"title": req.Title, "body": req.Body, "head": req.Branch,
			"base": publisher.config.TargetBranch,
		},
		http.StatusCreated,
		&pullRequest,
	)
	if err != nil {
		// A previous attempt may have created the PR but failed before saving
		// its URL. Re-read open PRs to make publication retry-safe.
		if existingURL, prNumber, found, lookupErr := publisher.findOpenPullRequest(ctx, req.Branch); lookupErr == nil && found {
			return &TicketPublishResult{
				URL:                 existingURL,
				Provider:            "github",
				Project:             publisher.config.Repository,
				RemoteRequestNumber: fmt.Sprintf("%d", prNumber),
			}, nil
		}
		return nil, fmt.Errorf("create GitHub Pull Request: %w", err)
	}
	if strings.TrimSpace(pullRequest.HTMLURL) == "" {
		return nil, errors.New("GitHub API returned a Pull Request without a web URL")
	}
	return &TicketPublishResult{
		URL:                 pullRequest.HTMLURL,
		Provider:            "github",
		Project:             publisher.config.Repository,
		RemoteRequestNumber: fmt.Sprintf("%d", pullRequest.Number),
	}, nil
}

func (publisher *GitHubPublisher) publishFiles(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
	files []TerraformBundleFile,
) (*TicketPublishResult, error) {
	if ticket.TicketNo == nil || strings.TrimSpace(*ticket.TicketNo) == "" {
		return nil, errors.New("ticket number is required for GitHub publication")
	}
	if ticket.AccountID == nil {
		return nil, errors.New("ticket account ID is required for GitHub publication")
	}
	if !isAWSAccountID(request.AWSAccountID) {
		return nil, errors.New("valid AWS account ID is required for GitHub publication")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, maxPublishSequenceDuration)
	defer cancel()

	ticketNo := *ticket.TicketNo
	sourceBranch := "iam-ticket/" + strings.ToLower(ticketNo)
	if len(files) == 0 {
		return nil, errors.New("at least one Terraform file is required for GitHub publication")
	}
	directory := path.Join(publisher.config.TerraformPath, "account-"+request.AWSAccountID)
	branchFiles := make([]BranchPublishFile, 0, len(files))
	for _, file := range files {
		if strings.TrimSpace(file.Key) == "" || path.Base(file.Key) != file.Key || strings.ContainsAny(file.Key, `/\`) {
			return nil, fmt.Errorf("invalid Terraform bundle file key %q", file.Key)
		}
		branchFiles = append(branchFiles, BranchPublishFile{
			FileName: path.Join(directory, file.Key+".tf"),
			Content:  file.Content,
		})
	}
	title := fmt.Sprintf("IAM ticket %s: %s", ticketNo, request.PrincipalName)
	if request.TicketType == TicketTypeRollback {
		title = fmt.Sprintf("Rollback %s of IAM ticket %s: %s", ticketNo, request.TargetTicketNo, request.PrincipalName)
	}
	description := fmt.Sprintf("Generated Terraform for IAM ticket %s.\n\nSubmitter: %s", ticketNo, valueOrEmpty(ticket.Submitter))

	return publisher.PublishBranch(timeoutCtx, BranchPublishRequest{
		Branch: sourceBranch,
		Title:  title,
		Body:   description,
		Files:  branchFiles,
	})
}

// FetchTerraformFile reads the ticket's Terraform file from the target branch
// (main) via the GitHub contents API (base64). UPDATE_ROLE 块级 patch 以 main
// 上的现文件为基底，读取失败即报错（不静默回退整文件生成——那会重新引入互踩）。
func (publisher *GitHubPublisher) FetchTerraformFile(
	ctx context.Context,
	ticket model.IAMTicket,
	request CreateIAMTicketRequest,
) (string, error) {
	if ticket.AccountID == nil {
		return "", errors.New("ticket account ID is required to fetch Terraform file")
	}
	if !isAWSAccountID(request.AWSAccountID) {
		return "", errors.New("valid AWS account ID is required to fetch Terraform file")
	}
	fallback := ""
	if ticket.TicketNo != nil {
		fallback = *ticket.TicketNo
	}
	fileName := path.Join(
		publisher.config.TerraformPath,
		"account-"+request.AWSAccountID,
		strings.ToLower(request.terraformFileTicketNo(fallback))+".tf",
	)
	endpoint := fmt.Sprintf("%s?ref=%s",
		publisher.repositoryURL("/contents/"+fileName),
		url.QueryEscape(publisher.config.TargetBranch),
	)
	// Direct request instead of requestJSON: a 404 is a meaningful answer
	// ("file not on main yet"), not a transport failure — see
	// ErrTerraformFileNotFound.
	// 瞬态传输错误（EOF/连接重置，status==0）小退避重试：校验预览与发布
	// 共用此读取路径，GitHub 网络抖动不应直接变成用户的 500。实测出口
	// 网络对 GitHub 有时连续丢包（失败率可达 50%），3 次不够，5 次退避
	// 共 ~4 秒把单次读取成功率抬到 ~97%。
	var responseBody []byte
	var status int
	var err error
	const fetchAttempts = 5
	for attempt := 1; attempt <= fetchAttempts; attempt++ {
		responseBody, status, err = publisher.request(ctx, http.MethodGet, endpoint, nil)
		if err == nil || status != 0 {
			break
		}
		if attempt == fetchAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("fetch Terraform file %s: %w", fileName, ctx.Err())
		case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
		}
	}
	if err != nil {
		if status == http.StatusNotFound {
			return "", fmt.Errorf("%w: %s (branch %s)",
				ErrTerraformFileNotFound, fileName, publisher.config.TargetBranch)
		}
		return "", fmt.Errorf("fetch Terraform file %s: %w", fileName, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("fetch Terraform file %s: GitHub API returned unexpected status %d", fileName, status)
	}
	var response struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("decode Terraform file %s: %w", fileName, err)
	}
	content, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(response.Content, "\n", ""))
	if err != nil {
		return "", fmt.Errorf("decode Terraform file %s: %w", fileName, err)
	}
	if strings.TrimSpace(string(content)) == "" {
		return "", fmt.Errorf("Terraform file %s is empty on branch %s", fileName, publisher.config.TargetBranch)
	}
	return string(content), nil
}

// TerraformFileMeta reports whether fileName exists on the target branch and,
// when it does, its git blob SHA. Read-only contents API call; implements the
// baseline bundle's conflict check, and lets the publish step compare the SHA
// against a locally computed blob SHA of the desired content to detect real
// changes without downloading file bodies.
func (publisher *GitHubPublisher) TerraformFileMeta(
	ctx context.Context,
	fileName string,
) (blobSHA string, exists bool, err error) {
	if strings.TrimSpace(fileName) == "" {
		return "", false, errors.New("file name must not be empty")
	}
	endpoint := publisher.repositoryURL("/contents/"+escapeGitHubPath(fileName)) +
		"?ref=" + url.QueryEscape(publisher.config.TargetBranch)
	responseBody, status, err := publisher.request(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		if status == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	var contents struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(responseBody, &contents); err != nil {
		return "", false, fmt.Errorf("decode GitHub contents response for %s: %w", fileName, err)
	}
	return contents.SHA, true, nil
}

// DeleteBranch 删除远端分支（合并感知用）。分支不存在（已被删除/从未创建）
// 不是错误——重试安全。
func (publisher *GitHubPublisher) DeleteBranch(ctx context.Context, branch string) error {
	if strings.TrimSpace(branch) == "" {
		return errors.New("branch name must not be empty")
	}
	_, status, err := publisher.request(
		ctx, http.MethodDelete,
		publisher.repositoryURL("/git/refs/heads/"+escapeGitHubPath(branch)), nil,
	)
	if err != nil {
		if status == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("delete GitHub branch %s: %w", branch, err)
	}
	return nil
}

// TerraformFileTree 一次拉取目标分支上全部 blob 的「仓库相对路径 → git blob
// SHA」。基线发布要核对数百个文件是否已存在、内容是否变化：逐文件读 contents
// API 是 N 次串行请求（实测 338 个文件约 128 秒，网络抖动时还能翻几倍），而
// git/trees 一次就够。返回 error（含 truncated）时调用方退回逐文件查询——
// 批量只是加速，不是正确性的前提。
func (publisher *GitHubPublisher) TerraformFileTree(
	ctx context.Context,
) (map[string]string, error) {
	endpoint := publisher.repositoryURL(
		"/git/trees/"+escapeGitHubPath(publisher.config.TargetBranch)) + "?recursive=1"
	var (
		responseBody []byte
		status       int
		err          error
	)
	// 与 TerraformFileMeta 同样的瞬态重试：出口网络对 GitHub 有丢包，一次
	// 失败就退回 N 次逐文件查询，等于把优化丢掉。
	for attempt := 1; attempt <= 3; attempt++ {
		responseBody, status, err = publisher.requestLimited(
			ctx, http.MethodGet, endpoint, nil, maxGitHubTreeBodySize)
		if err == nil || status != 0 {
			break
		}
		if attempt == 3 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("list branch tree %s: %w", publisher.config.TargetBranch, err)
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(responseBody, &tree); err != nil {
		return nil, fmt.Errorf("decode branch tree %s: %w", publisher.config.TargetBranch, err)
	}
	// 截断的清单不能当「文件不存在」用：那会让发布误判为需要新建（GitHub
	// 会以 422 拒绝），宁可退回逐文件查询。
	if tree.Truncated {
		return nil, fmt.Errorf("branch tree %s is truncated; falling back to per-file lookup",
			publisher.config.TargetBranch)
	}
	blobs := make(map[string]string, len(tree.Tree))
	for _, entry := range tree.Tree {
		if entry.Type != "blob" {
			continue
		}
		blobs[entry.Path] = entry.SHA
	}
	return blobs, nil
}

// commitBranchFiles 把整批文件作为一次提交写到分支上（Git Data API：
// 读分支头 → 建树 → 建提交 → 移动引用）。逐文件走 contents API 是 2N 次
// 请求 + N 个提交：基线发布动辄数百文件，实测 337 个文件要 12 分钟（还会
// 撞二级限流），PR 里也堆出几百个提交没法审。整批提交后请求数与文件数无关，
// 且失败时不留半成品分支。
func (publisher *GitHubPublisher) commitBranchFiles(
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
		// 超出 Git Data API 单次上限：退回逐文件 upsert。慢，但不会被一次
		// 超限请求卡死。
		for _, file := range files {
			if err := publisher.upsertTerraformFile(
				ctx, file.FileName, branch, commitMessage, file.Content); err != nil {
				return fmt.Errorf("commit Terraform file %s: %w", file.FileName, err)
			}
		}
		return nil
	}

	headSHA, err := publisher.branchHeadSHA(ctx, branch)
	if err != nil {
		return err
	}
	var head struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := publisher.requestJSON(ctx, http.MethodGet,
		publisher.repositoryURL("/git/commits/"+url.PathEscape(headSHA)), nil,
		http.StatusOK, &head); err != nil {
		return fmt.Errorf("load head commit %s of branch %s: %w", headSHA, branch, err)
	}
	if head.Tree.SHA == "" {
		return fmt.Errorf("GitHub returned head commit %s without a tree SHA", headSHA)
	}

	type treeEntry struct {
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	entries := make([]treeEntry, 0, len(files))
	for _, file := range files {
		entries = append(entries, treeEntry{
			Path: file.FileName, Mode: "100644", Type: "blob", Content: file.Content,
		})
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if err := publisher.requestJSON(ctx, http.MethodPost,
		publisher.repositoryURL("/git/trees"),
		map[string]interface{}{"base_tree": head.Tree.SHA, "tree": entries},
		http.StatusCreated, &tree); err != nil {
		return fmt.Errorf("create Git tree for branch %s: %w", branch, err)
	}
	if tree.SHA == "" {
		return errors.New("GitHub returned a created tree without a SHA")
	}
	// 建出来的树与分支头一致 = 内容逐字节相同：不产生空提交（重试幂等，
	// 与逐文件 upsert 的「内容相同则跳过」等价）。
	if tree.SHA == head.Tree.SHA {
		return nil
	}

	var commit struct {
		SHA string `json:"sha"`
	}
	if err := publisher.requestJSON(ctx, http.MethodPost,
		publisher.repositoryURL("/git/commits"),
		map[string]interface{}{
			"message": commitMessage, "tree": tree.SHA, "parents": []string{headSHA},
		},
		http.StatusCreated, &commit); err != nil {
		return fmt.Errorf("create commit on branch %s: %w", branch, err)
	}
	if commit.SHA == "" {
		return errors.New("GitHub returned a created commit without a SHA")
	}
	if err := publisher.requestJSON(ctx, http.MethodPatch,
		publisher.repositoryURL("/git/refs/heads/"+escapeGitHubPath(branch)),
		map[string]interface{}{"sha": commit.SHA, "force": false},
		http.StatusOK, nil); err != nil {
		return fmt.Errorf("move branch %s to commit %s: %w", branch, commit.SHA, err)
	}
	return nil
}

// branchHeadSHA 读分支当前头提交。分支刚由 ensureBranch 建好时等于基线分支
// 的头——每次提交都重新读一次，避免用过期 SHA 覆盖并发写入。
func (publisher *GitHubPublisher) branchHeadSHA(
	ctx context.Context,
	branch string,
) (string, error) {
	var reference struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := publisher.requestJSON(ctx, http.MethodGet,
		publisher.repositoryURL("/git/ref/heads/"+escapeGitHubPath(branch)), nil,
		http.StatusOK, &reference); err != nil {
		return "", fmt.Errorf("load branch ref %s: %w", branch, err)
	}
	if reference.Object.SHA == "" {
		return "", fmt.Errorf("GitHub returned branch %s without a commit SHA", branch)
	}
	return reference.Object.SHA, nil
}

func (publisher *GitHubPublisher) ensureBranch(ctx context.Context, branch string) error {
	_, status, err := publisher.request(ctx, http.MethodGet, publisher.repositoryURL("/git/ref/heads/"+branch), nil)
	if err == nil && status == http.StatusOK {
		return nil
	}
	if err != nil && status != http.StatusNotFound {
		return err
	}

	var baseReference struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := publisher.requestJSON(
		ctx,
		http.MethodGet,
		publisher.repositoryURL("/git/ref/heads/"+publisher.config.TargetBranch),
		nil,
		http.StatusOK,
		&baseReference,
	); err != nil {
		return fmt.Errorf("load target branch %s: %w", publisher.config.TargetBranch, err)
	}
	if baseReference.Object.SHA == "" {
		return errors.New("GitHub API returned target branch without a commit SHA")
	}

	var created struct {
		Ref string `json:"ref"`
	}
	createErr := publisher.requestJSON(
		ctx,
		http.MethodPost,
		publisher.repositoryURL("/git/refs"),
		map[string]interface{}{
			"ref": "refs/heads/" + branch, "sha": baseReference.Object.SHA,
		},
		http.StatusCreated,
		&created,
	)
	if createErr == nil {
		return nil
	}
	// Concurrent retries can both observe a missing branch; accept the race
	// only if the desired branch now exists.
	_, status, lookupErr := publisher.request(ctx, http.MethodGet, publisher.repositoryURL("/git/ref/heads/"+branch), nil)
	if lookupErr == nil && status == http.StatusOK {
		return nil
	}
	return createErr
}

func (publisher *GitHubPublisher) upsertTerraformFile(
	ctx context.Context,
	fileName, branch, commitMessage, content string,
) error {
	fileURL := publisher.repositoryURL("/contents/" + escapeGitHubPath(fileName))
	getURL, err := url.Parse(fileURL)
	if err != nil {
		return err
	}
	query := getURL.Query()
	query.Set("ref", branch)
	getURL.RawQuery = query.Encode()

	var existing struct {
		SHA      string `json:"sha"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	responseBody, status, err := publisher.request(ctx, http.MethodGet, getURL.String(), nil)
	if err == nil && status == http.StatusOK {
		if err := json.Unmarshal(responseBody, &existing); err != nil {
			return fmt.Errorf("decode GitHub file response: %w", err)
		}
		if existing.Encoding == "base64" {
			decoded, decodeErr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(existing.Content), ""))
			if decodeErr == nil && bytes.Equal(decoded, []byte(content)) {
				return nil
			}
		}
	} else if err != nil && status != http.StatusNotFound {
		return err
	}

	body := map[string]string{
		"message": commitMessage,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"branch":  branch,
	}
	method := http.MethodPut
	expectedStatus := http.StatusCreated
	if existing.SHA != "" {
		body["sha"] = existing.SHA
		expectedStatus = http.StatusOK
	}
	if err := publisher.requestJSON(ctx, method, fileURL, body, expectedStatus, nil); err != nil {
		return err
	}
	return nil
}

func (publisher *GitHubPublisher) findOpenPullRequest(ctx context.Context, branch string) (string, int, bool, error) {
	endpoint, err := url.Parse(publisher.repositoryURL("/pulls"))
	if err != nil {
		return "", 0, false, err
	}
	query := endpoint.Query()
	query.Set("state", "open")
	query.Set("head", strings.SplitN(publisher.config.Repository, "/", 2)[0]+":"+branch)
	query.Set("base", publisher.config.TargetBranch)
	endpoint.RawQuery = query.Encode()

	var pullRequests []struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	if err := publisher.requestJSON(ctx, http.MethodGet, endpoint.String(), nil, http.StatusOK, &pullRequests); err != nil {
		return "", 0, false, err
	}
	for _, pullRequest := range pullRequests {
		if strings.TrimSpace(pullRequest.HTMLURL) != "" {
			return pullRequest.HTMLURL, pullRequest.Number, true, nil
		}
	}
	return "", 0, false, nil
}

func (publisher *GitHubPublisher) requestJSON(
	ctx context.Context,
	method, endpoint string,
	body interface{},
	expectedStatus int,
	result interface{},
) error {
	responseBody, status, err := publisher.request(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if status != expectedStatus {
		return fmt.Errorf("GitHub API returned unexpected status %d (expected %d)", status, expectedStatus)
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(responseBody, result); err != nil {
		return fmt.Errorf("decode GitHub API response: %w", err)
	}
	return nil
}

func (publisher *GitHubPublisher) request(
	ctx context.Context,
	method, endpoint string,
	body interface{},
) ([]byte, int, error) {
	return publisher.requestLimited(ctx, method, endpoint, body, maxGitHubBodySize)
}

// requestLimited 与 request 相同，但可指定响应体读取上限：整仓的文件清单
// （git/trees）比单个文件响应大得多，用 1 MB 的默认上限会被截断成解析失败。
func (publisher *GitHubPublisher) requestLimited(
	ctx context.Context,
	method, endpoint string,
	body interface{},
	limit int64,
) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encode GitHub API request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("create GitHub API request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+publisher.config.Token)
	request.Header.Set("X-GitHub-Api-Version", gitHubAPIVersion)
	request.Header.Set("User-Agent", "aws-iam-governance")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := publisher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("send GitHub API request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("read GitHub API response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseBody, response.StatusCode, fmt.Errorf("GitHub API returned status %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return responseBody, response.StatusCode, nil
}

func (publisher *GitHubPublisher) repositoryURL(endpoint string) string {
	owner, repository, _ := strings.Cut(publisher.config.Repository, "/")
	return publisher.apiURL + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository) + endpoint
}

func escapeGitHubPath(fileName string) string {
	segments := strings.Split(fileName, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return strings.Join(segments, "/")
}

var (
	_ TicketPublisher       = (*GitHubPublisher)(nil)
	_ BaselineBranchCleaner = (*GitHubPublisher)(nil)
)
