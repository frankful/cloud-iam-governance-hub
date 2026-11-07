package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/xanzy/go-gitlab"
)

// gitlabTestServer 模拟 PublishBranch / TerraformFileMeta / DeleteBranch 用到的
// GitLab API 端点。只覆盖服务实际走到的请求形态，断言集中在行为（建分支、
// 逐文件 upsert、开 MR、复用 MR、404 容忍）。
type gitlabTestServer struct {
	t           *testing.T
	mux         *http.ServeMux
	server      *httptest.Server
	fileOnMain  *string              // 目标分支上已存在的文件内容（可选）
	fileBlobs   map[string]string    // main 上文件的 blob_id
	branchFiles map[string]string    // 源分支上的文件内容
	openMR      *gitlab.MergeRequest // 已开放的 MR（列表接口直接返回）
	createMRGot bool
	// treeBlobs 是 repository/tree 返回的「路径 → blob id」。nil 时该接口 404
	// （模拟目录还不存在），发布器应退回逐文件 upsert。
	treeBlobs map[string]string
	// treePages 非空时按页返回（用于验证分页合并），优先于 treeBlobs。
	treePages []map[string]string
	// treeStatus 非 0 时 tree 接口直接返回该状态码（模拟不可用）。
	treeStatus int
	// commitActions 记录 commits API 收到的 actions，commitCalls 是调用次数。
	commitActions []map[string]interface{}
	commitCalls   int
	// perFileWrites 统计逐文件 upsert 的次数（批量路径下应为 0）。
	perFileWrites int
}

func newGitLabTestServer(t *testing.T) *gitlabTestServer {
	state := &gitlabTestServer{
		t:           t,
		mux:         http.NewServeMux(),
		fileBlobs:   map[string]string{},
		branchFiles: map[string]string{},
	}
	state.server = httptest.NewServer(state.mux)
	t.Cleanup(state.server.Close)
	state.register()
	return state
}

func (state *gitlabTestServer) register() {
	state.mux.HandleFunc("/api/v4/projects/", func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case strings.Contains(path, "/repository/files/") && request.Method == http.MethodPost,
			strings.Contains(path, "/repository/files/") && request.Method == http.MethodPut:
			state.perFileWrites++
			var body struct {
				Content string `json:"content"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			state.branchFiles["role-demo.tf"] = body.Content
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]string{"file_path": "iam/account-123/role-demo.tf"})
		case strings.Contains(path, "/repository/files/") && request.Method == http.MethodGet:
			if !strings.Contains(path, "role-demo.tf") {
				http.NotFound(writer, request)
				return
			}
			if state.branchFiles["role-demo.tf"] != "" {
				_ = json.NewEncoder(writer).Encode(gitlab.File{
					FilePath: "iam/account-123/role-demo.tf",
					Content:  state.branchFiles["role-demo.tf"], BlobID: "srcblob",
				})
				return
			}
			if state.fileOnMain == nil {
				http.NotFound(writer, request)
				return
			}
			_ = json.NewEncoder(writer).Encode(gitlab.File{
				FilePath: "iam/account-123/role-demo.tf",
				Content:  *state.fileOnMain, BlobID: state.fileBlobs["role-demo.tf"],
			})
		case strings.Contains(path, "/repository/tree") && request.Method == http.MethodGet:
			if state.treeStatus != 0 {
				writer.WriteHeader(state.treeStatus)
				return
			}
			page := 1
			if raw := request.URL.Query().Get("page"); raw != "" {
				if parsed, err := strconv.Atoi(raw); err == nil {
					page = parsed
				}
			}
			var entries map[string]string
			if len(state.treePages) > 0 {
				if page <= len(state.treePages) {
					entries = state.treePages[page-1]
				}
				if page < len(state.treePages) {
					writer.Header().Set("X-Next-Page", strconv.Itoa(page+1))
				}
			} else if state.treeBlobs != nil {
				entries = state.treeBlobs
			} else {
				http.NotFound(writer, request)
				return
			}
			nodes := make([]gitlab.TreeNode, 0, len(entries))
			for filePath, blob := range entries {
				nodes = append(nodes, gitlab.TreeNode{ID: blob, Path: filePath, Type: "blob", Mode: "100644"})
			}
			_ = json.NewEncoder(writer).Encode(nodes)
		case strings.Contains(path, "/repository/commits") && request.Method == http.MethodPost:
			state.commitCalls++
			var body struct {
				Actions []map[string]interface{} `json:"actions"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			state.commitActions = append(state.commitActions, body.Actions...)
			for _, action := range body.Actions {
				if filePath, ok := action["file_path"].(string); ok {
					if content, ok := action["content"].(string); ok {
						state.branchFiles[filePath[strings.LastIndex(filePath, "/")+1:]] = content
					}
				}
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]string{"id": "commit-sha"})
		case strings.Contains(path, "/repository/branches/") && request.Method == http.MethodDelete:
			// 惯例：测试里删除 baseline/1/1 成功，其它 404。
			if strings.HasSuffix(path, "baseline%2F1%2F1") || strings.HasSuffix(path, "baseline/1/1") {
				writer.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(writer, request)
		case strings.Contains(path, "/repository/branches") && request.Method == http.MethodPost:
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]string{"name": "baseline/1/1"})
		case strings.Contains(path, "/merge_requests") && request.Method == http.MethodGet:
			if state.openMR != nil {
				_ = json.NewEncoder(writer).Encode([]*gitlab.MergeRequest{state.openMR})
				return
			}
			_, _ = writer.Write([]byte("[]"))
		case strings.Contains(path, "/merge_requests") && request.Method == http.MethodPost:
			state.createMRGot = true
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]interface{}{
				"web_url": "https://gitlab.example.com/acme/infra/-/merge_requests/9", "iid": 9,
			})
		default:
			http.NotFound(writer, request)
		}
	})
}

func newGitLabTestPublisher(baseURL string) *GitLabSDKPublisher {
	publisher, err := NewGitLabSDKPublisher(GitLabConfig{
		BaseURL:      baseURL,
		Token:        "test-token",
		ProjectID:    "42",
		TargetBranch: "main",
	})
	if err != nil {
		panic(err)
	}
	return publisher
}

func TestGitLabTerraformFileMeta(t *testing.T) {
	state := newGitLabTestServer(t)
	content := "resource \"aws_iam_role\" \"demo\" {}\n"
	state.fileOnMain = &content
	state.fileBlobs["role-demo.tf"] = "blobsha123"
	publisher := newGitLabTestPublisher(state.server.URL)

	blobSHA, exists, err := publisher.TerraformFileMeta(context.Background(), "iam/account-123/role-demo.tf")
	if err != nil || !exists {
		t.Fatalf("exists = %v, err = %v; want exists with no error", exists, err)
	}
	if blobSHA != "blobsha123" {
		t.Errorf("blob sha = %q, want blobsha123", blobSHA)
	}

	_, exists, err = publisher.TerraformFileMeta(context.Background(), "iam/account-123/absent.tf")
	if err != nil || exists {
		t.Fatalf("absent file: exists = %v, err = %v; want false / nil", exists, err)
	}
}

func TestGitLabPublishBranchCreatesBranchFilesAndMR(t *testing.T) {
	state := newGitLabTestServer(t)
	publisher := newGitLabTestPublisher(state.server.URL)

	result, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "baseline/111122223333/28",
		Title:  "IAM baseline for account 111122223333",
		Body:   "Generated baseline bundle.",
		Files: []BranchPublishFile{
			{FileName: "iam/account-111122223333/role-demo.tf", Content: "resource \"aws_iam_role\" \"demo\" {}"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.URL == "" || result.RemoteRequestNumber != "9" || result.Provider != "gitlab" {
		t.Errorf("unexpected result: %+v", result)
	}
	if !state.createMRGot {
		t.Error("expected a Merge Request creation call")
	}
}

func TestGitLabPublishBranchReusesOpenMR(t *testing.T) {
	state := newGitLabTestServer(t)
	state.openMR = &gitlab.MergeRequest{
		WebURL: "https://gitlab.example.com/acme/infra/-/merge_requests/8", IID: 8,
	}
	publisher := newGitLabTestPublisher(state.server.URL)

	result, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "baseline/111122223333/28",
		Title:  "IAM baseline for account 111122223333",
		Body:   "Generated baseline bundle.",
		Files: []BranchPublishFile{
			{FileName: "iam/account-111122223333/role-demo.tf", Content: "resource \"aws_iam_role\" \"demo\" {}"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RemoteRequestNumber != "8" {
		t.Errorf("remote request number = %q, want reused MR 8", result.RemoteRequestNumber)
	}
	if state.createMRGot {
		t.Error("an open MR must be reused, not duplicated")
	}
}

func TestGitLabPublishBranchRejectsInvalidInput(t *testing.T) {
	publisher := newGitLabTestPublisher("http://127.0.0.1:1") // 不应触网
	if _, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "", Title: "t", Files: []BranchPublishFile{{FileName: "a.tf", Content: "x"}},
	}); err == nil {
		t.Error("empty branch must be rejected")
	}
	if _, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "b", Title: "t", Files: []BranchPublishFile{{FileName: "../escape.tf", Content: "x"}},
	}); err == nil {
		t.Error("directory traversal must be rejected")
	}
}

func TestGitLabDeleteBranchToleratesMissingBranch(t *testing.T) {
	state := newGitLabTestServer(t)
	publisher := newGitLabTestPublisher(state.server.URL)

	if err := publisher.DeleteBranch(context.Background(), "baseline/1/1"); err != nil {
		t.Fatalf("existing branch delete: %v", err)
	}
	if err := publisher.DeleteBranch(context.Background(), "baseline/2/2"); err != nil {
		t.Fatalf("missing branch delete must be tolerated: %v", err)
	}
}

// 整批文件必须一次提交写完：C12 的核心诉求（逐文件 PUT 是 2N 次请求 +
// N 个提交，300+ 文件要十几分钟，PR 里堆几百个提交没法审）。
func TestGitLabPublishBranchCommitsOnce(t *testing.T) {
	state := newGitLabTestServer(t)
	state.treeBlobs = map[string]string{
		"iam/account-1/role-demo.tf": "old-role-blob",
		"iam/account-1/user-demo.tf": "old-user-blob",
	}
	publisher := newGitLabTestPublisher(state.server.URL)

	if _, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "baseline/1/1",
		Title:  "baseline",
		Body:   "body",
		Files: []BranchPublishFile{
			{FileName: "iam/account-1/role-demo.tf", Content: "resource \"aws_iam_role\" \"demo\" {}\n"},
			{FileName: "iam/account-1/user-demo.tf", Content: "resource \"aws_iam_user\" \"demo\" {}\n"},
		},
	}); err != nil {
		t.Fatalf("PublishBranch() error = %v", err)
	}
	if state.commitCalls != 1 {
		t.Fatalf("commit calls = %d, want exactly 1", state.commitCalls)
	}
	if state.perFileWrites != 0 {
		t.Fatalf("per-file writes = %d, want 0 (batch path)", state.perFileWrites)
	}
	if len(state.commitActions) != 2 {
		t.Fatalf("actions = %d, want 2", len(state.commitActions))
	}
	for _, action := range state.commitActions {
		if action["action"] != "update" {
			t.Errorf("action = %v, want update for files that already exist", action["action"])
		}
	}
}

// 内容逐字节相同 = 不提交（重试幂等，且不会产生空提交）；新文件用 create。
func TestGitLabPublishBranchSkipsUnchangedFiles(t *testing.T) {
	state := newGitLabTestServer(t)
	unchanged := "resource \"aws_iam_role\" \"demo\" {}\n"
	state.treeBlobs = map[string]string{
		"iam/account-1/role-demo.tf": gitBlobSHA(unchanged),
	}
	publisher := newGitLabTestPublisher(state.server.URL)

	if _, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "baseline/1/1",
		Title:  "baseline",
		Body:   "body",
		Files: []BranchPublishFile{
			{FileName: "iam/account-1/role-demo.tf", Content: unchanged},
			{FileName: "iam/account-1/group-new.tf", Content: "resource \"aws_iam_group\" \"new\" {}\n"},
		},
	}); err != nil {
		t.Fatalf("PublishBranch() error = %v", err)
	}
	if state.commitCalls != 1 {
		t.Fatalf("commit calls = %d, want 1", state.commitCalls)
	}
	if len(state.commitActions) != 1 {
		t.Fatalf("actions = %+v, want only the new file", state.commitActions)
	}
	if state.commitActions[0]["action"] != "create" ||
		state.commitActions[0]["file_path"] != "iam/account-1/group-new.tf" {
		t.Fatalf("action = %+v, want create group-new.tf", state.commitActions[0])
	}
}

// 全部未变化时一个提交都不应产生。
func TestGitLabPublishBranchSkipsCommitWhenNothingChanged(t *testing.T) {
	state := newGitLabTestServer(t)
	content := "resource \"aws_iam_role\" \"demo\" {}\n"
	state.treeBlobs = map[string]string{"iam/account-1/role-demo.tf": gitBlobSHA(content)}
	publisher := newGitLabTestPublisher(state.server.URL)

	if _, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "baseline/1/1", Title: "baseline", Body: "body",
		Files: []BranchPublishFile{{FileName: "iam/account-1/role-demo.tf", Content: content}},
	}); err != nil {
		t.Fatalf("PublishBranch() error = %v", err)
	}
	if state.commitCalls != 0 || state.perFileWrites != 0 {
		t.Fatalf("commitCalls = %d, perFileWrites = %d; want 0 / 0", state.commitCalls, state.perFileWrites)
	}
}

// 树接口分页：一页 100 条，必须翻完所有页才算清单完整（截断的清单会让发布
// 把「更新」误判成「新建」，GitLab 会整批拒绝）。
func TestGitLabTerraformFileTreePaginates(t *testing.T) {
	state := newGitLabTestServer(t)
	state.treePages = []map[string]string{
		{"iam/account-1/a.tf": "blob-a", "iam/account-1/b.tf": "blob-b"},
		{"iam/account-1/c.tf": "blob-c"},
	}
	publisher := newGitLabTestPublisher(state.server.URL)

	tree, err := publisher.TerraformFileTree(context.Background())
	if err != nil {
		t.Fatalf("TerraformFileTree() error = %v", err)
	}
	if len(tree) != 3 || tree["iam/account-1/c.tf"] != "blob-c" {
		t.Fatalf("tree = %v, want all three blobs across pages", tree)
	}
}

// 树不可用时退回逐文件 upsert：批量是加速，不是正确性的前提。
func TestGitLabPublishBranchFallsBackWhenTreeUnavailable(t *testing.T) {
	state := newGitLabTestServer(t)
	// 403 而不是 500：SDK 对 5xx 会退避重试，用例会空等十几秒；本用例验证的是
	// 「树读不到就退回逐文件」，与状态码无关。
	state.treeStatus = http.StatusForbidden
	publisher := newGitLabTestPublisher(state.server.URL)

	if _, err := publisher.PublishBranch(context.Background(), BranchPublishRequest{
		Branch: "baseline/1/1", Title: "baseline", Body: "body",
		Files: []BranchPublishFile{
			{FileName: "iam/account-1/role-demo.tf", Content: "resource \"aws_iam_role\" \"demo\" {}\n"},
		},
	}); err != nil {
		t.Fatalf("PublishBranch() error = %v", err)
	}
	if state.commitCalls != 0 {
		t.Fatalf("commit calls = %d, want 0 on the fallback path", state.commitCalls)
	}
	if state.perFileWrites != 1 {
		t.Fatalf("per-file writes = %d, want 1", state.perFileWrites)
	}
}
