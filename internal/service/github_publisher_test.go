package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// githubBranchState 模拟远端分支，用来断言「整批一次提交」的语义：请求数
// 与文件数无关、内容没变就不产生提交、写文件只经 Git Data API。
type githubBranchState struct {
	headSHA      string
	treeSHA      string
	nextTreeSHA  string
	branchExists bool
	treeEntries  []map[string]string
	commits      []string
	refMoves     []string
	contentGETs  int
}

func (state *githubBranchState) server(t *testing.T, pulls string, createdPR string) *httptest.Server {
	t.Helper()
	if state.nextTreeSHA == "" {
		state.nextTreeSHA = "new-tree"
	}
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case request.Method == http.MethodGet && strings.Contains(path, "/git/ref/heads/"):
			if strings.HasSuffix(path, "/heads/main") {
				_, _ = writer.Write([]byte(`{"object":{"sha":"base-sha"}}`))
				return
			}
			if !state.branchExists {
				http.Error(writer, `{"message":"Not Found"}`, http.StatusNotFound)
				return
			}
			_, _ = writer.Write([]byte(`{"object":{"sha":"` + state.headSHA + `"}}`))
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/git/refs"):
			var body struct {
				Ref string `json:"ref"`
				SHA string `json:"sha"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode branch request: %v", err)
			}
			if body.SHA != "base-sha" {
				t.Errorf("branch base = %q, want base-sha", body.SHA)
			}
			state.branchExists = true
			state.headSHA = body.SHA
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"ref":"` + body.Ref + `"}`))
		case request.Method == http.MethodGet && strings.Contains(path, "/git/commits/"):
			_, _ = writer.Write([]byte(`{"tree":{"sha":"` + state.treeSHA + `"}}`))
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/git/trees"):
			var body struct {
				BaseTree string              `json:"base_tree"`
				Tree     []map[string]string `json:"tree"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode tree request: %v", err)
			}
			if body.BaseTree != state.treeSHA {
				t.Errorf("base_tree = %q, want %q", body.BaseTree, state.treeSHA)
			}
			state.treeEntries = body.Tree
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"sha":"` + state.nextTreeSHA + `"}`))
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/git/commits"):
			var body struct {
				Message string   `json:"message"`
				Tree    string   `json:"tree"`
				Parents []string `json:"parents"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode commit request: %v", err)
			}
			if body.Tree != state.nextTreeSHA {
				t.Errorf("commit tree = %q, want %q", body.Tree, state.nextTreeSHA)
			}
			if len(body.Parents) != 1 || body.Parents[0] != state.headSHA {
				t.Errorf("commit parents = %v, want [%s]", body.Parents, state.headSHA)
			}
			state.commits = append(state.commits, body.Message)
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"sha":"new-commit"}`))
		case request.Method == http.MethodPatch && strings.Contains(path, "/git/refs/heads/"):
			var body struct {
				SHA string `json:"sha"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode ref update request: %v", err)
			}
			state.refMoves = append(state.refMoves, body.SHA)
			_, _ = writer.Write([]byte(`{"ref":"refs/heads/branch"}`))
		case request.Method == http.MethodGet && strings.HasSuffix(path, "/pulls"):
			_, _ = writer.Write([]byte(pulls))
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/pulls"):
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(createdPR))
		case strings.Contains(path, "/contents/"):
			// 批量提交路径不应再逐文件读写 contents API。
			state.contentGETs++
			t.Errorf("unexpected contents API call: %s %s", request.Method, path)
			http.NotFound(writer, request)
		default:
			t.Errorf("unexpected GitHub request: %s %s", request.Method, path)
			http.NotFound(writer, request)
		}
	}))
}

func TestGitHubPublisherCreatesBranchAndCommitsInOneRequest(t *testing.T) {
	const terraform = `resource "aws_iam_role" "managed_role" {}`
	state := &githubBranchState{treeSHA: "base-tree"}
	server := state.server(t, `[]`, `{"html_url":"https://github.com/acme/iac/pull/123","number":123}`)
	defer server.Close()

	publisher, err := NewGitHubPublisher(GitHubConfig{
		BaseURL:      server.URL,
		Token:        "test-token",
		Repository:   "acme/iac",
		TargetBranch: "main",
	})
	if err != nil {
		t.Fatalf("NewGitHubPublisher() error = %v", err)
	}
	ticketNo := "IAM-123"
	accountID := int64(12)
	ticket := model.IAMTicket{
		TicketNo:  &ticketNo,
		AccountID: &accountID,
		Submitter: stringPointer("requester"),
	}
	request := validTicketRequest()
	request.AWSAccountID = "123456789012"

	publishResult, err := publisher.Publish(context.Background(), ticket, request, terraform)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if publishResult == nil || publishResult.URL != "https://github.com/acme/iac/pull/123" {
		t.Errorf("Pull Request URL = %v", publishResult)
	}
	if len(state.treeEntries) != 1 {
		t.Fatalf("tree entries = %d, want 1", len(state.treeEntries))
	}
	entry := state.treeEntries[0]
	if entry["path"] != "iam/account-123456789012/role-billing-reader.tf" ||
		entry["mode"] != "100644" || entry["type"] != "blob" || entry["content"] != terraform {
		t.Errorf("tree entry = %+v", entry)
	}
	if len(state.commits) != 1 || state.commits[0] == "" {
		t.Errorf("commits = %v, want exactly one non-empty message", state.commits)
	}
	if len(state.refMoves) != 1 || state.refMoves[0] != "new-commit" {
		t.Errorf("ref moves = %v, want [new-commit]", state.refMoves)
	}
	if state.contentGETs != 0 {
		t.Errorf("contents API calls = %d, want 0", state.contentGETs)
	}
}

func TestGitHubPublisherPublishesBundleFilesInOneCommit(t *testing.T) {
	state := &githubBranchState{branchExists: true, headSHA: "branch-sha", treeSHA: "base-tree"}
	server := state.server(t, `[]`, `{"html_url":"https://github.com/acme/iac/pull/321","number":321}`)
	defer server.Close()

	publisher, err := NewGitHubPublisher(GitHubConfig{
		BaseURL: server.URL, Token: "test-token", Repository: "acme/iac",
	})
	if err != nil {
		t.Fatalf("NewGitHubPublisher() error = %v", err)
	}
	ticketNo := "IAM-BATCH-1"
	accountID := int64(12)
	ticket := model.IAMTicket{TicketNo: &ticketNo, AccountID: &accountID}
	request := CreateIAMTicketRequest{AWSAccountID: "123456789012", PrincipalName: "workspaces_DefaultRole"}
	result, err := publisher.PublishBundle(context.Background(), ticket, request, []TerraformBundleFile{
		{Key: "role-workspaces_defaultrole-policy-one", Content: `resource "aws_iam_role_policy" "one" {}`},
		{Key: "role-workspaces_defaultrole-policy-two", Content: `resource "aws_iam_role_policy" "two" {}`},
	})
	if err != nil {
		t.Fatalf("PublishBundle() error = %v", err)
	}
	if result == nil || result.URL != "https://github.com/acme/iac/pull/321" {
		t.Fatalf("PublishBundle() result = %+v", result)
	}
	// 两个文件必须进同一个提交：旧实现是 2 次 PUT = 2 个提交。
	if len(state.treeEntries) != 2 {
		t.Fatalf("tree entries = %d, want 2", len(state.treeEntries))
	}
	if len(state.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(state.commits))
	}
}

func TestGitHubPublisherSkipsCommitWhenTreeIsUnchanged(t *testing.T) {
	// 建出来的树与分支头相同 = 内容逐字节一致：不产生空提交，直接复用 PR。
	state := &githubBranchState{
		branchExists: true, headSHA: "branch-sha", treeSHA: "same-tree", nextTreeSHA: "same-tree",
	}
	server := state.server(t, `[{"html_url":"https://github.com/acme/iac/pull/124"}]`, `{}`)
	defer server.Close()

	publisher, err := NewGitHubPublisher(GitHubConfig{
		BaseURL: server.URL, Token: "test-token", Repository: "acme/iac",
	})
	if err != nil {
		t.Fatalf("NewGitHubPublisher() error = %v", err)
	}
	ticketNo := "IAM-124"
	accountID := int64(12)
	ticket := model.IAMTicket{TicketNo: &ticketNo, AccountID: &accountID}
	request := validTicketRequest()
	request.AWSAccountID = "123456789012"

	publishResult, err := publisher.Publish(context.Background(), ticket, request,
		`resource "aws_iam_role" "managed_role" {}`)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if publishResult == nil || publishResult.URL != "https://github.com/acme/iac/pull/124" {
		t.Errorf("Pull Request URL = %v", publishResult)
	}
	if len(state.commits) != 0 || len(state.refMoves) != 0 {
		t.Errorf("unexpected writes: commits/ref moves = %d/%d", len(state.commits), len(state.refMoves))
	}
}

func TestGitHubPublisherTerraformFileTree(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet ||
			!strings.Contains(request.URL.Path, "/git/trees/main") ||
			request.URL.Query().Get("recursive") != "1" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL)
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write([]byte(`{"truncated":false,"tree":[
			{"path":"iam/account-1/role-a.tf","type":"blob","sha":"blob-a"},
			{"path":"iam/account-1","type":"tree","sha":"tree-a"},
			{"path":"README.md","type":"blob","sha":"blob-readme"}]}`))
	}))
	defer server.Close()

	publisher, err := NewGitHubPublisher(GitHubConfig{
		BaseURL: server.URL, Token: "test-token", Repository: "acme/iac", TargetBranch: "main",
	})
	if err != nil {
		t.Fatalf("NewGitHubPublisher() error = %v", err)
	}
	blobs, err := publisher.TerraformFileTree(context.Background())
	if err != nil {
		t.Fatalf("TerraformFileTree() error = %v", err)
	}
	if len(blobs) != 2 || blobs["iam/account-1/role-a.tf"] != "blob-a" ||
		blobs["README.md"] != "blob-readme" {
		t.Fatalf("blobs = %v", blobs)
	}
}

func TestGitHubPublisherTerraformFileTreeRejectsTruncatedTree(t *testing.T) {
	// 截断的清单不能当「文件不存在」用：必须报错让调用方退回逐文件查询。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"truncated":true,"tree":[]}`))
	}))
	defer server.Close()

	publisher, err := NewGitHubPublisher(GitHubConfig{
		BaseURL: server.URL, Token: "test-token", Repository: "acme/iac", TargetBranch: "main",
	})
	if err != nil {
		t.Fatalf("NewGitHubPublisher() error = %v", err)
	}
	if _, err := publisher.TerraformFileTree(context.Background()); err == nil {
		t.Fatal("TerraformFileTree() error = nil, want truncation error")
	}
}

func TestNewGitHubPublisherValidatesConfiguration(t *testing.T) {
	for _, config := range []GitHubConfig{
		{Repository: "acme/iac"},
		{Token: "token", Repository: "iac"},
		{Token: "token", Repository: "acme/iac", BaseURL: "http://github.example.com/api/v3"},
	} {
		if _, err := NewGitHubPublisher(config); err == nil {
			t.Errorf("NewGitHubPublisher(%+v) error = nil", config)
		}
	}
}

func TestGitHubPublisherRequiresAWSAccountID(t *testing.T) {
	publisher, err := NewGitHubPublisher(GitHubConfig{
		Token: "token", Repository: "acme/iac", BaseURL: "http://127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketNo := "IAM-125"
	accountID := int64(12)
	_, err = publisher.Publish(context.Background(),
		model.IAMTicket{TicketNo: &ticketNo, AccountID: &accountID},
		validTicketRequest(),
		"terraform",
	)
	if err == nil || !strings.Contains(err.Error(), "valid AWS account ID") {
		t.Fatalf("Publish() error = %v, want account ID validation error", err)
	}
}
