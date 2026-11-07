package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frankful/cloud-iam-governance-hub/internal/service"
	"github.com/gin-gonic/gin"
)

type baselineDeclarationFake struct {
	declarations []service.BaselineDeclaration
	loadErr      error
	report       *service.DeclarationFreshnessReport
	reconcileErr error
	reconciled   struct {
		accountID int64
		directory string
	}
}

func (fake *baselineDeclarationFake) LoadCurrent(
	_ context.Context, _ int64,
) ([]service.BaselineDeclaration, error) {
	if fake.loadErr != nil {
		return nil, fake.loadErr
	}
	return fake.declarations, nil
}

func (fake *baselineDeclarationFake) ReconcileFreshness(
	_ context.Context, accountDBID int64, repoDirectory string,
	_ service.DeclarationFileMetaReader,
) (*service.DeclarationFreshnessReport, error) {
	fake.reconciled.accountID = accountDBID
	fake.reconciled.directory = repoDirectory
	if fake.reconcileErr != nil {
		return nil, fake.reconcileErr
	}
	return fake.report, nil
}

func newBaselineDeclarationTestRouter(
	t *testing.T, fake *baselineDeclarationFake, reader service.DeclarationFileMetaReader, roles []string,
) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := NewBaselineDeclarationHandler(fake, reader, "iam", nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "someone")
		context.Set(AuthenticatedRolesContextKey, roles)
	})
	RegisterBaselineDeclarationRoutes(api, handler)
	return router
}

// TestBaselineDeclarationRoutesRequirePlatformAdmin 声明快照是运维面：它描述
// 漂移基准由什么构成，普通用户不该看到，更不该能触发对远端仓库的批量读取。
func TestBaselineDeclarationRoutesRequirePlatformAdmin(t *testing.T) {
	router := newBaselineDeclarationTestRouter(
		t, &baselineDeclarationFake{}, nil, []string{"standard_user"})
	for _, testCase := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/baseline-declarations?account_id=7", ""},
		{http.MethodPost, "/api/v1/baseline-declarations/refresh", `{"account_id":7}`},
	} {
		request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(testCase.body))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s: expected forbidden, got %d", testCase.method, testCase.path, response.Code)
		}
	}
}

// TestBaselineDeclarationListSummarizesPerFile 列表按文件汇总并提供过期计数：
// 运维要一眼看出「哪个文件的基准不可信」。
func TestBaselineDeclarationListSummarizesPerFile(t *testing.T) {
	staleAt := time.Now()
	fake := &baselineDeclarationFake{declarations: []service.BaselineDeclaration{
		{AWSAccountID: "123456789012", ResourceKey: "role:app", FileKey: "role-app",
			Kind: "role", Name: "app", ContentBlobSHA: "sha-a"},
		{AWSAccountID: "123456789012", ResourceKey: "role:app:inline:x", FileKey: "role-app",
			Kind: "role", Name: "app", ContentBlobSHA: "sha-a", StaleAt: &staleAt,
			StaleReason: service.DeclarationStaleContentChanged},
		{AWSAccountID: "123456789012", ResourceKey: "group:devs", FileKey: "group-devs",
			Kind: "group", Name: "devs"},
	}}
	router := newBaselineDeclarationTestRouter(t, fake, nil, []string{"platform_admin"})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/api/v1/baseline-declarations?account_id=7", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		AccountID    int64  `json:"account_id"`
		AWSAccountID string `json:"aws_account_id"`
		Total        int    `json:"total"`
		Stale        int    `json:"stale"`
		Files        []struct {
			FileKey      string `json:"file_key"`
			Declarations int    `json:"declarations"`
			Stale        int    `json:"stale"`
		} `json:"files"`
		Declarations []service.BaselineDeclaration `json:"declarations"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.AccountID != 7 || payload.AWSAccountID != "123456789012" {
		t.Errorf("account = %d/%q, want 7/123456789012", payload.AccountID, payload.AWSAccountID)
	}
	if payload.Total != 3 || payload.Stale != 1 || len(payload.Declarations) != 3 {
		t.Errorf("total = %d, stale = %d, rows = %d; want 3 / 1 / 3",
			payload.Total, payload.Stale, len(payload.Declarations))
	}
	if len(payload.Files) != 2 || payload.Files[0].FileKey != "group-devs" ||
		payload.Files[1].FileKey != "role-app" || payload.Files[1].Stale != 1 {
		t.Errorf("file summaries = %+v, want group-devs then role-app with 1 stale", payload.Files)
	}
}

// TestBaselineDeclarationRefreshRefusesWithoutPublisher 没配发布器就没有仓库
// 可读：必须显式拒绝，绝不能返回一份「全部新鲜」的假报告——那会让人以为
// 基准是可信的。
func TestBaselineDeclarationRefreshRefusesWithoutPublisher(t *testing.T) {
	router := newBaselineDeclarationTestRouter(
		t, &baselineDeclarationFake{}, nil, []string{"platform_admin"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodPost, "/api/v1/baseline-declarations/refresh", strings.NewReader(`{"account_id":7}`)))
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (publisher missing)", response.Code)
	}
}

// TestBaselineDeclarationRefreshUsesAccountDirectory 核对路径必须与发布器同源
// （<terraformPath>/account-<AWS账号ID>），否则会拿另一个目录的文件去比，
// 把所有声明误判成过期。
func TestBaselineDeclarationRefreshUsesAccountDirectory(t *testing.T) {
	fake := &baselineDeclarationFake{
		declarations: []service.BaselineDeclaration{
			{AWSAccountID: "123456789012", ResourceKey: "role:app", FileKey: "role-app"},
		},
		report: &service.DeclarationFreshnessReport{
			AccountDBID: 7,
			Files:       []service.DeclarationFreshnessFile{},
		},
	}
	router := newBaselineDeclarationTestRouter(
		t, fake, &declarationFakeReader{}, []string{"platform_admin"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodPost, "/api/v1/baseline-declarations/refresh", strings.NewReader(`{"account_id":7}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if fake.reconciled.accountID != 7 {
		t.Errorf("reconciled account = %d, want 7", fake.reconciled.accountID)
	}
	if fake.reconciled.directory != "iam/account-123456789012" {
		t.Errorf("reconciled directory = %q, want iam/account-123456789012", fake.reconciled.directory)
	}
}

// TestBaselineDeclarationRefreshWithoutDeclarations 还没发布过基线的账号是
// 正常状态：返回空报告，不查仓库也不报错。
func TestBaselineDeclarationRefreshWithoutDeclarations(t *testing.T) {
	fake := &baselineDeclarationFake{}
	router := newBaselineDeclarationTestRouter(
		t, fake, &declarationFakeReader{}, []string{"platform_admin"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodPost, "/api/v1/baseline-declarations/refresh", strings.NewReader(`{"account_id":7}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if fake.reconciled.accountID != 0 {
		t.Error("no declarations must not trigger a repository scan")
	}
}

// declarationFakeReader 只用于让 handler 认为发布器可用。
type declarationFakeReader struct{}

func (declarationFakeReader) TerraformFileMeta(
	context.Context, string,
) (string, bool, error) {
	return "", false, nil
}
