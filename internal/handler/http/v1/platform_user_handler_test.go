package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakePlatformUserService struct {
	users       []service.PlatformUser
	tokens      []service.PlatformTokenInfo
	upserted    service.UpsertPlatformUser
	upsertActor string
	upsertErr   error
	issueActor  string
	issueUser   string
	issueName   string
	issueErr    error
	listErr     error
}

func (userService *fakePlatformUserService) ListUsers(context.Context) ([]service.PlatformUser, error) {
	if userService.listErr != nil {
		return nil, userService.listErr
	}
	return userService.users, nil
}

func (userService *fakePlatformUserService) UpsertUser(
	_ context.Context,
	user service.UpsertPlatformUser,
	actorID string,
) error {
	if userService.upsertErr != nil {
		return userService.upsertErr
	}
	userService.upserted = user
	userService.upsertActor = actorID
	return nil
}

func (userService *fakePlatformUserService) IssueToken(
	_ context.Context,
	actorID, userID, name string,
	expiresAt *time.Time,
) (service.IssuedPlatformToken, error) {
	if userService.issueErr != nil {
		return service.IssuedPlatformToken{}, userService.issueErr
	}
	userService.issueActor = actorID
	userService.issueUser = userID
	userService.issueName = name
	return service.IssuedPlatformToken{
		ID: 9, UserID: userID, Name: name, Prefix: "iamg_abcdefgh", Token: "iamg_secret",
	}, nil
}

func (userService *fakePlatformUserService) ListTokens(
	_ context.Context,
	userID string,
) ([]service.PlatformTokenInfo, error) {
	if userService.listErr != nil {
		return nil, userService.listErr
	}
	return userService.tokens, nil
}

func newPlatformUserRouter(
	t *testing.T,
	userService *fakePlatformUserService,
	actor string,
	roles []string,
) *gin.Engine {
	t.Helper()
	handler, err := NewPlatformUserHandler(userService)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, actor)
		context.Set(AuthenticatedRolesContextKey, roles)
	})
	RegisterPlatformUserRoutes(router, handler)
	return router
}

// 用户与令牌管理是平台上最敏感的操作：只有 platform_admin 能进。
func TestPlatformUserRoutesRequireAdministrator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		method     string
		path       string
		roles      []string
		wantStatus int
	}{
		{name: "list users as standard user", method: http.MethodGet, path: "/platform/users", roles: []string{"standard_user"}, wantStatus: http.StatusForbidden},
		{name: "list users as approver", method: http.MethodGet, path: "/platform/users", roles: []string{"approval_admin"}, wantStatus: http.StatusForbidden},
		{name: "list users as administrator", method: http.MethodGet, path: "/platform/users", roles: []string{"platform_admin"}, wantStatus: http.StatusOK},
		{name: "issue token as standard user", method: http.MethodPost, path: "/platform/users/alice/tokens", roles: []string{"standard_user"}, wantStatus: http.StatusForbidden},
		{name: "upsert user as approver", method: http.MethodPut, path: "/platform/users/alice", roles: []string{"approval_admin"}, wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			userService := &fakePlatformUserService{}
			router := newPlatformUserRouter(t, userService, "alice", test.roles)
			var body *strings.Reader = strings.NewReader("{}")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(test.method, test.path, body))
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestPlatformUserUpsertForwardsRolesAndActor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userService := &fakePlatformUserService{}
	router := newPlatformUserRouter(t, userService, "admin", []string{"platform_admin"})

	body := `{"display_name":"Alice","email":"alice@example.com","is_active":true,"roles":["standard_user","approval_admin"]}`
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/platform/users/alice", strings.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if userService.upserted.UserID != "alice" || userService.upserted.DisplayName != "Alice" {
		t.Fatalf("upserted user = %+v", userService.upserted)
	}
	if len(userService.upserted.Roles) != 2 {
		t.Fatalf("upserted roles = %v", userService.upserted.Roles)
	}
	if userService.upsertActor != "admin" {
		t.Fatalf("upsert actor = %q, want the authenticated administrator", userService.upsertActor)
	}
}

// 令牌明文只出现在签发响应里一次。
func TestPlatformUserIssueTokenReturnsSecretOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userService := &fakePlatformUserService{}
	router := newPlatformUserRouter(t, userService, "admin", []string{"platform_admin"})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/platform/users/alice/tokens", strings.NewReader(`{"name":"laptop","expires_in_hours":24}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Token != "iamg_secret" {
		t.Fatalf("token = %q, want the one-time secret", payload.Token)
	}
	if userService.issueActor != "admin" || userService.issueUser != "alice" || userService.issueName != "laptop" {
		t.Fatalf("issue call = actor %q user %q name %q", userService.issueActor, userService.issueUser, userService.issueName)
	}
}

func TestPlatformUserIssueTokenReportsUnknownUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userService := &fakePlatformUserService{issueErr: service.ErrInvalidPlatformUser}
	router := newPlatformUserRouter(t, userService, "admin", []string{"platform_admin"})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/platform/users/ghost/tokens", strings.NewReader(`{"name":"laptop"}`)))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", response.Code, response.Body.String())
	}
}

func TestPlatformUserListReturnsUsersAndTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userService := &fakePlatformUserService{
		users:  []service.PlatformUser{{UserID: "alice", DisplayName: "Alice", IsActive: true, Roles: []string{"standard_user"}}},
		tokens: []service.PlatformTokenInfo{{ID: 1, UserID: "alice", Name: "laptop", Prefix: "iamg_abcdefgh"}},
	}
	router := newPlatformUserRouter(t, userService, "admin", []string{"platform_admin"})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/platform/users", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "alice") {
		t.Fatalf("users response missing the user: %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/platform/tokens?user_id=alice", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "iamg_abcdefgh") {
		t.Fatalf("tokens response missing the token prefix: %s", response.Body.String())
	}
}

func TestNewPlatformUserHandlerRequiresService(t *testing.T) {
	if _, err := NewPlatformUserHandler(nil); err == nil {
		t.Fatal("NewPlatformUserHandler(nil) expected error")
	}
}
