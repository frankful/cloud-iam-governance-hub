package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakePlatformTokenAuthenticator struct {
	identity service.AuthenticatedIdentity
	err      error
	token    string
}

func (authenticator *fakePlatformTokenAuthenticator) Authenticate(
	_ context.Context,
	token string,
) (service.AuthenticatedIdentity, error) {
	authenticator.token = token
	return authenticator.identity, authenticator.err
}

func TestPlatformTokenAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		header     string
		authErr    error
		wantStatus int
		wantUser   string
		wantAuth   bool
	}{
		{name: "missing bearer", header: "Basic abc", wantStatus: http.StatusUnauthorized},
		{name: "invalid token", header: "Bearer secret", authErr: service.ErrInvalidPlatformToken, wantStatus: http.StatusUnauthorized, wantAuth: true},
		{name: "repository failure", header: "Bearer token", authErr: errors.New("database unavailable"), wantStatus: http.StatusInternalServerError, wantAuth: true},
		{name: "valid token", header: "Bearer token-value", wantStatus: http.StatusNoContent, wantUser: "alice", wantAuth: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &fakePlatformTokenAuthenticator{
				identity: service.AuthenticatedIdentity{
					UserID: "alice", TokenID: 7, Roles: []string{"standard_user"},
				},
				err: test.authErr,
			}
			router := gin.New()
			router.Use(PlatformTokenAuthentication(authenticator))
			router.GET("/private", func(context *gin.Context) {
				user, _ := context.Get(AuthenticatedUserContextKey)
				if user != test.wantUser {
					t.Errorf("authenticated user = %v, want %q", user, test.wantUser)
				}
				context.Status(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodGet, "/private", nil)
			request.Header.Set("Authorization", test.header)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if !test.wantAuth && authenticator.token != "" {
				t.Fatalf("authenticator received token for malformed header: %q", authenticator.token)
			}
		})
	}
}

func TestRequireRolesUsesDenyByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		roles      []string
		wantStatus int
	}{
		{name: "missing roles", wantStatus: http.StatusForbidden},
		{name: "wrong role", roles: []string{"standard_user"}, wantStatus: http.StatusForbidden},
		{name: "allowed role", roles: []string{"approval_admin"}, wantStatus: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(context *gin.Context) {
				context.Set(AuthenticatedUserContextKey, "alice")
				if test.roles != nil {
					context.Set(AuthenticatedRolesContextKey, test.roles)
				}
			})
			router.GET("/admin", RequireRoles("platform_admin", "approval_admin"), func(context *gin.Context) {
				context.Status(http.StatusNoContent)
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin", nil))
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestTicketListScopesStandardUserToOwnTickets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name      string
		roles     []string
		wantOwner string
	}{
		{name: "standard user", roles: []string{"standard_user"}, wantOwner: "alice"},
		{name: "approval admin", roles: []string{"approval_admin"}, wantOwner: "bob"},
		{name: "platform admin", roles: []string{"platform_admin"}, wantOwner: "bob"},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(context *gin.Context) {
				context.Set(AuthenticatedUserContextKey, "alice")
				context.Set(AuthenticatedRolesContextKey, test.roles)
			})
			fake := &fakeTicketAPIService{listTotal: 1}
			RegisterTicketRoutes(router, &TicketHandler{service: fake})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/tickets?submitter=bob", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			if fake.lastListFilter.Submitter != test.wantOwner {
				t.Errorf("submitter filter = %q, want %q", fake.lastListFilter.Submitter, test.wantOwner)
			}
		})
	}
}

func TestApproversRouteRequiresKnownRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		roles      []string
		wantStatus int
	}{
		{name: "missing roles", wantStatus: http.StatusForbidden},
		{name: "standard user", roles: []string{"standard_user"}, wantStatus: http.StatusOK},
		{name: "unknown role", roles: []string{"viewer"}, wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(context *gin.Context) {
				context.Set(AuthenticatedUserContextKey, "alice")
				if test.roles != nil {
					context.Set(AuthenticatedRolesContextKey, test.roles)
				}
			})
			RegisterTicketRoutes(router, &TicketHandler{service: &fakeTicketAPIService{}})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/approvers", nil))
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestStandardUserCanOnlyReadOwnTicket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		submitter  string
		wantStatus int
	}{
		{name: "owner", submitter: "alice", wantStatus: http.StatusOK},
		{name: "other user", submitter: "bob", wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(context *gin.Context) {
				context.Set(AuthenticatedUserContextKey, "alice")
				context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
			})
			submitter := test.submitter
			handler := &TicketHandler{service: &fakeTicketAPIService{
				ticket: model.IAMTicket{Submitter: &submitter},
			}}
			RegisterTicketRoutes(router, handler)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/tickets/IAM-123", nil))
			if response.Code != test.wantStatus {
				t.Fatalf("ticket read status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

// A5 全链路组合：认证中间件 + RequireRoles + 身份传递串成一条真实形态的
// 路由，覆盖 401（未认证）/ 403（角色不足）/ 200（角色匹配 + 身份进入
// handler context）三层。分层单测已各自存在，这里锁「组装后的整体行为」。
func TestAuthAndRBACRouteChain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func() (*gin.Engine, *fakePlatformTokenAuthenticator) {
		authenticator := &fakePlatformTokenAuthenticator{
			identity: service.AuthenticatedIdentity{
				UserID: "alice", TokenID: 7, Roles: []string{"standard_user"},
			},
		}
		router := gin.New()
		router.Use(PlatformTokenAuthentication(authenticator))
		handler := func(context *gin.Context) {
			user, _ := context.Get(AuthenticatedUserContextKey)
			context.String(http.StatusOK, "user=%v", user)
		}
		router.GET("/open-to-any-role", RequireRoles("standard_user", "platform_admin"), handler)
		router.GET("/admin-only", RequireRoles("platform_admin"), handler)
		return router, authenticator
	}

	do := func(router *gin.Engine, header string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("no header is 401 without touching the authenticator", func(t *testing.T) {
		router, authenticator := newRouter()
		if response := do(router, ""); response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", response.Code)
		}
		if authenticator.token != "" {
			t.Fatalf("authenticator invoked for missing header: %q", authenticator.token)
		}
	})

	t.Run("invalid token is 401", func(t *testing.T) {
		router, authenticator := newRouter()
		authenticator.err = service.ErrInvalidPlatformToken
		request := httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		request.Header.Set("Authorization", "Bearer token-value")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", response.Code)
		}
	})

	t.Run("valid token with insufficient role is 403", func(t *testing.T) {
		router, _ := newRouter()
		request := httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		request.Header.Set("Authorization", "Bearer token-value")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", response.Code)
		}
	})

	t.Run("valid token with matching role is 200 and identity is propagated", func(t *testing.T) {
		router, _ := newRouter()
		request := httptest.NewRequest(http.MethodGet, "/open-to-any-role", nil)
		request.Header.Set("Authorization", "Bearer token-value")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.String() != "user=alice" {
			t.Fatalf("status = %d body = %q, want 200 user=alice", response.Code, response.Body.String())
		}
	})
}
