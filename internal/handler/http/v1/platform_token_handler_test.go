package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type fakePlatformTokenService struct {
	actor   service.AuthenticatedIdentity
	tokenID int64
	err     error
}

func (tokenService *fakePlatformTokenService) RevokeToken(
	_ context.Context,
	tokenID int64,
	actor service.AuthenticatedIdentity,
) error {
	tokenService.tokenID = tokenID
	tokenService.actor = actor
	return tokenService.err
}

func TestPlatformTokenRevokeRequiresOwnerOrAdministratorServiceDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name       string
		path       string
		actor      string
		roles      []string
		serviceErr error
		wantStatus int
		wantID     int64
	}{
		{name: "owner revokes own token", path: "/platform/tokens/12/revoke", actor: "alice", roles: []string{"standard_user"}, wantStatus: http.StatusNoContent, wantID: 12},
		{name: "admin revokes token", path: "/platform/tokens/15/revoke", actor: "admin", roles: []string{"platform_admin"}, wantStatus: http.StatusNoContent, wantID: 15},
		{name: "other user cannot revoke", path: "/platform/tokens/19/revoke", actor: "bob", roles: []string{"standard_user"}, serviceErr: service.ErrInvalidPlatformToken, wantStatus: http.StatusNotFound, wantID: 19},
		{name: "invalid token id", path: "/platform/tokens/nope/revoke", actor: "alice", roles: []string{"standard_user"}, wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			tokenService := &fakePlatformTokenService{err: test.serviceErr}
			handler, err := NewPlatformTokenHandler(tokenService)
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.Use(func(context *gin.Context) {
				context.Set(AuthenticatedUserContextKey, test.actor)
				context.Set(AuthenticatedRolesContextKey, test.roles)
			})
			RegisterPlatformTokenRoutes(router, handler)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, test.path, nil))
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantID > 0 && tokenService.tokenID != test.wantID {
				t.Fatalf("revoke token ID = %d, want %d", tokenService.tokenID, test.wantID)
			}
			if test.wantID > 0 && tokenService.actor.UserID != test.actor {
				t.Fatalf("revoke actor = %+v, want %q", tokenService.actor, test.actor)
			}
		})
	}
}

func TestNewPlatformTokenHandlerRequiresService(t *testing.T) {
	if _, err := NewPlatformTokenHandler(nil); err == nil {
		t.Fatal("NewPlatformTokenHandler(nil) expected error")
	}
}
