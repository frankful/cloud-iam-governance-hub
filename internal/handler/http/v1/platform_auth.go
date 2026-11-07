package v1

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

const AuthenticatedRolesContextKey = "authenticated_roles"

// abortError writes the unified error envelope and stops the middleware chain.
func abortError(context *gin.Context, status int, message string) {
	writeError(context, status, message)
	context.Abort()
}

// PlatformTokenAuthentication authenticates a strict Bearer token without
// logging or returning credential material.
func PlatformTokenAuthentication(authenticator interface {
	Authenticate(ctx context.Context, token string) (service.AuthenticatedIdentity, error)
}) gin.HandlerFunc {
	return func(context *gin.Context) {
		if authenticator == nil {
			abortError(context, http.StatusInternalServerError, "authentication is unavailable")
			return
		}
		scheme, token, ok := strings.Cut(strings.TrimSpace(context.GetHeader("Authorization")), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" ||
			strings.ContainsAny(strings.TrimSpace(token), " \t\r\n") {
			abortError(context, http.StatusUnauthorized, "bearer token is required")
			return
		}
		identity, err := authenticator.Authenticate(context.Request.Context(), strings.TrimSpace(token))
		if err != nil {
			if errors.Is(err, service.ErrInvalidPlatformToken) {
				abortError(context, http.StatusUnauthorized, "invalid or inactive bearer token")
				return
			}
			abortError(context, http.StatusInternalServerError, "authentication failed")
			return
		}
		context.Set(AuthenticatedUserContextKey, identity.UserID)
		context.Set(AuthenticatedRolesContextKey, identity.Roles)
		context.Set("authenticated_token_id", identity.TokenID)
		context.Next()
	}
}

// RequireRoles denies requests unless the authenticated identity has at least
// one of the listed roles. It must be used after an authentication middleware.
func RequireRoles(roles ...string) gin.HandlerFunc {
	required := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if role = strings.TrimSpace(role); role != "" {
			required[role] = struct{}{}
		}
	}
	return func(context *gin.Context) {
		if _, ok := authenticatedUser(context); !ok {
			abortError(context, http.StatusUnauthorized, "authentication is required")
			return
		}
		value, exists := context.Get(AuthenticatedRolesContextKey)
		userRoles, ok := value.([]string)
		if !exists || !ok {
			abortError(context, http.StatusForbidden, "required role is missing")
			return
		}
		for _, role := range userRoles {
			if _, allowed := required[role]; allowed {
				context.Next()
				return
			}
		}
		abortError(context, http.StatusForbidden, "insufficient role")
	}
}
