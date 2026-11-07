package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthHandler exposes the small amount of unauthenticated auth metadata the
// SPA needs before it can choose between development and bearer-token login.
type AuthHandler struct {
	mode string
}

func NewAuthHandler(mode string) (*AuthHandler, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "development" && mode != "api-token" {
		return nil, errors.New("auth mode must be development or api-token")
	}
	return &AuthHandler{mode: mode}, nil
}

// Config is registered outside the authenticated API group. It intentionally
// returns only the auth mode, never credentials or user data.
func (handler *AuthHandler) Config(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"mode": handler.mode})
}

// Me returns the identity established by the authentication middleware. The
// SPA uses it to validate a stored bearer token and to render role-aware
// navigation.
func (handler *AuthHandler) Me(context *gin.Context) {
	userID, ok := authenticatedUser(context)
	if !ok {
		writeError(context, http.StatusUnauthorized, "authenticated user is required")
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"roles":   authenticatedRoles(context),
	})
}

func authenticatedRoles(context *gin.Context) []string {
	value, exists := context.Get(AuthenticatedRolesContextKey)
	if !exists {
		return []string{}
	}
	roles, ok := value.([]string)
	if !ok || roles == nil {
		return []string{}
	}
	return roles
}

func hasAnyRole(roles []string, allowed ...string) bool {
	for _, role := range roles {
		for _, candidate := range allowed {
			if role == candidate {
				return true
			}
		}
	}
	return false
}
