package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthHandlerConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, mode := range []string{"development", "api-token"} {
		handler, err := NewAuthHandler(mode)
		if err != nil {
			t.Fatalf("NewAuthHandler(%q): %v", mode, err)
		}
		router := gin.New()
		router.GET("/auth/config", handler.Config)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.Code)
		}
		want := `{"mode":"` + mode + `"}`
		if response.Body.String() != want {
			t.Errorf("body = %s, want %s", response.Body.String(), want)
		}
	}
}

func TestAuthHandlerRejectsUnknownMode(t *testing.T) {
	if _, err := NewAuthHandler(""); err == nil {
		t.Fatal("NewAuthHandler accepted an empty mode")
	}
	if _, err := NewAuthHandler("production"); err == nil {
		t.Fatal("NewAuthHandler accepted an unsupported mode")
	}
}

func TestAuthHandlerMe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAuthHandler("api-token")
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "alice")
		context.Set(AuthenticatedRolesContextKey, []string{"approval_admin"})
	})
	router.GET("/auth/me", handler.Me)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	want := `{"roles":["approval_admin"],"user_id":"alice"}`
	if response.Body.String() != want {
		t.Errorf("body = %s, want %s", response.Body.String(), want)
	}
}

func TestAuthHandlerMeRequiresAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAuthHandler("api-token")
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/auth/me", handler.Me)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}
