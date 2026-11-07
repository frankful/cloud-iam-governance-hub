package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type accountConfigHandlerServiceFake struct {
	createdInput service.AWSAccountConfigInput
	actorID      string
}

func (fake *accountConfigHandlerServiceFake) Create(
	_ context.Context,
	input service.AWSAccountConfigInput,
	actorID string,
) (model.AWSAccountConfig, error) {
	fake.createdInput, fake.actorID = input, actorID
	return model.AWSAccountConfig{
		ID: 3, AWSAccountID: input.AWSAccountID, DisplayName: input.DisplayName,
		SyncMode: input.SyncMode, SyncEnabled: input.SyncEnabled,
		Tags: model.JSONB(input.Tags), LastSyncError: stringPointer("sensitive internal detail"),
	}, nil
}

func (fake *accountConfigHandlerServiceFake) Update(
	context.Context, int64, service.AWSAccountConfigInput, string,
) (model.AWSAccountConfig, error) {
	return model.AWSAccountConfig{}, nil
}

func (fake *accountConfigHandlerServiceFake) Get(context.Context, int64) (model.AWSAccountConfig, error) {
	return model.AWSAccountConfig{}, nil
}

func (fake *accountConfigHandlerServiceFake) List(context.Context, int, int) ([]model.AWSAccountConfig, error) {
	return nil, nil
}

func (fake *accountConfigHandlerServiceFake) SetSyncEnabled(
	context.Context, int64, bool, string,
) (model.AWSAccountConfig, error) {
	return model.AWSAccountConfig{}, nil
}

func (fake *accountConfigHandlerServiceFake) TestConnection(
	context.Context, int64, string,
) (service.AWSAccountConnectionIdentity, error) {
	return service.AWSAccountConnectionIdentity{}, nil
}

func TestAWSAccountConfigRoutesRequirePlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAWSAccountConfigHandler(&accountConfigHandlerServiceFake{})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "regular-user")
		context.Set(AuthenticatedRolesContextKey, []string{"standard_user"})
	})
	RegisterAWSAccountConfigRoutes(api, handler)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/aws/account-configs", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected standard user to be forbidden, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAWSAccountConfigCreateReturnsSafeResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	serviceFake := &accountConfigHandlerServiceFake{}
	handler, err := NewAWSAccountConfigHandler(serviceFake)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Set(AuthenticatedUserContextKey, "admin")
		context.Set(AuthenticatedRolesContextKey, []string{"platform_admin"})
	})
	RegisterAWSAccountConfigRoutes(api, handler)

	requestBody := `{"aws_account_id":"123456789012","display_name":"Production","sync_mode":"CURRENT_CREDENTIALS","sync_enabled":false}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/aws/account-configs", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	if serviceFake.actorID != "admin" || serviceFake.createdInput.AWSAccountID != "123456789012" {
		t.Fatalf("handler did not pass authenticated actor and input to service: %+v", serviceFake)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(response.Body.String(), "sensitive internal detail") ||
		strings.Contains(response.Body.String(), "last_sync_error") {
		t.Fatalf("response leaked internal sync error: %s", response.Body.String())
	}
}

func stringPointer(value string) *string { return &value }
