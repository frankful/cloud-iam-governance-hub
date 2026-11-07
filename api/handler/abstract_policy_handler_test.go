package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	awsadapter "github.com/frankful/cloud-iam-governance-hub/pkg/adapter/aws"
)

func TestTranslateFromAWSRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAbstractPolicyHandler(&awsadapter.AwsAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	RegisterAbstractPolicyRoutes(router.Group("/api/v1"), handler)
	body := `{"policy_json":"{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}}"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/abstract/policy/translate-from-aws", bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	var result struct {
		ParseStatus string `json:"parse_status"`
		Policy      struct {
			Statements []struct {
				Actions []string `json:"actions"`
			} `json:"statements"`
		} `json:"abstract_policy"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ParseStatus != awsadapter.ParseStatusSuccess || len(result.Policy.Statements) != 1 ||
		result.Policy.Statements[0].Actions[0] != "s3:*" {
		t.Fatalf("response = %#v", result)
	}
}

func TestTranslateToAWSRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewAbstractPolicyHandler(&awsadapter.AwsAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	RegisterAbstractPolicyRoutes(router.Group("/api/v1"), handler)
	body := `{"abstract_policy":{"statements":[{"effect":"Allow","actions":["s3:GetObject"],"resources":["arn:aws:s3:::reports/*"]}]}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/abstract/policy/translate-to-aws", bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	var result struct {
		PolicyJSON json.RawMessage `json:"policy_json"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(result.PolicyJSON) {
		t.Fatalf("policy_json invalid: %s", result.PolicyJSON)
	}
}
