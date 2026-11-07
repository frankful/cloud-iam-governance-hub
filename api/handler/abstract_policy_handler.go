package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	awsadapter "github.com/frankful/cloud-iam-governance-hub/pkg/adapter/aws"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

const maxPolicyRequestSize = 1 << 20

// writeAPIError writes the unified API error envelope
// ({"code","message","details"}) shared by all platform endpoints.
func writeAPIError(context *gin.Context, status int, code, message string) {
	context.JSON(status, gin.H{"code": code, "message": message, "details": gin.H{}})
}

type AbstractPolicyHandler struct {
	adapter *awsadapter.AwsAdapter
}

func NewAbstractPolicyHandler(adapter *awsadapter.AwsAdapter) (*AbstractPolicyHandler, error) {
	if adapter == nil {
		return nil, errors.New("AWS adapter must not be nil")
	}
	return &AbstractPolicyHandler{adapter: adapter}, nil
}

func RegisterAbstractPolicyRoutes(router gin.IRoutes, handler *AbstractPolicyHandler) {
	router.POST("/abstract/policy/translate-from-aws", handler.TranslateFromAWS)
	router.POST("/abstract/policy/translate-to-aws", handler.TranslateToAWS)
}

func (handler *AbstractPolicyHandler) TranslateFromAWS(context *gin.Context) {
	var request struct {
		PolicyJSON string `json:"policy_json" binding:"required"`
	}
	context.Request.Body = http.MaxBytesReader(context.Writer, context.Request.Body, maxPolicyRequestSize)
	if err := context.ShouldBindJSON(&request); err != nil {
		writeAPIError(context, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	policy, status, message, err := handler.adapter.FromCloudPolicy(json.RawMessage(request.PolicyJSON))
	if err != nil && status != awsadapter.ParseStatusFailed {
		writeAPIError(context, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to parse AWS policy")
		return
	}
	response := gin.H{
		"abstract_policy": policy,
		"parse_status":    status,
		"parse_msg":       message,
	}
	if status == awsadapter.ParseStatusFailed {
		context.JSON(http.StatusOK, response)
		return
	}
	context.JSON(http.StatusOK, response)
}

func (handler *AbstractPolicyHandler) TranslateToAWS(context *gin.Context) {
	var request struct {
		AbstractPolicy *abstractiam.AbstractPolicy `json:"abstract_policy" binding:"required"`
	}
	context.Request.Body = http.MaxBytesReader(context.Writer, context.Request.Body, maxPolicyRequestSize)
	if err := context.ShouldBindJSON(&request); err != nil {
		writeAPIError(context, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	policyJSON, err := handler.adapter.ToCloudPolicy(request.AbstractPolicy)
	if err != nil {
		writeAPIError(context, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	context.JSON(http.StatusOK, gin.H{"policy_json": json.RawMessage(policyJSON)})
}
