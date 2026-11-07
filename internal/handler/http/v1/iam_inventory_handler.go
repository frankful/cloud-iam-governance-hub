package v1

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

type iamInventoryService interface {
	ListPrincipals(context.Context, service.PrincipalListFilter) ([]service.PrincipalSummary, int, error)
	GetPrincipal(context.Context, int64) (service.PrincipalDetail, error)
	ListGroups(context.Context, service.GroupListFilter) ([]service.GroupSummary, int, error)
	GetGroup(context.Context, int64) (service.GroupDetail, error)
	ListManagedPolicies(context.Context, service.ManagedPolicyFilter) ([]service.ManagedPolicySummary, int, error)
	GetManagedPolicy(context.Context, int64) (service.ManagedPolicyDetail, error)
	ListInlinePolicies(context.Context, service.InlinePolicyListFilter) ([]service.InlinePolicySummary, int, error)
	GetInlinePolicy(context.Context, int64) (service.InlinePolicyDetail, error)
	ListInstanceProfiles(context.Context, service.InstanceProfileListFilter) ([]service.InstanceProfileSummary, int, error)
	GetInstanceProfile(context.Context, int64) (service.InstanceProfileDetail, error)
	GetRoleInlinePolicy(context.Context, int64, string, string) (json.RawMessage, bool, error)
	GetGroupInlinePolicy(context.Context, int64, string, string) (json.RawMessage, bool, error)
}

// IAMInventoryHandler serves the inventoried IAM principals and groups.
type IAMInventoryHandler struct {
	service iamInventoryService
}

// NewIAMInventoryHandler creates an IAMInventoryHandler.
func NewIAMInventoryHandler(inventoryService iamInventoryService) (*IAMInventoryHandler, error) {
	if inventoryService == nil {
		return nil, errors.New("IAM inventory service must not be nil")
	}
	return &IAMInventoryHandler{service: inventoryService}, nil
}

// RegisterIAMInventoryRoutes registers the inventory read endpoints.
func RegisterIAMInventoryRoutes(router gin.IRoutes, handler *IAMInventoryHandler) {
	read := RequireRoles("platform_admin", "approval_admin", "standard_user")
	router.GET("/aws/principals", read, handler.ListPrincipals)
	router.GET("/aws/principals/:principalID", read, handler.GetPrincipal)
	router.GET("/aws/principals/:principalID/inline-policy/:policyName", read, handler.GetRoleInlinePolicy)
	router.GET("/aws/groups", read, handler.ListGroups)
	router.GET("/aws/groups/:groupID", read, handler.GetGroup)
	router.GET("/aws/groups/:groupID/inline-policy/:policyName", read, handler.GetGroupInlinePolicy)
	router.GET("/aws/policies", read, handler.ListManagedPolicies)
	router.GET("/aws/policies/:policyID", read, handler.GetManagedPolicy)
	router.GET("/aws/inline-policies", read, handler.ListInlinePolicies)
	router.GET("/aws/inline-policies/:policyID", read, handler.GetInlinePolicy)
	router.GET("/aws/instance-profiles", read, handler.ListInstanceProfiles)
	router.GET("/aws/instance-profiles/:profileID", read, handler.GetInstanceProfile)
}

// ListPrincipals handles GET /aws/principals.
func (handler *IAMInventoryHandler) ListPrincipals(context *gin.Context) {
	awsFilter, ok := parseAWSQuery(context)
	if !ok {
		return
	}
	filter := service.PrincipalListFilter{
		AccountID: parseOptionalPositiveInt64(context, "account_id"),
		Type:      strings.TrimSpace(context.Query("type")),
		Q:         strings.TrimSpace(context.Query("q")),
		ManagedBy: strings.TrimSpace(context.Query("managed_by")),
		AWS:       awsFilter,
		Limit:     20,
		Offset:    0,
	}
	if filter.AccountID == -1 {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	principals, total, err := handler.service.ListPrincipals(context.Request.Context(), filter)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"principals": principals, "total": total, "limit": limit, "offset": offset,
	})
}

// GetPrincipal handles GET /aws/principals/:principalID.
func (handler *IAMInventoryHandler) GetPrincipal(context *gin.Context) {
	principalID, ok := parsePolicyDerivedID(context, "principalID")
	if !ok {
		return
	}
	principal, err := handler.service.GetPrincipal(context.Request.Context(), principalID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"principal": principal})
}

// ListGroups handles GET /aws/groups.
func (handler *IAMInventoryHandler) ListGroups(context *gin.Context) {
	filter := service.GroupListFilter{
		AccountID: parseOptionalPositiveInt64(context, "account_id"),
		Q:         strings.TrimSpace(context.Query("q")),
		ManagedBy: strings.TrimSpace(context.Query("managed_by")),
		Limit:     20,
		Offset:    0,
	}
	if filter.AccountID == -1 {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	groups, total, err := handler.service.ListGroups(context.Request.Context(), filter)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"groups": groups, "total": total, "limit": limit, "offset": offset,
	})
}

// GetGroup handles GET /aws/groups/:groupID.
func (handler *IAMInventoryHandler) GetGroup(context *gin.Context) {
	groupID, ok := parsePolicyDerivedID(context, "groupID")
	if !ok {
		return
	}
	group, err := handler.service.GetGroup(context.Request.Context(), groupID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"group": group})
}

// GetRoleInlinePolicy handles GET /aws/principals/:principalID/inline-policy/:policyName.
func (handler *IAMInventoryHandler) GetRoleInlinePolicy(context *gin.Context) {
	principalID, ok := parsePolicyDerivedID(context, "principalID")
	if !ok {
		return
	}
	policyName := strings.TrimSpace(context.Param("policyName"))
	if policyName == "" {
		writeError(context, http.StatusBadRequest, "policy name is required")
		return
	}
	// Fetch principal to get account_id and name
	principal, err := handler.service.GetPrincipal(context.Request.Context(), principalID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	document, found, err := handler.service.GetRoleInlinePolicy(context.Request.Context(), principal.AccountID, principal.PrincipalName, policyName)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	if !found {
		writeError(context, http.StatusNotFound, "inline policy not found")
		return
	}
	context.Data(http.StatusOK, "application/json", document)
}

// GetGroupInlinePolicy handles GET /aws/groups/:groupID/inline-policy/:policyName.
func (handler *IAMInventoryHandler) GetGroupInlinePolicy(context *gin.Context) {
	groupID, ok := parsePolicyDerivedID(context, "groupID")
	if !ok {
		return
	}
	policyName := strings.TrimSpace(context.Param("policyName"))
	if policyName == "" {
		writeError(context, http.StatusBadRequest, "policy name is required")
		return
	}
	group, err := handler.service.GetGroup(context.Request.Context(), groupID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	document, found, err := handler.service.GetGroupInlinePolicy(context.Request.Context(), group.AccountID, group.GroupName, policyName)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	if !found {
		writeError(context, http.StatusNotFound, "inline policy not found")
		return
	}
	context.Data(http.StatusOK, "application/json", document)
}

// ListManagedPolicies handles GET /aws/policies: the inventoried managed
// policies (AWS-managed and customer-managed) used to populate the
// ATTACH_USER_POLICY picker. Q matches policy name or ARN.
func (handler *IAMInventoryHandler) ListManagedPolicies(context *gin.Context) {
	awsFilter, ok := parseAWSQuery(context)
	if !ok {
		return
	}
	filter := service.ManagedPolicyFilter{
		Q:         strings.TrimSpace(context.Query("q")),
		ManagedBy: strings.TrimSpace(context.Query("managed_by")),
		AWS:       awsFilter,
		AccountID: parseOptionalPositiveInt64(context, "account_id"),
	}
	if filter.AccountID == -1 {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	policies, total, err := handler.service.ListManagedPolicies(context.Request.Context(), filter)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"policies": policies, "total": total, "limit": limit, "offset": offset,
	})
}

// GetManagedPolicy handles GET /aws/policies/:policyID: full policy detail
// including the current document, used to prefill the update-policy editor
// and to show the reference-count risk hint.
func (handler *IAMInventoryHandler) GetManagedPolicy(context *gin.Context) {
	policyID, ok := parsePolicyDerivedID(context, "policyID")
	if !ok {
		return
	}
	policy, err := handler.service.GetManagedPolicy(context.Request.Context(), policyID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"policy": policy})
}

// parseAWSQuery validates the optional aws filter query parameter. Only
// "true" / "false" / empty are accepted; anything else is a 400.
func parseAWSQuery(context *gin.Context) (string, bool) {
	value := strings.TrimSpace(context.Query("aws"))
	switch value {
	case "", "true", "false":
		return value, true
	default:
		writeError(context, http.StatusBadRequest, "aws filter must be true or false")
		return "", false
	}
}

// parseOptionalPositiveInt64 parses an optional positive int64 query
// parameter. It returns -1 after writing a 400 when the value is invalid.
func parseOptionalPositiveInt64(context *gin.Context, name string) int64 {
	raw := strings.TrimSpace(context.Query(name))
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		writeError(context, http.StatusBadRequest, name+" must be a positive integer")
		return -1
	}
	return value
}

func parseInventoryLimitOffset(context *gin.Context) (int, int, bool) {
	limit := 20
	if raw := strings.TrimSpace(context.Query("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(context, http.StatusBadRequest, "limit must be between 1 and 100")
			return 0, 0, false
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(context.Query("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(context, http.StatusBadRequest, "offset must be a non-negative integer")
			return 0, 0, false
		}
		offset = parsed
	}
	return limit, offset, true
}

func writeInventoryError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrIAMPrincipalNotFound):
		writeError(context, http.StatusNotFound, "IAM principal not found")
	case errors.Is(err, service.ErrIAMGroupNotFound):
		writeError(context, http.StatusNotFound, "IAM group not found")
	case errors.Is(err, service.ErrIAMPolicyNotFound):
		writeError(context, http.StatusNotFound, "IAM managed policy not found")
	case errors.Is(err, service.ErrInvalidPrincipalType):
		writeError(context, http.StatusBadRequest, err.Error())
	case errors.Is(err, service.ErrInvalidInventoryAWSFilter):
		writeError(context, http.StatusBadRequest, err.Error())
	case errors.Is(err, service.ErrIAMInstanceProfileNotFound):
		writeError(context, http.StatusNotFound, "IAM instance profile not found")
	default:
		// 未知错误必须落日志：500 只给客户端一句笼统话，排障全靠这里。
		slog.Error("iam inventory request failed",
			"path", context.FullPath(), "error", err)
		writeError(context, http.StatusInternalServerError, "failed to query IAM inventory")
	}
}

// ListInlinePolicies handles GET /aws/inline-policies: inline policies with
// their owning principal, for the inventory's ticket-modifiable / AWS-owned
// split. The aws query parameter narrows by the owner's AWS-owned mark.
func (handler *IAMInventoryHandler) ListInlinePolicies(context *gin.Context) {
	awsFilter, ok := parseAWSQuery(context)
	if !ok {
		return
	}
	filter := service.InlinePolicyListFilter{
		AccountID: parseOptionalPositiveInt64(context, "account_id"),
		Q:         strings.TrimSpace(context.Query("q")),
		AWS:       awsFilter,
	}
	if filter.AccountID == -1 {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	policies, total, err := handler.service.ListInlinePolicies(context.Request.Context(), filter)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"policies": policies, "total": total, "limit": limit, "offset": offset,
	})
}

// ListInstanceProfiles handles GET /aws/instance-profiles: the inventoried
// instance profiles. They are all read-only here (no ticket type touches
// them); the EKS-managed mark distinguishes node-group-owned profiles.
func (handler *IAMInventoryHandler) ListInstanceProfiles(context *gin.Context) {
	filter := service.InstanceProfileListFilter{
		AccountID: parseOptionalPositiveInt64(context, "account_id"),
		Q:         strings.TrimSpace(context.Query("q")),
	}
	if filter.AccountID == -1 {
		return
	}
	limit, offset, ok := parseInventoryLimitOffset(context)
	if !ok {
		return
	}
	filter.Limit, filter.Offset = limit, offset
	profiles, total, err := handler.service.ListInstanceProfiles(context.Request.Context(), filter)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"profiles": profiles, "total": total, "limit": limit, "offset": offset,
	})
}

// GetInlinePolicy handles GET /aws/inline-policies/:policyID: one inline
// policy with its document and owning principal, for the inventory detail
// drawer (works for both ticket-modifiable and AWS-owned policies).
func (handler *IAMInventoryHandler) GetInlinePolicy(context *gin.Context) {
	policyID, ok := parsePolicyDerivedID(context, "policyID")
	if !ok {
		return
	}
	policy, err := handler.service.GetInlinePolicy(context.Request.Context(), policyID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"policy": policy})
}

// GetInstanceProfile handles GET /aws/instance-profiles/:profileID: one
// instance profile with tags and bound role, for the inventory detail drawer.
func (handler *IAMInventoryHandler) GetInstanceProfile(context *gin.Context) {
	profileID, ok := parsePolicyDerivedID(context, "profileID")
	if !ok {
		return
	}
	profile, err := handler.service.GetInstanceProfile(context.Request.Context(), profileID)
	if err != nil {
		writeInventoryError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"profile": profile})
}
