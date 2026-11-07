package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/frankful/cloud-iam-governance-hub/internal/adapter"
	"github.com/frankful/cloud-iam-governance-hub/internal/apperr"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

// 收敛双路（phase4-drift-design.md §7）。
//
// 判定只负责把「声明 vs 实态」摆出来；改变现实只有两条路，且都必须由人
// 点：
//
//   - 接受现状（acknowledge）：重发基线，把当前实态写成代码。语义是追认，
//     不是回滚——文案必须写清，否则运维会以为点一下就恢复原状。
//   - 回滚到声明（rollback）：用声明快照里的旧值预填一张 UPDATE_* 草稿，
//     走正常审批 → 发布 → apply。草稿只是草稿：审批人看到的 diff 才是变更
//     本身，这里不替人提交。
//
// 按归属分流：资源由工单声明时（declaration.ticket_id 非空），重发基线改不
// 动它（0027 更新门禁会拒），只能走回滚；由基线声明时两路都给。
const (
	DriftRouteAcknowledge = "acknowledge"
	DriftRouteRollback    = "rollback"

	DriftOwnerBaseline = "baseline"
	DriftOwnerTicket   = "ticket"
)

// DriftRemediation 是一次收敛动作的结果或可行性说明。Reason 非空表示这条路
// 当前走不通（例如该差异类型没有对应工单），属于能力边界而不是错误——页面
// 要把它当成解释展示，而不是红色报错。
type DriftRemediation struct {
	FindingID int64  `json:"finding_id"`
	Route     string `json:"route"`
	Owner     string `json:"owner"`
	// AllowedRoutes 是当前发现可用的收敛路径，页面据此决定按钮显隐。
	AllowedRoutes []string `json:"allowed_routes"`

	TicketType string `json:"ticket_type,omitempty"`
	TicketNo   string `json:"ticket_no,omitempty"`

	Publication      *BaselinePublication `json:"publication,omitempty"`
	AlreadyPublished bool                 `json:"already_published,omitempty"`
	// InFlight 表示该账号已有同快照的基线发布在跑：返回的是既有台账，
	// 调用方不要再驱动一次。
	InFlight bool `json:"in_flight,omitempty"`

	Reason string `json:"reason,omitempty"`
}

// driftRemediationFindings / Tickets / Publications 是收敛服务对三块能力的
// 最小依赖：读发现、建草稿、发基线。收窄接口是为了让「生成什么工单」的
// 逻辑能脱离 HTTP 与数据库单测。
type driftRemediationFindings interface {
	GetFinding(ctx context.Context, id int64) (DriftFinding, error)
}

type driftRemediationTickets interface {
	CreateDraft(ctx context.Context, submitter string, request CreateIAMTicketRequest) (model.IAMTicket, error)
}

type driftRemediationPublications interface {
	Create(ctx context.Context, accountRef, requestedBy string) (*BaselinePublication, bool, error)
}

type DriftRemediationService struct {
	findings     driftRemediationFindings
	declarations *BaselineDeclarationService
	tickets      driftRemediationTickets
	publications driftRemediationPublications
	logger       *slog.Logger
}

func NewDriftRemediationService(
	findings driftRemediationFindings,
	declarations *BaselineDeclarationService,
	tickets driftRemediationTickets,
	publications driftRemediationPublications,
	logger *slog.Logger,
) (*DriftRemediationService, error) {
	if findings == nil {
		return nil, errors.New("drift finding reader must not be nil")
	}
	if declarations == nil {
		return nil, errors.New("baseline declaration service must not be nil")
	}
	if tickets == nil {
		return nil, errors.New("ticket service must not be nil")
	}
	if publications == nil {
		return nil, errors.New("baseline publication service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DriftRemediationService{
		findings: findings, declarations: declarations,
		tickets: tickets, publications: publications, logger: logger,
	}, nil
}

// Acknowledge 重发该账号的基线：main 上的文件随之更新成当前实态，下一轮
// 判定自然不再有差异。幂等命中（同一次同步已发过）直接返回既有台账。
func (service *DriftRemediationService) Acknowledge(
	ctx context.Context,
	findingID int64,
	actor string,
) (DriftRemediation, error) {
	plan := DriftRemediation{FindingID: findingID, Route: DriftRouteAcknowledge}
	finding, err := service.findings.GetFinding(ctx, findingID)
	if err != nil {
		return plan, err
	}
	evaluateDriftRemediationPlan(&plan, finding, service.declarationFor(ctx, finding))
	if !containsRoute(plan.AllowedRoutes, DriftRouteAcknowledge) {
		plan.Reason = "该资源由工单声明，重发基线改不动它；请用回滚开一张 UPDATE_* 工单"
		return plan, nil
	}
	publication, alreadyPublished, err := service.publications.Create(
		ctx, finding.AWSAccountID, strings.TrimSpace(actor))
	if err != nil {
		return plan, err
	}
	plan.Publication = publication
	plan.AlreadyPublished = alreadyPublished
	if publication != nil {
		plan.InFlight = publication.InFlight
	}
	return plan, nil
}

// Rollback 按声明快照生成一张 DRAFT 工单。生成失败（差异类型没有对应工单、
// 字段不在可写范围内）不返回错误，而是把原因写进 Reason——这是产品能力的
// 边界，不该让页面弹 500。
func (service *DriftRemediationService) Rollback(
	ctx context.Context,
	findingID int64,
	actor string,
) (DriftRemediation, error) {
	plan := DriftRemediation{FindingID: findingID, Route: DriftRouteRollback}
	finding, err := service.findings.GetFinding(ctx, findingID)
	if err != nil {
		return plan, err
	}
	declaration := service.declarationFor(ctx, finding)
	evaluateDriftRemediationPlan(&plan, finding, declaration)
	if !containsRoute(plan.AllowedRoutes, DriftRouteRollback) {
		plan.Reason = "该发现没有可回滚的声明快照；请人工处理或接受现状"
		return plan, nil
	}
	request, reason := BuildDriftRollbackTicket(finding, declaration, finding.AccountDBID)
	if request == nil {
		plan.Reason = reason
		return plan, nil
	}
	plan.TicketType = request.TicketType
	ticket, err := service.tickets.CreateDraft(ctx, strings.TrimSpace(actor), *request)
	if err != nil {
		// 校验失败（账号没绑其他审批人、角色不在库存、已有在途工单）不是
		// 500，也不是「功能坏了」——把原因交给页面解释，运维才知道该先
		// 做什么。
		if apperr.IsValidationError(err) {
			plan.Reason = err.Error()
			return plan, nil
		}
		return plan, err
	}
	if ticket.TicketNo != nil {
		plan.TicketNo = *ticket.TicketNo
	}
	service.logger.Info("drift rollback draft created",
		"finding_id", findingID, "ticket_no", plan.TicketNo,
		"ticket_type", plan.TicketType, "resource_key", finding.ResourceKey)
	return plan, nil
}

// declarationFor 找出该发现所依据的当前声明。子资源发现（挂载 / 成员 /
// 内联策略）可能没有同 key 的声明——它的归属要按文件推断：同一文件的声明
// 由基线还是工单写入，决定了「重发基线」是否动得了它。
func (service *DriftRemediationService) declarationFor(
	ctx context.Context,
	finding DriftFinding,
) *BaselineDeclaration {
	declarations, err := service.declarations.LoadCurrent(ctx, finding.AccountDBID)
	if err != nil {
		service.logger.Warn("load declarations for remediation failed",
			"finding_id", finding.ID, "error", err)
		return nil
	}
	var sameFile *BaselineDeclaration
	for index := range declarations {
		declaration := declarations[index]
		if declaration.ResourceKey == finding.ResourceKey {
			return &declarations[index]
		}
		if declaration.FileKey == finding.FileKey && sameFile == nil {
			sameFile = &declarations[index]
		}
	}
	return sameFile
}

func evaluateDriftRemediationPlan(
	plan *DriftRemediation,
	finding DriftFinding,
	declaration *BaselineDeclaration,
) {
	plan.Owner = DriftOwnerBaseline
	if declaration != nil && declaration.TicketID != nil {
		plan.Owner = DriftOwnerTicket
	}
	rollbackable := declaration != nil &&
		DriftRollbackTicketType(finding, *declaration) != ""
	routes := make([]string, 0, 2)
	if plan.Owner == DriftOwnerBaseline {
		routes = append(routes, DriftRouteAcknowledge)
	}
	if rollbackable {
		routes = append(routes, DriftRouteRollback)
	}
	plan.AllowedRoutes = routes
}

func containsRoute(routes []string, route string) bool {
	for _, candidate := range routes {
		if candidate == route {
			return true
		}
	}
	return false
}

// DriftRollbackTicketType 返回该差异可以回滚成的工单类型；空字符串表示
// 当前能力覆盖不到。判定与建单共用这一处，避免「按钮能点、点完 400」。
func DriftRollbackTicketType(finding DriftFinding, declaration BaselineDeclaration) string {
	if finding.ChangeType != DriftChangeAttribute {
		return ""
	}
	switch declaration.Kind {
	case BaselineKindRole:
		return TicketTypeUpdateRole
	case BaselineKindPolicy:
		return TicketTypeUpdateManagedPolicy
	case BaselineKindInlinePolicy:
		ownerKind := declarationAttributeString(declaration, declarationAttributeOwnerKind)
		// UPDATE_GROUP_INLINE_POLICY 只覆盖组与角色；用户内联策略没有对应
		// 的更新工单类型，强行放开只会造出一张提交不了的草稿。
		if ownerKind == BaselineKindGroup || ownerKind == BaselineKindRole {
			return TicketTypeUpdateGroupInlinePolicy
		}
	}
	return ""
}

// BuildDriftRollbackTicket 把「声明里本该是什么」翻译成一张预填工单。
//
// 只回填**有差异的字段**：声明里其他字段本来就和实态一致，一起写进去只会
// 扩大 diff、增加审批负担。返回第二值是「为什么不能自动生成」，供页面展示。
func BuildDriftRollbackTicket(
	finding DriftFinding,
	declaration *BaselineDeclaration,
	accountDBID int64,
) (*CreateIAMTicketRequest, string) {
	if declaration == nil {
		return nil, "该发现没有对应的声明快照，无法还原目标配置"
	}
	ticketType := DriftRollbackTicketType(finding, *declaration)
	if ticketType == "" {
		return nil, "该差异类型不在自动回滚范围内（只有属性漂移能生成 UPDATE_* 草稿），请人工处理"
	}
	attributes, err := decodeDeclarationAttributes(declaration.Attributes)
	if err != nil {
		return nil, "声明快照属性无法解析：" + err.Error()
	}
	changed := map[string]bool{}
	for _, field := range finding.Fields {
		changed[field.Field] = true
	}
	request := &CreateIAMTicketRequest{
		TicketType:    ticketType,
		AccountID:     accountDBID,
		PrincipalName: declaration.Name,
		// AUTO 只决定「审批人从账号绑定解析」，不是免审批：草稿仍然要人
		// 提交、走审批与发布。MANUAL 会强制调用方先选审批人，而这里没有
		// 交互界面可选——把选择权留给打开草稿的人改。
		ApprovalMode: ApprovalModeAuto,
	}
	switch ticketType {
	case TicketTypeUpdateRole:
		config, reason := driftRollbackRoleConfig(attributes, changed)
		if config == nil {
			return nil, reason
		}
		request.UpdateRole = config
	case TicketTypeUpdateManagedPolicy:
		document, reason := driftRollbackPolicyDocument(attributes)
		if document == nil {
			return nil, reason
		}
		request.UpdatePolicy = &adapter.UpdatePolicyConfig{
			PolicyARN:  driftManagedPolicyARN(declaration, attributes),
			PolicyName: declaration.Name,
			Document:   document,
		}
	case TicketTypeUpdateGroupInlinePolicy:
		document, reason := driftRollbackPolicyDocument(attributes)
		if document == nil {
			return nil, reason
		}
		config := &adapter.UpdatePolicyConfig{
			InlinePolicyName: declaration.Name,
			Document:         document,
		}
		ownerKind := declarationAttributeString(*declaration, declarationAttributeOwnerKind)
		owner := declarationAttributeString(*declaration, declarationAttributeOwner)
		if owner == "" {
			return nil, "声明快照缺少内联策略的属主信息"
		}
		if ownerKind == BaselineKindGroup {
			config.GroupName = owner
			request.PrincipalType = "Group"
		} else {
			config.RoleName = owner
			request.PrincipalType = "Role"
		}
		request.PrincipalName = owner
		request.UpdatePolicy = config
	}
	return request, ""
}

// driftRollbackRoleConfig 只取声明里写过、且本次确实有差异的字段。返回 nil
// 表示没有任何一个字段能通过 UPDATE_ROLE 写回去（例如 path / 边界策略没有
// 对应的更新通道）。
func driftRollbackRoleConfig(
	attributes map[string]any,
	changed map[string]bool,
) (*adapter.UpdateRoleConfig, string) {
	config := &adapter.UpdateRoleConfig{}
	if changed[declarationAttributeDescription] {
		if value, ok := attributes[declarationAttributeDescription].(string); ok {
			description := value
			config.Description = &description
		}
	}
	if changed[declarationAttributeMaxSession] {
		if value, ok := driftAttributeInt(attributes[declarationAttributeMaxSession]); ok {
			config.MaxSessionDuration = &value
		}
	}
	if changed[declarationAttributeTrustPolicy] {
		if document, ok := driftAttributeDocument(attributes[declarationAttributeTrustPolicy]); ok {
			config.TrustPolicy = &document
		}
	}
	if changed[declarationAttributeTags] {
		config.Tags = driftAttributeTags(attributes[declarationAttributeTags])
	}
	if config.Description == nil && config.MaxSessionDuration == nil &&
		config.TrustPolicy == nil && len(config.Tags) == 0 {
		return nil, "差异字段（如 path / 权限边界）没有对应的更新通道，请人工处理"
	}
	return config, ""
}

func driftRollbackPolicyDocument(attributes map[string]any) (json.RawMessage, string) {
	document, ok := driftAttributeRawDocument(attributes[declarationAttributeDocument])
	if !ok || len(document) == 0 {
		return nil, "声明快照缺少策略文档，无法还原"
	}
	return document, ""
}

func decodeDeclarationAttributes(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	attributes := map[string]any{}
	if err := json.Unmarshal(raw, &attributes); err != nil {
		return nil, fmt.Errorf("decode declaration attributes: %w", err)
	}
	return attributes, nil
}

func declarationAttributeString(declaration BaselineDeclaration, key string) string {
	attributes, err := decodeDeclarationAttributes(declaration.Attributes)
	if err != nil {
		return ""
	}
	value, _ := attributes[key].(string)
	return value
}

// driftManagedPolicyARN 由账号 + 路径 + 名称还原客户托管策略的 ARN：声明里
// 只有 name/path，而 UPDATE_MANAGED_POLICY 要 ARN 才能定位。
func driftManagedPolicyARN(declaration *BaselineDeclaration, attributes map[string]any) string {
	path := "/"
	if value, ok := attributes[declarationAttributePath].(string); ok && strings.TrimSpace(value) != "" {
		path = value
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return fmt.Sprintf("arn:aws:iam::%s:policy%s%s", declaration.AWSAccountID, path, declaration.Name)
}

func driftAttributeRawDocument(value any) (json.RawMessage, bool) {
	switch typed := value.(type) {
	case nil:
		return nil, false
	case json.RawMessage:
		return typed, true
	case []byte:
		return json.RawMessage(typed), true
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return nil, false
		}
		return json.RawMessage(encoded), true
	}
}

func driftAttributeDocument(value any) (map[string]interface{}, bool) {
	raw, ok := driftAttributeRawDocument(value)
	if !ok {
		return nil, false
	}
	document := map[string]interface{}{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, false
	}
	return document, true
}

func driftAttributeInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	}
	return 0, false
}

func driftAttributeTags(value any) map[string]string {
	decoded, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	tags := make(map[string]string, len(decoded))
	for key, item := range decoded {
		if text, ok := item.(string); ok {
			tags[key] = text
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}
