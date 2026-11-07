package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// driftLiveResource 是一条「线上实态」的归一化视图。属性名必须与声明快照
// （baseline_bundle_service.go 的 declare）逐字一致，否则比对永远不相等——
// 两边词汇表的唯一保障是 declaration_extract_test.go 里那个「声明 vs 反解」
// 的形状测试，以及 drift_test.go 的比对用例。
type driftLiveResource struct {
	ResourceKey string
	Kind        string
	Name        string
	Attributes  map[string]any
}

// driftLiveSnapshot 是一次判定用的库存快照。加载一次、判定全部复用：判定
// 过程中库存可能变化（同步正在写），逐条查询会得到互相矛盾的证据。
type driftLiveSnapshot struct {
	resources map[string]driftLiveResource
}

func (snapshot driftLiveSnapshot) get(resourceKey string) (driftLiveResource, bool) {
	resource, ok := snapshot.resources[resourceKey]
	return resource, ok
}

// loadDriftLiveSnapshot 读取账号的当前库存。只读，不加锁：判定与同步在同一
// 个 worker 串行执行（账号级同步锁），不存在读到半轮写入的窗口。
func loadDriftLiveSnapshot(
	ctx context.Context,
	db *sql.DB,
	accountDBID int64,
	awsAccountID string,
) (driftLiveSnapshot, error) {
	snapshot := driftLiveSnapshot{resources: map[string]driftLiveResource{}}
	if err := loadDriftPrincipals(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftGroups(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftPolicies(ctx, db, awsAccountID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftInlinePolicies(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftAttachments(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftMemberships(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftInstanceProfiles(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	if err := loadDriftProviders(ctx, db, accountDBID, snapshot.resources); err != nil {
		return driftLiveSnapshot{}, err
	}
	return snapshot, nil
}

func loadDriftPrincipals(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT principal_type, principal_name, COALESCE(path, '/'),
		       COALESCE(trust_policy::text, ''), COALESCE(description, ''),
		       COALESCE(max_session_duration, 0),
		       COALESCE(permissions_boundary_arn, ''), COALESCE(tags::text, '')
		FROM iam_principal
		WHERE account_id = $1 AND is_deleted = FALSE
		  AND principal_type IN ('Role', 'User')`, accountDBID)
	if err != nil {
		return fmt.Errorf("load drift principals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var principalType, name, path, trustPolicy, description string
		var maxSession int
		var boundary, tags string
		if err := rows.Scan(&principalType, &name, &path, &trustPolicy,
			&description, &maxSession, &boundary, &tags); err != nil {
			return fmt.Errorf("scan drift principal: %w", err)
		}
		attributes := map[string]any{"path": path}
		if principalType == "Role" {
			if trustPolicy != "" {
				attributes["trust_policy"] = json.RawMessage(trustPolicy)
			}
			if description != "" {
				attributes["description"] = description
			}
			if maxSession > 0 {
				attributes["max_session_duration"] = maxSession
			}
			if boundary != "" {
				attributes["permissions_boundary"] = boundary
			}
		}
		if decoded := decodeDriftTags(tags); len(decoded) > 0 {
			attributes["tags"] = decoded
		}
		kind := BaselineKindUser
		if principalType == "Role" {
			kind = BaselineKindRole
		}
		key := kind + ":" + name
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: kind, Name: name, Attributes: attributes,
		}
	}
	return rows.Err()
}

func loadDriftGroups(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT group_name, COALESCE(path, '/') FROM iam_group WHERE account_id = $1`,
		accountDBID)
	if err != nil {
		return fmt.Errorf("load drift groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, path string
		if err := rows.Scan(&name, &path); err != nil {
			return fmt.Errorf("scan drift group: %w", err)
		}
		key := BaselineKindGroup + ":" + name
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: BaselineKindGroup, Name: name,
			Attributes: map[string]any{"path": path},
		}
	}
	return rows.Err()
}

func loadDriftPolicies(
	ctx context.Context, db *sql.DB, awsAccountID string,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(policy_name, ''), policy_arn,
		       COALESCE(policy_document::text, ''), COALESCE(description, ''),
		       COALESCE(tags::text, '')
		FROM iam_policy
		WHERE policy_type = 'managed'
		  AND policy_arn LIKE 'arn:aws:iam::' || $1 || ':policy/%'`, awsAccountID)
	if err != nil {
		return fmt.Errorf("load drift policies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, arn, document, description, tags string
		if err := rows.Scan(&name, &arn, &document, &description, &tags); err != nil {
			return fmt.Errorf("scan drift policy: %w", err)
		}
		if name == "" {
			continue
		}
		attributes := map[string]any{"path": policyPathFromARN(arn)}
		if document != "" {
			attributes["document"] = json.RawMessage(document)
		}
		if description != "" {
			attributes["description"] = description
		}
		if decoded := decodeDriftTags(tags); len(decoded) > 0 {
			attributes["tags"] = decoded
		}
		key := BaselineKindPolicy + ":" + name
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: BaselineKindPolicy, Name: name, Attributes: attributes,
		}
	}
	return rows.Err()
}

func loadDriftInlinePolicies(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT owner_kind, owner_name, pol.policy_name, pol.policy_document::text
		FROM (
			SELECT pp.policy_id, 'role' AS owner_kind, p.principal_name AS owner_name
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE AND p.principal_type = 'Role'
			UNION ALL
			SELECT pp.policy_id, 'user', p.principal_name
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE AND p.principal_type = 'User'
			UNION ALL
			SELECT gp.policy_id, 'group', g.group_name
			FROM iam_group_policy gp
			JOIN iam_group g ON g.id = gp.group_id
			WHERE g.account_id = $1
		) owners
		JOIN iam_policy pol ON pol.id = owners.policy_id
		WHERE pol.policy_type = 'inline'`, accountDBID)
	if err != nil {
		return fmt.Errorf("load drift inline policies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ownerKind, owner, policyName, document string
		if err := rows.Scan(&ownerKind, &owner, &policyName, &document); err != nil {
			return fmt.Errorf("scan drift inline policy: %w", err)
		}
		key := ownerKind + ":" + owner + ":inline:" + policyName
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: BaselineKindInlinePolicy, Name: policyName,
			Attributes: map[string]any{
				"owner_kind": ownerKind,
				"owner":      owner,
				"policy":     policyName,
				"document":   json.RawMessage(document),
			},
		}
	}
	return rows.Err()
}

func loadDriftAttachments(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	// 与基线候选同一个口径，但不排除「解绑工单进行中」的挂载：判定要看的
	// 是当下库存，在途变更由发布预约（第 4 层门禁）挡掉，不在这里猜。
	rows, err := db.QueryContext(ctx, `
		WITH attachments AS (
			SELECT p.principal_type, p.principal_name, pol.policy_arn, pol.policy_name
			FROM iam_principal_policy pp
			JOIN iam_principal p ON p.id = pp.principal_id
			JOIN iam_policy pol ON pol.id = pp.policy_id
			WHERE p.account_id = $1 AND p.is_deleted = FALSE
			  AND COALESCE(pol.policy_arn, '') <> ''
			UNION ALL
			SELECT 'Group' AS principal_type, g.group_name, pol.policy_arn, pol.policy_name
			FROM iam_group_policy gp
			JOIN iam_group g ON g.id = gp.group_id
			JOIN iam_policy pol ON pol.id = gp.policy_id
			WHERE g.account_id = $1
			  AND pol.policy_type = 'managed'
			  AND COALESCE(pol.policy_arn, '') <> ''
		)
		SELECT principal_type, principal_name, policy_arn, COALESCE(policy_name, '')
		FROM attachments
		ORDER BY principal_type, principal_name, policy_arn`, accountDBID)
	if err != nil {
		return fmt.Errorf("load drift attachments: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var principalType, principal, policyARN, policyName string
		if err := rows.Scan(&principalType, &principal, &policyARN, &policyName); err != nil {
			return fmt.Errorf("scan drift attachment: %w", err)
		}
		kind := strings.ToLower(principalType)
		key := "attachment:" + kind + ":" + principal + ":" + policyARN
		if policyName == "" {
			policyName = adapterPolicyNameFromARN(policyARN)
		}
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: "attachment", Name: policyName,
			Attributes: map[string]any{
				"principal_kind": kind,
				"principal":      principal,
				"policy_arn":     policyARN,
			},
		}
	}
	return rows.Err()
}

func loadDriftMemberships(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT g.group_name, p.principal_name
		FROM iam_group_membership m
		JOIN iam_group g ON g.id = m.group_id
		JOIN iam_principal p ON p.id = m.user_principal_id
		WHERE g.account_id = $1 AND p.is_deleted = FALSE
		ORDER BY g.group_name, p.principal_name`, accountDBID)
	if err != nil {
		return fmt.Errorf("load drift memberships: %w", err)
	}
	defer rows.Close()
	members := map[string][]string{}
	for rows.Next() {
		var group, user string
		if err := rows.Scan(&group, &user); err != nil {
			return fmt.Errorf("scan drift membership: %w", err)
		}
		members[group] = append(members[group], user)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for group, list := range members {
		sort.Strings(list)
		key := "membership:group:" + group
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: "membership", Name: group,
			Attributes: map[string]any{"group": group, "members": list},
		}
	}
	return nil
}

func loadDriftInstanceProfiles(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT instance_profile_name, COALESCE(path, '/'), COALESCE(role_arn, '')
		FROM iam_instance_profile
		WHERE account_id = $1 AND is_deleted = FALSE`, accountDBID)
	if err != nil {
		return fmt.Errorf("load drift instance profiles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, path, roleARN string
		if err := rows.Scan(&name, &path, &roleARN); err != nil {
			return fmt.Errorf("scan drift instance profile: %w", err)
		}
		attributes := map[string]any{"path": path}
		if roleARN != "" {
			attributes["role"] = adapterPolicyNameFromARN(roleARN)
		}
		key := BaselineKindInstanceProfile + ":" + name
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: BaselineKindInstanceProfile, Name: name,
			Attributes: attributes,
		}
	}
	return rows.Err()
}

func loadDriftProviders(
	ctx context.Context, db *sql.DB, accountDBID int64,
	resources map[string]driftLiveResource,
) error {
	rows, err := db.QueryContext(ctx, `
		SELECT provider_type, provider_name, COALESCE(url, ''),
		       COALESCE(client_id_list::text, ''), COALESCE(thumbprint_list::text, ''),
		       COALESCE(saml_metadata_document, ''), tags
		FROM iam_identity_provider
		WHERE account_id = $1 AND is_deleted = FALSE`, accountDBID)
	if err != nil {
		return fmt.Errorf("load drift identity providers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var providerType, name, url, clientIDs, thumbprints, metadata string
		var tags []byte
		if err := rows.Scan(&providerType, &name, &url, &clientIDs,
			&thumbprints, &metadata, &tags); err != nil {
			return fmt.Errorf("scan drift identity provider: %w", err)
		}
		var attributes map[string]any
		kind := BaselineKindSAMLProvider
		if providerType == "OIDC" {
			kind = BaselineKindOIDCProvider
			ids := decodeStringList(clientIDs)
			prints := decodeStringList(thumbprints)
			sort.Strings(ids)
			sort.Strings(prints)
			attributes = map[string]any{
				"url":         normalizeOIDCProviderURL(url),
				"client_ids":  ids,
				"thumbprints": prints,
			}
			if decoded := decodeResourceTags(tags); len(decoded) > 0 {
				attributes["tags"] = decoded
			}
		} else {
			attributes = map[string]any{"metadata": metadata}
		}
		key := kind + ":" + name
		resources[key] = driftLiveResource{
			ResourceKey: key, Kind: kind, Name: name, Attributes: attributes,
		}
	}
	return rows.Err()
}

func decodeDriftTags(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var tags map[string]string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		return nil
	}
	return tags
}
