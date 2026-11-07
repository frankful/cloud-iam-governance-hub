package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const iamRiskScannerNote = "Static IAM rule scan (not an IAM simulator)"
const iamRiskScannerScope = "Static rule checks only; does not simulate AWS authorization or evaluate conditions, SCPs, permission boundaries, or runtime context."
const iamRiskTypePrefix = "phase0_iam_"

const (
	iamRiskWildcardAction   = iamRiskTypePrefix + "wildcard_action"
	iamRiskWildcardResource = iamRiskTypePrefix + "wildcard_resource"
	iamRiskAdminPermission  = iamRiskTypePrefix + "admin_permission"
	iamRiskAdminPolicy      = iamRiskTypePrefix + "admin_policy"
	iamRiskExternalTrust    = iamRiskTypePrefix + "external_trust"
)

var errNilIAMRiskDB = errors.New("IAM risk scanner database is nil")

// IAMRiskScanner checks the IAM policies and trust policies already persisted
// in PostgreSQL. It does not model AWS authorization or evaluate conditions.
type IAMRiskScanner struct {
	db *sql.DB
}

// IAMRiskScanSummary describes one completed static rule scan.
type IAMRiskScanSummary struct {
	Method            string `json:"method"`
	Scope             string `json:"scope"`
	PrincipalsScanned int    `json:"principals_scanned"`
	FindingsUpserted  int    `json:"findings_upserted"`
	FindingsResolved  int    `json:"findings_resolved"`
}

type iamRiskFinding struct {
	level        string
	descriptions []string
}

type iamRiskScanPrincipal struct {
	id          int64
	accountID   string
	trustPolicy []byte
	policyID    sql.NullInt64
	policyName  sql.NullString
	policyARN   sql.NullString
	policyDoc   []byte
}

type CandidatePolicyRiskFinding struct {
	RiskType    string `json:"risk_type"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
}

type CandidatePolicyRiskError struct {
	Findings []CandidatePolicyRiskFinding `json:"findings"`
}

func (riskError *CandidatePolicyRiskError) Error() string {
	return fmt.Sprintf("candidate IAM policy has %d static risk finding(s)", len(riskError.Findings))
}

type iamPolicyDocument struct {
	Statement json.RawMessage `json:"Statement"`
}

type iamPolicyStatement struct {
	Effect    string          `json:"Effect"`
	Action    iamStringList   `json:"Action"`
	Resource  iamStringList   `json:"Resource"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

type iamStringList []string

func (values *iamStringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*values = []string{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return fmt.Errorf("expected a string or array of strings: %w", err)
	}
	*values = multiple
	return nil
}

type iamTrustPrincipal struct {
	AWS       iamStringList `json:"AWS"`
	Federated iamStringList `json:"Federated"`
}

// NewIAMRiskScanner constructs a scanner backed by the existing PostgreSQL
// connection pool.
func NewIAMRiskScanner(db *sql.DB) (*IAMRiskScanner, error) {
	if db == nil {
		return nil, errNilIAMRiskDB
	}
	return &IAMRiskScanner{db: db}, nil
}

// Scan reads all persisted principals and their attached policy documents,
// then upserts current findings and resolves findings no longer present.
// Findings are intentionally limited to static rules; this is not an IAM
// simulator and does not account for conditions, SCPs, boundaries, or runtime
// authorization context.
func (scanner *IAMRiskScanner) Scan(ctx context.Context) (IAMRiskScanSummary, error) {
	if scanner == nil || scanner.db == nil {
		return IAMRiskScanSummary{}, errNilIAMRiskDB
	}

	tx, err := scanner.db.BeginTx(ctx, nil)
	if err != nil {
		return IAMRiskScanSummary{}, fmt.Errorf("begin IAM risk scan: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		WITH effective_policy AS (
			SELECT principal_id, policy_id FROM iam_principal_policy
			UNION
			SELECT membership.user_principal_id, group_policy.policy_id
			FROM iam_group_membership AS membership
			JOIN iam_group_policy AS group_policy ON group_policy.group_id = membership.group_id
		)
		SELECT principal.id,
		       COALESCE(account.account_id, ''),
		       principal.trust_policy,
		       policy.id,
		       policy.policy_name,
		       policy.policy_arn,
		       policy.policy_document
		FROM iam_principal AS principal
		LEFT JOIN aws_account AS account ON account.id = principal.account_id
		LEFT JOIN effective_policy ON effective_policy.principal_id = principal.id
		LEFT JOIN iam_policy AS policy ON policy.id = effective_policy.policy_id
		WHERE principal.is_deleted = FALSE
		ORDER BY principal.id, policy.id
		FOR UPDATE OF principal`)
	if err != nil {
		return IAMRiskScanSummary{}, fmt.Errorf("load persisted IAM policies and trust policies: %w", err)
	}

	principals := make([]iamRiskScanPrincipal, 0)
	for rows.Next() {
		var principal iamRiskScanPrincipal
		if err := rows.Scan(
			&principal.id,
			&principal.accountID,
			&principal.trustPolicy,
			&principal.policyID,
			&principal.policyName,
			&principal.policyARN,
			&principal.policyDoc,
		); err != nil {
			rows.Close()
			return IAMRiskScanSummary{}, fmt.Errorf("read persisted IAM policy: %w", err)
		}
		principals = append(principals, principal)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return IAMRiskScanSummary{}, fmt.Errorf("read persisted IAM policies: %w", err)
	}
	if err := rows.Close(); err != nil {
		return IAMRiskScanSummary{}, fmt.Errorf("close persisted IAM policy rows: %w", err)
	}

	findingsByPrincipal := make(map[int64]map[string]*iamRiskFinding)
	for _, principal := range principals {
		if _, exists := findingsByPrincipal[principal.id]; !exists {
			findingsByPrincipal[principal.id] = make(map[string]*iamRiskFinding)
		}
		if len(principal.trustPolicy) != 0 && string(principal.trustPolicy) != "null" {
			if err := addTrustPolicyFindings(findingsByPrincipal[principal.id], principal); err != nil {
				return IAMRiskScanSummary{}, fmt.Errorf("analyze trust policy for principal %d: %w", principal.id, err)
			}
		}
		if principal.policyID.Valid && len(principal.policyDoc) != 0 {
			if err := addPolicyFindings(findingsByPrincipal[principal.id], principal); err != nil {
				return IAMRiskScanSummary{}, fmt.Errorf("analyze policy %d for principal %d: %w", principal.policyID.Int64, principal.id, err)
			}
		}
	}

	summary := IAMRiskScanSummary{
		Method:            "static_rules",
		Scope:             iamRiskScannerScope,
		PrincipalsScanned: len(findingsByPrincipal),
	}
	resolvedRows, err := tx.QueryContext(ctx, `UPDATE iam_risk
		SET is_resolved = TRUE, resolved_at = NOW()
		WHERE is_resolved = FALSE
		  AND LEFT(risk_type, CHAR_LENGTH($1)) = $1
		  AND principal_id IN (
			SELECT id FROM iam_principal WHERE is_deleted = TRUE
		  )
		RETURNING id`, iamRiskTypePrefix)
	if err != nil {
		return IAMRiskScanSummary{}, fmt.Errorf("resolve findings for stale IAM principals: %w", err)
	}
	for resolvedRows.Next() {
		var ignoredID int64
		if err := resolvedRows.Scan(&ignoredID); err != nil {
			resolvedRows.Close()
			return IAMRiskScanSummary{}, fmt.Errorf("read resolved stale-principal risk: %w", err)
		}
		summary.FindingsResolved++
	}
	if err := resolvedRows.Err(); err != nil {
		resolvedRows.Close()
		return IAMRiskScanSummary{}, fmt.Errorf("iterate resolved stale-principal risks: %w", err)
	}
	if err := resolvedRows.Close(); err != nil {
		return IAMRiskScanSummary{}, fmt.Errorf("close resolved stale-principal risks: %w", err)
	}
	for principalID, findings := range findingsByPrincipal {
		upserted, resolved, err := syncPrincipalIAMRisks(ctx, tx, principalID, findings)
		if err != nil {
			return IAMRiskScanSummary{}, fmt.Errorf("synchronize IAM risks for principal %d: %w", principalID, err)
		}
		summary.FindingsUpserted += upserted
		summary.FindingsResolved += resolved
	}

	if err := tx.Commit(); err != nil {
		return IAMRiskScanSummary{}, fmt.Errorf("commit IAM risk scan: %w", err)
	}
	return summary, nil
}

func addPolicyFindings(findings map[string]*iamRiskFinding, principal iamRiskScanPrincipal) error {
	var document iamPolicyDocument
	if err := json.Unmarshal(principal.policyDoc, &document); err != nil {
		return fmt.Errorf("decode policy document: %w", err)
	}
	statements, err := decodePolicyStatements(document.Statement)
	if err != nil {
		return fmt.Errorf("decode policy statements: %w", err)
	}

	name := principal.policyName.String
	if !principal.policyName.Valid || name == "" {
		name = principal.policyARN.String
	}
	if name == "" {
		name = fmt.Sprintf("policy %d", principal.policyID.Int64)
	}
	source := fmt.Sprintf("policy %q", name)
	if isAdminLikePolicy(name) || (principal.policyARN.Valid && isAdminLikePolicy(principal.policyARN.String)) {
		addIAMRiskFinding(findings, iamRiskAdminPolicy, "HIGH", source+" has an administrator-like policy name or ARN")
	}

	for _, statement := range statements {
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "Allow") {
			continue
		}
		for _, action := range statement.Action {
			if strings.Contains(action, "*") {
				addIAMRiskFinding(findings, iamRiskWildcardAction, "HIGH", source+" allows action pattern "+fmt.Sprintf("%q", action))
			}
			if isAdminLikeAction(action) {
				addIAMRiskFinding(findings, iamRiskAdminPermission, "HIGH", source+" allows administrator-like action "+fmt.Sprintf("%q", action))
			}
		}
		for _, resource := range statement.Resource {
			if strings.Contains(resource, "*") {
				addIAMRiskFinding(findings, iamRiskWildcardResource, "MEDIUM", source+" allows resource pattern "+fmt.Sprintf("%q", resource))
			}
		}
	}
	return nil
}

// ScanCandidateIAMPolicy applies the persisted-policy static rules to an
// unpersisted candidate policy and trust policy without writing risk rows.
func ScanCandidateIAMPolicy(
	policyDocument json.RawMessage,
	trustPolicy json.RawMessage,
	policyName string,
	accountID string,
) ([]CandidatePolicyRiskFinding, error) {
	findings := make(map[string]*iamRiskFinding)
	principal := iamRiskScanPrincipal{
		accountID:   accountID,
		trustPolicy: trustPolicy,
		policyDoc:   policyDocument,
		policyName:  sql.NullString{String: policyName, Valid: policyName != ""},
	}
	if err := addPolicyFindings(findings, principal); err != nil {
		return nil, fmt.Errorf("scan candidate IAM policy: %w", err)
	}
	if len(trustPolicy) != 0 && string(trustPolicy) != "null" {
		if err := addTrustPolicyFindings(findings, principal); err != nil {
			return nil, fmt.Errorf("scan candidate IAM trust policy: %w", err)
		}
	}
	riskTypes := make([]string, 0, len(findings))
	for riskType := range findings {
		riskTypes = append(riskTypes, riskType)
	}
	sort.Strings(riskTypes)
	result := make([]CandidatePolicyRiskFinding, 0, len(riskTypes))
	for _, riskType := range riskTypes {
		finding := findings[riskType]
		sort.Strings(finding.descriptions)
		result = append(result, CandidatePolicyRiskFinding{
			RiskType: riskType, RiskLevel: finding.level,
			Description: iamRiskScannerNote + ": " +
				strings.Join(uniqueStrings(finding.descriptions), "; "),
		})
	}
	return result, nil
}

func addTrustPolicyFindings(findings map[string]*iamRiskFinding, principal iamRiskScanPrincipal) error {
	var document iamPolicyDocument
	if err := json.Unmarshal(principal.trustPolicy, &document); err != nil {
		return fmt.Errorf("decode trust policy: %w", err)
	}
	statements, err := decodePolicyStatements(document.Statement)
	if err != nil {
		return fmt.Errorf("decode trust policy statements: %w", err)
	}

	for _, statement := range statements {
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "Allow") || len(statement.Principal) == 0 {
			continue
		}
		external, description, err := hasExternalTrust(
			statement.Principal,
			statement.Action,
			statement.Condition,
			principal.accountID,
		)
		if err != nil {
			return err
		}
		if external {
			addIAMRiskFinding(findings, iamRiskExternalTrust, "HIGH", "trust policy allows "+description)
		}
	}
	return nil
}

func decodePolicyStatements(raw json.RawMessage) ([]iamPolicyStatement, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var statements []iamPolicyStatement
	if err := json.Unmarshal(raw, &statements); err == nil {
		return statements, nil
	}
	var single iamPolicyStatement
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, err
	}
	return []iamPolicyStatement{single}, nil
}

func hasExternalTrust(
	raw json.RawMessage,
	action iamStringList,
	condition json.RawMessage,
	accountID string,
) (bool, string, error) {
	var wildcard string
	if err := json.Unmarshal(raw, &wildcard); err == nil {
		if wildcard == "*" {
			return true, `wildcard principal "*"`, nil
		}
		return isExternalAWSPrincipal(wildcard, accountID), fmt.Sprintf("AWS principal %q", wildcard), nil
	}

	var principals map[string]json.RawMessage
	if err := json.Unmarshal(raw, &principals); err != nil {
		return false, "", fmt.Errorf("decode trust policy Principal: %w", err)
	}
	var external []string
	for principalType, rawValues := range principals {
		var values iamStringList
		if err := json.Unmarshal(rawValues, &values); err != nil {
			return false, "", fmt.Errorf("decode trust policy %s principal: %w", principalType, err)
		}
		for _, value := range values {
			if value == "*" || (strings.EqualFold(principalType, "Federated") &&
				!isScopedEKSWebIdentityTrust(value, action, condition, accountID)) ||
				(strings.EqualFold(principalType, "AWS") && isExternalAWSPrincipal(value, accountID)) {
				external = append(external, principalType+":"+value)
			}
		}
	}
	if len(external) == 0 {
		return false, "", nil
	}
	sort.Strings(external)
	return true, strings.Join(external, ", "), nil
}

func isScopedEKSWebIdentityTrust(
	provider string,
	action iamStringList,
	condition json.RawMessage,
	accountID string,
) bool {
	if len(action) != 1 || !strings.EqualFold(action[0], "sts:AssumeRoleWithWebIdentity") {
		return false
	}

	arnParts := strings.Split(provider, ":")
	if len(arnParts) < 6 || arnParts[0] != "arn" || arnParts[2] != "iam" ||
		(arnParts[1] != "aws" && arnParts[1] != "aws-us-gov" && arnParts[1] != "aws-cn") {
		return false
	}
	if accountID != "" && arnParts[4] != accountID {
		return false
	}

	const providerPrefix = "oidc-provider/"
	if !strings.HasPrefix(arnParts[5], providerPrefix) {
		return false
	}
	issuer := strings.TrimPrefix(arnParts[5], providerPrefix)
	if !strings.HasPrefix(issuer, "oidc.eks.") {
		return false
	}
	idMarker := ".amazonaws.com/id/"
	if markerIndex := strings.Index(issuer, idMarker); markerIndex == -1 ||
		markerIndex+len(idMarker) == len(issuer) {
		return false
	}

	var conditions map[string]map[string]iamStringList
	if err := json.Unmarshal(condition, &conditions); err != nil {
		return false
	}
	stringEquals := conditions["StringEquals"]
	return hasExactConditionValue(stringEquals[issuer+":aud"], "sts.amazonaws.com") &&
		hasExactServiceAccountSubject(stringEquals[issuer+":sub"])
}

func hasExactConditionValue(values iamStringList, expected string) bool {
	return len(values) == 1 && values[0] == expected
}

func hasExactServiceAccountSubject(values iamStringList) bool {
	if len(values) != 1 {
		return false
	}
	parts := strings.Split(values[0], ":")
	return len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" &&
		parts[2] != "" && parts[3] != "" &&
		!strings.ContainsAny(parts[2]+parts[3], "*?")
}

func isExternalAWSPrincipal(value, accountID string) bool {
	value = strings.TrimSpace(value)
	if value == "*" {
		return true
	}
	identifiedAccount := value
	if strings.HasPrefix(value, "arn:") {
		parts := strings.Split(value, ":")
		if len(parts) < 6 || parts[2] != "iam" {
			return false
		}
		identifiedAccount = parts[4]
	}
	if identifiedAccount == "" || identifiedAccount == "root" {
		return false
	}
	if accountID == "" {
		return true
	}
	return identifiedAccount != accountID
}

func isAdminLikePolicy(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "admin") ||
		strings.Contains(value, ":policy/administratoraccess") ||
		strings.HasSuffix(value, "/administratoraccess")
}

func isAdminLikeAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "*" || action == "iam:*" || action == "organizations:*" ||
		action == "sso:*" || action == "identitycenter:*" {
		return true
	}
	switch action {
	case "iam:attachgrouppolicy", "iam:attachrolepolicy", "iam:attachuserpolicy",
		"iam:createaccesskey", "iam:createpolicyversion", "iam:createrole",
		"iam:createuser", "iam:putgrouppolicy", "iam:putrolepolicy",
		"iam:putuserpolicy", "iam:setdefaultpolicyversion":
		return true
	default:
		return false
	}
}

func addIAMRiskFinding(findings map[string]*iamRiskFinding, riskType, level, description string) {
	finding := findings[riskType]
	if finding == nil {
		finding = &iamRiskFinding{level: level}
		findings[riskType] = finding
	}
	finding.descriptions = append(finding.descriptions, description)
}

func syncPrincipalIAMRisks(
	ctx context.Context,
	tx *sql.Tx,
	principalID int64,
	findings map[string]*iamRiskFinding,
) (int, int, error) {
	riskTypes := make([]string, 0, len(findings))
	for riskType := range findings {
		riskTypes = append(riskTypes, riskType)
	}
	sort.Strings(riskTypes)
	active := make(map[string]bool, len(findings))
	upserted := 0
	resolved := 0

	for _, riskType := range riskTypes {
		finding := findings[riskType]
		active[riskType] = true
		sort.Strings(finding.descriptions)
		description := iamRiskScannerNote + ": " + strings.Join(uniqueStrings(finding.descriptions), "; ")
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM iam_risk
			WHERE principal_id = $1 AND risk_type = $2 AND is_resolved = FALSE
			ORDER BY id
			FOR UPDATE`, principalID, riskType)
		if err != nil {
			return 0, 0, err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return 0, 0, err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, 0, err
		}
		if err := rows.Close(); err != nil {
			return 0, 0, err
		}

		if len(ids) == 0 {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO iam_risk (principal_id, risk_type, risk_level, description, is_resolved)
				VALUES ($1, $2, $3, $4, FALSE)`, principalID, riskType, finding.level, description); err != nil {
				return 0, 0, err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
				UPDATE iam_risk
				SET risk_level = $1, description = $2
				WHERE id = $3`, finding.level, description, ids[0]); err != nil {
				return 0, 0, err
			}
			if len(ids) > 1 {
				if _, err := tx.ExecContext(ctx, `
					UPDATE iam_risk
					SET is_resolved = TRUE, resolved_at = NOW()
					WHERE principal_id = $1 AND risk_type = $2
					  AND is_resolved = FALSE AND id <> $3`,
					principalID, riskType, ids[0]); err != nil {
					return 0, 0, err
				}
				resolved += len(ids) - 1
			}
		}
		upserted++
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, risk_type FROM iam_risk
		WHERE principal_id = $1 AND is_resolved = FALSE
		  AND LEFT(risk_type, CHAR_LENGTH($2)) = $2
		ORDER BY id
		FOR UPDATE`, principalID, iamRiskTypePrefix)
	if err != nil {
		return 0, 0, err
	}
	type activeRisk struct {
		id       int64
		riskType sql.NullString
	}
	var activeRisks []activeRisk
	for rows.Next() {
		var risk activeRisk
		if err := rows.Scan(&risk.id, &risk.riskType); err != nil {
			rows.Close()
			return 0, 0, err
		}
		activeRisks = append(activeRisks, risk)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}
	for _, risk := range activeRisks {
		if risk.riskType.Valid && active[risk.riskType.String] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE iam_risk SET is_resolved = TRUE, resolved_at = NOW()
			WHERE id = $1`, risk.id); err != nil {
			return 0, 0, err
		}
		resolved++
	}
	return upserted, resolved, nil
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	unique := values[:1]
	for _, value := range values[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}
