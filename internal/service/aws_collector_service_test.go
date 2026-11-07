package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

type fakeOrganizationsClient struct {
	awsOrganizationsAPI
	accounts []orgtypes.Account
	err      error
	calls    int
}

func (client *fakeOrganizationsClient) ListAccounts(
	_ context.Context,
	input *organizations.ListAccountsInput,
	_ ...func(*organizations.Options),
) (*organizations.ListAccountsOutput, error) {
	client.calls++
	if client.err != nil {
		return nil, client.err
	}
	if input.NextToken == nil {
		return &organizations.ListAccountsOutput{
			Accounts:  client.accounts[:1],
			NextToken: aws.String("page-2"),
		}, nil
	}
	return &organizations.ListAccountsOutput{Accounts: client.accounts[1:]}, nil
}

type fakeSTSClient struct {
	awsSTSAPI
	err        error
	accountID  string
	roleARNs   []string
	session    []string
	externalID []string
}

func (client *fakeSTSClient) GetCallerIdentity(
	_ context.Context,
	_ *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options),
) (*sts.GetCallerIdentityOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	accountID := client.accountID
	if accountID == "" {
		accountID = "123456789012"
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String(accountID),
		Arn:     aws.String("arn:aws:iam::" + accountID + ":user/test"),
	}, nil
}

func (client *fakeSTSClient) AssumeRole(
	_ context.Context,
	input *sts.AssumeRoleInput,
	_ ...func(*sts.Options),
) (*sts.AssumeRoleOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	client.roleARNs = append(client.roleARNs, aws.ToString(input.RoleArn))
	client.session = append(client.session, aws.ToString(input.RoleSessionName))
	client.externalID = append(client.externalID, aws.ToString(input.ExternalId))
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("temporary-access-key"),
		SecretAccessKey: aws.String("temporary-secret-key"),
		SessionToken:    aws.String("temporary-session-token"),
		Expiration:      aws.Time(time.Now().Add(time.Hour)),
	}}, nil
}

type fakeIAMClient struct {
	awsIAMAPI
	listPoliciesErr      error
	listPolicyTagsErr    error
	listPolicyTagsCalls  int
	rolePolicyErr        error
	groupCalls           int
	groupListErrAt       int
	groupGetMarkers      []string
	groupListMarkers     []string
	attachedGroupMarkers []string
	inlineGroupMarkers   []string
}

func (client *fakeIAMClient) ListPolicies(
	_ context.Context,
	input *iam.ListPoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListPoliciesOutput, error) {
	if client.listPoliciesErr != nil {
		return nil, client.listPoliciesErr
	}
	if input != nil && input.Scope == iamtypes.PolicyScopeTypeAws {
		return &iam.ListPoliciesOutput{
			Policies: []iamtypes.Policy{{
				Arn:        aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
				PolicyName: aws.String("AdministratorAccess"),
			}},
		}, nil
	}
	return &iam.ListPoliciesOutput{
		Policies: []iamtypes.Policy{{
			Arn:              aws.String("arn:aws:iam::123456789012:policy/LocalRead"),
			PolicyName:       aws.String("LocalRead"),
			DefaultVersionId: aws.String("v3"),
			// AWS 的 ListPolicies 响应不含 Description（仅 GetPolicy 返回），
			// fake 必须保持一致，防止采集端误从 listed 行取值。
		}},
	}, nil
}

func (client *fakeIAMClient) GetPolicy(
	_ context.Context,
	input *iam.GetPolicyInput,
	_ ...func(*iam.Options),
) (*iam.GetPolicyOutput, error) {
	name := "AWSRead"
	if aws.ToString(input.PolicyArn) == "arn:aws:iam::123456789012:policy/LocalRead" {
		name = "LocalRead"
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn:              input.PolicyArn,
		PolicyName:       aws.String(name),
		DefaultVersionId: aws.String("v3"),
		Description:      aws.String("Local read policy for poc"),
	}}, nil
}

func (*fakeIAMClient) GetPolicyVersion(
	_ context.Context,
	input *iam.GetPolicyVersionInput,
	_ ...func(*iam.Options),
) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		Document: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[]}`)),
	}}, nil
}

func (client *fakeIAMClient) ListPolicyTags(
	_ context.Context,
	input *iam.ListPolicyTagsInput,
	_ ...func(*iam.Options),
) (*iam.ListPolicyTagsOutput, error) {
	client.listPolicyTagsCalls++
	if client.listPolicyTagsErr != nil {
		return nil, client.listPolicyTagsErr
	}
	tags := []iamtypes.Tag{{Key: aws.String("Owner"), Value: aws.String("platform-team")}}
	if aws.ToString(input.PolicyArn) == "arn:aws:iam::123456789012:policy/LocalRead" {
		tags = append(tags, iamtypes.Tag{Key: aws.String("env"), Value: aws.String("poc")})
	}
	return &iam.ListPolicyTagsOutput{Tags: tags}, nil
}

func (*fakeIAMClient) ListRoles(
	_ context.Context,
	_ *iam.ListRolesInput,
	_ ...func(*iam.Options),
) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: aws.String("app-role"),
		Arn:      aws.String("arn:aws:iam::123456789012:role/app-role"),
	}}}, nil
}

func (*fakeIAMClient) GetRole(
	_ context.Context,
	input *iam.GetRoleInput,
	_ ...func(*iam.Options),
) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{Role: &iamtypes.Role{
		RoleName:                 input.RoleName,
		Arn:                      aws.String("arn:aws:iam::123456789012:role/app-role"),
		Path:                     aws.String("/app/"),
		Description:              aws.String("application role"),
		AssumeRolePolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[]}`)),
		PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
			PermissionsBoundaryArn:  aws.String("arn:aws:iam::123456789012:policy/app-boundary"),
			PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentTypePolicy,
		},
		MaxSessionDuration: aws.Int32(7200),
		Tags: []iamtypes.Tag{
			{Key: aws.String("team"), Value: aws.String("otel")},
			{Key: aws.String("env"), Value: aws.String("prod")},
		},
		RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: aws.Time(time.Unix(1700000000, 0))},
	}}, nil
}

func (*fakeIAMClient) ListAttachedRolePolicies(
	_ context.Context,
	_ *iam.ListAttachedRolePoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{
		{
			PolicyArn:  aws.String("arn:aws:iam::123456789012:policy/LocalRead"),
			PolicyName: aws.String("LocalRead"),
		},
		{
			PolicyArn:  aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"),
			PolicyName: aws.String("ReadOnlyAccess"),
		},
	}}, nil
}

func (client *fakeIAMClient) ListRolePolicies(
	_ context.Context,
	_ *iam.ListRolePoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListRolePoliciesOutput, error) {
	if client.rolePolicyErr != nil {
		return nil, client.rolePolicyErr
	}
	return &iam.ListRolePoliciesOutput{PolicyNames: []string{"InlineRole"}}, nil
}

func (*fakeIAMClient) GetRolePolicy(
	_ context.Context,
	input *iam.GetRolePolicyInput,
	_ ...func(*iam.Options),
) (*iam.GetRolePolicyOutput, error) {
	return &iam.GetRolePolicyOutput{
		PolicyName:     input.PolicyName,
		PolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)),
	}, nil
}

func (*fakeIAMClient) ListUsers(
	_ context.Context,
	_ *iam.ListUsersInput,
	_ ...func(*iam.Options),
) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: []iamtypes.User{{
		UserName: aws.String("app-user"),
		Arn:      aws.String("arn:aws:iam::123456789012:user/app-user"),
	}}}, nil
}

func (*fakeIAMClient) GetUser(
	_ context.Context,
	input *iam.GetUserInput,
	_ ...func(*iam.Options),
) (*iam.GetUserOutput, error) {
	return &iam.GetUserOutput{User: &iamtypes.User{
		UserName:         input.UserName,
		Arn:              aws.String("arn:aws:iam::123456789012:user/app-user"),
		Path:             aws.String("/ops/"),
		PasswordLastUsed: aws.Time(time.Unix(1700000100, 0)),
		PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
			PermissionsBoundaryArn:  aws.String("arn:aws:iam::123456789012:policy/user-boundary"),
			PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentTypePolicy,
		},
		Tags: []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("sre")}},
	}}, nil
}

func (client *fakeIAMClient) ListGroups(
	_ context.Context,
	input *iam.ListGroupsInput,
	_ ...func(*iam.Options),
) (*iam.ListGroupsOutput, error) {
	client.groupCalls++
	client.groupListMarkers = append(client.groupListMarkers, aws.ToString(input.Marker))
	if client.groupCalls == client.groupListErrAt {
		return nil, errors.New("group listing failed")
	}
	if client.groupCalls == 1 {
		return &iam.ListGroupsOutput{
			Groups: []iamtypes.Group{{
				GroupName: aws.String("app-team"),
				Arn:       aws.String("arn:aws:iam::123456789012:group/app-team"),
				Path:      aws.String("/"),
			}},
			IsTruncated: true,
			Marker:      aws.String("groups-page-2"),
		}, nil
	}
	return &iam.ListGroupsOutput{Groups: []iamtypes.Group{{
		GroupName: aws.String("ops-team"),
		Arn:       aws.String("arn:aws:iam::123456789012:group/ops-team"),
		Path:      aws.String("/teams/"),
	}}}, nil
}

func (client *fakeIAMClient) GetGroup(
	_ context.Context,
	input *iam.GetGroupInput,
	_ ...func(*iam.Options),
) (*iam.GetGroupOutput, error) {
	client.groupGetMarkers = append(client.groupGetMarkers, aws.ToString(input.Marker))
	user := iamtypes.User{
		UserName: aws.String("app-user"),
		Arn:      aws.String("arn:aws:iam::123456789012:user/app-user"),
	}
	if input.Marker == nil {
		return &iam.GetGroupOutput{
			Group:       &iamtypes.Group{Path: aws.String("/teams/")},
			Users:       []iamtypes.User{user},
			IsTruncated: true,
			Marker:      aws.String("members-page-2"),
		}, nil
	}
	return &iam.GetGroupOutput{}, nil
}

func (client *fakeIAMClient) ListAttachedGroupPolicies(
	_ context.Context,
	input *iam.ListAttachedGroupPoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListAttachedGroupPoliciesOutput, error) {
	client.attachedGroupMarkers = append(client.attachedGroupMarkers, aws.ToString(input.Marker))
	if input.Marker == nil {
		return &iam.ListAttachedGroupPoliciesOutput{
			AttachedPolicies: []iamtypes.AttachedPolicy{{
				PolicyArn: aws.String("arn:aws:iam::123456789012:policy/LocalRead"),
			}},
			IsTruncated: true,
			Marker:      aws.String("attached-page-2"),
		}, nil
	}
	return &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{
		PolicyArn:  aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"),
		PolicyName: aws.String("ReadOnlyAccess"),
	}}}, nil
}

func (client *fakeIAMClient) ListGroupPolicies(
	_ context.Context,
	input *iam.ListGroupPoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListGroupPoliciesOutput, error) {
	client.inlineGroupMarkers = append(client.inlineGroupMarkers, aws.ToString(input.Marker))
	if input.Marker == nil {
		return &iam.ListGroupPoliciesOutput{
			PolicyNames: []string{"InlineGroup"},
			IsTruncated: true,
			Marker:      aws.String("inline-page-2"),
		}, nil
	}
	return &iam.ListGroupPoliciesOutput{PolicyNames: []string{"InlineGroupTwo"}}, nil
}

func (*fakeIAMClient) GetGroupPolicy(
	_ context.Context,
	input *iam.GetGroupPolicyInput,
	_ ...func(*iam.Options),
) (*iam.GetGroupPolicyOutput, error) {
	return &iam.GetGroupPolicyOutput{
		PolicyName:     input.PolicyName,
		PolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[]}`)),
	}, nil
}

func (*fakeIAMClient) ListAttachedUserPolicies(
	_ context.Context,
	_ *iam.ListAttachedUserPoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{}, nil
}

func (*fakeIAMClient) ListUserPolicies(
	_ context.Context,
	_ *iam.ListUserPoliciesInput,
	_ ...func(*iam.Options),
) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: []string{"InlineUser"}}, nil
}

func (*fakeIAMClient) GetUserPolicy(
	_ context.Context,
	input *iam.GetUserPolicyInput,
	_ ...func(*iam.Options),
) (*iam.GetUserPolicyOutput, error) {
	return &iam.GetUserPolicyOutput{
		PolicyName:     input.PolicyName,
		PolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[]}`)),
	}, nil
}

func (*fakeIAMClient) ListInstanceProfiles(
	_ context.Context,
	_ *iam.ListInstanceProfilesInput,
	_ ...func(*iam.Options),
) (*iam.ListInstanceProfilesOutput, error) {
	return &iam.ListInstanceProfilesOutput{InstanceProfiles: []iamtypes.InstanceProfile{{
		InstanceProfileName: aws.String("app-profile"),
		Arn:                 aws.String("arn:aws:iam::123456789012:instance-profile/app-profile"),
		Path:                aws.String("/app/"),
		Roles: []iamtypes.Role{{
			Arn: aws.String("arn:aws:iam::123456789012:role/app-role"),
		}},
		Tags: []iamtypes.Tag{{Key: aws.String("env"), Value: aws.String("prod")}},
	}}}, nil
}

func (*fakeIAMClient) ListOpenIDConnectProviders(
	_ context.Context,
	_ *iam.ListOpenIDConnectProvidersInput,
	_ ...func(*iam.Options),
) (*iam.ListOpenIDConnectProvidersOutput, error) {
	return &iam.ListOpenIDConnectProvidersOutput{OpenIDConnectProviderList: []iamtypes.OpenIDConnectProviderListEntry{{
		Arn: aws.String("arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"),
	}}}, nil
}

func (*fakeIAMClient) GetOpenIDConnectProvider(
	_ context.Context,
	input *iam.GetOpenIDConnectProviderInput,
	_ ...func(*iam.Options),
) (*iam.GetOpenIDConnectProviderOutput, error) {
	return &iam.GetOpenIDConnectProviderOutput{
		Url:            aws.String("oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"),
		ClientIDList:   []string{"sts.amazonaws.com"},
		ThumbprintList: []string{"9e99a48a9960b14926bb7f3b02e22da2b0ab7280"},
		Tags:           []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("otel")}},
	}, nil
}

func (*fakeIAMClient) ListSAMLProviders(
	_ context.Context,
	_ *iam.ListSAMLProvidersInput,
	_ ...func(*iam.Options),
) (*iam.ListSAMLProvidersOutput, error) {
	return &iam.ListSAMLProvidersOutput{SAMLProviderList: []iamtypes.SAMLProviderListEntry{{
		Arn: aws.String("arn:aws:iam::123456789012:saml-provider/corp-sso"),
	}}}, nil
}

func (*fakeIAMClient) GetSAMLProvider(
	_ context.Context,
	_ *iam.GetSAMLProviderInput,
	_ ...func(*iam.Options),
) (*iam.GetSAMLProviderOutput, error) {
	return &iam.GetSAMLProviderOutput{
		SAMLMetadataDocument: aws.String("<EntityDescriptor/>"),
		Tags:                 []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("iam")}},
	}, nil
}

type fakeAWSAssetRepository struct {
	accounts               []model.AWSAccount
	collectionAccount      model.AWSAccount
	upsertOrgID            int64
	currentAccountID       string
	upsertErr              error
	accountErr             error
	saveErr                error
	saveCalls              int
	savedAccount           model.AWSAccount
	savedPrincipals        []collectedIAMPrincipal
	savedGroups            []collectedIAMGroup
	savedManaged           []model.IAMPolicy
	savedAWSManaged        []model.IAMPolicy
	savedInstanceProfiles  []model.IAMInstanceProfile
	savedIdentityProviders []model.IAMIdentityProvider
	configuredAccount      model.AWSAccount
	configuredError        error
	currentAssets          []CurrentIAMAsset
	currentAssetsErr       error
	currentAssetsAccountID int64
}

type recordedSQLCall struct {
	query string
	args  []driver.NamedValue
}

type recordingSQLDriver struct {
	mu         sync.Mutex
	calls      []recordedSQLCall
	nextID     int64
	committed  bool
	rolledBack bool
	execErrOn  string
}

type recordingSQLConnector struct {
	state *recordingSQLDriver
}

type recordingSQLConn struct {
	state *recordingSQLDriver
}

type recordingSQLTx struct {
	state *recordingSQLDriver
}

type recordingSQLRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (connector recordingSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &recordingSQLConn{state: connector.state}, nil
}

func (recordingSQLConnector) Driver() driver.Driver {
	return &recordingSQLDriver{}
}

func (*recordingSQLDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected direct driver open")
}

func (connection *recordingSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not expected")
}

func (*recordingSQLConn) Close() error { return nil }

func (connection *recordingSQLConn) Begin() (driver.Tx, error) {
	return connection.BeginTx(context.Background(), driver.TxOptions{})
}

func (connection *recordingSQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return &recordingSQLTx{state: connection.state}, nil
}

func (connection *recordingSQLConn) ExecContext(
	_ context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Result, error) {
	connection.state.record(query, args)
	if connection.state.execErrOn != "" && strings.Contains(query, connection.state.execErrOn) {
		return nil, errors.New("injected SQL execution failure")
	}
	return driver.RowsAffected(1), nil
}

func (connection *recordingSQLConn) QueryContext(
	_ context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Rows, error) {
	connection.state.record(query, args)
	if strings.Contains(query, "SELECT id FROM iam_principal") {
		return &recordingSQLRows{values: [][]driver.Value{{int64(11)}}}, nil
	}
	// RoleAttributes 的投影包含 path / permissions_boundary_arn：列与 Scan
	// 目标数量必须一致（历史上漏扫一列直接让接口 500）。
	if strings.Contains(query, "permissions_boundary_arn") && strings.Contains(query, "FROM iam_principal") {
		return &recordingSQLRows{
			columns: []string{"description", "max_session_duration", "tags", "path", "permissions_boundary_arn"},
			values: [][]driver.Value{{
				"application role",
				int64(7200),
				[]byte(`{"team":"otel"}`),
				"/app/",
				"arn:aws:iam::123456789012:policy/app-boundary",
			}},
		}, nil
	}
	if strings.Contains(query, "SELECT id FROM iam_policy") {
		return &recordingSQLRows{}, nil
	}
	if strings.Contains(query, "RETURNING id") {
		connection.state.nextID++
		return &recordingSQLRows{values: [][]driver.Value{{connection.state.nextID}}}, nil
	}
	return &recordingSQLRows{}, nil
}

func (state *recordingSQLDriver) record(query string, args []driver.NamedValue) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.calls = append(state.calls, recordedSQLCall{query: query, args: append([]driver.NamedValue(nil), args...)})
}

func (transaction *recordingSQLTx) Commit() error {
	transaction.state.mu.Lock()
	transaction.state.committed = true
	transaction.state.mu.Unlock()
	return nil
}

func (transaction *recordingSQLTx) Rollback() error {
	transaction.state.mu.Lock()
	transaction.state.rolledBack = true
	transaction.state.mu.Unlock()
	return nil
}

func (*recordingSQLRows) Close() error { return nil }
func (rows *recordingSQLRows) Columns() []string {
	if len(rows.columns) > 0 {
		return rows.columns
	}
	return []string{"id"}
}

func (rows *recordingSQLRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func (repository *fakeAWSAssetRepository) UpsertOrganizationAccounts(
	_ context.Context,
	organizationID int64,
	accounts []model.AWSAccount,
) error {
	repository.upsertOrgID = organizationID
	repository.accounts = append([]model.AWSAccount(nil), accounts...)
	return repository.upsertErr
}

func (repository *fakeAWSAssetRepository) GetAccountCollectionInfo(
	_ context.Context,
	accountID string,
) (model.AWSAccount, error) {
	if repository.accountErr != nil {
		return model.AWSAccount{}, repository.accountErr
	}
	account := repository.collectionAccount
	account.AccountID = accountID
	return account, nil
}

func (repository *fakeAWSAssetRepository) EnsureCurrentAccount(
	_ context.Context,
	accountID string,
) (model.AWSAccount, error) {
	repository.currentAccountID = accountID
	if repository.accountErr != nil {
		return model.AWSAccount{}, repository.accountErr
	}
	return model.AWSAccount{ID: 27, AccountID: accountID}, nil
}

func (repository *fakeAWSAssetRepository) EnsureConfiguredAccount(
	_ context.Context,
	config model.AWSAccountConfig,
) (model.AWSAccount, error) {
	if repository.configuredError != nil {
		return model.AWSAccount{}, repository.configuredError
	}
	account := repository.configuredAccount
	account.AccountID = config.AWSAccountID
	return account, nil
}

func (repository *fakeAWSAssetRepository) ListCurrentIAMAssets(
	_ context.Context,
	accountDBID int64,
) ([]CurrentIAMAsset, error) {
	if repository.currentAssetsErr != nil {
		return nil, repository.currentAssetsErr
	}
	repository.currentAssetsAccountID = accountDBID
	return repository.currentAssets, nil
}

func (repository *fakeAWSAssetRepository) SaveAccountIAM(
	_ context.Context,
	account model.AWSAccount,
	inventory collectedIAMInventory,
) error {
	repository.saveCalls++
	repository.savedAccount = account
	repository.savedPrincipals = append([]collectedIAMPrincipal(nil), inventory.Principals...)
	repository.savedGroups = append([]collectedIAMGroup(nil), inventory.Groups...)
	repository.savedManaged = append([]model.IAMPolicy(nil), inventory.ManagedPolicies...)
	repository.savedAWSManaged = append([]model.IAMPolicy(nil), inventory.AWSManagedPolicies...)
	repository.savedInstanceProfiles = append([]model.IAMInstanceProfile(nil), inventory.InstanceProfiles...)
	repository.savedIdentityProviders = append([]model.IAMIdentityProvider(nil), inventory.IdentityProviders...)
	return repository.saveErr
}

func newTestAWSCollector(
	t *testing.T,
	organizationsClient awsOrganizationsAPI,
	stsClient awsSTSAPI,
	iamClient awsIAMAPI,
	repository AWSAssetRepository,
) *AWSCollectorService {
	t.Helper()
	service, err := newAWSCollectorService(
		AWSCollectorConfig{
			Region:              "us-east-1",
			RoleSessionName:     "collector-test",
			ExternalID:          "external-test",
			MaxAttempts:         4,
			SyncTimeout:         time.Second,
			ManagementAccountID: "000000000000",
		},
		organizationsClient,
		stsClient,
		func(aws.Config) awsIAMAPI { return iamClient },
		repository,
		nil,
	)
	if err != nil {
		t.Fatalf("newAWSCollectorService() error = %v", err)
	}
	return service
}

func TestSyncOrganizationCollectsIAMAssetsAcrossAccounts(t *testing.T) {
	organizationsClient := &fakeOrganizationsClient{accounts: []orgtypes.Account{
		{Id: aws.String("000000000000"), Name: aws.String("management"), Status: orgtypes.AccountStatusActive},
		{Id: aws.String("123456789012"), Name: aws.String("production"), Status: orgtypes.AccountStatusActive},
		{Id: aws.String("123456789013"), Name: aws.String("suspended"), Status: orgtypes.AccountStatusSuspended},
	}}
	stsClient := &fakeSTSClient{}
	iamClient := &fakeIAMClient{}
	roleARN := "arn:aws:iam::123456789012:role/CollectorReadOnly"
	repository := &fakeAWSAssetRepository{
		collectionAccount: model.AWSAccount{
			ID:              19,
			ReadOnlyRoleARN: &roleARN,
		},
	}
	service := newTestAWSCollector(t, organizationsClient, stsClient, iamClient, repository)

	if err := service.SyncOrganization(context.Background(), 7); err != nil {
		t.Fatalf("SyncOrganization() error = %v", err)
	}
	if organizationsClient.calls != 2 {
		t.Errorf("Organizations ListAccounts calls = %d, want 2", organizationsClient.calls)
	}
	if repository.upsertOrgID != 7 || len(repository.accounts) != 3 {
		t.Fatalf("upserted org/accounts = %d/%d, want 7/3", repository.upsertOrgID, len(repository.accounts))
	}
	if len(stsClient.roleARNs) != 1 || stsClient.roleARNs[0] != roleARN {
		t.Fatalf("assumed role ARNs = %v, want only %s", stsClient.roleARNs, roleARN)
	}
	if stsClient.session[0] != "collector-test" || stsClient.externalID[0] != "external-test" {
		t.Errorf("AssumeRole session/external ID = %v/%v", stsClient.session, stsClient.externalID)
	}
	if len(repository.savedPrincipals) != 2 {
		t.Fatalf("collected principal count = %d, want role and user", len(repository.savedPrincipals))
	}

	principalsByARN := make(map[string]collectedIAMPrincipal)
	for _, principal := range repository.savedPrincipals {
		principalsByARN[principal.Principal.ARN] = principal
	}
	role := principalsByARN["arn:aws:iam::123456789012:role/app-role"]
	if role.Principal.PrincipalType != "Role" || string(role.Principal.TrustPolicy) != `{"Version":"2012-10-17","Statement":[]}` {
		t.Errorf("collected role metadata = %#v", role.Principal)
	}
	if role.Principal.LastUsedAt == nil || role.Principal.Description == nil || *role.Principal.Description != "application role" {
		t.Errorf("role last-used/description not collected: %#v", role.Principal)
	}
	// ② 采集扩展：max_session_duration / tags（回滚还原所需）
	if role.Principal.MaxSessionDuration == nil || *role.Principal.MaxSessionDuration != 7200 {
		t.Errorf("role max session duration not collected: %#v", role.Principal.MaxSessionDuration)
	}
	if role.Principal.Tags["team"] != "otel" || role.Principal.Tags["env"] != "prod" {
		t.Errorf("role tags not collected: %#v", role.Principal.Tags)
	}
	// 基线前置字段：path / permissions_boundary 在 AWS provider 里是 ForceNew，
	// 采不到就等于基线首次 apply 重建角色（ARN 变化 -> 挂载全断）。
	if role.Principal.Path != "/app/" {
		t.Errorf("role path = %q, want /app/", role.Principal.Path)
	}
	if role.Principal.PermissionsBoundaryARN == nil ||
		*role.Principal.PermissionsBoundaryARN != "arn:aws:iam::123456789012:policy/app-boundary" ||
		role.Principal.PermissionsBoundaryType == nil ||
		*role.Principal.PermissionsBoundaryType != "PermissionsBoundaryPolicy" {
		t.Errorf("role permissions boundary = %v/%v",
			role.Principal.PermissionsBoundaryARN, role.Principal.PermissionsBoundaryType)
	}
	if len(role.Policies) != 3 {
		t.Errorf("role policy count = %d, want 2 managed and 1 inline", len(role.Policies))
	}
	user := principalsByARN["arn:aws:iam::123456789012:user/app-user"]
	if user.Principal.PrincipalType != "User" || user.Principal.LastUsedAt == nil || len(user.Policies) != 1 {
		t.Errorf("collected user metadata/policies = %#v", user)
	}
	if user.Principal.Path != "/ops/" || user.Principal.Tags["team"] != "sre" {
		t.Errorf("user path/tags not collected: %#v", user.Principal)
	}
	if user.Principal.PermissionsBoundaryARN == nil ||
		*user.Principal.PermissionsBoundaryARN != "arn:aws:iam::123456789012:policy/user-boundary" {
		t.Errorf("user permissions boundary = %v", user.Principal.PermissionsBoundaryARN)
	}
	// instance profile 与角色的绑定：基线要声明 aws_iam_instance_profile，
	// 否则角色重建后运行中的 EC2 实例会静默失联。
	if len(repository.savedInstanceProfiles) != 1 {
		t.Fatalf("collected instance profile count = %d, want 1", len(repository.savedInstanceProfiles))
	}
	profile := repository.savedInstanceProfiles[0]
	if profile.InstanceProfileName != "app-profile" || profile.Path != "/app/" ||
		profile.RoleARN == nil || *profile.RoleARN != "arn:aws:iam::123456789012:role/app-role" ||
		profile.Tags["env"] != "prod" {
		t.Errorf("collected instance profile = %#v", profile)
	}
	// OIDC / SAML provider 是可声明的独立资源，也是 IRSA 信任策略的引用目标。
	if len(repository.savedIdentityProviders) != 2 {
		t.Fatalf("collected identity provider count = %d, want OIDC and SAML",
			len(repository.savedIdentityProviders))
	}
	providersByType := make(map[string]model.IAMIdentityProvider)
	for _, provider := range repository.savedIdentityProviders {
		providersByType[provider.ProviderType] = provider
	}
	oidc := providersByType["OIDC"]
	if oidc.ProviderName != "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" ||
		oidc.URL == nil || *oidc.URL != "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" ||
		len(oidc.ClientIDList) != 1 || oidc.ClientIDList[0] != "sts.amazonaws.com" ||
		len(oidc.ThumbprintList) != 1 || oidc.Tags["team"] != "otel" {
		t.Errorf("collected OIDC provider = %#v", oidc)
	}
	saml := providersByType["SAML"]
	if saml.ProviderName != "corp-sso" ||
		saml.SAMLMetadataDocument == nil || *saml.SAMLMetadataDocument != "<EntityDescriptor/>" ||
		saml.Tags["owner"] != "iam" {
		t.Errorf("collected SAML provider = %#v", saml)
	}
	if len(repository.savedManaged) != 2 {
		t.Errorf("managed policy count = %d, want local and attached AWS-managed for principals/groups", len(repository.savedManaged))
	}
	// C2: AWS 托管策略目录随同步刷新，只存元数据；文档留给挂载时按需抓取。
	if len(repository.savedAWSManaged) != 1 {
		t.Fatalf("AWS-managed catalog count = %d, want 1", len(repository.savedAWSManaged))
	}
	catalog := repository.savedAWSManaged[0]
	if catalog.PolicyARN == nil || *catalog.PolicyARN != "arn:aws:iam::aws:policy/AdministratorAccess" ||
		catalog.PolicyDocument != nil {
		t.Errorf("AWS-managed catalog entry = %#v", catalog)
	}
	if len(repository.savedGroups) != 2 {
		t.Fatalf("collected group count = %d, want 2", len(repository.savedGroups))
	}
	group := repository.savedGroups[0]
	if group.Group.GroupName != "app-team" || group.Group.ARN != "arn:aws:iam::123456789012:group/app-team" {
		t.Errorf("collected group metadata = %#v", group.Group)
	}
	if len(group.MemberARNs) != 1 || group.MemberARNs[0] != "arn:aws:iam::123456789012:user/app-user" {
		t.Errorf("collected group memberships = %v", group.MemberARNs)
	}
	if len(group.Policies) != 4 {
		t.Errorf("collected group policies = %d, want two managed and two inline", len(group.Policies))
	}
	if len(iamClient.groupListMarkers) != 2 || iamClient.groupListMarkers[1] != "groups-page-2" ||
		len(iamClient.groupGetMarkers) != 4 || iamClient.groupGetMarkers[1] != "members-page-2" {
		t.Errorf("group pagination markers list/get = %v/%v", iamClient.groupListMarkers, iamClient.groupGetMarkers)
	}
	if len(iamClient.attachedGroupMarkers) != 4 || iamClient.attachedGroupMarkers[1] != "attached-page-2" ||
		len(iamClient.inlineGroupMarkers) != 4 || iamClient.inlineGroupMarkers[1] != "inline-page-2" {
		t.Errorf("group policy pagination markers attached/inline = %v/%v", iamClient.attachedGroupMarkers, iamClient.inlineGroupMarkers)
	}
}

func TestSyncCurrentAccountUsesCurrentCredentialsWithoutOrganizationsOrAssumeRole(t *testing.T) {
	organizationsClient := &fakeOrganizationsClient{}
	stsClient := &fakeSTSClient{accountID: "123456789012"}
	repository := &fakeAWSAssetRepository{}
	service := newTestAWSCollector(t, organizationsClient, stsClient, &fakeIAMClient{}, repository)

	account, err := service.SyncCurrentAccount(context.Background())
	if err != nil {
		t.Fatalf("SyncCurrentAccount() error = %v", err)
	}
	if account.ID != 27 || account.AccountID != "123456789012" {
		t.Fatalf("SyncCurrentAccount() account = %+v", account)
	}
	if repository.currentAccountID != "123456789012" {
		t.Fatalf("registered account ID = %q", repository.currentAccountID)
	}
	if repository.saveCalls != 1 || repository.savedAccount.ID != account.ID {
		t.Fatalf("SaveAccountIAM() calls/account = %d/%+v", repository.saveCalls, repository.savedAccount)
	}
	if organizationsClient.calls != 0 || len(stsClient.roleARNs) != 0 {
		t.Fatalf("direct sync called Organizations or AssumeRole: %d/%v", organizationsClient.calls, stsClient.roleARNs)
	}
}

func TestSyncConfiguredAccountUsesOnlyConfiguredAssumeRole(t *testing.T) {
	organizationsClient := &fakeOrganizationsClient{}
	stsClient := &fakeSTSClient{}
	iamClient := &fakeIAMClient{}
	repository := &fakeAWSAssetRepository{
		configuredAccount: model.AWSAccount{ID: 34},
	}
	service := newTestAWSCollector(t, organizationsClient, stsClient, iamClient, repository)
	roleARN := "arn:aws:iam::123456789012:role/readonly"
	account, _, err := service.SyncConfiguredAccount(context.Background(), model.AWSAccountConfig{
		ID: 5, AWSAccountID: "123456789012", DisplayName: "configured",
		ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncAssumeRole, SyncEnabled: true,
	})
	if err != nil {
		t.Fatalf("SyncConfiguredAccount() error = %v", err)
	}
	if account.ID != 34 || account.AccountID != "123456789012" ||
		repository.saveCalls != 1 || repository.savedAccount.ID != account.ID {
		t.Fatalf("configured account was not persisted: account=%+v repo=%+v", account, repository)
	}
	if len(stsClient.roleARNs) != 1 || stsClient.roleARNs[0] != roleARN ||
		stsClient.externalID[0] != "external-test" || organizationsClient.calls != 0 {
		t.Fatalf("sync did not use only configured role: roles=%v external_ids=%v organizations_calls=%d",
			stsClient.roleARNs, stsClient.externalID, organizationsClient.calls)
	}
}

func TestSyncConfiguredCurrentCredentialsRejectsDifferentAccount(t *testing.T) {
	stsClient := &fakeSTSClient{accountID: "999999999999"}
	repository := &fakeAWSAssetRepository{configuredAccount: model.AWSAccount{ID: 35}}
	service := newTestAWSCollector(t, &fakeOrganizationsClient{}, stsClient, &fakeIAMClient{}, repository)
	_, _, err := service.SyncConfiguredAccount(context.Background(), model.AWSAccountConfig{
		ID: 6, AWSAccountID: "123456789012", SyncMode: AWSAccountSyncCurrentCredentials, SyncEnabled: true,
	})
	if err == nil {
		t.Fatal("expected current credentials account mismatch to fail")
	}
	if repository.saveCalls != 0 || len(stsClient.roleARNs) != 0 {
		t.Fatalf("mismatched account must not call IAM collection or persist assets: saves=%d roles=%v",
			repository.saveCalls, stsClient.roleARNs)
	}
}

func TestSyncConfiguredAccountSkipsDisabledConfiguration(t *testing.T) {
	repository := &fakeAWSAssetRepository{}
	stsClient := &fakeSTSClient{}
	service := newTestAWSCollector(t, &fakeOrganizationsClient{}, stsClient, &fakeIAMClient{}, repository)
	_, _, err := service.SyncConfiguredAccount(context.Background(), model.AWSAccountConfig{
		ID: 7, AWSAccountID: "123456789012", SyncMode: AWSAccountSyncCurrentCredentials, SyncEnabled: false,
	})
	if err == nil {
		t.Fatal("expected disabled configuration to be rejected")
	}
	if repository.saveCalls != 0 || repository.configuredAccount.ID != 0 || len(stsClient.roleARNs) != 0 {
		t.Fatalf("disabled configuration triggered collection: %+v", repository)
	}
}

func TestSQLAWSAssetRepositoryPersistsGroupMembershipAndPoliciesTransactionally(t *testing.T) {
	state := &recordingSQLDriver{}
	db := sql.OpenDB(recordingSQLConnector{state: state})
	defer db.Close()
	db.SetMaxOpenConns(1)
	repository, err := NewSQLAWSAssetRepository(db)
	if err != nil {
		t.Fatalf("NewSQLAWSAssetRepository() error = %v", err)
	}

	managedARN := "arn:aws:iam::123456789012:policy/GroupManaged"
	managedName, managedType := "GroupManaged", "managed"
	inlineName, inlineType := "InlineGroup", "inline"
	if err := repository.SaveAccountIAM(
		context.Background(),
		model.AWSAccount{ID: 7, AccountID: "123456789012"},
		collectedIAMInventory{
			Principals: []collectedIAMPrincipal{{
				Principal: model.IAMPrincipal{
					PrincipalType: "User",
					PrincipalName: "member",
					ARN:           "arn:aws:iam::123456789012:user/member",
				},
			}},
			Groups: []collectedIAMGroup{{
				Group: model.IAMGroup{
					AccountID: 7,
					GroupName: "engineering",
					ARN:       "arn:aws:iam::123456789012:group/engineering",
					Path:      "/",
				},
				MemberARNs: []string{"arn:aws:iam::123456789012:user/member"},
				Policies: []model.IAMPolicy{
					{
						PolicyARN:      &managedARN,
						PolicyName:     &managedName,
						PolicyType:     &managedType,
						PolicyDocument: model.JSONB(`{"Version":"2012-10-17","Statement":[]}`),
					},
					{
						PolicyName:     &inlineName,
						PolicyType:     &inlineType,
						PolicyDocument: model.JSONB(`{"Version":"2012-10-17","Statement":[]}`),
					},
				},
			}},
		},
	); err != nil {
		t.Fatalf("SaveAccountIAM() error = %v", err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.committed {
		t.Fatal("SaveAccountIAM() did not commit the transaction")
	}
	var staleGroupDelete, membershipInsert, managedPolicyLink, inlinePolicyLink bool
	for _, call := range state.calls {
		switch {
		case strings.Contains(call.query, "DELETE FROM iam_group WHERE account_id = $1"):
			staleGroupDelete = true
			if !strings.Contains(call.query, "arn NOT IN ($2)") ||
				len(call.args) != 2 || call.args[0].Value != int64(7) ||
				call.args[1].Value != "arn:aws:iam::123456789012:group/engineering" {
				t.Errorf("stale group deletion is not account-scoped and parameterized: %#v", call)
			}
		case strings.Contains(call.query, "INSERT INTO iam_group_membership"):
			membershipInsert = true
			if len(call.args) != 2 || !strings.Contains(call.query, "$1") || !strings.Contains(call.query, "$2") {
				t.Errorf("membership insert is not parameterized: %#v", call)
			}
		case strings.Contains(call.query, "INSERT INTO iam_group_policy"):
			if len(call.args) != 2 || !strings.Contains(call.query, "$1") || !strings.Contains(call.query, "$2") {
				t.Errorf("group policy insert is not parameterized: %#v", call)
			}
			if len(call.args) == 2 && call.args[1].Value == int64(3) {
				managedPolicyLink = true
			}
			if len(call.args) == 2 && call.args[1].Value == int64(4) {
				inlinePolicyLink = true
			}
		}
	}
	if !staleGroupDelete || !membershipInsert || !managedPolicyLink || !inlinePolicyLink {
		t.Errorf("persisted reconciliation/associations stale/membership/managed/inline = %v/%v/%v/%v",
			staleGroupDelete, membershipInsert, managedPolicyLink, inlinePolicyLink)
	}
}

func TestSQLAWSAssetRepositoryRollsBackGroupReconciliationOnFailure(t *testing.T) {
	state := &recordingSQLDriver{execErrOn: "INSERT INTO iam_group_policy"}
	db := sql.OpenDB(recordingSQLConnector{state: state})
	defer db.Close()
	db.SetMaxOpenConns(1)
	repository, err := NewSQLAWSAssetRepository(db)
	if err != nil {
		t.Fatalf("NewSQLAWSAssetRepository() error = %v", err)
	}
	policyName, policyType := "inline", "inline"
	err = repository.SaveAccountIAM(
		context.Background(),
		model.AWSAccount{ID: 7, AccountID: "123456789012"},
		collectedIAMInventory{
			Groups: []collectedIAMGroup{{
				Group: model.IAMGroup{
					AccountID: 7,
					GroupName: "engineering",
					ARN:       "arn:aws:iam::123456789012:group/engineering",
					Path:      "/",
				},
				Policies: []model.IAMPolicy{{
					PolicyName:     &policyName,
					PolicyType:     &policyType,
					PolicyDocument: model.JSONB(`{"Version":"2012-10-17","Statement":[]}`),
				}},
			}},
		},
	)
	if err == nil {
		t.Fatal("SaveAccountIAM() expected injected group policy association failure")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.committed || !state.rolledBack {
		t.Errorf("transaction committed/rolled back = %v/%v, want false/true", state.committed, state.rolledBack)
	}
	foundReconciliation := false
	for _, call := range state.calls {
		if strings.Contains(call.query, "DELETE FROM iam_group WHERE account_id = $1") {
			foundReconciliation = true
			break
		}
	}
	if !foundReconciliation {
		t.Fatal("transaction did not attempt stale group reconciliation")
	}
}

func TestSQLAWSAssetRepositoryPersistsBaselineCollectionFields(t *testing.T) {
	state := &recordingSQLDriver{}
	db := sql.OpenDB(recordingSQLConnector{state: state})
	defer db.Close()
	db.SetMaxOpenConns(1)
	repository, err := NewSQLAWSAssetRepository(db)
	if err != nil {
		t.Fatalf("NewSQLAWSAssetRepository() error = %v", err)
	}

	boundaryARN := "arn:aws:iam::123456789012:policy/app-boundary"
	boundaryType := "PermissionsBoundaryPolicy"
	roleARN := "arn:aws:iam::123456789012:role/app-role"
	providerURL := "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	metadata := "<EntityDescriptor/>"
	profileTags := map[string]string{"env": "prod"}
	providerTags := map[string]string{"team": "otel"}

	if err := repository.SaveAccountIAM(
		context.Background(),
		model.AWSAccount{ID: 7, AccountID: "123456789012"},
		collectedIAMInventory{
			Principals: []collectedIAMPrincipal{{
				Principal: model.IAMPrincipal{
					PrincipalType:           "Role",
					PrincipalName:           "app-role",
					ARN:                     roleARN,
					Path:                    "/app/",
					PermissionsBoundaryARN:  &boundaryARN,
					PermissionsBoundaryType: &boundaryType,
				},
			}},
			InstanceProfiles: []model.IAMInstanceProfile{{
				InstanceProfileName: "app-profile",
				ARN:                 "arn:aws:iam::123456789012:instance-profile/app-profile",
				Path:                "/app/",
				RoleARN:             &roleARN,
				Tags:                profileTags,
			}},
			IdentityProviders: []model.IAMIdentityProvider{
				{
					ProviderType:   "OIDC",
					ARN:            "arn:aws:iam::123456789012:oidc-provider/" + providerURL,
					ProviderName:   providerURL,
					URL:            &providerURL,
					ClientIDList:   []string{"sts.amazonaws.com"},
					ThumbprintList: []string{"9e99a48a9960b14926bb7f3b02e22da2b0ab7280"},
					Tags:           providerTags,
				},
				{
					ProviderType:         "SAML",
					ARN:                  "arn:aws:iam::123456789012:saml-provider/corp-sso",
					ProviderName:         "corp-sso",
					SAMLMetadataDocument: &metadata,
				},
			},
		},
	); err != nil {
		t.Fatalf("SaveAccountIAM() error = %v", err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.committed {
		t.Fatal("SaveAccountIAM() did not commit the transaction")
	}

	var principalInsert, profileStale, profileInsert, providerStale struct {
		found bool
		call  recordedSQLCall
	}
	providerInserts := make([]recordedSQLCall, 0, 2)
	for _, call := range state.calls {
		switch {
		case strings.Contains(call.query, "INSERT INTO iam_principal"):
			if principalInsert.found {
				continue
			}
			principalInsert = struct {
				found bool
				call  recordedSQLCall
			}{true, call}
		case strings.Contains(call.query, "UPDATE iam_instance_profile SET is_deleted = TRUE"):
			profileStale = struct {
				found bool
				call  recordedSQLCall
			}{true, call}
		case strings.Contains(call.query, "INSERT INTO iam_instance_profile"):
			profileInsert = struct {
				found bool
				call  recordedSQLCall
			}{true, call}
		case strings.Contains(call.query, "UPDATE iam_identity_provider SET is_deleted = TRUE"):
			providerStale = struct {
				found bool
				call  recordedSQLCall
			}{true, call}
		case strings.Contains(call.query, "INSERT INTO iam_identity_provider"):
			providerInserts = append(providerInserts, call)
		}
	}

	if !principalInsert.found {
		t.Fatal("principal insert not issued")
	}
	// ForceNew 属性必须真的写进库，否则基线读到的 path 是默认 "/"。
	if len(principalInsert.call.args) < 7 ||
		principalInsert.call.args[4].Value != "/app/" ||
		principalInsert.call.args[5].Value != boundaryARN ||
		principalInsert.call.args[6].Value != boundaryType {
		t.Errorf("principal insert does not carry path/boundary: %#v", principalInsert.call.args)
	}
	if !profileStale.found || profileStale.call.args[0].Value != int64(7) {
		t.Errorf("instance profile stale marking missing or not account-scoped: %#v", profileStale.call)
	}
	if !profileInsert.found || len(profileInsert.call.args) < 5 ||
		profileInsert.call.args[3].Value != "/app/" ||
		profileInsert.call.args[4].Value != roleARN {
		t.Errorf("instance profile insert does not carry path/role binding: %#v", profileInsert.call.args)
	}
	if !providerStale.found || providerStale.call.args[0].Value != int64(7) {
		t.Errorf("identity provider stale marking missing or not account-scoped: %#v", providerStale.call)
	}
	if len(providerInserts) != 2 {
		t.Fatalf("identity provider inserts = %d, want OIDC and SAML", len(providerInserts))
	}
	for _, call := range providerInserts {
		switch call.args[1].Value {
		case "OIDC":
			if call.args[3].Value != providerURL || call.args[4].Value != providerURL ||
				call.args[5].Value == nil || call.args[6].Value == nil {
				t.Errorf("OIDC provider insert lost url/client ids/thumbprints: %#v", call.args)
			}
		case "SAML":
			if call.args[7].Value != metadata {
				t.Errorf("SAML provider insert lost metadata document: %#v", call.args)
			}
		default:
			t.Errorf("unexpected provider type %v", call.args[1].Value)
		}
	}
}

func TestIAMResourceNameKeepsProviderPathSegments(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE": "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
		"arn:aws:iam::123456789012:saml-provider/corp-sso":                                    "corp-sso",
		"arn:aws:iam::123456789012:instance-profile/app/profile":                              "app/profile",
		"arn:aws:iam::123456789012:role/app/role":                                             "app/role",
		"not-an-arn": "not-an-arn",
	}
	for arn, want := range cases {
		if got := iamResourceName(arn); got != want {
			t.Errorf("iamResourceName(%q) = %q, want %q", arn, got, want)
		}
	}
}

func TestNormalizedIAMPathDefaultsToRoot(t *testing.T) {
	if got := normalizedIAMPath(""); got != "/" {
		t.Errorf("normalizedIAMPath(\"\") = %q, want /", got)
	}
	if got := normalizedIAMPath("/app/"); got != "/app/" {
		t.Errorf("normalizedIAMPath(\"/app/\") = %q, want /app/", got)
	}
}

func TestSyncOrganizationPropagatesFailures(t *testing.T) {
	t.Run("organizations API", func(t *testing.T) {
		repository := &fakeAWSAssetRepository{}
		service := newTestAWSCollector(t,
			&fakeOrganizationsClient{err: errors.New("organizations unavailable")},
			&fakeSTSClient{},
			&fakeIAMClient{},
			repository,
		)
		if err := service.SyncOrganization(context.Background(), 1); err == nil {
			t.Fatal("SyncOrganization() expected Organizations error")
		}
	})

	t.Run("missing account role", func(t *testing.T) {
		repository := &fakeAWSAssetRepository{}
		service := newTestAWSCollector(t,
			&fakeOrganizationsClient{accounts: []orgtypes.Account{
				{Id: aws.String("123456789012"), Status: orgtypes.AccountStatusActive},
			}},
			&fakeSTSClient{},
			&fakeIAMClient{},
			repository,
		)
		if err := service.SyncOrganization(context.Background(), 1); err == nil {
			t.Fatal("SyncOrganization() expected missing role error")
		}
	})

	t.Run("AssumeRole error", func(t *testing.T) {
		roleARN := "arn:aws:iam::123456789012:role/CollectorReadOnly"
		repository := &fakeAWSAssetRepository{collectionAccount: model.AWSAccount{ID: 1, ReadOnlyRoleARN: &roleARN}}
		service := newTestAWSCollector(t,
			&fakeOrganizationsClient{accounts: []orgtypes.Account{
				{Id: aws.String("123456789012"), Status: orgtypes.AccountStatusActive},
			}},
			&fakeSTSClient{err: errors.New("access denied")},
			&fakeIAMClient{},
			repository,
		)
		if err := service.SyncOrganization(context.Background(), 1); err == nil {
			t.Fatal("SyncOrganization() expected AssumeRole error")
		}
	})

	t.Run("IAM API throttling error", func(t *testing.T) {
		roleARN := "arn:aws:iam::123456789012:role/CollectorReadOnly"
		repository := &fakeAWSAssetRepository{collectionAccount: model.AWSAccount{ID: 1, ReadOnlyRoleARN: &roleARN}}
		service := newTestAWSCollector(t,
			&fakeOrganizationsClient{accounts: []orgtypes.Account{
				{Id: aws.String("123456789012"), Status: orgtypes.AccountStatusActive},
			}},
			&fakeSTSClient{},
			&fakeIAMClient{listPoliciesErr: errors.New("throttling")},
			repository,
		)
		if err := service.SyncOrganization(context.Background(), 1); err == nil {
			t.Fatal("SyncOrganization() expected IAM API error")
		}
	})

	t.Run("partial group listing does not persist collected groups", func(t *testing.T) {
		roleARN := "arn:aws:iam::123456789012:role/CollectorReadOnly"
		repository := &fakeAWSAssetRepository{collectionAccount: model.AWSAccount{ID: 1, ReadOnlyRoleARN: &roleARN}}
		iamClient := &fakeIAMClient{groupListErrAt: 2}
		service := newTestAWSCollector(t,
			&fakeOrganizationsClient{accounts: []orgtypes.Account{
				{Id: aws.String("123456789012"), Status: orgtypes.AccountStatusActive},
			}},
			&fakeSTSClient{},
			iamClient,
			repository,
		)
		if err := service.SyncOrganization(context.Background(), 1); err == nil {
			t.Fatal("SyncOrganization() expected second-page group listing error")
		}
		if repository.saveCalls != 0 {
			t.Fatalf("SaveAccountIAM() calls after partial group listing = %d, want 0", repository.saveCalls)
		}
	})
}

func TestDecodeIAMPolicyDocument(t *testing.T) {
	for _, document := range []string{
		`{"Version":"2012-10-17","Statement":[]}`,
		url.QueryEscape(`{"Version":"2012-10-17","Statement":[]}`),
	} {
		decoded, err := decodeIAMPolicyDocument(document)
		if err != nil {
			t.Errorf("decodeIAMPolicyDocument(%q) error = %v", document, err)
			continue
		}
		if string(decoded) != `{"Version":"2012-10-17","Statement":[]}` {
			t.Errorf("decoded document = %s", decoded)
		}
	}
	if _, err := decodeIAMPolicyDocument("not-json"); err == nil {
		t.Fatal("decodeIAMPolicyDocument() expected invalid JSON error")
	}
}

func TestAWSCollectorValidation(t *testing.T) {
	if _, err := NewSQLAWSAssetRepository(nil); err == nil {
		t.Fatal("NewSQLAWSAssetRepository(nil) expected an error")
	}
	if _, err := newAWSCollectorService(AWSCollectorConfig{}, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("newAWSCollectorService() expected missing client error")
	}

	service := newTestAWSCollector(t,
		&fakeOrganizationsClient{},
		&fakeSTSClient{},
		&fakeIAMClient{},
		&fakeAWSAssetRepository{},
	)
	if err := service.SyncOrganization(context.Background(), 0); err == nil {
		t.Fatal("SyncOrganization() expected invalid organization ID error")
	}
}

func TestDiffIAMAssets(t *testing.T) {
	previous := []CurrentIAMAsset{
		{ARN: "arn:aws:iam::1:user/keep", Name: "keep", Type: "User"},
		{ARN: "arn:aws:iam::1:user/gone", Name: "gone", Type: "User"},
		{ARN: "arn:aws:iam::1:group/old", Name: "old", IsGroup: true},
	}
	principals := []collectedIAMPrincipal{
		{Principal: model.IAMPrincipal{PrincipalType: "User", PrincipalName: "keep", ARN: "arn:aws:iam::1:user/keep"}},
		{Principal: model.IAMPrincipal{PrincipalType: "Role", PrincipalName: "fresh", ARN: "arn:aws:iam::1:role/fresh"}},
	}
	groups := []collectedIAMGroup{
		{Group: model.IAMGroup{GroupName: "newgrp", ARN: "arn:aws:iam::1:group/newgrp"}},
	}

	changes := diffIAMAssets(previous, principals, groups)
	if changes == nil {
		t.Fatal("expected changes, got nil")
	}
	if len(changes.PrincipalsAdded) != 1 || changes.PrincipalsAdded[0].Name != "fresh" ||
		changes.PrincipalsAdded[0].Type != "Role" {
		t.Errorf("PrincipalsAdded = %+v, want [fresh Role]", changes.PrincipalsAdded)
	}
	if len(changes.PrincipalsRemoved) != 1 || changes.PrincipalsRemoved[0].Name != "gone" {
		t.Errorf("PrincipalsRemoved = %+v, want [gone]", changes.PrincipalsRemoved)
	}
	if len(changes.GroupsAdded) != 1 || changes.GroupsAdded[0].Name != "newgrp" {
		t.Errorf("GroupsAdded = %+v, want [newgrp]", changes.GroupsAdded)
	}
	if len(changes.GroupsRemoved) != 1 || changes.GroupsRemoved[0].Name != "old" {
		t.Errorf("GroupsRemoved = %+v, want [old]", changes.GroupsRemoved)
	}
}

func TestDiffIAMAssetsNilWhenUnchanged(t *testing.T) {
	previous := []CurrentIAMAsset{
		{ARN: "arn:aws:iam::1:user/keep", Name: "keep", Type: "User"},
		{ARN: "arn:aws:iam::1:group/g", Name: "g", IsGroup: true},
	}
	principals := []collectedIAMPrincipal{
		{Principal: model.IAMPrincipal{PrincipalType: "User", PrincipalName: "keep", ARN: "arn:aws:iam::1:user/keep"}},
	}
	groups := []collectedIAMGroup{
		{Group: model.IAMGroup{GroupName: "g", ARN: "arn:aws:iam::1:group/g"}},
	}
	if changes := diffIAMAssets(previous, principals, groups); changes != nil {
		t.Fatalf("unchanged inventory must produce nil diff, got %+v", changes)
	}
}

func TestSyncConfiguredAccountUnchangedInventoryRecordsNoDiff(t *testing.T) {
	// Regression: a sync that finds no inventory movement returns a nil diff;
	// the collector must not dereference it (previously panicked in logging).
	repository := &fakeAWSAssetRepository{
		configuredAccount: model.AWSAccount{ID: 41},
		currentAssets: []CurrentIAMAsset{
			{ARN: "arn:aws:iam::123456789012:role/app-role", Name: "app-role", Type: "Role"},
			{ARN: "arn:aws:iam::123456789012:user/app-user", Name: "app-user", Type: "User"},
			{ARN: "arn:aws:iam::123456789012:group/app-team", Name: "app-team", IsGroup: true},
			{ARN: "arn:aws:iam::123456789012:group/ops-team", Name: "ops-team", IsGroup: true},
		},
	}
	roleARN := "arn:aws:iam::123456789012:role/readonly"
	service := newTestAWSCollector(t, &fakeOrganizationsClient{}, &fakeSTSClient{}, &fakeIAMClient{}, repository)

	account, changes, err := service.SyncConfiguredAccount(context.Background(), model.AWSAccountConfig{
		ID: 8, AWSAccountID: "123456789012", DisplayName: "configured",
		ReadOnlyRoleARN: &roleARN, SyncMode: AWSAccountSyncAssumeRole, SyncEnabled: true,
	})
	if err != nil {
		t.Fatalf("SyncConfiguredAccount() error = %v", err)
	}
	if account.ID != 41 {
		t.Fatalf("account.ID = %d, want 41", account.ID)
	}
	if changes != nil {
		t.Fatalf("unchanged inventory must record nil diff, got %+v", changes)
	}
	if repository.saveCalls != 1 {
		t.Fatalf("SaveAccountIAM calls = %d, want 1", repository.saveCalls)
	}
	if repository.currentAssetsAccountID != 41 {
		t.Fatalf("inventory snapshot queried account %d, want 41", repository.currentAssetsAccountID)
	}
}

func TestCollectManagedPoliciesCarriesDescriptionAndTags(t *testing.T) {
	client := &fakeIAMClient{}
	service := &AWSCollectorService{}

	policies, err := service.collectManagedPolicies(context.Background(), client)
	if err != nil {
		t.Fatalf("collectManagedPolicies returned error: %v", err)
	}
	policy, ok := policies["arn:aws:iam::123456789012:policy/LocalRead"]
	if !ok {
		t.Fatalf("LocalRead policy missing from collection: %v", policies)
	}
	if policy.Description == nil || *policy.Description != "Local read policy for poc" {
		t.Fatalf("policy description not carried from ListPolicies: %v", policy.Description)
	}
	if policy.Tags["env"] != "poc" || policy.Tags["Owner"] != "platform-team" {
		t.Fatalf("policy tags not fetched via ListPolicyTags: %v", policy.Tags)
	}
	if client.listPolicyTagsCalls == 0 {
		t.Fatal("ListPolicyTags was never called")
	}
}

func TestCollectManagedPoliciesSurfacesListPolicyTagsDenial(t *testing.T) {
	client := &fakeIAMClient{listPolicyTagsErr: errors.New(
		"AccessDenied: not authorized to perform: iam:ListPolicyTags")}
	service := &AWSCollectorService{}

	_, err := service.collectManagedPolicies(context.Background(), client)
	if err == nil {
		t.Fatal("expected ListPolicyTags denial to fail the collection, got nil")
	}
	if !strings.Contains(err.Error(), "ListPolicyTags") {
		t.Fatalf("error should name the denied operation, got: %v", err)
	}
}
