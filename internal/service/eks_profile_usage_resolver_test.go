package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

// usageFakeDB 只回答解析器路径上的两条 SQL：账号没有只读角色 ARN、
// 但处于 CURRENT_CREDENTIALS 模式，于是解析走进程自身凭证。
type usageFakeDB struct {
	responses []usageFakeResponse
	// queryHook 优先于 responses：按参数分发行集（同一 SELECT 不同账号
	// 返回不同结果）。返回 false 则继续走 responses 匹配。
	queryHook func(query string, args []driver.NamedValue) (usageFakeResponse, bool)
}

type usageFakeResponse struct {
	match   string
	columns []string
	rows    [][]driver.Value
}

func (db *usageFakeDB) lookup(query string) usageFakeResponse {
	for _, response := range db.responses {
		if strings.Contains(query, response.match) {
			return response
		}
	}
	return usageFakeResponse{}
}

func (db *usageFakeDB) Connect(context.Context) (driver.Conn, error) {
	return &usageFakeConn{state: db}, nil
}
func (db *usageFakeDB) Driver() driver.Driver { return db }
func (db *usageFakeDB) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected direct driver open")
}

type usageFakeConn struct {
	state *usageFakeDB
}

func (*usageFakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not expected")
}
func (*usageFakeConn) Close() error { return nil }
func (connection *usageFakeConn) Begin() (driver.Tx, error) {
	return usageFakeTx{}, nil
}
func (connection *usageFakeConn) QueryContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	if strings.Contains(query, "$") && len(args) == 0 {
		return nil, fmt.Errorf("query has placeholders but 0 args passed: %.80s", query)
	}
	if connection.state.queryHook != nil {
		if response, ok := connection.state.queryHook(query, args); ok {
			return &usageFakeRows{response: response}, nil
		}
	}
	response := connection.state.lookup(query)
	return &usageFakeRows{response: response}, nil
}

func (connection *usageFakeConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	if strings.Contains(query, "$") && len(args) == 0 {
		return nil, fmt.Errorf("exec has placeholders but 0 args passed: %.80s", query)
	}
	if connection.state.queryHook != nil {
		if _, ok := connection.state.queryHook(query, args); ok {
			return driver.RowsAffected(1), nil
		}
	}
	return driver.RowsAffected(1), nil
}

type usageFakeTx struct{}

func (usageFakeTx) Commit() error   { return nil }
func (usageFakeTx) Rollback() error { return nil }

type usageFakeRows struct {
	response usageFakeResponse
	index    int
}

func (rows *usageFakeRows) Columns() []string {
	if len(rows.response.columns) > 0 {
		return rows.response.columns
	}
	if len(rows.response.rows) > 0 {
		names := make([]string, len(rows.response.rows[0]))
		for index := range names {
			names[index] = fmt.Sprintf("col_%d", index)
		}
		return names
	}
	return nil
}
func (rows *usageFakeRows) Close() error { return nil }
func (rows *usageFakeRows) Next(dest []driver.Value) error {
	if rows.index >= len(rows.response.rows) {
		return io.EOF
	}
	copy(dest, rows.response.rows[rows.index])
	rows.index++
	return nil
}

// usageFakeEKS / usageFakeEC2 记录调用次数，用来断言第二次解析走缓存。
type usageFakeEKS struct {
	describeNodegroupCalls int
}

func (fake *usageFakeEKS) ListClusters(
	context.Context, *eks.ListClustersInput, ...func(*eks.Options),
) (*eks.ListClustersOutput, error) {
	return &eks.ListClustersOutput{Clusters: []string{"cluster-a"}}, nil
}

func (fake *usageFakeEKS) ListNodegroups(
	context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options),
) (*eks.ListNodegroupsOutput, error) {
	return &eks.ListNodegroupsOutput{Nodegroups: []string{"ng-a"}}, nil
}

func (fake *usageFakeEKS) DescribeNodegroup(
	context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options),
) (*eks.DescribeNodegroupOutput, error) {
	fake.describeNodegroupCalls++
	role := "arn:aws:iam::123456789012:role/node-role"
	return &eks.DescribeNodegroupOutput{Nodegroup: &ekstypes.Nodegroup{
		NodeRole: &role,
	}}, nil
}

type usageFakeEC2 struct {
	versionCalls int
}

func (fake *usageFakeEC2) DescribeLaunchTemplates(
	context.Context, *ec2.DescribeLaunchTemplatesInput, ...func(*ec2.Options),
) (*ec2.DescribeLaunchTemplatesOutput, error) {
	id := "lt-1"
	name := "eks-template"
	return &ec2.DescribeLaunchTemplatesOutput{
		LaunchTemplates: []ec2types.LaunchTemplate{{LaunchTemplateId: &id, LaunchTemplateName: &name}},
	}, nil
}

func (fake *usageFakeEC2) DescribeLaunchTemplateVersions(
	context.Context, *ec2.DescribeLaunchTemplateVersionsInput, ...func(*ec2.Options),
) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	fake.versionCalls++
	arn := "arn:aws:iam::123456789012:instance-profile/eks-used"
	return &ec2.DescribeLaunchTemplateVersionsOutput{
		LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{{
			LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
				IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{Arn: &arn},
			},
		}},
	}, nil
}

func newUsageTestResolver(t *testing.T) (*EKSProfileUsageResolver, *usageFakeEKS, *usageFakeEC2) {
	t.Helper()
	fake := &usageFakeDB{}
	// 顺序敏感：aws_account_config 先注册，避免被 aws_account 前缀匹配截胡。
	fake.responses = append(fake.responses,
		usageFakeResponse{
			match:   "FROM aws_account_config",
			columns: []string{"sync_mode"},
			rows:    [][]driver.Value{{AWSAccountSyncCurrentCredentials}},
		},
		usageFakeResponse{
			match:   "FROM aws_account WHERE",
			columns: []string{"read_only_role_arn"},
			rows:    [][]driver.Value{{nil}},
		},
	)
	database := sql.OpenDB(fake)
	t.Cleanup(func() { database.Close() })
	resolver, err := NewEKSProfileUsageResolver(database, "ap-east-1", "", "iam-governance-test", "")
	if err != nil {
		t.Fatalf("NewEKSProfileUsageResolver: %v", err)
	}
	eksFake := &usageFakeEKS{}
	ec2Fake := &usageFakeEC2{}
	resolver.eksFactory = func(aws.Config) eksUsageAPI { return eksFake }
	resolver.ec2Factory = func(aws.Config) ec2UsageAPI { return ec2Fake }
	return resolver, eksFake, ec2Fake
}

// TestResolveUsedProfilesCachesByAccount 复现待清理页 8~25 秒的问题：
// 解析结果必须按账号缓存，第二次调用不得再打 AWS API。
func TestResolveUsedProfilesCachesByAccount(t *testing.T) {
	resolver, eksFake, ec2Fake := newUsageTestResolver(t)
	ctx := context.Background()

	first, err := resolver.ResolveUsedProfiles(ctx, "123456789012")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if !first.available() {
		t.Fatalf("first result should be available")
	}
	if !first.isUsed("arn:aws:iam::123456789012:instance-profile/eks-used", "eks-used") {
		t.Fatalf("launch template reference should mark profile used")
	}
	if eksFake.describeNodegroupCalls != 1 || ec2Fake.versionCalls != 1 {
		t.Fatalf("expected one AWS round (eks=%d ec2=%d)",
			eksFake.describeNodegroupCalls, ec2Fake.versionCalls)
	}

	second, err := resolver.ResolveUsedProfiles(ctx, "123456789012")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if eksFake.describeNodegroupCalls != 1 || ec2Fake.versionCalls != 1 {
		t.Fatalf("second resolve must be served from cache (eks=%d ec2=%d)",
			eksFake.describeNodegroupCalls, ec2Fake.versionCalls)
	}
	if !second.isUsed("eks-used", "") {
		t.Fatalf("cached result lost profile references")
	}
	if second.roleInUse("ARN:AWS:IAM::123456789012:ROLE/node-role") != true {
		t.Fatalf("cached result lost nodegroup role evidence")
	}
}

// usageFakeEKSDenied 模拟只读角色没有单独授予的 EKS 权限：ListClusters 403。
type usageFakeEKSDenied struct{}

func (fake *usageFakeEKSDenied) ListClusters(
	context.Context, *eks.ListClustersInput, ...func(*eks.Options),
) (*eks.ListClustersOutput, error) {
	return nil, errors.New("operation error EKS: ListClusters, https response error StatusCode: 403, " +
		"api error AccessDeniedException: User is not authorized to perform: eks:ListClusters")
}

func (fake *usageFakeEKSDenied) ListNodegroups(
	context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options),
) (*eks.ListNodegroupsOutput, error) {
	return nil, errors.New("ListNodegroups must not be called when ListClusters is denied")
}

func (fake *usageFakeEKSDenied) DescribeNodegroup(
	context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options),
) (*eks.DescribeNodegroupOutput, error) {
	return nil, errors.New("DescribeNodegroup must not be called when ListClusters is denied")
}

// usageFakeEC2Denied 模拟 EC2 侧权限也未授予。
type usageFakeEC2Denied struct{}

func (fake *usageFakeEC2Denied) DescribeLaunchTemplates(
	context.Context, *ec2.DescribeLaunchTemplatesInput, ...func(*ec2.Options),
) (*ec2.DescribeLaunchTemplatesOutput, error) {
	return nil, errors.New("operation error EC2: DescribeLaunchTemplates, https response error StatusCode: 403, " +
		"api error UnauthorizedOperation: not authorized to perform: ec2:DescribeLaunchTemplates")
}

func (fake *usageFakeEC2Denied) DescribeLaunchTemplateVersions(
	context.Context, *ec2.DescribeLaunchTemplateVersionsInput, ...func(*ec2.Options),
) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	return nil, errors.New("DescribeLaunchTemplateVersions must not be called when listing is denied")
}

// TestCollectProfileUsageEKSDeniedDegradesGracefully EKS 权限需要单独授予：
// 被拒时不能影响 EC2 侧证据（条目判定照常），只置 EKSUnavailable 让上层给
// 权限提示，且不得把原始 AccessDenied 文本刷进页面。
func TestCollectProfileUsageEKSDeniedDegradesGracefully(t *testing.T) {
	result, err := collectProfileUsage(context.Background(), &usageFakeEKSDenied{}, &usageFakeEC2{})
	if err != nil {
		t.Fatalf("EKS denial must not fail the whole resolution: %v", err)
	}
	if !result.available() {
		t.Fatalf("EC2 evidence must survive EKS denial")
	}
	if !result.isUsed("arn:aws:iam::123456789012:instance-profile/eks-used", "eks-used") {
		t.Fatalf("launch template evidence lost: %#v", result.UsedProfiles)
	}
	if !result.EKSUnavailable {
		t.Fatalf("EKS denial must set EKSUnavailable")
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("access denied must not leak raw AWS errors into warnings: %v", result.Warnings)
	}
}

// TestCollectProfileUsageEC2DeniedFailsCleanly EC2 被拒时没有硬证据可用，
// 整体退回错误（上层降级为「需确认」），但错误文本要是可读的权限提示。
func TestCollectProfileUsageEC2DeniedFailsCleanly(t *testing.T) {
	_, err := collectProfileUsage(context.Background(), &usageFakeEKS{}, &usageFakeEC2Denied{})
	if err == nil {
		t.Fatalf("EC2 denial must fail the resolution (no hard evidence available)")
	}
	if !strings.Contains(err.Error(), "EC2 侧权限未授予") {
		t.Fatalf("error should carry a readable permission hint: %v", err)
	}
	if strings.Contains(err.Error(), "operation error") {
		t.Fatalf("raw AWS error text should not surface to users: %v", err)
	}
}
