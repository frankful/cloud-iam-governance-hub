package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
)

// reservationFakeDB 是参数感知的最小驱动：冲突查询按 file_key 参数决定
// 是否返回持有行，其余 Exec 一律成功。reservation 服务在事务里先
// releaseOwn、逐文件 INSERT、再逐 key SELECT 冲突，这个 fake 足以驱动
// 全部路径。
type reservationFakeDB struct {
	mu       sync.Mutex
	held     map[string]PublishReservationConflict // file_key -> 持有者
	execs    []string
	rollback bool
}

func newReservationFakeDB() *reservationFakeDB {
	return &reservationFakeDB{held: map[string]PublishReservationConflict{}}
}

func (db *reservationFakeDB) Connect(context.Context) (driver.Conn, error) {
	return &reservationFakeConn{state: db}, nil
}
func (db *reservationFakeDB) Driver() driver.Driver { return db }
func (db *reservationFakeDB) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected direct open")
}

func (db *reservationFakeDB) hasHolders() bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	return len(db.held) > 0
}

type reservationFakeConn struct {
	state *reservationFakeDB
}

func (*reservationFakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not expected")
}
func (*reservationFakeConn) Close() error              { return nil }
func (*reservationFakeConn) Begin() (driver.Tx, error) { return inventoryFakeTx{}, nil }

func (connection *reservationFakeConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	connection.state.mu.Lock()
	defer connection.state.mu.Unlock()
	connection.state.execs = append(connection.state.execs, query)
	return driver.RowsAffected(1), nil
}

func (connection *reservationFakeConn) QueryContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	state := connection.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !strings.Contains(query, "NOT (channel = $3 AND ref = $4)") {
		return &inventoryFakeRows{}, nil
	}
	// args: $1 account_id, $2 file_key, $3 channel, $4 ref
	key, _ := args[1].Value.(string)
	holder, held := state.held[key]
	if !held || (holder.Channel == args[2].Value && holder.Ref == args[3].Value) {
		return &inventoryFakeRows{}, nil
	}
	return &inventoryFakeRows{response: inventoryFakeResponse{
		columns: []string{"channel", "ref"},
		rows:    [][]driver.Value{{holder.Channel, holder.Ref}},
	}}, nil
}

// TestReserveForTicketHappyPath 无冲突：先释放自己的旧预约，再逐文件
// 插入，冲突检查逐 key 走一遍。
func TestReserveForTicketHappyPath(t *testing.T) {
	fake := newReservationFakeDB()
	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewPublishReservationService(database, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	conflicts, err := service.ReserveForTicket(context.Background(), 7, "IAM-1",
		[]string{"role-foo", "role-foo", "", "attachment-user-foo-bar"})
	if err != nil {
		t.Fatalf("ReserveForTicket: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %v, want none", conflicts)
	}
	inserts, releases := 0, 0
	for _, query := range fake.execs {
		switch {
		case strings.Contains(query, "INSERT INTO publish_reservation"):
			inserts++
		case strings.Contains(query, "WHERE channel = $1 AND ref = $2 AND status = 'OPEN'"):
			releases++
		}
	}
	if inserts != 2 || releases != 1 {
		t.Fatalf("inserts = %d (want 2, dedup + empty filtered), releases = %d (want 1)",
			inserts, releases)
	}
}

// TestReserveForTicketConflictIsAtomic 有持有者时工单预约整体失败，
// 错误信息必须指明占用者（「为什么我发不了布」要自解释）。
func TestReserveForTicketConflictIsAtomic(t *testing.T) {
	fake := newReservationFakeDB()
	fake.held["role-foo"] = PublishReservationConflict{
		FileKey: "role-foo", Channel: PublishChannelTicket, Ref: "IAM-9999",
	}
	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewPublishReservationService(database, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	conflicts, err := service.ReserveForTicket(context.Background(), 7, "IAM-1",
		[]string{"role-foo", "policy-bar"})
	if !errors.Is(err, ErrPublishFileReserved) {
		t.Fatalf("err = %v, want ErrPublishFileReserved", err)
	}
	if len(conflicts) != 1 || conflicts[0].FileKey != "role-foo" || conflicts[0].Ref != "IAM-9999" {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if !strings.Contains(err.Error(), "IAM-9999") {
		t.Fatalf("error must name the holder: %v", err)
	}
}

// TestReserveForPublicationDefersConflicts 基线预约允许部分成功：冲突
// 文件返回给调用方让路，其余照常预约。
func TestReserveForPublicationDefersConflicts(t *testing.T) {
	fake := newReservationFakeDB()
	fake.held["role-foo"] = PublishReservationConflict{
		FileKey: "role-foo", Channel: PublishChannelTicket, Ref: "IAM-9999",
	}
	database := sql.OpenDB(fake)
	defer database.Close()
	service, err := NewPublishReservationService(database, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	conflicts, err := service.ReserveForPublication(context.Background(), 7, 9,
		[]string{"role-foo", "policy-bar"})
	if err != nil {
		t.Fatalf("ReserveForPublication: %v", err)
	}
	if len(conflicts) != 1 || conflicts[0].Channel != PublishChannelTicket {
		t.Fatalf("conflicts = %+v, want the held ticket reservation", conflicts)
	}
}

// TestConflictDescribe 占用说明按渠道渲染，拒绝时用户看到的是这句话。
func TestConflictDescribe(t *testing.T) {
	cases := []struct {
		conflict PublishReservationConflict
		want     string
	}{
		{
			PublishReservationConflict{FileKey: "role-foo", Channel: PublishChannelTicket, Ref: "IAM-9"},
			"role-foo (held by ticket IAM-9)",
		},
		{
			PublishReservationConflict{FileKey: "role-foo", Channel: PublishChannelBaseline, Ref: "12"},
			"role-foo (held by baseline publication 12)",
		},
	}
	for _, testCase := range cases {
		if got := testCase.conflict.Describe(); got != testCase.want {
			t.Errorf("Describe() = %q, want %q", got, testCase.want)
		}
	}
}
