// Command diagtest directly executes the RecordDecision SQL to debug the 500 error.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func parseEnv(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

func main() {
	env := parseEnv(".env")
	dbURL := env["DATABASE_URL"]
	ticketNo := "IAM-50F85598D87D0178"
	if len(os.Args) > 1 {
		ticketNo = os.Args[1]
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		fmt.Println("db open error:", err)
		os.Exit(1)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Step 1: lock ticket (same as RecordDecision)
	var ticketID int64
	var status string
	err = db.QueryRowContext(ctx, `SELECT id, status FROM iam_ticket WHERE ticket_no = $1 FOR UPDATE`, ticketNo).Scan(&ticketID, &status)
	if err != nil {
		fmt.Println("lock ticket error:", err)
		os.Exit(1)
	}
	fmt.Printf("ticket locked: id=%d status=%s\n", ticketID, status)

	// Step 2: update approval (same as RecordDecision)
	result, err := db.ExecContext(ctx, `UPDATE ticket_approval
		SET approval_result = $1, comment = $2
		WHERE ticket_id = $3 AND approver = $4 AND approval_result IS NULL`,
		"APPROVE", "approved for e2e test", ticketID, "admin",
	)
	if err != nil {
		fmt.Println("update approval error:", err)
		os.Exit(1)
	}
	rows, _ := result.RowsAffected()
	fmt.Printf("approval update rows affected: %d\n", rows)

	// Step 3: count pending
	var pending int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ticket_approval WHERE ticket_id = $1 AND approval_result IS NULL`, ticketID).Scan(&pending)
	if err != nil {
		fmt.Println("count pending error:", err)
		os.Exit(1)
	}
	fmt.Printf("pending approvers: %d\n", pending)

	// Step 4: if no pending, approve ticket
	if pending == 0 {
		_, err = db.ExecContext(ctx, `UPDATE iam_ticket SET status = $1, updated_at = NOW() WHERE id = $2`, "APPROVED", ticketID)
		if err != nil {
			fmt.Println("approve ticket error:", err)
			os.Exit(1)
		}
		fmt.Println("ticket approved!")
	}

	// Verify
	var newStatus string
	db.QueryRowContext(ctx, `SELECT status FROM iam_ticket WHERE id = $1`, ticketID).Scan(&newStatus)
	fmt.Printf("final status: %s\n", newStatus)
}
