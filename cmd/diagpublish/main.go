// diagpublish prints the persisted publication failure reason for a ticket.
// Temporary E2E diagnostic; not part of the platform surface.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ticketNo := os.Args[1]
	db, err := sql.Open("pgx", "postgres://finops:finops@127.0.0.1:5432/finops?sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var id int64
	var status string
	var remoteRequestNumber sql.NullString
	err = db.QueryRowContext(ctx,
		`SELECT id, status, remote_request_number FROM iam_ticket WHERE ticket_no = $1`, ticketNo).Scan(&id, &status, &remoteRequestNumber)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ticket %s: id=%d status=%s remote_request_number=%v\n", ticketNo, id, status, remoteRequestNumber)

	rows, err := db.QueryContext(ctx, `
		SELECT provider, merge_state, ci_state, apply_result, attempt, sanitized_error, observed_at
		FROM iac_execution_record WHERE ticket_id = $1 ORDER BY id DESC LIMIT 5`, id)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var provider, mergeState, ciState, applyResult, sanitizedErr sql.NullString
		var attempt int
		var observedAt time.Time
		if err := rows.Scan(&provider, &mergeState, &ciState, &applyResult, &attempt, &sanitizedErr, &observedAt); err != nil {
			panic(err)
		}
		errText := ""
		if sanitizedErr.Valid {
			errText = sanitizedErr.String
		}
		fmt.Printf("record: provider=%s merge=%s ci=%s apply=%s attempt=%d observed=%s\n  error: %s\n",
			provider.String, mergeState.String, ciState.String, applyResult.String, attempt, observedAt.Format(time.RFC3339), errText)
	}

	// One-time E2E backfill removed: SavePublication now persists git metadata.
}
