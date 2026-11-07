package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer db.Close()
	var status, reason, closedBy, merge, ci, apply string
	var attempts int
	err = db.QueryRow(`SELECT status, closure_reason, closed_by, git_merge_state, git_ci_state, git_apply_result, poll_attempt_count FROM iam_ticket WHERE ticket_no='IAM-CC81BDF9D0F134C9'`).
		Scan(&status, &reason, &closedBy, &merge, &ci, &apply, &attempts)
	if err != nil {
		fmt.Println("query:", err)
		os.Exit(1)
	}
	fmt.Printf("status=%s closure_reason=%s closed_by=%s\n", status, reason, closedBy)
	fmt.Printf("merge=%s ci=%s apply=%s attempts=%d\n", merge, ci, apply, attempts)
}
