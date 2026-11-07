package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

// Usage: go run ./cmd/diagpolicy [name-substring]
func main() {
	godotenv.Load()
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	pattern := "%"
	if len(os.Args) > 1 {
		pattern = "%" + os.Args[1] + "%"
	}

	rows, err := db.Query(`
		SELECT p.id, a.account_id, p.principal_name, p.principal_type
		FROM iam_principal p
		JOIN aws_account a ON a.id = p.account_id
		WHERE p.principal_name ILIKE $1
		ORDER BY p.principal_name`, pattern)
	if err != nil {
		log.Fatal(err)
	}
	type principal struct {
		id, accountDB, accountAWS int64
		name, ptype               string
	}
	var principals []principal
	for rows.Next() {
		var p principal
		if err := rows.Scan(&p.id, &p.accountAWS, &p.name, &p.ptype); err != nil {
			log.Fatal(err)
		}
		principals = append(principals, p)
	}
	rows.Close()

	for _, p := range principals {
		fmt.Printf("principal_id=%d account_id=%d name=%s type=%s\n", p.id, p.accountAWS, p.name, p.ptype)
		polRows, err := db.Query(`
			SELECT pol.policy_name, pol.policy_type
			FROM iam_principal_policy pp
			JOIN iam_policy pol ON pol.id = pp.policy_id
			WHERE pp.principal_id = $1
			ORDER BY pol.policy_name`, p.id)
		if err != nil {
			log.Fatal(err)
		}
		for polRows.Next() {
			var name, ptype string
			if err := polRows.Scan(&name, &ptype); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("  - %s (%s)\n", name, ptype)
		}
		polRows.Close()
	}
	if len(principals) == 0 {
		fmt.Println("no principals match:", strings.Trim(pattern, "%"))
	}
}
