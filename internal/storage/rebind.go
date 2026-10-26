package storage

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/stdlib"
)

// IsPostgres reports whether db is backed by the pgx stdlib driver.
func IsPostgres(db *sql.DB) bool {
	if db == nil {
		return false
	}
	_, ok := db.Driver().(*stdlib.Driver)
	return ok
}

// Rebind rewrites `?` placeholders to `$1, $2, …` when db is Postgres.
// SQLite accepts `?` natively and gets the query unchanged.
//
// Every repo used to carry its own copy that matched on
// fmt.Sprintf("%T", db.Driver()) containing "pgx" — but the type prints as
// "*stdlib.Driver", so no query was ever rewritten and the Postgres backend
// failed on every parameterised statement. Queries must not contain a
// literal '?' outside placeholders.
func Rebind(db *sql.DB, query string) string {
	if !IsPostgres(db) {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	idx := 1
	for _, r := range query {
		if r == '?' {
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(idx))
			idx++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
