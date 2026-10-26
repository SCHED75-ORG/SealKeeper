package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// InsertReturningID runs a single-row INSERT and returns the new row's id.
//
// pgx does not implement sql.Result.LastInsertId, so on Postgres the
// statement gets a `RETURNING id` suffix and the id is scanned from the
// result row; SQLite keeps ExecContext + LastInsertId. query uses `?`
// placeholders and must not already carry a RETURNING clause; it is
// rebound here, so callers pass it raw.
func InsertReturningID(ctx context.Context, db *sql.DB, query string, args ...any) (int64, error) {
	if IsPostgres(db) {
		q := strings.TrimRight(strings.TrimSpace(query), ";") + " RETURNING id"
		var id int64
		if err := db.QueryRowContext(ctx, Rebind(db, q), args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// IsUniqueViolation reports whether err is a UNIQUE or PRIMARY KEY conflict:
// SQLSTATE 23505 on Postgres, SQLITE_CONSTRAINT_UNIQUE / _PRIMARYKEY on
// SQLite. Other constraint failures (foreign key, NOT NULL, CHECK) return
// false on both dialects — the per-repo message sniffers this replaces
// matched SQLite's generic "constraint failed" and so mapped a dangling
// foreign key to "already exists" on SQLite only.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	var liteErr *sqlite.Error
	if errors.As(err, &liteErr) {
		switch liteErr.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return true
		}
	}
	return false
}
