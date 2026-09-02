// Package sqlutil holds the database plumbing both metadata engines share:
// row collection, transactions, timestamp conversion, and the compiler that
// turns a Visibility into a SQL predicate.
//
// Queries themselves are not shared. They are hand-written per engine (ADR
// 0006) because the engines diverge where it matters -- placeholders, LEAST
// versus min, row-level locking -- and hiding that behind an abstraction is
// how a query stops being auditable. What is shared is everything that must
// behave identically no matter which engine is underneath: in particular the
// scope filter, because two engines that disagreed about what a binding makes
// visible would be a disclosure bug in one of them (ADR 0003).
package sqlutil

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/steveokay/trove/internal/meta"
)

// Querier is the part of *sql.DB and *sql.Tx the stores use, so a helper can
// run inside a transaction or outside one without caring which.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Scanner is the part of *sql.Row and *sql.Rows a row decoder needs, so one
// decoder serves both single-row and listing queries.
type Scanner interface {
	Scan(dest ...any) error
}

// Collect runs a query and scans every row. Funnelling listings through one
// helper keeps the number of places that can mis-handle a scan error to one.
func Collect[T any](ctx context.Context, q Querier, query string, args []any, scan func(*sql.Rows) (T, error)) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// Exists reports whether a query matches any row. The query must select a
// single column.
func Exists(ctx context.Context, q Querier, query string, args ...any) (bool, error) {
	var probe int
	err := q.QueryRowContext(ctx, query, args...).Scan(&probe)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("query: %w", err)
	default:
		return true, nil
	}
}

// Execute runs a statement and reports how many rows it changed.
func Execute(ctx context.Context, q Querier, query string, args ...any) (int64, error) {
	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("exec: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return affected, nil
}

// InTx runs fn in a transaction, rolling back unless it returns nil. Every
// multi-statement operation goes through it: a manifest without its reference
// edges, or a subject without its bindings removed, is a corrupt state that
// nothing downstream can detect.
func InTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Millis converts a time to UTC epoch milliseconds, mapping the zero time to
// NULL so "unset" stays distinguishable from "the epoch".
func Millis(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UTC().UnixMilli(), Valid: true}
}

// AsTime converts a stored timestamp back, in UTC.
func AsTime(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMilli(v.Int64).UTC()
}

// Placeholder renders the parameter marker for the nth argument, counting from
// one. It is the only piece of query syntax this package has to know about,
// and the only reason the scope compiler cannot be a plain constant.
type Placeholder func(n int) string

// Question numbers nothing: SQLite and friends take a bare "?".
func Question(int) string { return "?" }

// Dollar renders "$1", "$2", ...: the PostgreSQL form.
func Dollar(n int) string { return "$" + strconv.Itoa(n) }

// VisibilityClause compiles a Visibility into a SQL predicate over the given
// column, together with its arguments. Filtering happens in the query and
// nowhere else: a handler-side filter leaks through counts and pagination
// (ADR 0003), and one compiler shared by both engines is what stops them
// disagreeing about what a subject can see.
//
// Arguments are numbered from start, so a caller can place the clause among
// other parameters. The predicate is assembled from literal fragments and the
// caller's column name; every value is bound, never interpolated.
func VisibilityClause(column string, v meta.Visibility, ph Placeholder, start int) (string, []any) {
	if v.IsUnrestricted() {
		return "1 = 1", nil
	}

	var (
		clauses []string
		args    []any
	)
	next := func() string {
		return ph(start + len(args))
	}
	for _, f := range v.Filters() {
		switch {
		case f.All:
			return "1 = 1", nil
		case f.Exact != "":
			clauses = append(clauses, column+" = "+next())
			args = append(args, f.Exact)
		case f.Prefix != "":
			// Matches ScopeFilter.Matches: the name must be under the prefix,
			// not equal to it, so "team-a/" never selects a repository called
			// "team-a/".
			n := utf8.RuneCountInString(f.Prefix)
			var parts strings.Builder
			parts.WriteString("(substr(" + column + ", 1, " + next() + ") = ")
			args = append(args, n)
			parts.WriteString(next() + " AND length(" + column + ") > ")
			args = append(args, f.Prefix)
			parts.WriteString(next() + ")")
			args = append(args, n)
			clauses = append(clauses, parts.String())
		}
	}
	if len(clauses) == 0 {
		// No filters means no visibility. This is the case a nil slice would
		// have quietly turned into "everything".
		return "1 = 0", nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}
