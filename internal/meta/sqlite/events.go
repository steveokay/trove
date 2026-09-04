package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
)

const eventColumns = `id, type, repo_name, resource, actor, payload, at`

func scanEvent(sc sqlutil.Scanner) (meta.Event, error) {
	var (
		event   meta.Event
		repo    sql.NullString
		payload []byte
		at      sql.NullInt64
	)
	if err := sc.Scan(&event.ID, &event.Type, &repo, &event.Resource, &event.Actor, &payload, &at); err != nil {
		return meta.Event{}, err
	}
	event.Repository = repo.String
	event.Payload = json.RawMessage(payload)
	event.At = sqlutil.AsTime(at)
	return event, nil
}

func scanEventRow(rows *sql.Rows) (meta.Event, error) { return scanEvent(rows) }

// validEvent rejects an event the outbox could not be read back from. The ID
// and the type are what a receiver deduplicates and routes on, and an event
// with no timestamp cannot be ordered against anything, so all three are
// required rather than defaulted.
func validEvent(e meta.Event) error {
	switch {
	case e.ID == "":
		return meta.Invalid("id", "must not be empty")
	case e.Type == "":
		return meta.Invalid("type", "must not be empty")
	case e.At.IsZero():
		return meta.Invalid("at", "must not be zero")
	default:
		return nil
	}
}

// nullRepository maps the empty repository to NULL, which is how a system event
// is stored and how the listing tells one apart from a repository event.
func nullRepository(name string) sql.NullString {
	return sql.NullString{String: name, Valid: name != ""}
}

// tx is the transaction-scoped write surface WithinTx hands out. It holds the
// transaction and nothing else: a Tx that outlived its call would otherwise
// have a handle to write through.
type tx struct {
	tx *sql.Tx
}

// AppendEvent records one event inside the caller's transaction.
func (t *tx) AppendEvent(ctx context.Context, event meta.Event) error {
	if err := validEvent(event); err != nil {
		return err
	}

	taken, err := sqlutil.Exists(ctx, t.tx, `SELECT 1 FROM events WHERE id = ?`, event.ID)
	if err != nil {
		return err
	}
	if taken {
		return meta.Conflict("event", event.ID)
	}
	_, err = sqlutil.Execute(ctx, t.tx,
		`INSERT INTO events (`+eventColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Type, nullRepository(event.Repository), event.Resource, event.Actor,
		[]byte(event.Payload), sqlutil.Millis(event.At))
	return err
}

// WithinTx runs fn in one transaction, committing only if it returns nil.
func (s *Store) WithinTx(ctx context.Context, fn func(meta.Tx) error) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	return sqlutil.InTx(ctx, s.db, func(sqlTx *sql.Tx) error {
		return fn(&tx{tx: sqlTx})
	})
}

// ListEvents returns a permission-filtered page of events, oldest first.
func (s *Store) ListEvents(ctx context.Context, opts meta.ListOptions) (meta.EventPage, error) {
	if err := s.ready(ctx); err != nil {
		return meta.EventPage{}, err
	}

	// A system event has no repository, so a restricted view cannot check it
	// against anything and does not see it. The clause is built here rather
	// than left to the caller because forgetting it would hand every
	// subject's denials to anyone holding one binding.
	where, args := sqlutil.VisibilityClause("repo_name", opts.Visibility, sqlutil.Question, 1)
	if !opts.Visibility.IsUnrestricted() {
		where = "(repo_name IS NOT NULL AND " + where + ")"
	}

	limit := opts.EffectiveLimit()
	args = append(args, opts.Cursor, limit+1)

	events, err := sqlutil.Collect(ctx, s.db,
		`SELECT `+eventColumns+` FROM events WHERE `+where+` AND id > ? ORDER BY id LIMIT ?`,
		args, scanEventRow)
	if err != nil {
		return meta.EventPage{}, err
	}

	page := meta.EventPage{Events: events}
	if len(events) > limit {
		page.Events = events[:limit]
		page.NextCursor = events[limit-1].ID
	}
	return page, nil
}
