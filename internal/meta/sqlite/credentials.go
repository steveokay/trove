package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// --- user credentials ---

// PutUserCredential stores or replaces a user's password verifier. The hash
// arrives complete, carrying its own salt and parameters, so raising the
// parameters later does not invalidate existing passwords.
func (s *Store) PutUserCredential(ctx context.Context, cred meta.UserCredential) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if cred.Hash == "" {
		return meta.Invalid("hash", "must not be empty")
	}

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.subject(ctx, tx, cred.Subject); err != nil {
			return err
		}
		_, err := execute(ctx, tx,
			`INSERT INTO user_credentials (subject_name, hash, must_rotate, rotated_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT (subject_name) DO UPDATE SET
			     hash = excluded.hash,
			     must_rotate = excluded.must_rotate,
			     rotated_at = excluded.rotated_at`,
			cred.Subject, cred.Hash, cred.MustRotate, millis(cred.RotatedAt))
		return err
	})
}

// GetUserCredential returns a user's verifier. Verification happens in authn;
// the store only supplies the hash.
func (s *Store) GetUserCredential(ctx context.Context, subject string) (meta.UserCredential, error) {
	if err := s.ready(ctx); err != nil {
		return meta.UserCredential{}, err
	}

	var (
		cred    meta.UserCredential
		rotated sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT subject_name, hash, must_rotate, rotated_at FROM user_credentials WHERE subject_name = ?`,
		subject).Scan(&cred.Subject, &cred.Hash, &cred.MustRotate, &rotated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.UserCredential{}, meta.NotFound("user credential", subject)
	case err != nil:
		return meta.UserCredential{}, fmt.Errorf("scan user credential: %w", err)
	}
	cred.RotatedAt = asTime(rotated)
	return cred, nil
}

// DeleteUserCredential removes a password verifier, leaving the subject: an
// account with no password is disabled-for-login, not deleted.
func (s *Store) DeleteUserCredential(ctx context.Context, subject string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := execute(ctx, s.db, `DELETE FROM user_credentials WHERE subject_name = ?`, subject)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("user credential", subject)
	}
	return nil
}

// --- robot credentials ---

// PutRobotCredential stores or replaces a robot's secret digest. Expiry is
// mandatory: robot accounts always expire (ADR 0004).
func (s *Store) PutRobotCredential(ctx context.Context, cred meta.RobotCredential) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if len(cred.SecretHash) == 0 {
		return meta.Invalid("secret_hash", "must not be empty")
	}
	if cred.ExpiresAt.IsZero() {
		return meta.Invalid("expires_at", "robot accounts must expire (ADR 0004)")
	}

	return s.inTx(ctx, func(tx *sql.Tx) error {
		subject, err := s.subject(ctx, tx, cred.Subject)
		if err != nil {
			return err
		}
		// A user holding a robot secret would be a second, weaker password path.
		if subject.Kind != meta.Robot {
			return meta.Invalid("subject", "robot credentials belong to robot accounts")
		}
		_, err = execute(ctx, tx,
			`INSERT INTO robot_credentials (subject_name, secret_hash, expires_at, rotated_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT (subject_name) DO UPDATE SET
			     secret_hash = excluded.secret_hash,
			     expires_at = excluded.expires_at,
			     rotated_at = excluded.rotated_at`,
			cred.Subject, cred.SecretHash, cred.ExpiresAt.UTC().UnixMilli(), millis(cred.RotatedAt))
		return err
	})
}

// GetRobotCredential returns a live robot secret digest. Expired and absent are
// deliberately the same answer: an authentication path should not reveal which
// robots used to exist.
func (s *Store) GetRobotCredential(ctx context.Context, subject string, now time.Time) (meta.RobotCredential, error) {
	if err := s.ready(ctx); err != nil {
		return meta.RobotCredential{}, err
	}

	var (
		cred    meta.RobotCredential
		expires int64
		rotated sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT subject_name, secret_hash, expires_at, rotated_at FROM robot_credentials WHERE subject_name = ?`,
		subject).Scan(&cred.Subject, &cred.SecretHash, &expires, &rotated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.RobotCredential{}, meta.NotFound("robot credential", subject)
	case err != nil:
		return meta.RobotCredential{}, fmt.Errorf("scan robot credential: %w", err)
	}

	cred.ExpiresAt = time.UnixMilli(expires).UTC()
	cred.RotatedAt = asTime(rotated)
	if !now.Before(cred.ExpiresAt) {
		return meta.RobotCredential{}, meta.NotFound("robot credential", subject)
	}
	return cred, nil
}

// DeleteRobotCredential revokes a robot's secret. The next use fails,
// regardless of any token minted while it was valid.
func (s *Store) DeleteRobotCredential(ctx context.Context, subject string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := execute(ctx, s.db, `DELETE FROM robot_credentials WHERE subject_name = ?`, subject)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("robot credential", subject)
	}
	return nil
}

// --- access tokens ---

const accessTokenColumns = `id, subject_name, name, token_hash, created_at, expires_at, last_used_at`

func scanAccessToken(sc scanner) (meta.AccessToken, error) {
	var (
		token   meta.AccessToken
		created sql.NullInt64
		expires sql.NullInt64
		used    sql.NullInt64
	)
	if err := sc.Scan(&token.ID, &token.Subject, &token.Name, &token.TokenHash, &created, &expires, &used); err != nil {
		return meta.AccessToken{}, err
	}
	token.CreatedAt = asTime(created)
	token.ExpiresAt = asTime(expires)
	token.LastUsedAt = asTime(used)
	return token, nil
}

// CreateAccessToken stores a personal access token. It carries no permissions
// of its own -- authorization always reads live bindings -- so revoking it is
// the only thing revocation here has to mean.
func (s *Store) CreateAccessToken(ctx context.Context, token meta.AccessToken) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if token.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if len(token.TokenHash) == 0 {
		return meta.Invalid("token_hash", "must not be empty")
	}

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.subject(ctx, tx, token.Subject); err != nil {
			return err
		}
		taken, err := exists(ctx, tx, `SELECT 1 FROM access_tokens WHERE id = ?`, token.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("access token", token.ID)
		}
		// Two records with the same digest would make authentication
		// ambiguous: whichever the store happened to return would win.
		registered, err := exists(ctx, tx, `SELECT 1 FROM access_tokens WHERE token_hash = ?`, token.TokenHash)
		if err != nil {
			return err
		}
		if registered {
			return meta.Conflict("access token", "hash already registered")
		}

		_, err = execute(ctx, tx,
			`INSERT INTO access_tokens (`+accessTokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			token.ID, token.Subject, token.Name, token.TokenHash,
			millis(token.CreatedAt), millis(token.ExpiresAt), millis(token.LastUsedAt))
		return err
	})
}

// GetAccessTokenByHash resolves a presented token. Lookup is by hash because
// that is all the store holds.
func (s *Store) GetAccessTokenByHash(ctx context.Context, hash []byte, now time.Time) (meta.AccessToken, error) {
	if err := s.ready(ctx); err != nil {
		return meta.AccessToken{}, err
	}
	if len(hash) == 0 {
		return meta.AccessToken{}, meta.Invalid("hash", "must not be empty")
	}

	token, err := scanAccessToken(s.db.QueryRowContext(ctx,
		`SELECT `+accessTokenColumns+` FROM access_tokens WHERE token_hash = ?`, hash))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.AccessToken{}, meta.NotFound("access token", "presented token")
	case err != nil:
		return meta.AccessToken{}, fmt.Errorf("scan access token: %w", err)
	}
	// An expired token is not found: the authentication path treats every
	// failure the same way.
	if token.Expired(now) {
		return meta.AccessToken{}, meta.NotFound("access token", "presented token")
	}
	return token, nil
}

// ListAccessTokens returns a subject's tokens, ordered by name, including
// expired ones so an operator can see and clean them up.
func (s *Store) ListAccessTokens(ctx context.Context, subject string) ([]meta.AccessToken, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := s.subject(ctx, s.db, subject); err != nil {
		return nil, err
	}

	return collect(ctx, s.db,
		`SELECT `+accessTokenColumns+` FROM access_tokens WHERE subject_name = ? ORDER BY name, id`,
		[]any{subject},
		func(rows *sql.Rows) (meta.AccessToken, error) { return scanAccessToken(rows) })
}

// TouchAccessToken records that a token was used, which is what "this token
// has not been used in a year" hygiene reads.
func (s *Store) TouchAccessToken(ctx context.Context, id string, at time.Time) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := execute(ctx, s.db, `UPDATE access_tokens SET last_used_at = ? WHERE id = ?`,
		millis(at), id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("access token", id)
	}
	return nil
}

// DeleteAccessToken revokes one token by id.
func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := execute(ctx, s.db, `DELETE FROM access_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("access token", id)
	}
	return nil
}

// --- sessions ---

const sessionColumns = `id, subject_name, csrf_token, created_at, idle_expires_at, absolute_expires_at`

func scanSession(sc scanner) (meta.Session, error) {
	var (
		session  meta.Session
		created  sql.NullInt64
		idle     int64
		absolute int64
	)
	if err := sc.Scan(&session.ID, &session.Subject, &session.CSRFToken, &created, &idle, &absolute); err != nil {
		return meta.Session{}, err
	}
	session.CreatedAt = asTime(created)
	session.IdleExpiresAt = time.UnixMilli(idle).UTC()
	session.AbsoluteExpiresAt = time.UnixMilli(absolute).UTC()
	return session, nil
}

// CreateSession stores a browser session. Both bounds are required: the idle
// one logs out an abandoned session, the absolute one stops a session living
// forever just because somebody keeps clicking.
func (s *Store) CreateSession(ctx context.Context, session meta.Session) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if session.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if session.CSRFToken == "" {
		return meta.Invalid("csrf_token", "must not be empty")
	}
	if session.IdleExpiresAt.IsZero() || session.AbsoluteExpiresAt.IsZero() {
		return meta.Invalid("expiry", "sessions need both an idle and an absolute bound")
	}

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.subject(ctx, tx, session.Subject); err != nil {
			return err
		}
		taken, err := exists(ctx, tx, `SELECT 1 FROM sessions WHERE id = ?`, session.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("session", session.ID)
		}
		_, err = execute(ctx, tx,
			`INSERT INTO sessions (`+sessionColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
			session.ID, session.Subject, session.CSRFToken, millis(session.CreatedAt),
			session.IdleExpiresAt.UTC().UnixMilli(), session.AbsoluteExpiresAt.UTC().UnixMilli())
		return err
	})
}

// GetSession returns a live session. An expired one is indistinguishable from
// one that never existed.
func (s *Store) GetSession(ctx context.Context, id string, now time.Time) (meta.Session, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Session{}, err
	}

	session, err := scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Session{}, meta.NotFound("session", id)
	case err != nil:
		return meta.Session{}, fmt.Errorf("scan session: %w", err)
	}
	if session.Expired(now) {
		return meta.Session{}, meta.NotFound("session", id)
	}
	return session, nil
}

// RefreshSession extends a session's idle bound. Asking for one beyond the
// absolute bound clamps rather than extends: otherwise a session that is used
// regularly never ends, which is exactly what the absolute bound prevents.
func (s *Store) RefreshSession(ctx context.Context, id string, idleExpiresAt time.Time) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	_, err := execute(ctx, s.db,
		`UPDATE sessions SET idle_expires_at = min(?, absolute_expires_at) WHERE id = ?`,
		idleExpiresAt.UTC().UnixMilli(), id)
	if err != nil {
		return err
	}
	// RowsAffected reports zero for an update that changed nothing, so
	// existence is asked separately rather than inferred from it.
	found, err := exists(ctx, s.db, `SELECT 1 FROM sessions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if !found {
		return meta.NotFound("session", id)
	}
	return nil
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := execute(ctx, s.db, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("session", id)
	}
	return nil
}

// DeleteSubjectSessions ends every session belonging to a subject. A password
// change and a disable both call it, so a compromised session cannot outlive
// the credential it came from.
func (s *Store) DeleteSubjectSessions(ctx context.Context, subject string) (int, error) {
	if err := s.ready(ctx); err != nil {
		return 0, err
	}

	affected, err := execute(ctx, s.db, `DELETE FROM sessions WHERE subject_name = ?`, subject)
	return int(affected), err
}

// DeleteExpiredSessions removes sessions that expired before the given time, so
// the table does not grow without bound.
func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) (int, error) {
	if err := s.ready(ctx); err != nil {
		return 0, err
	}

	cutoff := before.UTC().UnixMilli()
	affected, err := execute(ctx, s.db,
		`DELETE FROM sessions WHERE idle_expires_at <= ? OR absolute_expires_at <= ?`,
		cutoff, cutoff)
	return int(affected), err
}
