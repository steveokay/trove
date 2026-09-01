package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// --- user credentials ---

// PutUserCredential stores or replaces a password verifier.
func (s *Store) PutUserCredential(ctx context.Context, cred meta.UserCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if cred.Hash == "" {
		return meta.Invalid("hash", "must not be empty")
	}
	if _, ok := s.subjects[cred.Subject]; !ok {
		return meta.NotFound("subject", cred.Subject)
	}

	s.userCredentials[cred.Subject] = cred
	return nil
}

// GetUserCredential returns a password verifier.
func (s *Store) GetUserCredential(ctx context.Context, subject string) (meta.UserCredential, error) {
	if err := ctx.Err(); err != nil {
		return meta.UserCredential{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.UserCredential{}, err
	}

	cred, ok := s.userCredentials[subject]
	if !ok {
		return meta.UserCredential{}, meta.NotFound("user credential", subject)
	}
	return cred, nil
}

// DeleteUserCredential removes a password verifier.
func (s *Store) DeleteUserCredential(ctx context.Context, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.userCredentials[subject]; !ok {
		return meta.NotFound("user credential", subject)
	}
	delete(s.userCredentials, subject)
	return nil
}

// --- robot credentials ---

// PutRobotCredential stores or replaces a robot secret digest.
func (s *Store) PutRobotCredential(ctx context.Context, cred meta.RobotCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if len(cred.SecretHash) == 0 {
		return meta.Invalid("secret_hash", "must not be empty")
	}
	if cred.ExpiresAt.IsZero() {
		return meta.Invalid("expires_at", "robot accounts must expire (ADR 0004)")
	}
	subject, ok := s.subjects[cred.Subject]
	if !ok {
		return meta.NotFound("subject", cred.Subject)
	}
	if subject.Kind != meta.Robot {
		return meta.Invalid("subject", "robot credentials belong to robot accounts")
	}

	stored := cred
	stored.SecretHash = append([]byte(nil), cred.SecretHash...)
	s.robotCredentials[cred.Subject] = stored
	return nil
}

// GetRobotCredential returns a live robot secret digest.
func (s *Store) GetRobotCredential(ctx context.Context, subject string, now time.Time) (meta.RobotCredential, error) {
	if err := ctx.Err(); err != nil {
		return meta.RobotCredential{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.RobotCredential{}, err
	}

	cred, ok := s.robotCredentials[subject]
	if !ok || !now.Before(cred.ExpiresAt) {
		// Expired and absent are deliberately the same answer.
		return meta.RobotCredential{}, meta.NotFound("robot credential", subject)
	}
	return cloneRobotCredential(cred), nil
}

// DeleteRobotCredential revokes a robot secret.
func (s *Store) DeleteRobotCredential(ctx context.Context, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.robotCredentials[subject]; !ok {
		return meta.NotFound("robot credential", subject)
	}
	delete(s.robotCredentials, subject)
	return nil
}

// --- access tokens ---

// CreateAccessToken stores a personal access token.
func (s *Store) CreateAccessToken(ctx context.Context, token meta.AccessToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if token.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if len(token.TokenHash) == 0 {
		return meta.Invalid("token_hash", "must not be empty")
	}
	if _, ok := s.subjects[token.Subject]; !ok {
		return meta.NotFound("subject", token.Subject)
	}
	if _, exists := s.accessTokens[token.ID]; exists {
		return meta.Conflict("access token", token.ID)
	}
	for _, existing := range s.accessTokens {
		if bytes.Equal(existing.TokenHash, token.TokenHash) {
			return meta.Conflict("access token", "hash already registered")
		}
	}

	stored := token
	stored.TokenHash = append([]byte(nil), token.TokenHash...)
	s.accessTokens[token.ID] = stored
	return nil
}

// GetAccessTokenByHash resolves a presented token.
func (s *Store) GetAccessTokenByHash(ctx context.Context, hash []byte, now time.Time) (meta.AccessToken, error) {
	if err := ctx.Err(); err != nil {
		return meta.AccessToken{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.AccessToken{}, err
	}

	if len(hash) == 0 {
		return meta.AccessToken{}, meta.Invalid("hash", "must not be empty")
	}

	for _, token := range s.accessTokens {
		if !bytes.Equal(token.TokenHash, hash) {
			continue
		}
		if token.Expired(now) {
			break
		}
		return cloneAccessToken(token), nil
	}
	return meta.AccessToken{}, meta.NotFound("access token", "presented token")
}

// ListAccessTokens returns a subject's tokens ordered by name.
func (s *Store) ListAccessTokens(ctx context.Context, subject string) ([]meta.AccessToken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	if _, ok := s.subjects[subject]; !ok {
		return nil, meta.NotFound("subject", subject)
	}

	var out []meta.AccessToken
	for _, token := range s.accessTokens {
		if token.Subject == subject {
			out = append(out, cloneAccessToken(token))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// TouchAccessToken records that a token was used.
func (s *Store) TouchAccessToken(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	token, ok := s.accessTokens[id]
	if !ok {
		return meta.NotFound("access token", id)
	}
	token.LastUsedAt = at
	s.accessTokens[id] = token
	return nil
}

// DeleteAccessToken revokes one token.
func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.accessTokens[id]; !ok {
		return meta.NotFound("access token", id)
	}
	delete(s.accessTokens, id)
	return nil
}

// --- sessions ---

// CreateSession stores a browser session.
func (s *Store) CreateSession(ctx context.Context, session meta.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
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
	if _, ok := s.subjects[session.Subject]; !ok {
		return meta.NotFound("subject", session.Subject)
	}
	if _, exists := s.sessions[session.ID]; exists {
		return meta.Conflict("session", session.ID)
	}

	s.sessions[session.ID] = session
	return nil
}

// GetSession returns a live session.
func (s *Store) GetSession(ctx context.Context, id string, now time.Time) (meta.Session, error) {
	if err := ctx.Err(); err != nil {
		return meta.Session{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Session{}, err
	}

	session, ok := s.sessions[id]
	if !ok || session.Expired(now) {
		return meta.Session{}, meta.NotFound("session", id)
	}
	return session, nil
}

// RefreshSession extends the idle bound only.
func (s *Store) RefreshSession(ctx context.Context, id string, idleExpiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	session, ok := s.sessions[id]
	if !ok {
		return meta.NotFound("session", id)
	}
	// Refreshing past the absolute bound would make it meaningless, so it
	// clamps rather than extends.
	if idleExpiresAt.After(session.AbsoluteExpiresAt) {
		idleExpiresAt = session.AbsoluteExpiresAt
	}
	session.IdleExpiresAt = idleExpiresAt
	s.sessions[id] = session
	return nil
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.sessions[id]; !ok {
		return meta.NotFound("session", id)
	}
	delete(s.sessions, id)
	return nil
}

// DeleteSubjectSessions ends every session belonging to a subject.
func (s *Store) DeleteSubjectSessions(ctx context.Context, subject string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return 0, err
	}

	removed := 0
	for id, session := range s.sessions {
		if session.Subject == subject {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}

// DeleteExpiredSessions prunes sessions that expired before the given time.
func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return 0, err
	}

	removed := 0
	for id, session := range s.sessions {
		if session.Expired(before) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}

// --- helpers ---

func cloneRobotCredential(c meta.RobotCredential) meta.RobotCredential {
	c.SecretHash = append([]byte(nil), c.SecretHash...)
	return c
}

func cloneAccessToken(t meta.AccessToken) meta.AccessToken {
	t.TokenHash = append([]byte(nil), t.TokenHash...)
	return t
}
