package metatest

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// credentialTests are appended to the contract suite by Run.
func credentialTests() []suiteCase {
	return []suiteCase{
		{"UserCredentials", testUserCredentials},
		{"RobotCredentials", testRobotCredentials},
		{"RobotCredentialsMustExpire", testRobotCredentialsMustExpire},
		{"RobotRevocationTakesEffectImmediately", testRobotRevocationTakesEffectImmediately},
		{"AccessTokens", testAccessTokens},
		{"AccessTokenExpiry", testAccessTokenExpiry},
		{"AccessTokenIntegrity", testAccessTokenIntegrity},
		{"Sessions", testSessions},
		{"SessionExpiryBounds", testSessionExpiryBounds},
		{"SessionRefreshCannotOutliveAbsoluteBound", testSessionRefreshCannotOutliveAbsoluteBound},
		{"DeletingSubjectRemovesItsSecrets", testDeletingSubjectRemovesItsSecrets},
	}
}

func hash(seed string) []byte { return []byte("hmac-" + seed) }

func testUserCredentials(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	cred := meta.UserCredential{
		Subject:    "alice",
		Hash:       "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		MustRotate: true,
		RotatedAt:  testTime,
	}
	if err := s.PutUserCredential(ctx(), cred); err != nil {
		t.Fatalf("PutUserCredential: %v", err)
	}

	got, err := s.GetUserCredential(ctx(), "alice")
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if got.Hash != cred.Hash {
		t.Errorf("hash = %q, want it stored verbatim: it carries its own salt and parameters", got.Hash)
	}
	if !got.MustRotate {
		t.Error("MustRotate did not round-trip; bootstrap depends on it")
	}

	// Replacing is how a password change works.
	cred.Hash = "$argon2id$v=19$m=65536,t=3,p=2$bmV3$bmV3aGFzaA"
	cred.MustRotate = false
	if err := s.PutUserCredential(ctx(), cred); err != nil {
		t.Fatalf("PutUserCredential (replace): %v", err)
	}
	got, err = s.GetUserCredential(ctx(), "alice")
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if got.Hash != cred.Hash || got.MustRotate {
		t.Errorf("credential = %+v, want the replacement", got)
	}

	requireErrIs(t, s.PutUserCredential(ctx(), meta.UserCredential{Subject: "alice"}),
		meta.ErrInvalid, "PutUserCredential with an empty hash")
	requireErrIs(t, s.PutUserCredential(ctx(), meta.UserCredential{Subject: "ghost", Hash: "x"}),
		meta.ErrNotFound, "PutUserCredential for a missing subject")
	_, err = s.GetUserCredential(ctx(), "ghost")
	requireErrIs(t, err, meta.ErrNotFound, "GetUserCredential for a missing subject")

	if err := s.DeleteUserCredential(ctx(), "alice"); err != nil {
		t.Fatalf("DeleteUserCredential: %v", err)
	}
	requireErrIs(t, s.DeleteUserCredential(ctx(), "alice"), meta.ErrNotFound, "DeleteUserCredential twice")

	// The subject survives losing its password: an account with no password
	// is disabled-for-login, not deleted.
	if _, err := s.GetSubject(ctx(), "alice"); err != nil {
		t.Errorf("subject disappeared with its credential: %v", err)
	}
}

func testRobotCredentials(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "robot$ci", meta.Robot)

	cred := meta.RobotCredential{
		Subject:    "robot$ci",
		SecretHash: hash("ci-secret"),
		ExpiresAt:  testTime.Add(90 * 24 * time.Hour),
		RotatedAt:  testTime,
	}
	if err := s.PutRobotCredential(ctx(), cred); err != nil {
		t.Fatalf("PutRobotCredential: %v", err)
	}

	got, err := s.GetRobotCredential(ctx(), "robot$ci", testTime)
	if err != nil {
		t.Fatalf("GetRobotCredential: %v", err)
	}
	if !bytes.Equal(got.SecretHash, cred.SecretHash) {
		t.Errorf("secret hash = %q, want it to round-trip", got.SecretHash)
	}

	// Mutating a returned digest must not reach stored state.
	got.SecretHash[0] = 'X'
	again, err := s.GetRobotCredential(ctx(), "robot$ci", testTime)
	if err != nil {
		t.Fatalf("GetRobotCredential: %v", err)
	}
	if !bytes.Equal(again.SecretHash, cred.SecretHash) {
		t.Error("mutating a returned secret hash changed stored state")
	}

	// Only robot accounts get robot secrets: a user with one would be a
	// second, weaker password path.
	mustCreateSubject(t, s, "alice", meta.User)
	requireErrIs(t, s.PutRobotCredential(ctx(), meta.RobotCredential{
		Subject: "alice", SecretHash: hash("x"), ExpiresAt: testTime.Add(time.Hour),
	}), meta.ErrInvalid, "PutRobotCredential for a user")

	requireErrIs(t, s.PutRobotCredential(ctx(), meta.RobotCredential{
		Subject: "robot$ci", ExpiresAt: testTime.Add(time.Hour),
	}), meta.ErrInvalid, "PutRobotCredential with an empty hash")
	requireErrIs(t, s.PutRobotCredential(ctx(), meta.RobotCredential{
		Subject: "ghost", SecretHash: hash("x"), ExpiresAt: testTime.Add(time.Hour),
	}), meta.ErrNotFound, "PutRobotCredential for a missing subject")
}

func testRobotCredentialsMustExpire(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "robot$ci", meta.Robot)

	// ADR 0004 makes expiry mandatory, so a credential without one cannot be
	// stored at all rather than being treated as "never expires".
	requireErrIs(t, s.PutRobotCredential(ctx(), meta.RobotCredential{
		Subject: "robot$ci", SecretHash: hash("forever"),
	}), meta.ErrInvalid, "PutRobotCredential without an expiry")

	expiry := testTime.Add(time.Hour)
	if err := s.PutRobotCredential(ctx(), meta.RobotCredential{
		Subject: "robot$ci", SecretHash: hash("ci"), ExpiresAt: expiry,
	}); err != nil {
		t.Fatalf("PutRobotCredential: %v", err)
	}

	if _, err := s.GetRobotCredential(ctx(), "robot$ci", expiry.Add(-time.Second)); err != nil {
		t.Errorf("credential rejected before its expiry: %v", err)
	}

	// Expired and absent are the same answer: an authentication path should
	// not reveal which robots used to exist.
	for _, at := range []time.Time{expiry, expiry.Add(time.Second)} {
		_, err := s.GetRobotCredential(ctx(), "robot$ci", at)
		requireErrIs(t, err, meta.ErrNotFound, "GetRobotCredential at or past expiry")
	}
	_, err := s.GetRobotCredential(ctx(), "robot$never-existed", testTime)
	requireErrIs(t, err, meta.ErrNotFound, "GetRobotCredential for a robot that never existed")
}

func testRobotRevocationTakesEffectImmediately(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "robot$ci", meta.Robot)

	if err := s.PutRobotCredential(ctx(), meta.RobotCredential{
		Subject: "robot$ci", SecretHash: hash("ci"), ExpiresAt: testTime.Add(time.Hour),
	}); err != nil {
		t.Fatalf("PutRobotCredential: %v", err)
	}

	if err := s.DeleteRobotCredential(ctx(), "robot$ci"); err != nil {
		t.Fatalf("DeleteRobotCredential: %v", err)
	}

	// Revocation must bite on the next use, not at the next mint: the whole
	// point is that an outstanding token cannot outlive the revocation.
	_, err := s.GetRobotCredential(ctx(), "robot$ci", testTime)
	requireErrIs(t, err, meta.ErrNotFound, "GetRobotCredential after revocation")

	requireErrIs(t, s.DeleteRobotCredential(ctx(), "robot$ci"), meta.ErrNotFound, "DeleteRobotCredential twice")

	// The robot subject itself survives, so it can be issued a new secret.
	if _, err := s.GetSubject(ctx(), "robot$ci"); err != nil {
		t.Errorf("robot subject disappeared with its secret: %v", err)
	}
}

func testAccessTokens(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	token := meta.AccessToken{
		ID:        "tok-1",
		Subject:   "alice",
		Name:      "laptop",
		TokenHash: hash("laptop-token"),
		CreatedAt: testTime,
	}
	if err := s.CreateAccessToken(ctx(), token); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	got, err := s.GetAccessTokenByHash(ctx(), hash("laptop-token"), testTime)
	if err != nil {
		t.Fatalf("GetAccessTokenByHash: %v", err)
	}
	if got.ID != "tok-1" || got.Subject != "alice" {
		t.Errorf("token = %+v, want it to resolve to alice's token", got)
	}

	// An unknown token is not found rather than an error of some other kind:
	// the authentication path treats every failure the same way.
	_, err = s.GetAccessTokenByHash(ctx(), hash("guessed"), testTime)
	requireErrIs(t, err, meta.ErrNotFound, "GetAccessTokenByHash with an unknown hash")

	if err := s.TouchAccessToken(ctx(), "tok-1", testTime.Add(time.Hour)); err != nil {
		t.Fatalf("TouchAccessToken: %v", err)
	}
	listed, err := s.ListAccessTokens(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListAccessTokens: %v", err)
	}
	if len(listed) != 1 || !listed[0].LastUsedAt.Equal(testTime.Add(time.Hour)) {
		t.Errorf("tokens = %+v, want last-used recorded", listed)
	}
	// Listing must not hand out material that could be replayed... but it
	// only ever holds a digest, so assert that is what comes back.
	if !bytes.Equal(listed[0].TokenHash, hash("laptop-token")) {
		t.Error("listed token does not carry its digest")
	}

	if err := s.DeleteAccessToken(ctx(), "tok-1"); err != nil {
		t.Fatalf("DeleteAccessToken: %v", err)
	}
	_, err = s.GetAccessTokenByHash(ctx(), hash("laptop-token"), testTime)
	requireErrIs(t, err, meta.ErrNotFound, "GetAccessTokenByHash after revocation")
	requireErrIs(t, s.DeleteAccessToken(ctx(), "tok-1"), meta.ErrNotFound, "DeleteAccessToken twice")
	requireErrIs(t, s.TouchAccessToken(ctx(), "tok-1", testTime), meta.ErrNotFound, "TouchAccessToken on a missing token")
}

func testAccessTokenExpiry(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	expiry := testTime.Add(24 * time.Hour)
	expiring := meta.AccessToken{
		ID: "tok-expiring", Subject: "alice", Name: "ci",
		TokenHash: hash("expiring"), CreatedAt: testTime, ExpiresAt: expiry,
	}
	perpetual := meta.AccessToken{
		ID: "tok-perpetual", Subject: "alice", Name: "admin",
		TokenHash: hash("perpetual"), CreatedAt: testTime,
	}
	for _, token := range []meta.AccessToken{expiring, perpetual} {
		if err := s.CreateAccessToken(ctx(), token); err != nil {
			t.Fatalf("CreateAccessToken(%s): %v", token.ID, err)
		}
	}

	if _, err := s.GetAccessTokenByHash(ctx(), hash("expiring"), expiry.Add(-time.Second)); err != nil {
		t.Errorf("token rejected before its expiry: %v", err)
	}
	_, err := s.GetAccessTokenByHash(ctx(), hash("expiring"), expiry)
	requireErrIs(t, err, meta.ErrNotFound, "GetAccessTokenByHash at expiry")

	// A zero expiry means no expiry, not "expired at the zero time".
	if _, err := s.GetAccessTokenByHash(ctx(), hash("perpetual"), expiry.Add(10*365*24*time.Hour)); err != nil {
		t.Errorf("token without an expiry was treated as expired: %v", err)
	}

	// Expired tokens still list, so an operator can see and clean them up.
	listed, err := s.ListAccessTokens(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListAccessTokens: %v", err)
	}
	if len(listed) != 2 {
		t.Errorf("got %d tokens, want both listed including the expired one", len(listed))
	}
	if listed[0].Name != "admin" || listed[1].Name != "ci" {
		t.Errorf("tokens = %+v, want them ordered by name", listed)
	}
}

func testAccessTokenIntegrity(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	valid := meta.AccessToken{ID: "tok-1", Subject: "alice", Name: "a", TokenHash: hash("one")}
	if err := s.CreateAccessToken(ctx(), valid); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	tests := []struct {
		name  string
		token meta.AccessToken
		want  error
	}{
		{"duplicate id", meta.AccessToken{ID: "tok-1", Subject: "alice", TokenHash: hash("two")}, meta.ErrConflict},
		{
			// Two records with the same digest would make authentication
			// ambiguous: whichever the store happened to return would win.
			name:  "duplicate hash",
			token: meta.AccessToken{ID: "tok-2", Subject: "alice", TokenHash: hash("one")},
			want:  meta.ErrConflict,
		},
		{"empty id", meta.AccessToken{Subject: "alice", TokenHash: hash("three")}, meta.ErrInvalid},
		{"empty hash", meta.AccessToken{ID: "tok-3", Subject: "alice"}, meta.ErrInvalid},
		{"missing subject", meta.AccessToken{ID: "tok-4", Subject: "ghost", TokenHash: hash("four")}, meta.ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireErrIs(t, s.CreateAccessToken(ctx(), tt.token), tt.want, "CreateAccessToken")
		})
	}

	_, err := s.GetAccessTokenByHash(ctx(), nil, testTime)
	requireErrIs(t, err, meta.ErrInvalid, "GetAccessTokenByHash with an empty hash")

	_, err = s.ListAccessTokens(ctx(), "ghost")
	requireErrIs(t, err, meta.ErrNotFound, "ListAccessTokens for a missing subject")
}

func testSessions(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	session := meta.Session{
		ID:                "sess-1",
		Subject:           "alice",
		CSRFToken:         "csrf-value",
		CreatedAt:         testTime,
		IdleExpiresAt:     testTime.Add(24 * time.Hour),
		AbsoluteExpiresAt: testTime.Add(7 * 24 * time.Hour),
	}
	if err := s.CreateSession(ctx(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := s.GetSession(ctx(), "sess-1", testTime)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.CSRFToken != "csrf-value" || got.Subject != "alice" {
		t.Errorf("session = %+v, want it to round-trip", got)
	}

	tests := []struct {
		name    string
		session meta.Session
		want    error
	}{
		{"duplicate id", session, meta.ErrConflict},
		{
			name:    "no csrf token",
			session: meta.Session{ID: "s2", Subject: "alice", IdleExpiresAt: testTime, AbsoluteExpiresAt: testTime},
			want:    meta.ErrInvalid,
		},
		{
			name:    "no expiry bounds",
			session: meta.Session{ID: "s3", Subject: "alice", CSRFToken: "c"},
			want:    meta.ErrInvalid,
		},
		{"empty id", meta.Session{Subject: "alice", CSRFToken: "c", IdleExpiresAt: testTime, AbsoluteExpiresAt: testTime}, meta.ErrInvalid},
		{
			name:    "missing subject",
			session: meta.Session{ID: "s4", Subject: "ghost", CSRFToken: "c", IdleExpiresAt: testTime, AbsoluteExpiresAt: testTime},
			want:    meta.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireErrIs(t, s.CreateSession(ctx(), tt.session), tt.want, "CreateSession")
		})
	}

	if err := s.DeleteSession(ctx(), "sess-1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	requireErrIs(t, s.DeleteSession(ctx(), "sess-1"), meta.ErrNotFound, "DeleteSession twice")
	requireErrIs(t, s.RefreshSession(ctx(), "sess-1", testTime), meta.ErrNotFound, "RefreshSession on a missing session")
}

func testSessionExpiryBounds(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	idle := testTime.Add(time.Hour)
	absolute := testTime.Add(24 * time.Hour)
	if err := s.CreateSession(ctx(), meta.Session{
		ID: "sess-1", Subject: "alice", CSRFToken: "c",
		CreatedAt: testTime, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := s.GetSession(ctx(), "sess-1", idle.Add(-time.Second)); err != nil {
		t.Errorf("live session rejected: %v", err)
	}

	// Either bound ends the session, and an expired one is indistinguishable
	// from one that never existed.
	_, err := s.GetSession(ctx(), "sess-1", idle)
	requireErrIs(t, err, meta.ErrNotFound, "GetSession past the idle bound")

	// Refreshing revives it, because only the idle bound had passed.
	if err := s.RefreshSession(ctx(), "sess-1", absolute.Add(-time.Minute)); err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if _, err := s.GetSession(ctx(), "sess-1", idle.Add(time.Minute)); err != nil {
		t.Errorf("refreshed session still rejected: %v", err)
	}

	// The absolute bound cannot be escaped by refreshing.
	_, err = s.GetSession(ctx(), "sess-1", absolute)
	requireErrIs(t, err, meta.ErrNotFound, "GetSession past the absolute bound")

	removed, err := s.DeleteExpiredSessions(ctx(), absolute.Add(time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if removed != 1 {
		t.Errorf("pruned %d sessions, want 1", removed)
	}
}

func testSessionRefreshCannotOutliveAbsoluteBound(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)

	absolute := testTime.Add(24 * time.Hour)
	if err := s.CreateSession(ctx(), meta.Session{
		ID: "sess-1", Subject: "alice", CSRFToken: "c",
		CreatedAt: testTime, IdleExpiresAt: testTime.Add(time.Hour), AbsoluteExpiresAt: absolute,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Asking for an idle bound beyond the absolute one clamps rather than
	// extends: otherwise a session that is used regularly never ends, which
	// is exactly what the absolute bound exists to prevent.
	if err := s.RefreshSession(ctx(), "sess-1", absolute.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	_, err := s.GetSession(ctx(), "sess-1", absolute)
	requireErrIs(t, err, meta.ErrNotFound, "GetSession past the absolute bound after a long refresh")
}

func testDeletingSubjectRemovesItsSecrets(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)
	mustCreateSubject(t, s, "bob", meta.User)

	for _, subject := range []string{"alice", "bob"} {
		if err := s.PutUserCredential(ctx(), meta.UserCredential{Subject: subject, Hash: "$argon2id$" + subject}); err != nil {
			t.Fatalf("PutUserCredential(%s): %v", subject, err)
		}
		if err := s.CreateAccessToken(ctx(), meta.AccessToken{
			ID: "tok-" + subject, Subject: subject, Name: "cli", TokenHash: hash(subject),
		}); err != nil {
			t.Fatalf("CreateAccessToken(%s): %v", subject, err)
		}
		if err := s.CreateSession(ctx(), meta.Session{
			ID: "sess-" + subject, Subject: subject, CSRFToken: "c",
			IdleExpiresAt: testTime.Add(time.Hour), AbsoluteExpiresAt: testTime.Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("CreateSession(%s): %v", subject, err)
		}
	}

	if err := s.DeleteSubject(ctx(), "alice"); err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}

	// A credential outliving its subject is a usable secret belonging to
	// nobody.
	if _, err := s.GetUserCredential(ctx(), "alice"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("password verifier survived its subject: %v", err)
	}
	if _, err := s.GetAccessTokenByHash(ctx(), hash("alice"), testTime); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("access token survived its subject: %v", err)
	}
	if _, err := s.GetSession(ctx(), "sess-alice", testTime); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("session survived its subject: %v", err)
	}

	// Bob is untouched.
	if _, err := s.GetUserCredential(ctx(), "bob"); err != nil {
		t.Errorf("deleting alice removed bob's credential: %v", err)
	}
	if _, err := s.GetSession(ctx(), "sess-bob", testTime); err != nil {
		t.Errorf("deleting alice removed bob's session: %v", err)
	}

	// Ending every session for a subject is what a password change calls, so
	// a stolen session cannot outlive the credential it came from.
	removed, err := s.DeleteSubjectSessions(ctx(), "bob")
	if err != nil {
		t.Fatalf("DeleteSubjectSessions: %v", err)
	}
	if removed != 1 {
		t.Errorf("ended %d sessions, want 1", removed)
	}
	if _, err := s.GetSession(ctx(), "sess-bob", testTime); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("session survived DeleteSubjectSessions: %v", err)
	}

	// Ending sessions for a subject with none is not an error.
	if removed, err := s.DeleteSubjectSessions(ctx(), "bob"); err != nil || removed != 0 {
		t.Errorf("DeleteSubjectSessions (empty) = %d, %v; want 0, nil", removed, err)
	}
}
