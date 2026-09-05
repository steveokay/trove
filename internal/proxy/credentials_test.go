package proxy_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/secretbox"
)

// The credential this file writes and then hunts for. Both halves are
// distinctive, so finding either in an error message is unambiguous.
const (
	credentialUser = "robot$upstream"
	credentialPass = "correct-horse-battery-staple-4471"
)

var credentialTime = time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)

// credentialFixture is a store holding two proxy repositories and the keyring
// their credentials are sealed with.
type credentialFixture struct {
	store *memory.Store
	keys  *secretbox.Keyring
}

func newCredentialFixture(t *testing.T, repositories ...string) credentialFixture {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	for _, name := range repositories {
		if _, err := store.CreateRepository(context.Background(), meta.Repository{
			Name: name, Type: meta.Proxy, CreatedAt: credentialTime, UpdatedAt: credentialTime,
		}); err != nil {
			t.Fatalf("CreateRepository(%q): %v", name, err)
		}
	}

	key, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring, err := secretbox.NewKeyring(key)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return credentialFixture{store: store, keys: ring}
}

// seal writes a credential for one repository and returns the stored value.
func (f credentialFixture) seal(t *testing.T, repository, username, password string) string {
	t.Helper()

	sealed, err := proxy.SealCredential(f.keys, repository, username, password)
	if err != nil {
		t.Fatalf("SealCredential(%q): %v", repository, err)
	}
	if err := f.store.PutProxyCredential(context.Background(), meta.ProxyCredential{
		Repository: repository, Sealed: sealed, RotatedAt: credentialTime,
	}); err != nil {
		t.Fatalf("PutProxyCredential(%q): %v", repository, err)
	}
	return sealed
}

func (f credentialFixture) credentials(repository string) proxy.StoredCredentials {
	return proxy.StoredCredentials{Repository: repository, Store: f.store, Keys: f.keys}
}

// The round trip: what the admin API seals is what the upstream client
// presents, and it satisfies the frozen Credentials interface.
func TestStoredCredentialsRoundTrip(t *testing.T) {
	t.Parallel()

	f := newCredentialFixture(t, "mirror")
	sealed := f.seal(t, "mirror", credentialUser, credentialPass)

	if !strings.HasPrefix(sealed, secretbox.Version+":") {
		t.Errorf("sealed value = %q, want the %s: prefix ADR 0016 specifies", sealed, secretbox.Version)
	}
	if strings.Contains(sealed, credentialUser) || strings.Contains(sealed, credentialPass) {
		t.Fatalf("the sealed value contains its own plaintext: %q", sealed)
	}

	var creds proxy.Credentials = f.credentials("mirror")
	username, password, err := creds.Basic(t.Context())
	if err != nil {
		t.Fatalf("Basic: %v", err)
	}
	if username != credentialUser || password != credentialPass {
		t.Errorf("Basic() = (%q, %q), want the pair that was sealed", username, password)
	}
}

// The AAD test. A ciphertext is bound to the repository it was sealed for, so
// a row lifted into another repository fails to open rather than
// authenticating that repository's upstream with somebody else's password --
// which is the whole reason the context exists (ADR 0016).
func TestStoredCredentialsAreBoundToTheirRepository(t *testing.T) {
	t.Parallel()

	f := newCredentialFixture(t, "alpha", "beta")
	stolen := f.seal(t, "alpha", credentialUser, credentialPass)

	// Exactly the attack: alpha's bytes, written verbatim into beta's row, by
	// somebody who reached the database directly.
	if err := f.store.PutProxyCredential(t.Context(), meta.ProxyCredential{
		Repository: "beta", Sealed: stolen, RotatedAt: credentialTime,
	}); err != nil {
		t.Fatalf("PutProxyCredential(beta): %v", err)
	}

	// alpha still opens: the row is intact, and the failure below is the
	// binding rather than a corrupted value.
	if _, _, err := f.credentials("alpha").Basic(t.Context()); err != nil {
		t.Fatalf("alpha's own credential: %v", err)
	}

	username, password, err := f.credentials("beta").Basic(t.Context())
	if err == nil {
		t.Fatalf("beta opened alpha's ciphertext and got (%q, %q)", username, password)
	}
	if username != "" || password != "" {
		t.Errorf("a failed open returned (%q, %q), want empty strings", username, password)
	}
	if !errors.Is(err, secretbox.ErrAuthentication) {
		t.Errorf("error = %v, want errors.Is(err, secretbox.ErrAuthentication)", err)
	}
	if !errors.Is(err, proxy.ErrCredentialUnavailable) {
		t.Errorf("error = %v, want errors.Is(err, proxy.ErrCredentialUnavailable)", err)
	}
	requireNoSecret(t, "the AAD failure", err.Error())
}

// A missing credential is an error, never a silent downgrade to anonymous:
// proceeding without one turns a revoked row into a 404 from the upstream, and
// the operator then debugs the wrong system entirely.
func TestStoredCredentialsRefuseToDowngrade(t *testing.T) {
	t.Parallel()

	f := newCredentialFixture(t, "mirror")

	username, password, err := f.credentials("mirror").Basic(t.Context())
	if err == nil {
		t.Fatalf("an unset credential produced (%q, %q) and no error", username, password)
	}
	if username != "" || password != "" {
		t.Errorf("Basic() = (%q, %q), want empty strings", username, password)
	}
	if !errors.Is(err, proxy.ErrCredentialUnavailable) {
		t.Errorf("error = %v, want errors.Is(err, proxy.ErrCredentialUnavailable)", err)
	}
	// The underlying cause is reachable, so a caller can tell "nobody set one"
	// from "the key is gone".
	if !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("error = %v, want errors.Is(err, meta.ErrNotFound)", err)
	}
}

// Every failure names the repository and none names the secret. These are the
// messages that end up in the log line of a failing pull, which is the
// most-read place in the system.
func TestStoredCredentialErrorsNameTheRepositoryAndNothingElse(t *testing.T) {
	t.Parallel()

	f := newCredentialFixture(t, "mirror")

	// A value sealed under a key this keyring does not hold: the retired-line
	// case ADR 0016 warns about.
	other := newCredentialFixture(t, "mirror")
	foreign, err := proxy.SealCredential(other.keys, "mirror", credentialUser, credentialPass)
	if err != nil {
		t.Fatalf("SealCredential: %v", err)
	}
	// A value this keyring's key produced, with one payload byte changed:
	// tampering, which GCM catches.
	valid, err := proxy.SealCredential(f.keys, "mirror", credentialUser, credentialPass)
	if err != nil {
		t.Fatalf("SealCredential: %v", err)
	}
	// The first payload character, which is part of the nonce: changing it
	// keeps the value canonical base64 (padding bits live in the last quantum)
	// while guaranteeing the open fails.
	const payloadStart = len(secretbox.Version) + 1 + secretbox.KeyIDLength + 1
	tampered := valid[:payloadStart] + flipBase64(valid[payloadStart:payloadStart+1]) + valid[payloadStart+1:]

	tests := []struct {
		what   string
		sealed string
		is     error
	}{
		{"a value from another keyring", foreign, secretbox.ErrUnknownKey},
		{"a tampered value", tampered, secretbox.ErrAuthentication},
		{"a value in no known format", credentialPass, secretbox.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.what, func(t *testing.T) {
			if err := f.store.PutProxyCredential(t.Context(), meta.ProxyCredential{
				Repository: "mirror", Sealed: tt.sealed, RotatedAt: credentialTime,
			}); err != nil {
				t.Fatalf("PutProxyCredential: %v", err)
			}

			_, _, err := f.credentials("mirror").Basic(t.Context())
			if !errors.Is(err, proxy.ErrCredentialUnavailable) {
				t.Fatalf("error = %v, want ErrCredentialUnavailable", err)
			}
			if !errors.Is(err, tt.is) {
				t.Errorf("error = %v, want errors.Is(err, %v)", err, tt.is)
			}
			if !strings.Contains(err.Error(), `"mirror"`) {
				t.Errorf("error = %q, want it to name the repository", err)
			}
			requireNoSecret(t, tt.what, err.Error(), tt.sealed, foreign, valid)
		})
	}
}

// flipBase64 changes a single standard-base64 character to a different one, so
// the decoded payload differs by a byte and still parses as canonical base64.
func flipBase64(s string) string {
	if s == "A" {
		return "B"
	}
	return "A"
}

// A decrypted value that is not a credential pair. The unmarshal error is
// dropped rather than wrapped, because an unmarshal error quotes the input it
// choked on -- and the input here is a decrypted credential.
func TestStoredCredentialsRefuseANonPairPayload(t *testing.T) {
	t.Parallel()

	f := newCredentialFixture(t, "mirror")
	sealed, err := f.keys.Seal([]byte("["+credentialPass+"]"), secretbox.ProxyCredential("mirror"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := f.store.PutProxyCredential(t.Context(), meta.ProxyCredential{
		Repository: "mirror", Sealed: sealed, RotatedAt: credentialTime,
	}); err != nil {
		t.Fatalf("PutProxyCredential: %v", err)
	}

	_, _, err = f.credentials("mirror").Basic(t.Context())
	if !errors.Is(err, proxy.ErrCredentialUnavailable) {
		t.Fatalf("error = %v, want ErrCredentialUnavailable", err)
	}
	requireNoSecret(t, "a non-pair payload", err.Error())
}

// brokenReader stands in for a store that cannot answer.
type brokenReader struct{ err error }

func (b brokenReader) GetProxyCredential(context.Context, string) (meta.ProxyCredential, error) {
	return meta.ProxyCredential{}, b.err
}

// A store failure is not an unset credential: an outage must not quietly turn
// an authenticated proxy into an anonymous one.
func TestStoredCredentialsSurfaceAStoreFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the disk went away")
	creds := proxy.StoredCredentials{
		Repository: "mirror",
		Store:      brokenReader{err: sentinel},
		Keys:       newCredentialFixture(t).keys,
	}

	_, _, err := creds.Basic(t.Context())
	if !errors.Is(err, sentinel) || !errors.Is(err, proxy.ErrCredentialUnavailable) {
		t.Fatalf("error = %v, want both the store's error and ErrCredentialUnavailable", err)
	}
}

// The zero value fails closed rather than authenticating with nothing.
func TestStoredCredentialsZeroValueRefuses(t *testing.T) {
	t.Parallel()

	f := newCredentialFixture(t, "mirror")
	for _, tt := range []struct {
		what  string
		creds proxy.StoredCredentials
	}{
		{"no store and no keyring", proxy.StoredCredentials{Repository: "mirror"}},
		{"no keyring", proxy.StoredCredentials{Repository: "mirror", Store: f.store}},
		{"no store", proxy.StoredCredentials{Repository: "mirror", Keys: f.keys}},
	} {
		if _, _, err := tt.creds.Basic(t.Context()); !errors.Is(err, proxy.ErrCredentialUnavailable) {
			t.Errorf("%s: error = %v, want ErrCredentialUnavailable", tt.what, err)
		}
	}
}

// Sealing refuses without key material, for the same reason opening does: a
// deployment with no keyring must not store a password in the clear.
func TestSealCredentialRefusesWithoutAKeyring(t *testing.T) {
	t.Parallel()

	sealed, err := proxy.SealCredential(nil, "mirror", credentialUser, credentialPass)
	if sealed != "" {
		t.Errorf("SealCredential returned %q with no keyring", sealed)
	}
	if !errors.Is(err, proxy.ErrCredentialUnavailable) || !errors.Is(err, secretbox.ErrNoKey) {
		t.Fatalf("error = %v, want ErrCredentialUnavailable wrapping ErrNoKey", err)
	}
	requireNoSecret(t, "a keyless seal", err.Error())

	// A keyring that holds no keys is the same situation arriving by another
	// route, and the message must still be clean.
	empty := &secretbox.Keyring{}
	if _, err := proxy.SealCredential(empty, "mirror", credentialUser, credentialPass); err == nil {
		t.Error("an empty keyring sealed a credential")
	} else {
		requireNoSecret(t, "an empty-keyring seal", err.Error())
	}
}

// requireNoSecret asserts that a rendered message carries no part of the
// credential, plus any ciphertexts the caller had in play.
//
// It does not scan for a bare "v1:" the way the HTTP probes do: a message here
// may legitimately quote the *format* ("want v1:<key-id>:<base64>") while
// carrying none of the value, and rejecting that would push the code towards a
// less useful error rather than a safer one. The ciphertexts are named
// explicitly instead, which is the stronger check anyway.
func requireNoSecret(t *testing.T, where, rendered string, ciphertexts ...string) {
	t.Helper()

	forbidden := []struct{ what, value string }{
		{"the password", credentialPass},
		{"the username", credentialUser},
	}
	for _, ciphertext := range ciphertexts {
		forbidden = append(forbidden, struct{ what, value string }{"a sealed value", ciphertext})
	}
	for _, f := range forbidden {
		if f.value != "" && strings.Contains(rendered, f.value) {
			t.Errorf("%s rendered %s: %q", where, f.what, rendered)
		}
	}
}
