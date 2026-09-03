// Package privesc is the living privilege-escalation suite (Z-019, §9).
//
// Every deliberate split in the permission vocabulary exists because
// collapsing it is a real incident class (ADR 0002), and every one of them is
// pinned here as a named regression: a binding that grants one side must not
// admit the other. The suite grows with the surfaces -- scenarios that need
// handlers land with those handlers -- and its cross-check reads the ADR
// itself, so documenting a new non-implication without testing it fails CI.
package privesc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authn/token"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/secretbox"
	"github.com/steveokay/trove/internal/server"
)

// nonImplications is the test's own list of ADR 0002's deliberate splits.
// TestNonImplicationListMatchesTheADR holds it equal to the document, so the
// two cannot drift apart in either direction.
var nonImplications = []struct {
	held   authz.Verb
	denied []authz.Verb
}{
	{authz.RepoWrite, []authz.Verb{authz.RepoDelete, authz.TagDelete, authz.ManifestDelete}},
	{authz.RepoConfigure, []authz.Verb{authz.RepoDelete, authz.RepoWrite}},
	{authz.PolicyWrite, []authz.Verb{authz.PolicyApply}},
	{authz.ProxyWrite, []authz.Verb{authz.ProxyCredentials}},
	{authz.WebhookWrite, []authz.Verb{authz.RepoRead}},
	{authz.ReferrerRead, []authz.Verb{authz.RepoRead}},
}

// TestNonImplications pins each split at the decision itself: a subject
// granted exactly the held verb -- at every scope shape at once, so no scope
// is the loophole -- is refused each verb the ADR says must not follow.
func TestNonImplications(t *testing.T) {
	t.Parallel()

	repo, err := authz.Repository("team-a/api")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	resources := map[string]authz.Resource{
		"repository": repo,
		"system":     authz.System(),
	}

	for _, tt := range nonImplications {
		t.Run(string(tt.held), func(t *testing.T) {
			t.Parallel()

			bindings := []authz.Binding{
				{ID: "b-star", Role: "held", Scope: "*", Verbs: []authz.Verb{tt.held}},
				{ID: "b-system", Role: "held", Scope: "system", Verbs: []authz.Verb{tt.held}},
			}

			// The held verb really is held -- a suite that only checks
			// refusals would pass against a broken Decide too.
			heldSomewhere := false
			for _, resource := range resources {
				if authz.Allows(bindings, tt.held, resource) {
					heldSomewhere = true
				}
			}
			if !heldSomewhere {
				t.Fatalf("%s is not granted anywhere; the fixture is broken", tt.held)
			}

			for _, denied := range tt.denied {
				for name, resource := range resources {
					if authz.Allows(bindings, denied, resource) {
						t.Errorf("%s implied %s on the %s resource", tt.held, denied, name)
					}
				}
			}
		})
	}
}

// gate:override is implied by nothing (ADR 0002): a custom role shaped like
// admin -- every verb except the override -- still cannot cross a gate, and
// among the built-ins only the two whose definitions say "everything" hold it.
func TestGateOverrideIsImpliedByNothing(t *testing.T) {
	t.Parallel()

	var everythingElse []authz.Verb
	for _, verb := range authz.AllVerbs() {
		if verb != authz.GateOverride {
			everythingElse = append(everythingElse, verb)
		}
	}
	bindings := []authz.Binding{
		{ID: "b-star", Role: "almost-admin", Scope: "*", Verbs: everythingElse},
		{ID: "b-system", Role: "almost-admin", Scope: "system", Verbs: everythingElse},
	}
	repo, err := authz.Repository("team-a/api")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	for name, resource := range map[string]authz.Resource{"repository": repo, "system": authz.System()} {
		if authz.Allows(bindings, authz.GateOverride, resource) {
			t.Errorf("every-verb-but-one implied gate:override on the %s resource", name)
		}
	}

	for _, role := range authz.BuiltinRoles() {
		holds := role.Grants(authz.GateOverride)
		wants := role.Name == authz.RoleAdmin || role.Name == authz.RoleOperator
		if holds != wants {
			t.Errorf("built-in %q holds gate:override = %v, want %v", role.Name, holds, wants)
		}
	}
}

// TestNonImplicationListMatchesTheADR reads ADR 0002's non-implication
// section and holds this suite to it: a split documented there without a
// subtest here fails, and so does a subtest for a split the ADR no longer
// claims. The two prose-only entries -- gate:override (its own test above)
// and webhook event delivery (E-004's behaviour, pinned here at verb level)
// -- are carried explicitly.
func TestNonImplicationListMatchesTheADR(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "adr", "0002-permission-vocabulary.md"))
	if err != nil {
		t.Fatalf("read ADR 0002: %v", err)
	}
	_, section, found := strings.Cut(string(raw), "### Deliberate non-implications")
	if !found {
		t.Fatal("ADR 0002 no longer has a non-implication section")
	}
	section, _, _ = strings.Cut(section, "### ")

	// Each bullet reads "`held` ↛ `a`, `b`" (possibly with a second "and ↛"
	// clause). The two prose bullets carry no arrow pairs and are covered by
	// their own tests.
	pair := regexp.MustCompile("`([a-z]+:[a-z]+)`")
	documented := map[string][]string{}
	for line := range strings.SplitSeq(section, "\n- ") {
		if !strings.Contains(line, "↛") {
			continue
		}
		verbs := pair.FindAllStringSubmatch(line, -1)
		if len(verbs) < 2 {
			continue
		}
		held := verbs[0][1]
		for _, denied := range verbs[1:] {
			documented[held] = append(documented[held], denied[1])
		}
	}
	if len(documented) == 0 {
		t.Fatal("parsed no pairs from the ADR; the format changed and this check went blind")
	}

	tested := map[string]map[string]bool{}
	for _, tt := range nonImplications {
		set := map[string]bool{}
		for _, denied := range tt.denied {
			set[string(denied)] = true
		}
		tested[string(tt.held)] = set
	}
	// The webhook and referrer bullets state behaviours in prose ("receiving
	// events", "grants nothing without") rather than as arrow pairs, so the
	// parser cannot lift them; their verb-level halves are recorded here --
	// but only while the ADR still carries the bullet, so deleting one there
	// still flags the orphaned subtest.
	for held, verbLevel := range map[string][]string{
		"webhook:write": {"repo:read"},
		"referrer:read": {"repo:read"},
	} {
		if strings.Contains(section, "`"+held+"`") {
			documented[held] = verbLevel
		}
	}

	for held, want := range documented {
		set := tested[held]
		if set == nil {
			t.Errorf("ADR 0002 documents %q as non-implying; this suite has no subtest for it", held)
			continue
		}
		for _, denied := range want {
			if !set[denied] {
				t.Errorf("ADR 0002 documents %s ↛ %s; this suite does not test it", held, denied)
			}
		}
	}
	for held := range tested {
		if _, ok := documented[held]; !ok {
			t.Errorf("this suite tests %q, which ADR 0002 no longer documents -- update one of them", held)
		}
	}
}

// TestRobotCannotCrossRepositories drives the §9 scenario through the real
// stack: a robot scoped to one subtree authenticates with its real secret and
// is refused everywhere else -- with the not-found answer, because an
// unreadable repository must look absent (ADR 0003).
func TestRobotCannotCrossRepositories(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	if err := store.CreateSubject(ctx, meta.Subject{ID: "r-ci", Kind: meta.Robot, Name: "robot$ci"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "reader", Verbs: []string{"repo:read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "b-ci", PrincipalKind: meta.PrincipalSubject, PrincipalID: "r-ci",
		Role: "reader", Scope: "team-a/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	key, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring, err := secretbox.NewKeyring(key)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	robots := authn.NewRobotSecrets(store, ring, nil, nil)
	secret, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	router := server.NewRouter(&server.Guard{
		Subjects: store, Bindings: store,
		Credentials: server.BasicAuth(login, robots),
	})
	router.HandleFunc(http.MethodGet, "/api/v1/repos/{name...}", server.Permission{
		Verb: authz.RepoRead,
		Resource: func(r *http.Request) (authz.Resource, error) {
			return authz.Repository(r.PathValue("name"))
		},
	}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	read := func(repo string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/repos/"+repo, nil)
		req.SetBasicAuth("robot$ci", secret)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := read("team-a/api"); rec.Code != http.StatusOK {
		t.Fatalf("in-scope read: %d, want 200", rec.Code)
	}
	if rec := read("team-b/api"); rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope read: %d, want 404: crossing must look like absence", rec.Code)
	}
}

// TestTokenReplayAfterRevocation is the §9 scenario: a cryptographically
// valid JWT whose binding has since been revoked must fail at the handler --
// the token names the subject, the bindings are the authority, and revocation
// takes effect within one request rather than one token lifetime (ADR 0004).
func TestTokenReplayAfterRevocation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	if err := store.CreateSubject(ctx, meta.Subject{ID: "u-alice", Kind: meta.User, Name: "alice"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	hash, err := authn.NewHasher().Hash("sesame")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.PutUserCredential(ctx, meta.UserCredential{Subject: "alice", Hash: hash}); err != nil {
		t.Fatalf("PutUserCredential: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "reader", Verbs: []string{"repo:read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "b-alice", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-alice",
		Role: "reader", Scope: "team-a/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := token.NewSigner(signingKey, 0, nil, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	credentials := server.Bearer(signer, server.BasicAuth(login, nil))
	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store, Credentials: credentials})
	(&server.TokenEndpoint{
		Credentials: credentials, Subjects: store, Bindings: store, Signer: signer,
	}).Register(router)
	router.HandleFunc(http.MethodGet, "/api/v1/repos/{name...}", server.Permission{
		Verb: authz.RepoRead,
		Resource: func(r *http.Request) (authz.Resource, error) {
			return authz.Repository(r.PathValue("name"))
		},
	}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	mint := httptest.NewRequest(http.MethodGet, "/token?scope=repository:team-a/api:pull", nil)
	mint.SetBasicAuth("alice", "sesame")
	minted := httptest.NewRecorder()
	router.ServeHTTP(minted, mint)
	if minted.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", minted.Code, minted.Body)
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(minted.Body.Bytes(), &response); err != nil || response.Token == "" {
		t.Fatalf("token response: %v (%s)", err, minted.Body)
	}

	read := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/repos/team-a/api", nil)
		req.Header.Set("Authorization", "Bearer "+response.Token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := read(); rec.Code != http.StatusOK {
		t.Fatalf("read before revocation: %d, want 200", rec.Code)
	}
	if err := store.DeleteBinding(ctx, "b-alice"); err != nil {
		t.Fatalf("DeleteBinding: %v", err)
	}
	if rec := read(); rec.Code != http.StatusNotFound {
		t.Fatalf("replay after revocation: %d, want 404 -- the token carries the scope, the bindings are the authority", rec.Code)
	}
}

// repositoryRoot walks up to the module root, so the suite can read the ADRs
// and status.md it ratchets against.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
