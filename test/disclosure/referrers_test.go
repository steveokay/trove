package disclosure

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// Surface 3: referrers listings.
//
// A referrer inherits the permission of the artifact it attaches to, so
// referrer:read on its own lists nothing: reading an SBOM, a signature, or a
// scan attestation additionally requires repo:read on the repository holding
// its subject (ADR 0002, ADR 0003 surface 3). This file walks that end to end
// -- the real guard in front of the real handler -- because the check lives in
// the handler rather than in the route table, and a check in a handler is the
// kind that gets dropped in a refactor.

// referrersSBOMType is the attachment the tests hide and reveal.
const referrersSBOMType = "application/spdx+json"

// referrersDisclosureFixture extends the suite's fixture with the two subjects
// this surface needs, and with real content in a repository nobody but root
// can read.
type referrersDisclosureFixture struct {
	fixture
	router  *server.Router
	imageDg string
	sbomDg  string
}

func referrersNewFixture(t *testing.T) referrersDisclosureFixture {
	t.Helper()

	f := newFixture(t)
	ctx := context.Background()

	for _, subject := range []meta.Subject{
		// Holds referrer:read everywhere and repo:read nowhere: the verb that
		// names the endpoint, without the permission on the subject artifact.
		{ID: "u-peeker", Kind: meta.User, Name: "peeker"},
		// Holds both, within carol's subtree.
		{ID: "u-sbomreader", Kind: meta.User, Name: "sbomreader"},
	} {
		if err := f.store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	for _, role := range []meta.Role{
		{Name: "referrer-only", Verbs: []string{"referrer:read"}},
		{Name: "referrer-reader", Verbs: []string{"repo:read", "referrer:read"}},
	} {
		if err := f.store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-peeker", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-peeker",
			Role: "referrer-only", Scope: "*"},
		{ID: "b-sbomreader", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-sbomreader",
			Role: "referrer-reader", Scope: "team-a/*"},
	} {
		if err := f.store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}

	// The same image with the same SBOM in both a readable and an unreadable
	// repository, so the two answers differ only by permission.
	image := `{"schemaVersion":2,"mediaType":"` + artifact.MediaTypeOCIManifest + `","config":{},"layers":[]}`
	imageDg := blob.FromBytes(blob.SHA256, []byte(image)).String()
	sbom := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"artifactType":%q,"subject":{"digest":%q}}`,
		artifact.MediaTypeOCIManifest, referrersSBOMType, imageDg)
	sbomDg := blob.FromBytes(blob.SHA256, []byte(sbom)).String()

	for _, repo := range []string{"team-a/api", "secret/vault"} {
		for _, record := range []meta.Manifest{
			{Repository: repo, Digest: meta.Digest(imageDg), MediaType: artifact.MediaTypeOCIManifest,
				Payload: []byte(image), Size: int64(len(image))},
			{Repository: repo, Digest: meta.Digest(sbomDg), MediaType: artifact.MediaTypeOCIManifest,
				ArtifactType: referrersSBOMType, Subject: meta.Digest(imageDg),
				Payload: []byte(sbom), Size: int64(len(sbom))},
		} {
			if err := f.store.PutManifest(ctx, record, nil); err != nil {
				t.Fatalf("PutManifest: %v", err)
			}
		}
	}

	// The suite's fixture guard speaks problem+json; the /v2/ tree speaks the
	// distribution envelope, and the byte-identity claim below is about the
	// bytes clients actually receive (ADR 0015).
	router := server.NewRouter(&server.Guard{
		Subjects: f.store,
		Bindings: f.store,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Referrers{Meta: f.store, Bindings: f.store}).Register(router)

	return referrersDisclosureFixture{fixture: f, router: router, imageDg: imageDg, sbomDg: sbomDg}
}

func (f referrersDisclosureFixture) get(t *testing.T, as, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// Surface 3, the §9 case: an SBOM attached to an image the subject cannot
// read. The listing must not merely omit the attachment -- that would still
// admit the repository exists -- but answer exactly what a repository that was
// never created answers, byte for byte, headers included.
func TestSurfaceReferrers(t *testing.T) {
	t.Parallel()
	f := referrersNewFixture(t)

	hidden := f.get(t, "peeker", "/v2/secret/vault/referrers/"+f.imageDg)
	absent := f.get(t, "peeker", "/v2/secret/absent/referrers/"+f.imageDg)

	if hidden.Code != http.StatusNotFound {
		t.Fatalf("referrers of an unreadable image: %d %s, want 404", hidden.Code, hidden.Body)
	}
	if strings.Contains(hidden.Body.String(), f.sbomDg) || strings.Contains(hidden.Body.String(), "vault") {
		t.Fatalf("the refusal describes what it is hiding: %s", hidden.Body)
	}
	if hidden.Code != absent.Code || hidden.Body.String() != absent.Body.String() {
		t.Fatalf("hidden: %d %s\nabsent: %d %s\nwant byte-identical answers",
			hidden.Code, hidden.Body, absent.Code, absent.Body)
	}
	if fmt.Sprint(hidden.Header()) != fmt.Sprint(absent.Header()) {
		t.Fatalf("headers differ between hidden and absent: %v vs %v", hidden.Header(), absent.Header())
	}

	// The same request where the subject does hold repo:read lists the
	// attachment, which is what makes the refusal above a permission decision
	// rather than a missing route.
	readable := f.get(t, "sbomreader", "/v2/team-a/api/referrers/"+f.imageDg)
	if readable.Code != http.StatusOK || !strings.Contains(readable.Body.String(), f.sbomDg) {
		t.Fatalf("readable listing: %d %s, want the SBOM", readable.Code, readable.Body)
	}

	// carol reads team-a/* but holds no referrer:read: readability already
	// disclosed the repository, so she gets the helpful 403 instead.
	denied := f.get(t, "carol", "/v2/team-a/api/referrers/"+f.imageDg)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("repo:read without referrer:read: %d %s, want 403", denied.Code, denied.Body)
	}
}
