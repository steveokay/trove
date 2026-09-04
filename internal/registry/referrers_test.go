package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// The referrers fixture adds two subjects to the shared stack, because none of
// carol, rita or mona holds referrer:read:
//
//   - sam holds referrer:read *and* repo:read on team-a/* -- the pair the
//     conjunction demands, and the only combination that lists anything.
//   - peek holds referrer:read everywhere and repo:read nowhere. That is the
//     §9 case: the verb that names the endpoint, without the permission on the
//     artifact the attachments hang off.
func referrersSeedIdentities(t *testing.T, s stack) {
	t.Helper()

	ctx := context.Background()
	for _, subject := range []meta.Subject{
		{ID: "u-sam", Kind: meta.User, Name: "sam"},
		{ID: "u-peek", Kind: meta.User, Name: "peek"},
	} {
		if err := s.metaDB.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	for _, role := range []meta.Role{
		{Name: "referrers-reader", Verbs: []string{"repo:read", "referrer:read"}},
		{Name: "referrers-peeker", Verbs: []string{"referrer:read"}},
	} {
		if err := s.metaDB.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-referrers-sam", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-sam",
			Role: "referrers-reader", Scope: "team-a/*"},
		// An entity that does not exist, so sam's refusal there comes from the
		// handler resolving the name rather than from the guard.
		{ID: "b-referrers-sam-ghost", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-sam",
			Role: "referrers-reader", Scope: "ghost/*"},
		{ID: "b-referrers-peek", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-peek",
			Role: "referrers-peeker", Scope: "*"},
	} {
		if err := s.metaDB.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}
}

// referrersRouter rebuilds the fixture's route table with the referrers route
// on it. The stores are parameters so a rigged one can be handed to the
// handler under test while the guard keeps a working one -- otherwise every
// failure would be answered by the guard before the handler ran.
func referrersRouter(t *testing.T, s stack, content registry.ReferrerMeta, bindings server.BindingStore) stack {
	t.Helper()

	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Manifests{Meta: s.metaDB, Now: func() time.Time { return fixedTime }}).Register(router)
	(&registry.Referrers{Meta: content, Bindings: bindings}).Register(router)
	return stack{handler: router, metaDB: s.metaDB, blobs: s.blobs}
}

// referrersStack is the ordinary fixture: real stores, referrers route wired,
// image blobs seeded so manifests push.
func referrersStack(t *testing.T) stack {
	t.Helper()

	s := newStack(t)
	referrersSeedIdentities(t, s)
	seedImageBlobs(t, s)
	return referrersRouter(t, s, s.metaDB, s.metaDB)
}

// The artifact types the attachments below carry: an SBOM and a signature, the
// two things §1 says the referrers API exists for.
const (
	referrersSBOMType      = "application/spdx+json"
	referrersSignatureType = "application/vnd.dev.cosign.simplesigning.v1+json"
)

// referrersAnnotations is the annotation block one attachment carries, so the
// listing has something to lift out of a stored payload.
const referrersAnnotations = `"annotations": {"io.trove.generator": "sbom-gen", "org.opencontainers.image.created": "2026-09-03T12:00:00Z"}`

// referrersAttachment builds a manifest attached to a subject digest.
func referrersAttachment(artifactType, subjectDigest string, subjectSize int, extra ...string) string {
	fields := append([]string{fmt.Sprintf(`"artifactType": %q`, artifactType)}, extra...)
	fields = append(fields, fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
		artifact.MediaTypeOCIManifest, subjectDigest, subjectSize))
	return imageManifest(fields...)
}

// referrersFixtureContent pushes the image and its two attachments, returning
// the subject digest and the payloads, so a test can assert sizes and digests
// against what it actually pushed.
type referrersContent struct {
	image     string
	imageDg   string
	sbom      string
	sbomDg    string
	signature string
	sigDg     string
}

func referrersPushContent(t *testing.T, s stack) referrersContent {
	t.Helper()

	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)

	sbom := referrersAttachment(referrersSBOMType, imageDg, len(image), referrersAnnotations)
	sbomDg := putManifest(t, s, "carol", manifestDigest(sbom), artifact.MediaTypeOCIManifest, sbom)

	signature := referrersAttachment(referrersSignatureType, imageDg, len(image))
	sigDg := putManifest(t, s, "carol", manifestDigest(signature), artifact.MediaTypeOCIManifest, signature)

	return referrersContent{
		image: image, imageDg: imageDg,
		sbom: sbom, sbomDg: sbomDg,
		signature: signature, sigDg: sigDg,
	}
}

// referrersDecode reads the returned index, insisting on the spec's envelope.
func referrersDecode(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("referrers: %d %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != artifact.MediaTypeOCIIndex {
		t.Errorf("Content-Type = %q, want the image index type", got)
	}
	var index struct {
		SchemaVersion int              `json:"schemaVersion"`
		MediaType     string           `json:"mediaType"`
		Manifests     []map[string]any `json:"manifests"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &index); err != nil {
		t.Fatalf("decode index: %v (%s)", err, rec.Body)
	}
	if index.SchemaVersion != 2 || index.MediaType != artifact.MediaTypeOCIIndex {
		t.Errorf("index envelope = %d %q", index.SchemaVersion, index.MediaType)
	}
	return index.Manifests
}

// referrersByDigest keys the returned descriptors so assertions do not depend
// on the store's ordering.
func referrersByDigest(descriptors []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, descriptor := range descriptors {
		digest, _ := descriptor["digest"].(string)
		out[digest] = descriptor
	}
	return out
}

// The round trip: attach an SBOM and a signature to an image, then list them.
// Both come back as descriptors of the referring manifests -- media type,
// digest, size, artifact type, and the annotations the SBOM carries.
func TestReferrersAttachAndList(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.ReferrerRead)

	s := referrersStack(t)
	content := referrersPushContent(t, s)

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+content.imageDg, "sam", "")
	descriptors := referrersDecode(t, rec)
	if rec.Header().Get("OCI-Filters-Applied") != "" {
		t.Errorf("OCI-Filters-Applied set on an unfiltered listing")
	}
	if len(descriptors) != 2 {
		t.Fatalf("listed %d referrers, want the SBOM and the signature: %s", len(descriptors), rec.Body)
	}

	byDigest := referrersByDigest(descriptors)
	sbom, ok := byDigest[content.sbomDg]
	if !ok {
		t.Fatalf("the SBOM is missing from %s", rec.Body)
	}
	if sbom["mediaType"] != artifact.MediaTypeOCIManifest ||
		sbom["artifactType"] != referrersSBOMType ||
		sbom["size"] != float64(len(content.sbom)) {
		t.Errorf("SBOM descriptor = %v", sbom)
	}
	annotations, ok := sbom["annotations"].(map[string]any)
	if !ok || annotations["io.trove.generator"] != "sbom-gen" ||
		annotations["org.opencontainers.image.created"] != "2026-09-03T12:00:00Z" {
		t.Errorf("SBOM annotations = %v, want the pushed block", sbom["annotations"])
	}

	signature, ok := byDigest[content.sigDg]
	if !ok {
		t.Fatalf("the signature is missing from %s", rec.Body)
	}
	if signature["artifactType"] != referrersSignatureType ||
		signature["size"] != float64(len(content.signature)) {
		t.Errorf("signature descriptor = %v", signature)
	}
	// The signature manifest carries no annotations, so the field is absent
	// rather than an empty object a client would have to distinguish.
	if _, present := signature["annotations"]; present {
		t.Errorf("annotations rendered for a manifest that has none: %v", signature)
	}
}

// The artifactType filter narrows the listing, and says so: the header is set
// exactly when a filter was applied, including when it matched nothing, so a
// client can tell an empty result from an ignored parameter.
func TestReferrersArtifactTypeFilter(t *testing.T) {
	t.Parallel()

	s := referrersStack(t)
	content := referrersPushContent(t, s)
	target := "/v2/team-a/api/referrers/" + content.imageDg

	// The type is escaped, as a client must: an unescaped "+" in a query
	// string is a space, and "application/spdx json" matches nothing.
	matched := s.do(t, http.MethodGet, target+"?artifactType="+url.QueryEscape(referrersSBOMType), "sam", "")
	descriptors := referrersDecode(t, matched)
	if len(descriptors) != 1 || descriptors[0]["digest"] != content.sbomDg {
		t.Fatalf("filtered listing = %s, want the SBOM alone", matched.Body)
	}
	if matched.Header().Get("OCI-Filters-Applied") != "artifactType" {
		t.Errorf("OCI-Filters-Applied = %q on a filtered listing", matched.Header().Get("OCI-Filters-Applied"))
	}

	empty := s.do(t, http.MethodGet, target+"?artifactType=application/vnd.example.nothing", "sam", "")
	if got := referrersDecode(t, empty); len(got) != 0 {
		t.Fatalf("filter that matches nothing returned %v", got)
	}
	if empty.Header().Get("OCI-Filters-Applied") != "artifactType" {
		t.Errorf("a filter that matched nothing was still applied, but the header says otherwise")
	}

	unfiltered := s.do(t, http.MethodGet, target, "sam", "")
	if unfiltered.Header().Get("OCI-Filters-Applied") != "" {
		t.Errorf("OCI-Filters-Applied set without a filter")
	}
}

// The wire shape, byte for byte. Fixed content gives fixed digests, so the
// whole body is stable and a change to it is a change to the contract.
func TestReferrersGoldenIndex(t *testing.T) {
	t.Parallel()

	s := referrersStack(t)
	content := referrersPushContent(t, s)

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+content.imageDg, "sam", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("referrers: %d %s", rec.Code, rec.Body)
	}
	golden := filepath.Join("testdata", "referrers", "index.golden")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v", golden, err)
	}
	if rec.Body.String() != string(want) {
		t.Fatalf("referrers body\n got: %s\nwant: %s", rec.Body, want)
	}
}

// referrersEmptyIndex is what a subject with nothing attached answers.
const referrersEmptyIndex = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}` + "\n"

// A readable repository always answers an index, never a 404: a subject with
// no attachments and a digest that was never pushed are the same answer, which
// is both what the spec requires and what stops the endpoint being used to
// test for the existence of a digest.
func TestReferrersEmptyIndex(t *testing.T) {
	t.Parallel()

	s := referrersStack(t)
	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)
	ghost := blob.FromBytes(blob.SHA256, []byte("never pushed")).String()

	for name, digest := range map[string]string{"unattached subject": imageDg, "absent subject": ghost} {
		rec := s.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+digest, "sam", "")
		if rec.Code != http.StatusOK || rec.Body.String() != referrersEmptyIndex {
			t.Errorf("%s: %d %s, want the empty index", name, rec.Code, rec.Body)
		}
	}
}

// The refusal table: what the route answers when the request, the repository,
// or the caller is wrong.
func TestReferrersRefusals(t *testing.T) {
	t.Parallel()
	verbtest.Negative(t, authz.ReferrerRead)

	s := referrersStack(t)
	digest := manifestDigest(imageManifest())

	tests := []struct {
		name     string
		target   string
		as       string
		wantCode int
		wantBody string
	}{
		{
			name:   "a malformed digest is refused at the gate",
			target: "/v2/team-a/api/referrers/sha256:short", as: "sam",
			wantCode: http.StatusBadRequest, wantBody: registry.CodeDigestInvalid,
		},
		{
			name:   "an absent entity is unknown",
			target: "/v2/ghost/none/referrers/" + digest, as: "sam",
			wantCode: http.StatusNotFound, wantBody: registry.CodeNameUnknown,
		},
		{
			// rita can pull from team-a/*, so the repository's existence is
			// already disclosed to her and the helpful answer costs nothing
			// (ADR 0003). referrer:read is simply not hers.
			name:   "repo:read without referrer:read is denied",
			target: "/v2/team-a/api/referrers/" + digest, as: "rita",
			wantCode: http.StatusForbidden, wantBody: registry.CodeDenied,
		},
		{
			name:   "repo:write does not imply referrer:read",
			target: "/v2/team-a/api/referrers/" + digest, as: "carol",
			wantCode: http.StatusForbidden, wantBody: registry.CodeDenied,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := s.do(t, http.MethodGet, tt.target, tt.as, "")
			if rec.Code != tt.wantCode || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("%s: %d %s, want %d with %s", tt.target, rec.Code, rec.Body, tt.wantCode, tt.wantBody)
			}
		})
	}

	// Anonymous gets the challenge, not a 404: it may be able to authenticate
	// into visibility, and `docker login` depends on being told so.
	anonymous := s.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+digest, "", "")
	if anonymous.Code != http.StatusUnauthorized ||
		anonymous.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("anonymous: %d, challenge %q", anonymous.Code, anonymous.Header().Get("WWW-Authenticate"))
	}
}

// The §9 case, and the reason this endpoint takes two permissions: a subject
// holding referrer:read everywhere but repo:read nowhere cannot read the SBOM
// of an image it cannot pull. The refusal is byte-identical -- body and
// headers -- to the one a repository that does not exist gets, so the
// attachment's existence, and its subject's, stay unknowable (ADR 0003).
func TestReferrersInheritTheSubjectPermission(t *testing.T) {
	t.Parallel()

	s := referrersStack(t)
	ctx := context.Background()

	// Something real to hide: an image in secret/vault with an SBOM attached,
	// seeded directly because nobody in the fixture may push there.
	image := imageManifest()
	imageDg := blob.FromBytes(blob.SHA256, []byte(image)).String()
	sbom := referrersAttachment(referrersSBOMType, imageDg, len(image))
	for _, record := range []meta.Manifest{
		{Repository: "secret/vault", Digest: meta.Digest(imageDg), MediaType: artifact.MediaTypeOCIManifest,
			Payload: []byte(image), Size: int64(len(image)), CreatedAt: fixedTime},
		{Repository: "secret/vault", Digest: meta.Digest(manifestDigest(sbom)),
			MediaType: artifact.MediaTypeOCIManifest, ArtifactType: referrersSBOMType,
			Subject: meta.Digest(imageDg), Payload: []byte(sbom), Size: int64(len(sbom)), CreatedAt: fixedTime},
	} {
		if err := s.metaDB.PutManifest(ctx, record, nil); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
	}

	hidden := s.do(t, http.MethodGet, "/v2/secret/vault/referrers/"+imageDg, "peek", "")
	absent := s.do(t, http.MethodGet, "/v2/secret/absent/referrers/"+imageDg, "peek", "")

	if hidden.Code != http.StatusNotFound || !strings.Contains(hidden.Body.String(), registry.CodeNameUnknown) {
		t.Fatalf("the SBOM of an unreadable image: %d %s, want a 404", hidden.Code, hidden.Body)
	}
	if strings.Contains(hidden.Body.String(), manifestDigest(sbom)) {
		t.Fatalf("the refusal names the attachment it is hiding: %s", hidden.Body)
	}
	if hidden.Code != absent.Code || hidden.Body.String() != absent.Body.String() {
		t.Fatalf("hidden %d %s vs absent %d %s: want byte-identical",
			hidden.Code, hidden.Body, absent.Code, absent.Body)
	}
	if fmt.Sprint(hidden.Header()) != fmt.Sprint(absent.Header()) {
		t.Fatalf("headers differ: %v vs %v", hidden.Header(), absent.Header())
	}

	// The same subject reads the same shape where it does hold repo:read, so
	// the 404 above is about the permission and not about the route.
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+imageDg, "sam", ""); rec.Code != http.StatusOK {
		t.Fatalf("readable listing: %d %s", rec.Code, rec.Body)
	}
}

// A stored payload that no longer parses contributes no annotations rather
// than failing the listing: the descriptor is still true, and the drift is
// P-012's to find.
func TestReferrersUnparseablePayloadHasNoAnnotations(t *testing.T) {
	t.Parallel()

	s := referrersStack(t)
	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)

	broken := []byte(`{"annotations":`)
	if err := s.metaDB.PutManifest(context.Background(), meta.Manifest{
		Repository: "team-a/api", Digest: meta.Digest(blob.FromBytes(blob.SHA256, broken).String()),
		MediaType: artifact.MediaTypeOCIManifest, ArtifactType: referrersSBOMType,
		Subject: meta.Digest(imageDg), Payload: broken, Size: int64(len(broken)), CreatedAt: fixedTime,
	}, nil); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	descriptors := referrersDecode(t, s.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+imageDg, "sam", ""))
	if len(descriptors) != 1 {
		t.Fatalf("listed %d referrers, want the seeded one", len(descriptors))
	}
	if _, present := descriptors[0]["annotations"]; present {
		t.Errorf("annotations invented from an unparseable payload: %v", descriptors[0])
	}
}

// referrersFaultyMeta fails one named store call so the handler's own read
// trips while the guard's lookups still succeed.
type referrersFaultyMeta struct {
	*metamem.Store
	fail string
}

var errReferrersDisk = errors.New("disk on fire")

func (f *referrersFaultyMeta) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if f.fail == "GetRepository" {
		return meta.Repository{}, errReferrersDisk
	}
	return f.Store.GetRepository(ctx, name)
}

func (f *referrersFaultyMeta) ListReferrers(ctx context.Context, repo string, subject meta.Digest, artifactType string) ([]meta.Manifest, error) {
	if f.fail == "ListReferrers" {
		return nil, errReferrersDisk
	}
	return f.Store.ListReferrers(ctx, repo, subject, artifactType)
}

// referrersFaultyBindings breaks the handler's own binding fetch, leaving the
// guard's intact: the sub-decision has to fail closed on its own.
type referrersFaultyBindings struct {
	*metamem.Store
}

func (referrersFaultyBindings) ListEffectiveBindings(context.Context, string) ([]meta.EffectiveBinding, error) {
	return nil, errReferrersDisk
}

// A store that cannot answer is a 500 in the spec's envelope. Neither an empty
// index nor a 404 is honest here: the first invents an answer, and the second
// would tell a caller with every permission that the repository is gone.
func TestReferrersStoreFailuresAreServerErrors(t *testing.T) {
	t.Parallel()

	digest := manifestDigest(imageManifest())

	tests := []struct {
		name  string
		build func(t *testing.T, s stack) stack
	}{
		{
			name: "GetRepository",
			build: func(t *testing.T, s stack) stack {
				return referrersRouter(t, s, &referrersFaultyMeta{Store: s.metaDB, fail: "GetRepository"}, s.metaDB)
			},
		},
		{
			name: "ListReferrers",
			build: func(t *testing.T, s stack) stack {
				return referrersRouter(t, s, &referrersFaultyMeta{Store: s.metaDB, fail: "ListReferrers"}, s.metaDB)
			},
		},
		{
			name: "the sub-decision's bindings",
			build: func(t *testing.T, s stack) stack {
				return referrersRouter(t, s, s.metaDB, referrersFaultyBindings{Store: s.metaDB})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := newStack(t)
			referrersSeedIdentities(t, base)
			armed := tt.build(t, base)

			rec := armed.do(t, http.MethodGet, "/v2/team-a/api/referrers/"+digest, "sam", "")
			if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), registry.CodeUnknown) {
				t.Fatalf("%s failing: %d %s, want a spec-shaped 500", tt.name, rec.Code, rec.Body)
			}
		})
	}
}

// referrersBrokenWriter is a client that went away mid-body.
type referrersBrokenWriter struct {
	*httptest.ResponseRecorder
}

func (referrersBrokenWriter) Write([]byte) (int, error) { return 0, errReferrersDisk }

// A connection that dies while the index is being written leaves the status
// line already sent: the handler logs and returns rather than trying to write
// a second answer over the first.
func TestReferrersWriteFailureKeepsTheStatus(t *testing.T) {
	t.Parallel()

	s := referrersStack(t)
	content := referrersPushContent(t, s)

	req := httptest.NewRequest(http.MethodGet, "/v2/team-a/api/referrers/"+content.imageDg, nil)
	req.Header.Set("X-Test-Subject", "sam")
	rec := referrersBrokenWriter{ResponseRecorder: httptest.NewRecorder()}
	s.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the 200 that was already committed", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body reached a writer that refused every byte: %s", rec.Body)
	}
}
