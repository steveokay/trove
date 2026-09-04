package registry_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// The distribution spec overloads DELETE /manifests/<reference> for two
// operations that destroy different things. ADR 0002 gives them different
// verbs, and a route carries one verb, so they are two routes told apart by
// the reference's shape. These tests are what hold that split honest.

// tagDeleteStack registers a Manifests handler that can serve both DELETE
// routes, with a subject holding each verb separately.
func tagDeleteStack(t *testing.T) stack {
	t.Helper()

	s := newStack(t)
	ctx := context.Background()

	// tilda holds tag:delete and nothing else that destroys; digger holds
	// manifest:delete. Neither implies the other, which is the point.
	for _, subject := range []meta.Subject{
		{ID: "u-tilda", Kind: meta.User, Name: "tilda"},
		{ID: "u-digger", Kind: meta.User, Name: "digger"},
	} {
		if err := s.metaDB.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	for _, role := range []meta.Role{
		{Name: "untagger", Verbs: []string{"repo:read", "repo:write", "tag:delete"}},
		{Name: "digger", Verbs: []string{"repo:read", "repo:write", "manifest:delete"}},
	} {
		if err := s.metaDB.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-tilda", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-tilda", Role: "untagger", Scope: "team-a/*"},
		{ID: "b-digger", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-digger", Role: "digger", Scope: "team-a/*"},
	} {
		if err := s.metaDB.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}
	return s
}

// Deleting a tag removes the name and leaves the content: the manifest still
// pulls by digest, and its other tags still resolve.
func TestTagDeleteRemovesOnlyTheName(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.TagDelete)

	s := tagDeleteStack(t)
	seedImageBlobs(t, s)
	payload := imageManifest()
	digest := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, payload)
	putManifest(t, s, "carol", "stable", artifact.MediaTypeOCIManifest, payload)

	rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/v1", "tilda", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("tag delete: %d %s", rec.Code, rec.Body)
	}

	if got := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "carol", ""); got.Code != http.StatusNotFound {
		t.Errorf("the deleted tag still resolves: %d", got.Code)
	}
	// The content survives, by digest and by its other name.
	if got := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "carol", ""); got.Code != http.StatusOK {
		t.Errorf("untagging destroyed the manifest: %d", got.Code)
	}
	if got := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/stable", "carol", ""); got.Code != http.StatusOK {
		t.Errorf("untagging one name removed another: %d", got.Code)
	}
}

// The two verbs do not imply each other, in either direction. This is the
// split the route constraint exists to make enforceable.
func TestTagDeleteAndManifestDeleteAreSeparateVerbs(t *testing.T) {
	t.Parallel()
	verbtest.Negative(t, authz.TagDelete)

	s := tagDeleteStack(t)
	seedImageBlobs(t, s)
	payload := imageManifest()
	digest := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, payload)

	// manifest:delete does not carry tag:delete.
	if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/v1", "digger", ""); rec.Code != http.StatusForbidden {
		t.Errorf("manifest:delete deleted a tag: %d %s", rec.Code, rec.Body)
	}
	// tag:delete does not carry manifest:delete.
	if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+digest, "tilda", ""); rec.Code != http.StatusForbidden {
		t.Errorf("tag:delete deleted a manifest: %d %s", rec.Code, rec.Body)
	}
	// repo:write carries neither.
	for _, reference := range []string{"v1", digest} {
		if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+reference, "carol", ""); rec.Code != http.StatusForbidden {
			t.Errorf("repo:write deleted %q: %d", reference, rec.Code)
		}
	}
	// Nothing was destroyed by any of the refusals.
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "carol", ""); rec.Code != http.StatusOK {
		t.Errorf("a refused delete removed the tag: %d", rec.Code)
	}
}

// Deleting a manifest by digest still takes its tags and referrer tree with
// it: the split changed which verb admits the request, not what it does.
func TestManifestDeleteStillCascadesAfterTheSplit(t *testing.T) {
	t.Parallel()

	s := tagDeleteStack(t)
	seedImageBlobs(t, s)
	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)

	sbom := imageManifest(
		`"artifactType": "application/spdx+json"`,
		fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
			artifact.MediaTypeOCIManifest, imageDg, len(image)))
	sbomDg := putManifest(t, s, "carol", manifestDigest(sbom), artifact.MediaTypeOCIManifest, sbom)

	if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+imageDg, "digger", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("manifest delete: %d %s", rec.Code, rec.Body)
	}
	for name, reference := range map[string]string{"tag": "v1", "manifest": imageDg, "sbom": sbomDg} {
		if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+reference, "carol", ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s survived the cascade: %d", name, rec.Code)
		}
	}
}

// An unknown tag and an illegal one answer the same unknown, so a probe learns
// nothing from the difference.
func TestTagDeleteUnknown(t *testing.T) {
	t.Parallel()

	s := tagDeleteStack(t)
	for _, tag := range []string{"never-existed", "!!!not-a-tag!!!"} {
		rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+tag, "tilda", "")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), registry.CodeManifestUnknown) {
			t.Errorf("DELETE %q: %d %s, want MANIFEST_UNKNOWN", tag, rec.Code, rec.Body)
		}
	}
}

// A proxy refuses tag deletion by type, like every other client write.
func TestTagDeleteRefusedOnProxy(t *testing.T) {
	t.Parallel()

	s := tagDeleteStack(t)
	ctx := context.Background()
	if err := s.metaDB.CreateBinding(ctx, meta.Binding{
		ID: "b-tilda-mirror", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-tilda",
		Role: "untagger", Scope: "mirror/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	rec := s.do(t, http.MethodDelete, "/v2/mirror/library/nginx/manifests/v1", "tilda", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), registry.CodeDenied) {
		t.Errorf("tag delete on a proxy: %d %s, want DENIED", rec.Code, rec.Body)
	}
}

// A store that cannot delete answers with a spec-shaped 500 rather than
// reporting a deletion that did not happen.
//
// The fixture is built here rather than reusing faultyStack because the shared
// one has no tag:delete subject -- and giving its maintainer that verb would
// quietly undo the split TestManifestDeleteDoesNotCarryTagDelete asserts.
func TestTagDeleteStoreFailure(t *testing.T) {
	t.Parallel()

	s := tagDeleteStack(t)
	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Manifests{
		Meta: &tagDeleteFaultyMeta{Store: s.metaDB}, Now: func() time.Time { return fixedTime },
	}).Register(router)
	armed := stack{handler: router, router: router, metaDB: s.metaDB, blobs: s.blobs}

	rec := armed.do(t, http.MethodDelete, "/v2/team-a/api/manifests/v1", "tilda", "")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), registry.CodeUnknown) {
		t.Fatalf("DeleteTag failing: %d %s, want a spec-shaped 500", rec.Code, rec.Body)
	}
}

// tagDeleteFaultyMeta refuses only the tag deletion, so the guard's lookups
// and the repository resolution both still work.
type tagDeleteFaultyMeta struct {
	*metamem.Store
}

func (tagDeleteFaultyMeta) DeleteTag(context.Context, string, string) error {
	return errors.New("the disk went away")
}

// The router's constraint is what makes the split possible: a digest-shaped
// reference reaches the manifest route and a tag-shaped one the tag route,
// decided before the guard runs. Registering an unknown constraint is a
// programming error and panics at wiring time rather than silently never
// matching.
func TestRouteConstraintRejectsUnknownKinds(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("registering an unknown constraint did not panic")
		}
	}()
	router := server.NewRouter(&server.Guard{})
	router.HandleOCI(http.MethodGet, "/manifests/{reference:nonsense}",
		server.Permission{Verb: authz.RepoRead, Resource: func(*http.Request) (authz.Resource, error) {
			return authz.Repository("x")
		}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
}
