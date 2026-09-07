package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlite"
)

// A pull through a proxy repository against a real `trove serve` (C-020).
//
// Everything below this test has been proven in isolation: the fill path
// against a contract-equivalent fake, the adapter against a fake filler, the
// dispatcher against a fake delegate. What none of them can show is that the
// wiring hands the right pieces to each other -- that the cache store is the
// cache-rooted one, that the client carries the entity's configuration, that
// a pull actually reaches an upstream and comes back. This is that test, and
// it is the first moment in the project where `docker pull` through a proxy
// would work.

// fakeUpstream is a registry serving one image.
type fakeUpstream struct {
	manifest []byte
	layer    []byte

	manifestDigest blob.Digest
	layerDigest    blob.Digest

	server *httptest.Server
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()

	layer := []byte("upstream layer bytes")
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		blob.FromBytes(blob.SHA256, []byte("config")).String() + `","size":6},"layers":[{"mediaType":` +
		`"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` +
		blob.FromBytes(blob.SHA256, layer).String() + `","size":20}]}`)

	u := &fakeUpstream{
		manifest: manifest, layer: layer,
		manifestDigest: blob.FromBytes(blob.SHA256, manifest),
		layerDigest:    blob.FromBytes(blob.SHA256, layer),
	}

	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			_, _ = w.Write([]byte("{}"))
		case strings.HasSuffix(r.URL.Path, "/manifests/1.27"),
			strings.HasSuffix(r.URL.Path, "/manifests/"+u.manifestDigest.String()):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", u.manifestDigest.String())
			_, _ = w.Write(u.manifest)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+u.layerDigest.String()):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(u.layer)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"NOT_FOUND"}]}`))
		}
	}))
	t.Cleanup(u.server.Close)
	return u
}

// TestServePullsThroughAProxy boots the real server over a data directory
// seeded with a proxy repository, pulls an image through it, and checks that
// what came back is the upstream's content and that the cache kept it.
func TestServePullsThroughAProxy(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	dir := t.TempDir()
	seedProxyDeployment(t, dir, upstream.server.URL)

	env, _, logs := newServeStreams()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)
	base := "http://" + servingAddress(t, logs)

	// A tag pull, anonymously: the deployment granted the anonymous subject
	// read on this proxy, which is what a public mirror looks like.
	manifest := get(t, base+"/v2/hub/library/nginx/manifests/1.27")
	if manifest.status != http.StatusOK {
		t.Fatalf("manifest pull: %d %s", manifest.status, manifest.body)
	}
	if string(manifest.body) != string(upstream.manifest) {
		t.Errorf("manifest body = %q, want the upstream's", manifest.body)
	}
	if got := manifest.header.Get("Docker-Content-Digest"); got != upstream.manifestDigest.String() {
		t.Errorf("Docker-Content-Digest = %q, want %s", got, upstream.manifestDigest)
	}

	// And the layer it names, which streams from the upstream into the cache
	// as the client reads it.
	layer := get(t, base+"/v2/hub/library/nginx/blobs/"+upstream.layerDigest.String())
	if layer.status != http.StatusOK {
		t.Fatalf("layer pull: %d %s", layer.status, layer.body)
	}
	if string(layer.body) != string(upstream.layer) {
		t.Errorf("layer body = %q, want the upstream's", layer.body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}

	// The cache kept what it served, in the cached family and under the cache
	// root -- which is the wiring this test exists to prove.
	assertCached(t, dir, upstream)
}

// TestServeStillPullsWhenTheUpstreamIsGone is the cache doing its job: the
// second pull is served from what the first one stored, with nothing to reach.
func TestServeStillPullsWhenTheUpstreamIsGone(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	dir := t.TempDir()
	seedProxyDeployment(t, dir, upstream.server.URL)

	env, _, logs := newServeStreams()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)
	base := "http://" + servingAddress(t, logs)

	// Warm the cache by digest, which is the reference a cached manifest is
	// served forever under: digests are immutable, so nothing revalidates.
	first := get(t, base+"/v2/hub/library/nginx/manifests/"+upstream.manifestDigest.String())
	if first.status != http.StatusOK {
		t.Fatalf("first pull: %d %s", first.status, first.body)
	}

	upstream.server.Close()

	second := get(t, base+"/v2/hub/library/nginx/manifests/"+upstream.manifestDigest.String())
	if second.status != http.StatusOK {
		t.Fatalf("pull with the upstream gone: %d %s", second.status, second.body)
	}
	if string(second.body) != string(upstream.manifest) {
		t.Errorf("cached body = %q, want the upstream's", second.body)
	}
}

// TestServeReportsAnUnreachableUpstream: content that was never cached and
// cannot be fetched is not "no such image". A client that cached that
// not-found would keep failing after the upstream came back.
func TestServeReportsAnUnreachableUpstream(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	dir := t.TempDir()
	seedProxyDeployment(t, dir, upstream.server.URL)
	upstream.server.Close()

	env, _, logs := newServeStreams()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)
	base := "http://" + servingAddress(t, logs)

	got := get(t, base+"/v2/hub/library/nginx/manifests/1.27")
	if got.status != http.StatusGatewayTimeout {
		t.Errorf("pull from a dead upstream: %d %s, want 504", got.status, got.body)
	}
}

// TestServePullsThroughAGroup is the product's headline feature, working for
// the first time: one registry URL, an ordered member list behind it, and a
// client that never learns which member answered.
//
// The group here is a hosted repository first and a proxy second, which is the
// quickstart's shape (ADR 0005: hosted before proxy is the preset ordering,
// not a rule). The hosted member has nothing, so the proxy answers -- and the
// response is byte-identical to pulling the proxy directly, because the group
// serves its member's content rather than a rendering of it.
func TestServePullsThroughAGroup(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	dir := t.TempDir()
	seedProxyDeployment(t, dir, upstream.server.URL)
	seedGroupOver(t, dir, "internal", "hub")

	env, _, logs := newServeStreams()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)
	base := "http://" + servingAddress(t, logs)

	group := get(t, base+"/v2/fleet/library/nginx/manifests/1.27")
	if group.status != http.StatusOK {
		t.Fatalf("group pull: %d %s", group.status, group.body)
	}
	if string(group.body) != string(upstream.manifest) {
		t.Errorf("group served %q, want the upstream's manifest", group.body)
	}

	// Identical to the direct pull: a group is a way of finding content, not a
	// way of changing it.
	direct := get(t, base+"/v2/hub/library/nginx/manifests/1.27")
	if string(direct.body) != string(group.body) ||
		direct.header.Get("Docker-Content-Digest") != group.header.Get("Docker-Content-Digest") {
		t.Errorf("group and direct pulls differ: group %s %s, direct %s %s",
			group.header.Get("Docker-Content-Digest"), group.body,
			direct.header.Get("Docker-Content-Digest"), direct.body)
	}

	// A layer through the group too, which is what a real pull does next.
	layer := get(t, base+"/v2/fleet/library/nginx/blobs/"+upstream.layerDigest.String())
	if layer.status != http.StatusOK || string(layer.body) != string(upstream.layer) {
		t.Errorf("group layer pull: %d %q", layer.status, layer.body)
	}
}

// TestAGroupMemberTheSubjectCannotReadIsInvisible over the real server: the
// anonymous subject may read the group and the hosted member, and knows
// nothing of the proxy -- so the pull finds nothing rather than being served
// content through a member it may not see (C-012).
func TestAGroupMemberTheSubjectCannotReadIsInvisible(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	dir := t.TempDir()
	seedProxyDeployment(t, dir, upstream.server.URL)
	seedGroupOver(t, dir, "internal", "hub")
	revokeAnonymousAccessTo(t, dir, "hub")

	env, _, logs := newServeStreams()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)
	base := "http://" + servingAddress(t, logs)

	got := get(t, base+"/v2/fleet/library/nginx/manifests/1.27")
	if got.status != http.StatusNotFound {
		t.Fatalf("group pull with the only useful member hidden: %d %s, want 404", got.status, got.body)
	}
	if !strings.Contains(string(got.body), "MANIFEST_UNKNOWN") {
		t.Errorf("body = %s, want the same answer as content that is not there", got.body)
	}
}

// seedGroupOver adds a group `fleet` over the members named, in order, and
// grants the anonymous subject read on the group and on every member.
func seedGroupOver(t *testing.T, dir string, members ...string) {
	t.Helper()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, sqlite.Options{Path: filepath.Join(dir, "trove.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := store.CreateRepository(ctx, meta.Repository{
		Name: "fleet", Type: meta.Group, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateRepository(fleet): %v", err)
	}

	stored := make([]meta.GroupMember, 0, len(members))
	for i, name := range members {
		if _, err := store.GetRepository(ctx, name); err != nil {
			if _, err := store.CreateRepository(ctx, meta.Repository{
				Name: name, Type: meta.Hosted, CreatedAt: time.Now(), UpdatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("CreateRepository(%q): %v", name, err)
			}
		}
		stored = append(stored, meta.GroupMember{Repository: name, Position: i + 1})
	}
	if err := store.SetGroupMembers(ctx, "fleet", stored); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}

	for i, scope := range append([]string{"fleet/*"}, membersScopes(members)...) {
		if err := store.CreateBinding(ctx, meta.Binding{
			ID:            fmt.Sprintf("anon-group-%d", i),
			PrincipalKind: meta.PrincipalSubject, PrincipalID: meta.AnonymousSubjectID,
			Role: "mirror-reader", Scope: scope,
		}); err != nil && !errors.Is(err, meta.ErrConflict) {
			t.Fatalf("CreateBinding(%q): %v", scope, err)
		}
	}
}

// membersScopes is one scope per member's content.
func membersScopes(members []string) []string {
	scopes := make([]string, 0, len(members))
	for _, member := range members {
		scopes = append(scopes, member+"/*")
	}
	return scopes
}

// revokeAnonymousAccessTo removes the anonymous subject's grant on one member,
// leaving the group readable and that member not.
func revokeAnonymousAccessTo(t *testing.T, dir, member string) {
	t.Helper()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, sqlite.Options{Path: filepath.Join(dir, "trove.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	bindings, err := store.ListEffectiveBindings(ctx, meta.AnonymousSubjectName)
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	for _, binding := range bindings {
		if binding.Scope == member+"/*" {
			if err := store.DeleteBinding(ctx, binding.ID); err != nil {
				t.Fatalf("DeleteBinding: %v", err)
			}
		}
	}
}

// seedProxyDeployment writes a data directory holding one proxy repository the
// anonymous subject may read.
//
// The rows are written directly rather than through the admin API: the API has
// its own tests (C-016), and what this file is about is the serving path.
func seedProxyDeployment(t *testing.T, dir, upstream string) {
	t.Helper()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, sqlite.Options{Path: filepath.Join(dir, "trove.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("closing the seeded store: %v", err)
		}
	}()

	config, err := json.Marshal(map[string]any{"upstream": upstream, "default_namespace": "library"})
	if err != nil {
		t.Fatalf("marshal the proxy config: %v", err)
	}
	if _, err := store.CreateRepository(ctx, meta.Repository{
		Name: "hub", Type: meta.Proxy, Config: config,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	if err := store.CreateRole(ctx, meta.Role{Name: "mirror-reader", Verbs: []string{"repo:read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	// The anonymous subject is a real subject with real bindings (ADR 0004),
	// which is what makes a public mirror expressible without a second code
	// path for "no credentials".
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "anon-hub", PrincipalKind: meta.PrincipalSubject, PrincipalID: meta.AnonymousSubjectID,
		Role: "mirror-reader", Scope: "hub/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
}

// assertCached reopens the deployment and checks that the pull left the
// content in the cached family, under the cache root.
func assertCached(t *testing.T, dir string, upstream *fakeUpstream) {
	t.Helper()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, sqlite.Options{Path: filepath.Join(dir, "trove.db")})
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := store.GetCachedManifest(ctx, "hub/library/nginx", meta.Digest(upstream.manifestDigest)); err != nil {
		t.Errorf("the pulled manifest is not in the cache: %v", err)
	}
	if _, err := store.GetCachedBlob(ctx, "hub/library/nginx", meta.Digest(upstream.layerDigest)); err != nil {
		t.Errorf("the pulled layer is not in the cache: %v", err)
	}

	// Hosted storage saw none of it: the cache is a different store over a
	// different root, chosen at wiring time (ADR 0009 wall 2).
	if _, err := store.GetBlob(ctx, meta.Digest(upstream.layerDigest)); err == nil {
		t.Error("a proxied layer was recorded as hosted content")
	}
	if _, err := store.GetManifest(ctx, "hub/library/nginx", meta.Digest(upstream.manifestDigest)); err == nil {
		t.Error("a proxied manifest was recorded as hosted content")
	}
}

// response is what a pull came back with.
type response struct {
	status int
	header http.Header
	body   []byte
}

func get(t *testing.T, url string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: body}
}
