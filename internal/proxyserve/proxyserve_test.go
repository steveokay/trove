package proxyserve_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxyserve"
	"github.com/steveokay/trove/internal/registry"
)

var testTime = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// fakeFiller records what it was asked for and answers with what a test set.
type fakeFiller struct {
	manifest proxy.ManifestResult
	blobRes  proxy.BlobResult
	tag      proxy.TagResolution

	resolveErr  error
	manifestErr error
	blobErr     error

	mu      sync.Mutex
	targets []proxy.Target
	tags    []string
	digests []blob.Digest
}

func (f *fakeFiller) ResolveTag(_ context.Context, t proxy.Target, tag string) (proxy.TagResolution, error) {
	f.mu.Lock()
	f.targets = append(f.targets, t)
	f.tags = append(f.tags, tag)
	f.mu.Unlock()
	if f.resolveErr != nil {
		return proxy.TagResolution{}, f.resolveErr
	}
	return f.tag, nil
}

func (f *fakeFiller) Manifest(_ context.Context, t proxy.Target, digest blob.Digest) (proxy.ManifestResult, error) {
	f.mu.Lock()
	f.targets = append(f.targets, t)
	f.digests = append(f.digests, digest)
	f.mu.Unlock()
	if f.manifestErr != nil {
		return proxy.ManifestResult{}, f.manifestErr
	}
	return f.manifest, nil
}

func (f *fakeFiller) Blob(_ context.Context, t proxy.Target, digest blob.Digest) (proxy.BlobResult, error) {
	f.mu.Lock()
	f.targets = append(f.targets, t)
	f.digests = append(f.digests, digest)
	f.mu.Unlock()
	if f.blobErr != nil {
		return proxy.BlobResult{}, f.blobErr
	}
	return f.blobRes, nil
}

func (f *fakeFiller) lastTarget(t *testing.T) proxy.Target {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.targets) == 0 {
		t.Fatal("the filler was never called")
	}
	return f.targets[len(f.targets)-1]
}

func (f *fakeFiller) calls() (tags []string, digests []blob.Digest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tags...), append([]blob.Digest(nil), f.digests...)
}

// fakeClients hands out a client that is never actually called: the filler is
// faked, so the client only has to be a value the target can carry.
type fakeClients struct {
	err error
}

func (c fakeClients) ClientFor(context.Context, string) (proxy.Client, error) {
	if c.err != nil {
		return nil, c.err
	}
	return stubClient{}, nil
}

type stubClient struct{ proxy.Client }

// recordingTouches captures what was reported to the LRU.
type recordingTouches struct {
	mu   sync.Mutex
	seen []string
}

func (r *recordingTouches) Touch(repo string, digest meta.Digest, kind meta.CachedKind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, string(kind)+" "+repo+"@"+string(digest))
}

func (r *recordingTouches) records() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// env is a store with one proxy entity and a server over it.
type env struct {
	t       *testing.T
	meta    *metamemory.Store
	filler  *fakeFiller
	touches *recordingTouches
}

func newEnv(t *testing.T, config string) *env {
	t.Helper()

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: "hub", Type: meta.Proxy, Config: json.RawMessage(config),
		CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	return &env{t: t, meta: store, filler: &fakeFiller{}, touches: &recordingTouches{}}
}

func (e *env) server(tweak ...func(*proxyserve.Options)) *proxyserve.Server {
	e.t.Helper()

	opts := proxyserve.Options{
		Meta: e.meta, Clients: fakeClients{}, Filler: e.filler, Touches: e.touches,
		TagTTL: 15 * time.Minute, NegativeTTL: time.Minute, Offline: proxy.ServeStale,
		Log: discardLogger(),
	}
	for _, apply := range tweak {
		apply(&opts)
	}
	server, err := proxyserve.New(opts)
	if err != nil {
		e.t.Fatalf("proxyserve.New: %v", err)
	}
	return server
}

const dockerHubConfig = `{"upstream":"https://registry-1.docker.io","default_namespace":"library"}`

func manifestResult(hit bool) proxy.ManifestResult {
	payload := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	return proxy.ManifestResult{
		Digest:    blob.FromBytes(blob.SHA256, payload),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   payload,
		Hit:       hit,
		Cached:    true,
	}
}

func TestNewRefusesUnusableOptions(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	for _, tc := range []struct {
		name string
		opts proxyserve.Options
	}{
		{name: "no store", opts: proxyserve.Options{Clients: fakeClients{}, Filler: env.filler}},
		{name: "no clients", opts: proxyserve.Options{Meta: env.meta, Filler: env.filler}},
		{name: "no filler", opts: proxyserve.Options{Meta: env.meta, Clients: fakeClients{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := proxyserve.New(tc.opts); !errors.Is(err, proxyserve.ErrInvalidOptions) {
				t.Fatalf("New error = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

// TestATagResolvesThroughTheLease: a tag is the one mutable thing a proxy
// holds, so it goes through the lease before the manifest is fetched by the
// digest it resolved to.
func TestATagResolvesThroughTheLease(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	result := manifestResult(false)
	env.filler.tag = proxy.TagResolution{Digest: result.Digest, Revalidated: true, Changed: true}
	env.filler.manifest = result

	served, err := env.server().Manifest(context.Background(), "hub/nginx", "1.27")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if served.Digest != result.Digest || served.MediaType != result.MediaType {
		t.Errorf("served %+v, want the filler's manifest", served)
	}
	if string(served.Payload) != string(result.Payload) {
		t.Errorf("payload = %q", served.Payload)
	}

	tags, digests := env.filler.calls()
	if len(tags) != 1 || tags[0] != "1.27" {
		t.Errorf("resolved tags = %v, want the reference as written", tags)
	}
	if len(digests) != 1 || digests[0] != result.Digest {
		t.Errorf("fetched digests = %v, want the digest the tag resolved to", digests)
	}
}

// TestADigestSkipsTheLease: digests are immutable, so there is nothing to
// revalidate and asking would be a request that could only confirm itself.
func TestADigestSkipsTheLease(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	result := manifestResult(false)
	env.filler.manifest = result

	if _, err := env.server().Manifest(context.Background(), "hub/nginx", result.Digest.String()); err != nil {
		t.Fatalf("Manifest: %v", err)
	}

	tags, digests := env.filler.calls()
	if len(tags) != 0 {
		t.Errorf("a digest pull resolved tags: %v", tags)
	}
	if len(digests) != 1 || digests[0] != result.Digest {
		t.Errorf("fetched %v, want the digest asked for", digests)
	}
}

// TestTheNamespaceRewrite is the behaviour ADR 0005 describes and nothing
// implemented until now: a bare name on a Docker Hub proxy is an official
// image.
func TestTheNamespaceRewrite(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		config    string
		content   string
		wantUpstr string
	}{
		{
			name: "a bare name gains the namespace", config: dockerHubConfig,
			content: "hub/nginx", wantUpstr: "library/nginx",
		},
		{
			// Already namespaced: prefixing would make library/library/nginx.
			name: "a namespaced name is left alone", config: dockerHubConfig,
			content: "hub/library/nginx", wantUpstr: "library/nginx",
		},
		{
			name: "somebody else's namespace is left alone", config: dockerHubConfig,
			content: "hub/myorg/app", wantUpstr: "myorg/app",
		},
		{
			name: "a deep path is left alone", config: dockerHubConfig,
			content: "hub/a/b/c", wantUpstr: "a/b/c",
		},
		{
			name:    "no namespace configured rewrites nothing",
			config:  `{"upstream":"https://ghcr.io"}`,
			content: "hub/owner/app", wantUpstr: "owner/app",
		},
		{
			name:    "no namespace configured leaves a bare name bare",
			config:  `{"upstream":"https://ghcr.io"}`,
			content: "hub/app", wantUpstr: "app",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t, tc.config)
			env.filler.manifest = manifestResult(false)
			env.filler.tag = proxy.TagResolution{Digest: env.filler.manifest.Digest}

			if _, err := env.server().Manifest(context.Background(), tc.content, "v1"); err != nil {
				t.Fatalf("Manifest: %v", err)
			}
			target := env.filler.lastTarget(t)
			if target.Upstream != tc.wantUpstr {
				t.Errorf("upstream path = %q, want %q", target.Upstream, tc.wantUpstr)
			}
			// The trove-side name is unchanged: it is what the cache is keyed
			// by and what a binding matches.
			if target.Repository != tc.content {
				t.Errorf("target repository = %q, want the content name %q", target.Repository, tc.content)
			}
		})
	}
}

// TestRoutingRulesEvaluateTheRewrittenPath is C-010's reconciled decision,
// stated as a test: a `library/*` rule admits `nginx`, which is the most
// common pull on the preset the rule was written for. Under the other reading
// it would deny it.
func TestRoutingRulesEvaluateTheRewrittenPath(t *testing.T) {
	t.Parallel()

	env := newEnv(t, `{"upstream":"https://registry-1.docker.io","default_namespace":"library",
		"allow":["library/*"],"default_deny":true}`)
	env.filler.manifest = manifestResult(false)
	env.filler.tag = proxy.TagResolution{Digest: env.filler.manifest.Digest}

	if _, err := env.server().Manifest(context.Background(), "hub/nginx", "1.27"); err != nil {
		t.Fatalf("a bare official image was refused: %v", err)
	}
	if got := env.filler.lastTarget(t).Upstream; got != "library/nginx" {
		t.Errorf("upstream = %q, want library/nginx", got)
	}
}

// TestARefusedPathLooksAbsent: which paths a proxy admits is configuration,
// and a client that could tell "blocked" from "not there" could map the rules
// by asking (ADR 0003).
func TestARefusedPathLooksAbsent(t *testing.T) {
	t.Parallel()

	env := newEnv(t, `{"upstream":"https://registry-1.docker.io","allow":["library/*"],"default_deny":true}`)
	env.filler.manifest = manifestResult(false)

	_, err := env.server().Manifest(context.Background(), "hub/myorg/private", "v1")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Fatalf("error = %v, want ErrContentUnknown", err)
	}
	if tags, digests := env.filler.calls(); len(tags)+len(digests) != 0 {
		t.Errorf("a refused path reached the filler: %v %v", tags, digests)
	}
}

// TestTheRepositoryConfigurationDecidesTheTTLs: a repository's own settings
// override the deployment defaults, and are read on the request rather than
// cached, so lowering a TTL takes effect on the next pull.
func TestTheRepositoryConfigurationDecidesTheTTLs(t *testing.T) {
	t.Parallel()

	env := newEnv(t, `{"upstream":"https://quay.io","tag_ttl":"30s","negative_ttl":"5s","offline_mode":"strict"}`)
	env.filler.manifest = manifestResult(false)
	env.filler.tag = proxy.TagResolution{Digest: env.filler.manifest.Digest}

	if _, err := env.server().Manifest(context.Background(), "hub/app", "v1"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}

	target := env.filler.lastTarget(t)
	if target.TagTTL != 30*time.Second || target.NegativeTTL != 5*time.Second {
		t.Errorf("TTLs = %v / %v, want the repository's overrides", target.TagTTL, target.NegativeTTL)
	}
	if target.Offline != proxy.Strict {
		t.Errorf("offline mode = %q, want strict", target.Offline)
	}
	if target.Remote != "quay.io" {
		t.Errorf("remote = %q, want the host alone: a URL can carry credentials", target.Remote)
	}
}

// TestTheDeploymentDefaultsApplyWhenTheRepositorySaysNothing, which is what
// makes a zero TTL mean "revalidate every pull" rather than "unset".
func TestTheDeploymentDefaultsApplyWhenTheRepositorySaysNothing(t *testing.T) {
	t.Parallel()

	env := newEnv(t, `{"upstream":"https://ghcr.io"}`)
	env.filler.manifest = manifestResult(false)
	env.filler.tag = proxy.TagResolution{Digest: env.filler.manifest.Digest}

	if _, err := env.server().Manifest(context.Background(), "hub/owner/app", "v1"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}

	target := env.filler.lastTarget(t)
	if target.TagTTL != 15*time.Minute || target.NegativeTTL != time.Minute {
		t.Errorf("TTLs = %v / %v, want the deployment defaults", target.TagTTL, target.NegativeTTL)
	}
	if target.Offline != proxy.ServeStale {
		t.Errorf("offline mode = %q, want the deployment default", target.Offline)
	}
}

// TestBlobsStream: the result carries the reader as it is, because the stream
// is what fills the cache while the client reads (C-004).
func TestBlobsStream(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	layer := blob.FromBytes(blob.SHA256, []byte("layer bytes"))
	env.filler.blobRes = proxy.BlobResult{
		Content: io.NopCloser(strings.NewReader("layer bytes")), Size: 11,
	}

	served, err := env.server().Blob(context.Background(), "hub/nginx", layer)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	defer func() { _ = served.Content.Close() }()

	if served.Size != 11 || served.Digest != layer {
		t.Errorf("served %d bytes as %s, want 11 as %s", served.Size, served.Digest, layer)
	}
	body, err := io.ReadAll(served.Content)
	if err != nil || string(body) != "layer bytes" {
		t.Errorf("body = %q, %v", body, err)
	}
}

// TestCacheHitsAreTouchedAndMissesAreNot: the LRU learns what is wanted, and a
// fill already recorded its own access time.
func TestCacheHitsAreTouchedAndMissesAreNot(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	hit := manifestResult(true)
	env.filler.manifest = hit
	env.filler.tag = proxy.TagResolution{Digest: hit.Digest, Hit: true}

	if _, err := env.server().Manifest(context.Background(), "hub/nginx", "1.27"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	layer := blob.FromBytes(blob.SHA256, []byte("layer bytes"))
	env.filler.blobRes = proxy.BlobResult{
		Content: io.NopCloser(strings.NewReader("layer bytes")), Size: 11, Hit: true,
	}
	served, err := env.server().Blob(context.Background(), "hub/nginx", layer)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	_ = served.Content.Close()

	got := env.touches.records()
	if len(got) != 2 {
		t.Fatalf("touches = %v, want one per cache hit", got)
	}
	if !strings.HasPrefix(got[0], "manifest hub/nginx@") || !strings.HasPrefix(got[1], "blob hub/nginx@") {
		t.Errorf("touches = %v, want the content name and kind of each hit", got)
	}

	// A miss is not touched: the fill wrote its own access time, and touching
	// again would be a second write for one pull.
	missEnv := newEnv(t, dockerHubConfig)
	missEnv.filler.manifest = manifestResult(false)
	missEnv.filler.tag = proxy.TagResolution{Digest: missEnv.filler.manifest.Digest}
	if _, err := missEnv.server().Manifest(context.Background(), "hub/nginx", "1.27"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if got := missEnv.touches.records(); len(got) != 0 {
		t.Errorf("a cache miss was touched: %v", got)
	}
}

// TestAServerWithoutATouchRecorderStillServes: recording is an optimisation
// for eviction, never a condition of a pull.
func TestAServerWithoutATouchRecorderStillServes(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	env.filler.manifest = manifestResult(true)
	env.filler.tag = proxy.TagResolution{Digest: env.filler.manifest.Digest, Hit: true}

	server := env.server(func(o *proxyserve.Options) { o.Touches = nil })
	if _, err := server.Manifest(context.Background(), "hub/nginx", "1.27"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
}

// TestUpstreamFailuresBecomeTheThreeAnswersAClientCanActOn is the collapse
// this package exists to perform.
func TestUpstreamFailuresBecomeTheThreeAnswersAClientCanActOn(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "absent upstream content", err: proxy.ErrNotFound, want: registry.ErrContentUnknown},
		{name: "rate limited", err: proxy.ErrRateLimited, want: registry.ErrUpstreamThrottled},
		{name: "unreachable", err: proxy.ErrUpstreamUnavailable, want: registry.ErrUpstreamUnavailable},
		{
			// The upstream lied about what it served. Nothing was cached; to
			// the client the content is unavailable, and the incident is in
			// the events and the log.
			name: "digest mismatch", err: proxy.ErrDigestMismatch, want: registry.ErrUpstreamUnavailable,
		},
		{
			// A configuration problem, not a missing image: reported so a
			// client retries rather than caching a not-found.
			name: "credentials refused", err: proxy.ErrUnauthorized, want: registry.ErrUpstreamUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t, dockerHubConfig)
			env.filler.manifestErr = tc.err
			env.filler.blobErr = tc.err
			env.filler.resolveErr = tc.err
			server := env.server()

			_, err := server.Manifest(context.Background(), "hub/nginx", "1.27")
			if !errors.Is(err, tc.want) {
				t.Errorf("manifest by tag: %v, want %v", err, tc.want)
			}
			_, err = server.Manifest(context.Background(), "hub/nginx", manifestResult(false).Digest.String())
			if !errors.Is(err, tc.want) {
				t.Errorf("manifest by digest: %v, want %v", err, tc.want)
			}
			_, err = server.Blob(context.Background(), "hub/nginx", manifestResult(false).Digest)
			if !errors.Is(err, tc.want) {
				t.Errorf("blob: %v, want %v", err, tc.want)
			}
		})
	}
}

// TestAnUnclassifiedFailureIsNotSwallowed: anything outside the closed set
// reaches the handler as itself, which renders it as an internal error. A
// failure nobody classified is a bug, and turning it into a 404 would hide it.
func TestAnUnclassifiedFailureIsNotSwallowed(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	env.filler.manifestErr = io.ErrUnexpectedEOF
	env.filler.tag = proxy.TagResolution{Digest: manifestResult(false).Digest}

	_, err := env.server().Manifest(context.Background(), "hub/nginx", "1.27")
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error = %v, want the failure as it was", err)
	}
	for _, classified := range []error{
		registry.ErrContentUnknown, registry.ErrUpstreamThrottled, registry.ErrUpstreamUnavailable,
	} {
		if errors.Is(err, classified) {
			t.Errorf("an unclassified failure was reported as %v", classified)
		}
	}
}

// TestARepositoryThatIsNotAProxyIsRefused: the dispatcher only sends proxies
// here, so this is a wiring error rather than a client's -- and it is checked
// anyway, because this is the function that decides which upstream to contact.
func TestARepositoryThatIsNotAProxyIsRefused(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	if _, err := env.meta.CreateRepository(context.Background(), meta.Repository{
		Name: "team-a", Type: meta.Hosted, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	_, err := env.server().Manifest(context.Background(), "team-a/api", "v1")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Errorf("error = %v, want ErrContentUnknown", err)
	}
}

// TestAnUnknownRepositoryIsAbsent, not an error: it is the same answer the
// hosted path gives, and for the same reason.
func TestAnUnknownRepositoryIsAbsent(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	_, err := env.server().Manifest(context.Background(), "ghost/app", "v1")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Errorf("error = %v, want ErrContentUnknown", err)
	}
}

// TestAClientThatCannotBeBuiltIsNotAMissingRepository: an unreadable
// credential or an unusable upstream URL is an operator's problem, and
// reporting it as a 404 would hide the one failure that needs somebody to act.
func TestAClientThatCannotBeBuiltIsNotAMissingRepository(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	broken := errors.New("the keyfile could not be read")
	server := env.server(func(o *proxyserve.Options) { o.Clients = fakeClients{err: broken} })

	_, err := server.Manifest(context.Background(), "hub/nginx", "1.27")
	if !errors.Is(err, broken) {
		t.Fatalf("error = %v, want the client failure", err)
	}
	if errors.Is(err, registry.ErrContentUnknown) {
		t.Error("a configuration failure was reported as a missing repository")
	}
}

// failingStore reports a store that cannot be read.
type failingStore struct{ err error }

func (f failingStore) GetRepository(context.Context, string) (meta.Repository, error) {
	return meta.Repository{}, f.err
}

// TestAStoreThatCannotBeReadIsNotAMissingRepository: a broken metadata store
// must not read as "no such image". A client that cached that not-found would
// keep failing after the store recovered.
func TestAStoreThatCannotBeReadIsNotAMissingRepository(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	broken := errors.New("the database is not answering")
	server := env.server(func(o *proxyserve.Options) { o.Meta = failingStore{err: broken} })

	_, err := server.Manifest(context.Background(), "hub/nginx", "1.27")
	if !errors.Is(err, broken) {
		t.Fatalf("error = %v, want the store's failure", err)
	}
	if errors.Is(err, registry.ErrContentUnknown) {
		t.Error("a store failure was reported as a missing repository")
	}
}

// TestBlobsRefuseTheSameThingsManifestsDo: the target is built the same way for
// both, so a blob request against an unknown repository must not reach the
// filler either.
func TestBlobsRefuseTheSameThingsManifestsDo(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	_, err := env.server().Blob(context.Background(), "ghost/app", blob.FromBytes(blob.SHA256, []byte("x")))
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Errorf("error = %v, want ErrContentUnknown", err)
	}
	if tags, digests := env.filler.calls(); len(tags)+len(digests) != 0 {
		t.Errorf("an unknown repository reached the filler: %v %v", tags, digests)
	}
}

// TestAnUnusableContentNameNeverBecomesAnUpstreamPath. The handler validated
// the name before it decided anything, so this is unreachable from a request
// -- and it fails closed anyway, because this is the function that builds the
// path a request would be sent to.
func TestAnUnusableContentNameNeverBecomesAnUpstreamPath(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	for _, name := range []string{"UPPER/case", "hub/../escape", "", "hub/a b"} {
		_, err := env.server().Manifest(context.Background(), name, "v1")
		if !errors.Is(err, registry.ErrContentUnknown) {
			t.Errorf("Manifest(%q) = %v, want ErrContentUnknown", name, err)
		}
	}
	if tags, digests := env.filler.calls(); len(tags)+len(digests) != 0 {
		t.Errorf("an unusable name reached the filler: %v %v", tags, digests)
	}
}

// TestAConfigurationRowNothingValidatedIsRefused: the admin API validates what
// it stores (C-001), so a row that does not parse was hand-edited or came from
// a botched migration. It is refused rather than half-interpreted -- an
// upstream guessed from a broken row is a request sent somewhere nobody chose.
func TestAConfigurationRowNothingValidatedIsRefused(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		config string
	}{
		{name: "not JSON", config: `{"upstream":`},
		{name: "no upstream", config: `{}`},
		{name: "an upstream that is not a URL", config: `{"upstream":"::::"}`},
		{name: "an unparseable TTL", config: `{"upstream":"https://ghcr.io","tag_ttl":"soon"}`},
		{name: "a routing pattern that is not one", config: `{"upstream":"https://ghcr.io","allow":["*/middle/*"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t, tc.config)
			_, err := env.server().Manifest(context.Background(), "hub/nginx", "1.27")
			if err == nil {
				t.Fatal("a configuration nothing validated was accepted")
			}
			// Not a missing repository: the repository is there and its
			// configuration is wrong, which is an operator's problem and needs
			// to look like one.
			if errors.Is(err, registry.ErrContentUnknown) {
				t.Errorf("a broken configuration was reported as a missing repository: %v", err)
			}
			if tags, digests := env.filler.calls(); len(tags)+len(digests) != 0 {
				t.Errorf("a broken configuration reached the filler: %v %v", tags, digests)
			}
		})
	}
}

// TestAServerBuildsOnItsDefaults: only the three required options.
func TestAServerBuildsOnItsDefaults(t *testing.T) {
	t.Parallel()

	env := newEnv(t, dockerHubConfig)
	env.filler.manifest = manifestResult(false)
	env.filler.tag = proxy.TagResolution{Digest: env.filler.manifest.Digest}

	server, err := proxyserve.New(proxyserve.Options{
		Meta: env.meta, Clients: fakeClients{}, Filler: env.filler,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := server.Manifest(context.Background(), "hub/nginx", "1.27"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// With no defaults supplied, a zero tag TTL means revalidate every pull --
	// the conservative reading, not a missing value the package fills in.
	if got := env.filler.lastTarget(t).TagTTL; got != 0 {
		t.Errorf("tag TTL = %v, want zero: unset means revalidate every pull", got)
	}
}
