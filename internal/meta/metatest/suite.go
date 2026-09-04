// Package metatest is the contract suite for meta.Store. Every implementation
// runs the same suite unmodified: the SQLite store, the Postgres store, and the
// in-memory reference implementation. A behaviour that is not asserted here is
// not part of the contract, and an implementation that passes here is
// substitutable for any other.
package metatest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// Factory builds a fresh, empty store for one test. The returned store is
// closed by the suite.
type Factory func(t *testing.T) meta.Store

// suiteCase is one contract case: a name and the assertions it makes against a
// freshly built store.
type suiteCase struct {
	name string
	run  func(t *testing.T, s meta.Store)
}

// Run executes the whole contract suite against the implementation built by f.
func Run(t *testing.T, f Factory) {
	t.Helper()

	tests := []suiteCase{
		{"RepositoryCRUD", testRepositoryCRUD},
		{"RepositoryConflict", testRepositoryConflict},
		{"RepositoryValidation", testRepositoryValidation},
		{"RepositoryOptimisticConcurrency", testRepositoryOptimisticConcurrency},
		{"RepositoryConfigIsCopied", testRepositoryConfigIsCopied},
		{"ConfigHistoryRecordsTheSupersededRevision", testConfigHistoryRecordsTheSupersededRevision},
		{"ConfigHistoryAccumulatesInVersionOrder", testConfigHistoryAccumulatesInVersionOrder},
		{"ConfigHistoryDiesWithTheRepository", testConfigHistoryDiesWithTheRepository},
		{"ListRepositoriesFiltersByVisibility", testListRepositoriesFiltersByVisibility},
		{"ListRepositoriesPaginates", testListRepositoriesPaginates},
		{"ListRepositoriesPaginatesUnderFiltering", testListRepositoriesPaginatesUnderFiltering},
		{"ListRepositoriesCursorIsStableUnderWrites", testListRepositoriesCursorIsStableUnderWrites},
		{"ListRepositoriesPageLimits", testListRepositoriesPageLimits},
		{"GroupMembership", testGroupMembership},
		{"GroupMembershipRules", testGroupMembershipRules},
		{"ManifestCRUD", testManifestCRUD},
		{"ContentLivesUnderItsEntity", testContentLivesUnderItsEntity},
		{"ManifestRefs", testManifestRefs},
		{"ManifestDeleteRefusedWhileIndexed", testManifestDeleteRefusedWhileIndexed},
		{"Referrers", testReferrers},
		{"Tags", testTags},
		{"TagsRequireVisibility", testTagsRequireVisibility},
		{"TagsPaginate", testTagsPaginate},
		{"ListContentNamesFiltersByVisibility", testListContentNamesFiltersByVisibility},
		{"ListContentNamesAreDistinct", testListContentNamesAreDistinct},
		{"ListContentNamesPaginateUnderFiltering", testListContentNamesPaginateUnderFiltering},
		{"ListContentNamesCursorIsStableUnderWrites", testListContentNamesCursorIsStableUnderWrites},
		{"DeletingManifestRemovesItsTags", testDeletingManifestRemovesItsTags},
		{"Blobs", testBlobs},
		{"Uploads", testUploads},
		{"StaleUploads", testStaleUploads},
		{"PullStats", testPullStats},
		{"PullStatsEmptyBatch", testPullStatsEmptyBatch},
		{"PullStatsValidation", testPullStatsValidation},
		{"DeleteRepositoryRemovesContent", testDeleteRepositoryRemovesContent},
		{"ContextCancellation", testContextCancellation},
		{"CloseIsIdempotent", testCloseIsIdempotent},
	}
	tests = append(tests, identityTests()...)
	tests = append(tests, credentialTests()...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := f(t)
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
			tt.run(t, store)
		})
	}
}

// --- helpers ---

var testTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// updateTime is when a reconfiguration happens: distinct from testTime so a
// store that recorded the creation time instead of the caller's is visible.
var updateTime = testTime.Add(24 * time.Hour)

func ctx() context.Context { return context.Background() }

// digest builds a syntactically plausible digest. The store treats digests as
// opaque, so the exact bytes only need to be distinct.
func digest(seed string) meta.Digest {
	return meta.Digest(fmt.Sprintf("sha256:%064x", []byte(seed)[:min(len(seed), 32)]))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mustCreateRepo(t *testing.T, s meta.Store, name string, typ meta.RepositoryType) meta.Repository {
	t.Helper()

	repo, err := s.CreateRepository(ctx(), meta.Repository{
		Name:      name,
		Type:      typ,
		Config:    json.RawMessage(`{"example":true}`),
		CreatedAt: testTime,
		UpdatedAt: testTime,
	})
	if err != nil {
		t.Fatalf("CreateRepository(%q): %v", name, err)
	}
	return repo
}

// mustSeedContent stores a manifest under a full content name, creating the
// entity that name belongs to if nothing has yet. Content is keyed by the full
// name and the row it needs is the entity -- its first path segment -- so a
// test that wants content at `team-a/api` has to say `team-a` once (ADR 0005).
func mustSeedContent(t *testing.T, s meta.Store, name string) {
	t.Helper()

	entity, _, _ := strings.Cut(name, "/")
	_, err := s.GetRepository(ctx(), entity)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		mustCreateRepo(t, s, entity, meta.Hosted)
	case err != nil:
		t.Fatalf("GetRepository(%q): %v", entity, err)
	}
	mustPutManifest(t, s, name, digest("content-"+name))
}

func mustPutManifest(t *testing.T, s meta.Store, repo string, d meta.Digest, refs ...meta.ManifestRef) meta.Manifest {
	t.Helper()

	m := meta.Manifest{
		Repository: repo,
		Digest:     d,
		MediaType:  "application/vnd.oci.image.manifest.v1+json",
		Payload:    []byte(`{"schemaVersion":2}`),
		Size:       19,
		CreatedAt:  testTime,
	}
	if err := s.PutManifest(ctx(), m, refs); err != nil {
		t.Fatalf("PutManifest(%s): %v", d, err)
	}
	return m
}

func requireErrIs(t *testing.T, err, target error, what string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: got nil error, want %v", what, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want errors.Is(err, %v)", what, err, target)
	}
}

// --- repositories ---

func testRepositoryCRUD(t *testing.T, s meta.Store) {
	created := mustCreateRepo(t, s, "team-a/api", meta.Hosted)

	if created.ConfigVersion != 1 {
		t.Errorf("ConfigVersion = %d, want 1 for a new repository", created.ConfigVersion)
	}

	got, err := s.GetRepository(ctx(), "team-a/api")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if got.Name != created.Name || got.Type != meta.Hosted {
		t.Errorf("GetRepository = %+v, want name and type to round-trip", got)
	}
	if string(got.Config) != `{"example":true}` {
		t.Errorf("Config = %s, want it to round-trip", got.Config)
	}

	if err := s.DeleteRepository(ctx(), "team-a/api"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	_, err = s.GetRepository(ctx(), "team-a/api")
	requireErrIs(t, err, meta.ErrNotFound, "GetRepository after delete")

	requireErrIs(t, s.DeleteRepository(ctx(), "team-a/api"), meta.ErrNotFound, "DeleteRepository twice")
}

func testRepositoryConflict(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dup", meta.Hosted)

	_, err := s.CreateRepository(ctx(), meta.Repository{Name: "dup", Type: meta.Proxy})
	requireErrIs(t, err, meta.ErrConflict, "CreateRepository with a taken name")
}

func testRepositoryValidation(t *testing.T, s meta.Store) {
	tests := []struct {
		name string
		repo meta.Repository
	}{
		{"empty name", meta.Repository{Type: meta.Hosted}},
		{"unknown type", meta.Repository{Name: "x", Type: meta.RepositoryType("virtual")}},
		{"empty type", meta.Repository{Name: "y"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.CreateRepository(ctx(), tt.repo)
			requireErrIs(t, err, meta.ErrInvalid, "CreateRepository")
		})
	}
}

func testRepositoryOptimisticConcurrency(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "cfg", meta.Proxy)

	updated, err := s.UpdateRepositoryConfig(ctx(), "cfg", []byte(`{"ttl":"15m"}`), 1, "alice", updateTime)
	if err != nil {
		t.Fatalf("UpdateRepositoryConfig: %v", err)
	}
	if updated.ConfigVersion != 2 {
		t.Errorf("ConfigVersion = %d, want 2 after one update", updated.ConfigVersion)
	}
	if string(updated.Config) != `{"ttl":"15m"}` {
		t.Errorf("Config = %s, want the new value", updated.Config)
	}
	// The row's UpdatedAt is the time the caller supplied: a repository whose
	// configuration changed at a time nothing recorded would make the field a
	// lie, and no store reads a clock of its own (§7).
	if !updated.UpdatedAt.Equal(updateTime) {
		t.Errorf("UpdatedAt = %v, want the update's time %v", updated.UpdatedAt, updateTime)
	}

	// A second writer holding the old version must lose, not silently
	// overwrite the first writer's change.
	_, err = s.UpdateRepositoryConfig(ctx(), "cfg", []byte(`{"ttl":"1h"}`), 1, "bob", updateTime)
	requireErrIs(t, err, meta.ErrStale, "UpdateRepositoryConfig with a stale version")

	current, err := s.GetRepository(ctx(), "cfg")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if string(current.Config) != `{"ttl":"15m"}` {
		t.Errorf("Config = %s, want the stale write to have been rejected", current.Config)
	}

	_, err = s.UpdateRepositoryConfig(ctx(), "missing", []byte(`{}`), 1, "alice", updateTime)
	requireErrIs(t, err, meta.ErrNotFound, "UpdateRepositoryConfig on a missing repository")
}

// An update records the revision it *replaced*, not the one it wrote. Getting
// this backwards would be invisible in a single-update test and would make the
// whole lineage off by one: the live row already holds the new document, so a
// history that repeated it would say nothing and lose the old one.
func testConfigHistoryRecordsTheSupersededRevision(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "cfg", meta.Proxy)

	// Nothing has been superseded yet. Creation writes no revision: the live
	// row is version 1, and the lineage is the history plus that row.
	revisions, err := s.ListConfigHistory(ctx(), "cfg")
	if err != nil {
		t.Fatalf("ListConfigHistory before any update: %v", err)
	}
	if len(revisions) != 0 {
		t.Fatalf("history after create = %+v, want none", revisions)
	}

	if _, err := s.UpdateRepositoryConfig(ctx(), "cfg", []byte(`{"ttl":"15m"}`), 1, "alice", updateTime); err != nil {
		t.Fatalf("UpdateRepositoryConfig: %v", err)
	}

	revisions, err = s.ListConfigHistory(ctx(), "cfg")
	if err != nil {
		t.Fatalf("ListConfigHistory: %v", err)
	}
	if len(revisions) != 1 {
		t.Fatalf("history = %+v, want exactly the one superseded revision", revisions)
	}
	got := revisions[0]
	if got.Repository != "cfg" || got.Version != 1 {
		t.Errorf("revision = %s@%d, want cfg@1: the version replaced, not the one written",
			got.Repository, got.Version)
	}
	if string(got.Config) != `{"example":true}` {
		t.Errorf("revision config = %s, want the document that was replaced", got.Config)
	}
	if got.Actor != "alice" {
		t.Errorf("revision actor = %q, want the subject that replaced it", got.Actor)
	}
	if !got.At.Equal(updateTime) {
		t.Errorf("revision time = %v, want the caller's %v", got.At, updateTime)
	}

	// A rejected write leaves no trace: the stale update below must not add a
	// revision for a change that never happened.
	_, err = s.UpdateRepositoryConfig(ctx(), "cfg", []byte(`{"ttl":"1h"}`), 1, "bob", updateTime)
	requireErrIs(t, err, meta.ErrStale, "UpdateRepositoryConfig with a stale version")
	revisions, err = s.ListConfigHistory(ctx(), "cfg")
	if err != nil {
		t.Fatalf("ListConfigHistory after a stale write: %v", err)
	}
	if len(revisions) != 1 {
		t.Errorf("history = %+v, want the refused write to have added nothing", revisions)
	}
}

// Two updates give two revisions, oldest first, and the live row holds the
// third document. The order is contract: a support bundle reads this as a
// timeline, and an unordered answer would read as one.
func testConfigHistoryAccumulatesInVersionOrder(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "cfg", meta.Proxy)

	if _, err := s.UpdateRepositoryConfig(ctx(), "cfg", []byte(`{"ttl":"15m"}`), 1, "alice", updateTime); err != nil {
		t.Fatalf("first UpdateRepositoryConfig: %v", err)
	}
	later := updateTime.Add(time.Hour)
	if _, err := s.UpdateRepositoryConfig(ctx(), "cfg", []byte(`{"ttl":"1h"}`), 2, "bob", later); err != nil {
		t.Fatalf("second UpdateRepositoryConfig: %v", err)
	}

	revisions, err := s.ListConfigHistory(ctx(), "cfg")
	if err != nil {
		t.Fatalf("ListConfigHistory: %v", err)
	}
	if len(revisions) != 2 {
		t.Fatalf("history = %+v, want two revisions", revisions)
	}
	want := []meta.ConfigRevision{
		{Repository: "cfg", Version: 1, Config: []byte(`{"example":true}`), Actor: "alice", At: updateTime},
		{Repository: "cfg", Version: 2, Config: []byte(`{"ttl":"15m"}`), Actor: "bob", At: later},
	}
	for i, w := range want {
		got := revisions[i]
		if got.Version != w.Version || string(got.Config) != string(w.Config) ||
			got.Actor != w.Actor || !got.At.Equal(w.At) {
			t.Errorf("revision %d = %+v, want %+v", i, got, w)
		}
	}

	current, err := s.GetRepository(ctx(), "cfg")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if current.ConfigVersion != 3 || string(current.Config) != `{"ttl":"1h"}` {
		t.Errorf("live row = v%d %s, want v3 with the newest document",
			current.ConfigVersion, current.Config)
	}
}

// History dies with the entity, and a name recreated afterwards starts clean.
// Inheriting a predecessor's lineage would attribute somebody else's upstreams
// to a repository that never had them -- and for a proxy that is a disclosure,
// not just an inaccuracy.
func testConfigHistoryDiesWithTheRepository(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "cfg", meta.Proxy)
	mustCreateRepo(t, s, "bystander", meta.Proxy)
	for _, name := range []string{"cfg", "bystander"} {
		if _, err := s.UpdateRepositoryConfig(ctx(), name, []byte(`{"ttl":"15m"}`), 1, "alice", updateTime); err != nil {
			t.Fatalf("UpdateRepositoryConfig(%q): %v", name, err)
		}
	}

	if err := s.DeleteRepository(ctx(), "cfg"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	revisions, err := s.ListConfigHistory(ctx(), "cfg")
	if err != nil {
		t.Fatalf("ListConfigHistory after delete: %v", err)
	}
	if len(revisions) != 0 {
		t.Errorf("history = %+v, want the lineage deleted with the entity", revisions)
	}

	// The neighbour's lineage is untouched: deletion is per entity.
	if revisions, err = s.ListConfigHistory(ctx(), "bystander"); err != nil {
		t.Fatalf("ListConfigHistory(bystander): %v", err)
	}
	if len(revisions) != 1 {
		t.Errorf("bystander history = %+v, want its one revision intact", revisions)
	}

	// Recreated at the same name, and starting from nothing.
	mustCreateRepo(t, s, "cfg", meta.Hosted)
	if revisions, err = s.ListConfigHistory(ctx(), "cfg"); err != nil {
		t.Fatalf("ListConfigHistory after recreate: %v", err)
	}
	if len(revisions) != 0 {
		t.Errorf("history = %+v, want a recreated entity to inherit nothing", revisions)
	}
}

func testRepositoryConfigIsCopied(t *testing.T, s meta.Store) {
	original := []byte(`{"mutate":"me"}`)
	if _, err := s.CreateRepository(ctx(), meta.Repository{
		Name: "copy", Type: meta.Hosted, Config: original,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	// Mutating the caller's slice must not reach stored state, and neither
	// must mutating a returned one: a database hands back a fresh copy.
	original[2] = 'X'

	got, err := s.GetRepository(ctx(), "copy")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if string(got.Config) != `{"mutate":"me"}` {
		t.Errorf("Config = %s, want the store to be unaffected by caller mutation", got.Config)
	}

	got.Config[2] = 'Y'
	again, err := s.GetRepository(ctx(), "copy")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if string(again.Config) != `{"mutate":"me"}` {
		t.Errorf("Config = %s, want mutation of a returned value to be harmless", again.Config)
	}
}

func testListRepositoriesFiltersByVisibility(t *testing.T, s meta.Store) {
	for _, name := range []string{"team-a/api", "team-a/web", "team-b/api", "public/nginx"} {
		mustCreateRepo(t, s, name, meta.Hosted)
	}

	tests := []struct {
		name       string
		visibility meta.Visibility
		want       []string
	}{
		{
			name:       "unrestricted sees everything",
			visibility: meta.Unrestricted(),
			want:       []string{"public/nginx", "team-a/api", "team-a/web", "team-b/api"},
		},
		{
			name:       "prefix scope",
			visibility: meta.VisibleTo(meta.ScopeFilter{Prefix: "team-a/"}),
			want:       []string{"team-a/api", "team-a/web"},
		},
		{
			name:       "exact scope",
			visibility: meta.VisibleTo(meta.ScopeFilter{Exact: "team-b/api"}),
			want:       []string{"team-b/api"},
		},
		{
			name:       "union of scopes",
			visibility: meta.VisibleTo(meta.ScopeFilter{Exact: "public/nginx"}, meta.ScopeFilter{Prefix: "team-b/"}),
			want:       []string{"public/nginx", "team-b/api"},
		},
		{
			name:       "wildcard scope",
			visibility: meta.VisibleTo(meta.ScopeFilter{All: true}),
			want:       []string{"public/nginx", "team-a/api", "team-a/web", "team-b/api"},
		},
		{
			// A subject with no bindings sees nothing. This is the case a nil
			// slice would have turned into "everything".
			name:       "no scopes sees nothing",
			visibility: meta.VisibleTo(),
			want:       nil,
		},
		{
			name:       "zero value sees nothing",
			visibility: meta.Visibility{},
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := s.ListRepositories(ctx(), meta.ListOptions{Visibility: tt.visibility})
			if err != nil {
				t.Fatalf("ListRepositories: %v", err)
			}

			var got []string
			for _, r := range page.Repositories {
				got = append(got, r.Name)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v (ordered by name)", got, tt.want)
				}
			}
		})
	}
}

func testListRepositoriesPaginates(t *testing.T, s meta.Store) {
	const total = 7
	for i := 0; i < total; i++ {
		mustCreateRepo(t, s, fmt.Sprintf("repo-%02d", i), meta.Hosted)
	}

	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("pagination did not terminate")
		}
		page, err := s.ListRepositories(ctx(), meta.ListOptions{
			Visibility: meta.Unrestricted(),
			Limit:      3,
			Cursor:     cursor,
		})
		if err != nil {
			t.Fatalf("ListRepositories: %v", err)
		}
		for _, r := range page.Repositories {
			seen = append(seen, r.Name)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(seen) != total {
		t.Fatalf("stitched pages returned %d repositories, want %d: %v", len(seen), total, seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("pages are not strictly ordered, or repeat: %v", seen)
		}
	}
}

func testListRepositoriesPaginatesUnderFiltering(t *testing.T, s meta.Store) {
	// Hidden repositories interleave with visible ones in name order, so page
	// boundaries fall beside rows the filter removes. A store that fetched a
	// page and filtered afterwards would show up here as a short page, a
	// duplicate, or a cursor naming a repository the subject cannot see -- the
	// count-and-pagination leak ADR 0003 forbids (Z-012).
	visible := []string{"team-a/api", "team-a/web", "team-c/api", "team-c/cli", "team-c/web", "zz-solo"}
	hidden := []string{"aaa-first", "team-a", "team-ab/api", "team-b/api", "team-b/web", "zz-solo-2", "zzz-last"}
	for _, name := range append(append([]string{}, visible...), hidden...) {
		mustCreateRepo(t, s, name, meta.Hosted)
	}
	vis := meta.VisibleTo(
		meta.ScopeFilter{Prefix: "team-a/"},
		meta.ScopeFilter{Prefix: "team-c/"},
		meta.ScopeFilter{Exact: "zz-solo"},
	)

	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > len(visible) {
			t.Fatal("pagination did not terminate")
		}
		page, err := s.ListRepositories(ctx(), meta.ListOptions{Visibility: vis, Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListRepositories: %v", err)
		}
		if len(page.Repositories) > 2 {
			t.Fatalf("page of %d repositories, want at most the limit of 2", len(page.Repositories))
		}
		for _, r := range page.Repositories {
			seen = append(seen, r.Name)
		}
		if page.NextCursor == "" {
			break
		}
		// The cursor is part of the response. One naming a hidden repository
		// would disclose it as surely as listing it.
		if !vis.Allows(page.NextCursor) {
			t.Fatalf("NextCursor %q names a repository the subject cannot see", page.NextCursor)
		}
		cursor = page.NextCursor
	}

	if fmt.Sprint(seen) != fmt.Sprint(visible) {
		t.Fatalf("stitched pages = %v, want exactly the visible set %v", seen, visible)
	}
}

func testListRepositoriesCursorIsStableUnderWrites(t *testing.T, s meta.Store) {
	// Cursors are keyset, not offset (ADR 0015): rows created behind the
	// cursor are not revisited and rows created ahead of it appear, but a page
	// walk never repeats or skips what already existed. The visibility names
	// repositories that do not exist yet, which is fine -- a binding's scope
	// is independent of what has been created under it.
	vis := meta.VisibleTo(
		meta.ScopeFilter{Exact: "r-00"}, meta.ScopeFilter{Exact: "r-01"},
		meta.ScopeFilter{Exact: "r-03"}, meta.ScopeFilter{Exact: "r-05"},
		meta.ScopeFilter{Exact: "r-07"},
	)
	for i := 1; i <= 6; i++ {
		mustCreateRepo(t, s, fmt.Sprintf("r-%02d", i), meta.Hosted)
	}

	first, err := s.ListRepositories(ctx(), meta.ListOptions{Visibility: vis, Limit: 1})
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(first.Repositories) != 1 || first.Repositories[0].Name != "r-01" || first.NextCursor != "r-01" {
		t.Fatalf("first page = %+v, want [r-01] with cursor r-01", first)
	}

	// Writes land mid-walk: a visible repository behind the cursor, a hidden
	// one between the remaining pages, and a visible one past the end.
	mustCreateRepo(t, s, "r-00", meta.Hosted)
	mustCreateRepo(t, s, "r-04x", meta.Hosted)
	mustCreateRepo(t, s, "r-07", meta.Hosted)

	seen := []string{first.Repositories[0].Name}
	cursor := first.NextCursor
	for pages := 0; cursor != ""; pages++ {
		if pages > 8 {
			t.Fatal("pagination did not terminate")
		}
		page, err := s.ListRepositories(ctx(), meta.ListOptions{Visibility: vis, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListRepositories: %v", err)
		}
		for _, r := range page.Repositories {
			seen = append(seen, r.Name)
		}
		cursor = page.NextCursor
	}

	// r-00 was created behind the cursor, so this walk legitimately misses
	// it; r-04x is not visible; r-07 was created ahead and appears.
	want := []string{"r-01", "r-03", "r-05", "r-07"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("stitched pages = %v, want %v: no repeats, no skips of what existed, nothing hidden", seen, want)
	}
}

func testListRepositoriesPageLimits(t *testing.T, s meta.Store) {
	for i := 0; i < 3; i++ {
		mustCreateRepo(t, s, fmt.Sprintf("r%d", i), meta.Hosted)
	}

	// A limit above the cap must be clamped, not honoured, and zero must mean
	// the default rather than "none".
	for _, limit := range []int{0, -1, meta.MaxPageSize + 1} {
		page, err := s.ListRepositories(ctx(), meta.ListOptions{
			Visibility: meta.Unrestricted(),
			Limit:      limit,
		})
		if err != nil {
			t.Fatalf("ListRepositories(limit=%d): %v", limit, err)
		}
		if len(page.Repositories) != 3 {
			t.Errorf("limit=%d returned %d repositories, want all 3", limit, len(page.Repositories))
		}
	}
}

func testGroupMembership(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "hosted-1", meta.Hosted)
	mustCreateRepo(t, s, "proxy-1", meta.Proxy)
	mustCreateRepo(t, s, "all", meta.Group)

	members := []meta.GroupMember{
		{Repository: "proxy-1", Position: 2},
		{Repository: "hosted-1", Position: 1, WriteTarget: true},
	}
	if err := s.SetGroupMembers(ctx(), "all", members); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}

	got, err := s.ListGroupMembers(ctx(), "all")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d members, want 2", len(got))
	}
	// Resolution order is first-match-wins, so the list must come back sorted
	// by position regardless of the order it was written in.
	if got[0].Repository != "hosted-1" || got[1].Repository != "proxy-1" {
		t.Errorf("members = %+v, want them ordered by position", got)
	}
	if !got[0].WriteTarget {
		t.Error("write target flag did not round-trip")
	}

	// Replacing the list is wholesale, not additive.
	if err := s.SetGroupMembers(ctx(), "all", []meta.GroupMember{{Repository: "proxy-1", Position: 1}}); err != nil {
		t.Fatalf("SetGroupMembers (replace): %v", err)
	}
	got, err = s.ListGroupMembers(ctx(), "all")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(got) != 1 || got[0].Repository != "proxy-1" {
		t.Errorf("members = %+v, want the list replaced", got)
	}
}

func testGroupMembershipRules(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "h1", meta.Hosted)
	mustCreateRepo(t, s, "h2", meta.Hosted)
	mustCreateRepo(t, s, "g1", meta.Group)
	mustCreateRepo(t, s, "g2", meta.Group)

	tests := []struct {
		name    string
		group   string
		members []meta.GroupMember
		want    error
	}{
		{
			name:    "missing group",
			group:   "nope",
			members: nil,
			want:    meta.ErrNotFound,
		},
		{
			name:    "not a group",
			group:   "h1",
			members: nil,
			want:    meta.ErrInvalid,
		},
		{
			name:    "missing member",
			group:   "g1",
			members: []meta.GroupMember{{Repository: "ghost", Position: 1}},
			want:    meta.ErrNotFound,
		},
		{
			name:    "self membership",
			group:   "g1",
			members: []meta.GroupMember{{Repository: "g1", Position: 1}},
			want:    meta.ErrInvalid,
		},
		{
			name:    "nested group",
			group:   "g1",
			members: []meta.GroupMember{{Repository: "g2", Position: 1}},
			want:    meta.ErrInvalid,
		},
		{
			// Ties in resolution order are an error, not a coin flip.
			name:  "duplicate position",
			group: "g1",
			members: []meta.GroupMember{
				{Repository: "h1", Position: 1},
				{Repository: "h2", Position: 1},
			},
			want: meta.ErrInvalid,
		},
		{
			name:  "two write targets",
			group: "g1",
			members: []meta.GroupMember{
				{Repository: "h1", Position: 1, WriteTarget: true},
				{Repository: "h2", Position: 2, WriteTarget: true},
			},
			want: meta.ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.SetGroupMembers(ctx(), tt.group, tt.members)
			requireErrIs(t, err, tt.want, "SetGroupMembers")
		})
	}

	if _, err := s.ListGroupMembers(ctx(), "nope"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("ListGroupMembers on a missing repository = %v, want ErrNotFound", err)
	}
}

// --- content ---

func testManifestCRUD(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)
	d := digest("manifest-one")

	mustPutManifest(t, s, "repo", d)

	got, err := s.GetManifest(ctx(), "repo", d)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got.Digest != d || string(got.Payload) != `{"schemaVersion":2}` {
		t.Errorf("manifest = %+v, want it to round-trip", got)
	}

	// Manifests are per repository: the same digest elsewhere is a miss.
	mustCreateRepo(t, s, "other", meta.Hosted)
	_, err = s.GetManifest(ctx(), "other", d)
	requireErrIs(t, err, meta.ErrNotFound, "GetManifest in another repository")

	if err := s.DeleteManifest(ctx(), "repo", d); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	requireErrIs(t, s.DeleteManifest(ctx(), "repo", d), meta.ErrNotFound, "DeleteManifest twice")

	err = s.PutManifest(ctx(), meta.Manifest{Repository: "ghost", Digest: d}, nil)
	requireErrIs(t, err, meta.ErrNotFound, "PutManifest into a missing entity")

	err = s.PutManifest(ctx(), meta.Manifest{Repository: "repo"}, nil)
	requireErrIs(t, err, meta.ErrInvalid, "PutManifest without a digest")
}

// A repository entity is mounted at the first path segment of a name, so the
// entity `team-a` holds `team-a/api` and there is never a row named
// `team-a/api` for it to hold (ADR 0005). Every write therefore checks the
// entity, and this is the case that says so: with one entity row and nothing
// else, content lands under a remainder, under a deeper remainder, and under
// the bare entity name -- and refuses when the entity is the thing that is
// missing.
func testContentLivesUnderItsEntity(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	// A neighbour whose name merely starts the same way, so nothing below can
	// pass by matching a prefix rather than a path segment.
	mustCreateRepo(t, s, "team-alpha", meta.Hosted)

	for _, name := range []string{"team-a", "team-a/api", "team-a/deep/nested/name"} {
		t.Run(name, func(t *testing.T) {
			d := digest("entity-" + name)
			mustPutManifest(t, s, name, d)

			got, err := s.GetManifest(ctx(), name, d)
			if err != nil {
				t.Fatalf("GetManifest(%q): %v", name, err)
			}
			if got.Repository != name {
				t.Errorf("manifest came back under %q, want the full name %q", got.Repository, name)
			}
			if err := s.PutTag(ctx(), meta.Tag{Repository: name, Name: "v1", Digest: d}); err != nil {
				t.Errorf("PutTag(%q): %v", name, err)
			}
			if err := s.CreateUpload(ctx(), meta.UploadSession{
				ID: "upload-" + name, Repository: name, StartedAt: testTime, LastChunkAt: testTime,
			}); err != nil {
				t.Errorf("CreateUpload(%q): %v", name, err)
			}
		})
	}

	// The entity is what has to exist, and what the refusal names: `ghost` is
	// absent, so nothing under it can be written.
	for _, name := range []string{"ghost", "ghost/api"} {
		requireErrIs(t, s.PutManifest(ctx(), meta.Manifest{Repository: name, Digest: digest("no")}, nil),
			meta.ErrNotFound, "PutManifest under the absent entity "+name)
		requireErrIs(t, s.PutTag(ctx(), meta.Tag{Repository: name, Name: "v1", Digest: digest("no")}),
			meta.ErrNotFound, "PutTag under the absent entity "+name)
		requireErrIs(t, s.CreateUpload(ctx(), meta.UploadSession{ID: "u-" + name, Repository: name}),
			meta.ErrNotFound, "CreateUpload under the absent entity "+name)
	}
}

func testManifestRefs(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	d := digest("with-refs")
	refs := []meta.ManifestRef{
		{Child: digest("config-blob"), Kind: meta.RefConfig},
		{Child: digest("layer-blob"), Kind: meta.RefLayer},
	}
	mustPutManifest(t, s, "repo", d, refs...)

	got, err := s.ListManifestRefs(ctx(), "repo", d)
	if err != nil {
		t.Fatalf("ListManifestRefs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d refs, want 2 -- GC reachability depends on these", len(got))
	}

	_, err = s.ListManifestRefs(ctx(), "repo", digest("absent"))
	requireErrIs(t, err, meta.ErrNotFound, "ListManifestRefs for a missing manifest")

	// Invalid edges are rejected: a bad reference kind would silently break
	// the reachability walk.
	err = s.PutManifest(ctx(), meta.Manifest{Repository: "repo", Digest: digest("bad")},
		[]meta.ManifestRef{{Child: digest("x"), Kind: meta.RefKind("sideways")}})
	requireErrIs(t, err, meta.ErrInvalid, "PutManifest with an unknown ref kind")

	err = s.PutManifest(ctx(), meta.Manifest{Repository: "repo", Digest: digest("bad2")},
		[]meta.ManifestRef{{Kind: meta.RefLayer}})
	requireErrIs(t, err, meta.ErrInvalid, "PutManifest with an empty ref digest")
}

func testManifestDeleteRefusedWhileIndexed(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	child := digest("child-amd64")
	index := digest("multi-arch-index")

	mustPutManifest(t, s, "repo", child)
	mustPutManifest(t, s, "repo", index, meta.ManifestRef{Child: child, Kind: meta.RefChild})

	parents, err := s.ListIndexParents(ctx(), "repo", child)
	if err != nil {
		t.Fatalf("ListIndexParents: %v", err)
	}
	if len(parents) != 1 || parents[0] != index {
		t.Fatalf("parents = %v, want the index", parents)
	}

	// Q10: deleting a child while an index references it is an error, and the
	// error names the index so an operator knows what to delete first.
	err = s.DeleteManifest(ctx(), "repo", child)
	requireErrIs(t, err, meta.ErrReferenced, "DeleteManifest on an indexed child")

	var refErr *meta.ReferencedError
	if !errors.As(err, &refErr) {
		t.Fatalf("error type = %T, want *meta.ReferencedError carrying the parents", err)
	}
	if len(refErr.By) != 1 || refErr.By[0] != string(index) {
		t.Errorf("referenced by %v, want the index digest", refErr.By)
	}

	// Deleting the index first releases the child.
	if err := s.DeleteManifest(ctx(), "repo", index); err != nil {
		t.Fatalf("DeleteManifest(index): %v", err)
	}
	if err := s.DeleteManifest(ctx(), "repo", child); err != nil {
		t.Fatalf("DeleteManifest(child) after the index went: %v", err)
	}
}

func testReferrers(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	subject := digest("image")
	mustPutManifest(t, s, "repo", subject)

	sbom := meta.Manifest{
		Repository:   "repo",
		Digest:       digest("sbom"),
		MediaType:    "application/vnd.oci.image.manifest.v1+json",
		ArtifactType: "application/spdx+json",
		Subject:      subject,
		CreatedAt:    testTime,
	}
	signature := meta.Manifest{
		Repository:   "repo",
		Digest:       digest("signature"),
		MediaType:    "application/vnd.oci.image.manifest.v1+json",
		ArtifactType: "application/vnd.dev.cosign.simplesigning.v1+json",
		Subject:      subject,
		CreatedAt:    testTime,
	}
	for _, m := range []meta.Manifest{sbom, signature} {
		if err := s.PutManifest(ctx(), m, []meta.ManifestRef{{Child: subject, Kind: meta.RefSubject}}); err != nil {
			t.Fatalf("PutManifest(referrer): %v", err)
		}
	}

	all, err := s.ListReferrers(ctx(), "repo", subject, "")
	if err != nil {
		t.Fatalf("ListReferrers: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d referrers, want 2", len(all))
	}
	// Ordered by digest: the interface promises it, because the rendered
	// referrers index is golden-tested and must not depend on the engine.
	if all[0].Digest > all[1].Digest {
		t.Errorf("referrers out of digest order: %s before %s", all[0].Digest, all[1].Digest)
	}

	filtered, err := s.ListReferrers(ctx(), "repo", subject, "application/spdx+json")
	if err != nil {
		t.Fatalf("ListReferrers(filtered): %v", err)
	}
	if len(filtered) != 1 || filtered[0].Digest != sbom.Digest {
		t.Errorf("filtered referrers = %+v, want only the SBOM", filtered)
	}

	// A subject with no attachments lists empty rather than failing: the
	// referrers API returns an empty index for a readable subject.
	none, err := s.ListReferrers(ctx(), "repo", digest("unattached"), "")
	if err != nil {
		t.Fatalf("ListReferrers(no referrers): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("got %d referrers, want none", len(none))
	}
}

func testTags(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)
	first := digest("v1")
	second := digest("v2")
	mustPutManifest(t, s, "repo", first)
	mustPutManifest(t, s, "repo", second)

	tag := meta.Tag{Repository: "repo", Name: "latest", Digest: first, CreatedAt: testTime, UpdatedAt: testTime}
	if err := s.PutTag(ctx(), tag); err != nil {
		t.Fatalf("PutTag: %v", err)
	}

	got, err := s.GetTag(ctx(), "repo", "latest")
	if err != nil {
		t.Fatalf("GetTag: %v", err)
	}
	if got.Digest != first {
		t.Errorf("tag points at %s, want %s", got.Digest, first)
	}

	// Repointing a tag is normal: tags are mutable, digests are not.
	tag.Digest = second
	if err := s.PutTag(ctx(), tag); err != nil {
		t.Fatalf("PutTag (repoint): %v", err)
	}
	got, err = s.GetTag(ctx(), "repo", "latest")
	if err != nil {
		t.Fatalf("GetTag: %v", err)
	}
	if got.Digest != second {
		t.Errorf("tag points at %s, want %s after repointing", got.Digest, second)
	}

	requireErrIs(t, s.PutTag(ctx(), meta.Tag{Repository: "repo", Name: "x", Digest: digest("ghost")}),
		meta.ErrNotFound, "PutTag pointing at a missing manifest")
	requireErrIs(t, s.PutTag(ctx(), meta.Tag{Repository: "ghost", Name: "x", Digest: first}),
		meta.ErrNotFound, "PutTag in a missing repository")
	requireErrIs(t, s.PutTag(ctx(), meta.Tag{Repository: "repo", Digest: first}),
		meta.ErrInvalid, "PutTag without a name")

	if err := s.DeleteTag(ctx(), "repo", "latest"); err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	requireErrIs(t, s.DeleteTag(ctx(), "repo", "latest"), meta.ErrNotFound, "DeleteTag twice")

	// Deleting a tag leaves the manifest, which is the whole point of the
	// separation.
	if _, err := s.GetManifest(ctx(), "repo", second); err != nil {
		t.Errorf("manifest disappeared with its tag: %v", err)
	}
}

func testTagsRequireVisibility(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "secret", meta.Hosted)
	d := digest("hidden")
	mustPutManifest(t, s, "secret/repo", d)
	if err := s.PutTag(ctx(), meta.Tag{Repository: "secret/repo", Name: "v1", Digest: d}); err != nil {
		t.Fatalf("PutTag: %v", err)
	}

	// An invisible repository must be indistinguishable from a missing one,
	// including when listing its tags (ADR 0003).
	_, err := s.ListTags(ctx(), "secret/repo", meta.ListOptions{
		Visibility: meta.VisibleTo(meta.ScopeFilter{Prefix: "public/"}),
	})
	requireErrIs(t, err, meta.ErrNotFound, "ListTags on an invisible repository")

	page, err := s.ListTags(ctx(), "secret/repo", meta.ListOptions{Visibility: meta.Unrestricted()})
	if err != nil {
		t.Fatalf("ListTags with visibility: %v", err)
	}
	if len(page.Tags) != 1 {
		t.Errorf("got %d tags, want 1", len(page.Tags))
	}

	_, err = s.ListTags(ctx(), "ghost", meta.ListOptions{Visibility: meta.Unrestricted()})
	requireErrIs(t, err, meta.ErrNotFound, "ListTags on a missing repository")

	// A name inside a real entity that nobody has pushed to is absent, not an
	// empty page: a typo must not come back looking like a repository that
	// exists and happens to hold nothing.
	_, err = s.ListTags(ctx(), "secret/typo", meta.ListOptions{Visibility: meta.Unrestricted()})
	requireErrIs(t, err, meta.ErrNotFound, "ListTags on a name nobody pushed to")

	// The entity itself is always a name the registry knows -- it is an
	// endpoint whether or not anything is under it -- so it lists empty.
	entityPage, err := s.ListTags(ctx(), "secret", meta.ListOptions{Visibility: meta.Unrestricted()})
	if err != nil {
		t.Fatalf("ListTags on the bare entity: %v", err)
	}
	if len(entityPage.Tags) != 0 {
		t.Errorf("bare entity listed %d tags, want an empty page", len(entityPage.Tags))
	}
}

func testTagsPaginate(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)
	d := digest("shared")
	mustPutManifest(t, s, "repo", d)

	const total = 5
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("v%d", i)
		if err := s.PutTag(ctx(), meta.Tag{Repository: "repo", Name: name, Digest: d}); err != nil {
			t.Fatalf("PutTag(%s): %v", name, err)
		}
	}

	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("tag pagination did not terminate")
		}
		page, err := s.ListTags(ctx(), "repo", meta.ListOptions{
			Visibility: meta.Unrestricted(),
			Limit:      2,
			Cursor:     cursor,
		})
		if err != nil {
			t.Fatalf("ListTags: %v", err)
		}
		for _, tag := range page.Tags {
			seen = append(seen, tag.Name)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(seen) != total {
		t.Fatalf("stitched pages returned %d tags, want %d: %v", len(seen), total, seen)
	}
}

// contentNames stitches every page of ListContentNames under one visibility,
// asserting the properties that must hold on every page as it goes: no page
// exceeds the limit, and no cursor names something the subject cannot see.
func contentNames(t *testing.T, s meta.Store, vis meta.Visibility, limit int) []string {
	t.Helper()

	var (
		seen   []string
		cursor string
	)
	for pages := 0; ; pages++ {
		if pages > 32 {
			t.Fatal("content-name pagination did not terminate")
		}
		page, err := s.ListContentNames(ctx(), meta.ListOptions{
			Visibility: vis, Limit: limit, Cursor: cursor,
		})
		if err != nil {
			t.Fatalf("ListContentNames: %v", err)
		}
		if limit > 0 && len(page.Names) > limit {
			t.Fatalf("page of %d names, want at most the limit of %d", len(page.Names), limit)
		}
		seen = append(seen, page.Names...)
		if page.NextCursor == "" {
			return seen
		}
		// The cursor is part of the response. One naming a hidden repository
		// would disclose it as surely as listing it (ADR 0003).
		if !vis.Allows(page.NextCursor) {
			t.Fatalf("NextCursor %q names a repository the subject cannot see", page.NextCursor)
		}
		cursor = page.NextCursor
	}
}

// The catalog lists the names that hold content, and it lists them filtered.
// A repository that exists but holds nothing names no endpoint to pull from,
// so it is not content; a repository the subject cannot see is not listed at
// all, and the filter runs in the query rather than over the answer.
func testListContentNamesFiltersByVisibility(t *testing.T, s meta.Store) {
	for _, name := range []string{"team-a/api", "team-a/web", "team-b/api"} {
		mustSeedContent(t, s, name)
	}
	// An entity nobody has pushed to. It is a real endpoint and it is not a
	// content name, which is the distinction this listing draws.
	mustCreateRepo(t, s, "empty", meta.Hosted)

	tests := []struct {
		name       string
		visibility meta.Visibility
		want       []string
	}{
		{
			// "empty" has a repository row and no manifests: it is not here.
			name:       "unrestricted sees every name with content",
			visibility: meta.Unrestricted(),
			want:       []string{"team-a/api", "team-a/web", "team-b/api"},
		},
		{
			name:       "prefix scope",
			visibility: meta.VisibleTo(meta.ScopeFilter{Prefix: "team-a/"}),
			want:       []string{"team-a/api", "team-a/web"},
		},
		{
			name:       "exact scope",
			visibility: meta.VisibleTo(meta.ScopeFilter{Exact: "team-b/api"}),
			want:       []string{"team-b/api"},
		},
		{
			// A subject with no bindings sees nothing. This is the case a nil
			// filter slice would have turned into "everything".
			name:       "no scopes sees nothing",
			visibility: meta.VisibleTo(),
			want:       nil,
		},
		{
			name:       "zero value sees nothing",
			visibility: meta.Visibility{},
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contentNames(t, s, tt.visibility, 0)
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("content names = %v, want %v in lexical order", got, tt.want)
			}
		})
	}
}

// One name, however much content is under it, is one row. A catalog that
// repeated a name once per manifest would page wrongly and would leak how much
// is stored in a repository the subject can only list.
func testListContentNamesAreDistinct(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	first := digest("distinct-one")
	second := digest("distinct-two")
	mustPutManifest(t, s, "repo", first)
	mustPutManifest(t, s, "repo", second)
	for _, name := range []string{"latest", "v1"} {
		if err := s.PutTag(ctx(), meta.Tag{Repository: "repo", Name: name, Digest: first}); err != nil {
			t.Fatalf("PutTag(%s): %v", name, err)
		}
	}

	got := contentNames(t, s, meta.Unrestricted(), 0)
	if len(got) != 1 || got[0] != "repo" {
		t.Fatalf("content names = %v, want exactly one row for the one repository", got)
	}

	// Deleting one of two manifests leaves the name; deleting the last one
	// takes it, because there is then nothing to pull.
	if err := s.DeleteManifest(ctx(), "repo", first); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if got := contentNames(t, s, meta.Unrestricted(), 0); len(got) != 1 {
		t.Fatalf("content names = %v, want the name to survive its first manifest", got)
	}
	if err := s.DeleteManifest(ctx(), "repo", second); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if got := contentNames(t, s, meta.Unrestricted(), 0); len(got) != 0 {
		t.Fatalf("content names = %v, want none once the repository holds no content", got)
	}
}

// Hidden names interleave with visible ones and sit at the page boundaries
// themselves, so a store that fetched a page and filtered afterwards shows up
// as a short page, a repeat, or a cursor naming something hidden -- the
// count-and-pagination leak ADR 0003 forbids.
func testListContentNamesPaginateUnderFiltering(t *testing.T, s meta.Store) {
	visible := []string{"team-a/api", "team-a/web", "team-c/api", "team-c/cli", "team-c/web", "zz-solo"}
	hidden := []string{"aaa-first", "team-ab/api", "team-b/api", "team-b/web", "zz-solo-2", "zzz-last"}
	for _, name := range append(append([]string{}, visible...), hidden...) {
		mustSeedContent(t, s, name)
	}
	vis := meta.VisibleTo(
		meta.ScopeFilter{Prefix: "team-a/"},
		meta.ScopeFilter{Prefix: "team-c/"},
		meta.ScopeFilter{Exact: "zz-solo"},
	)

	got := contentNames(t, s, vis, 2)
	if fmt.Sprint(got) != fmt.Sprint(visible) {
		t.Fatalf("stitched pages = %v, want exactly the visible set %v", got, visible)
	}
}

// Cursors are keyset, not offset (ADR 0015): content written behind the cursor
// is not revisited and content written ahead of it appears, but a page walk
// never repeats or skips what already existed.
func testListContentNamesCursorIsStableUnderWrites(t *testing.T, s meta.Store) {
	vis := meta.VisibleTo(
		meta.ScopeFilter{Exact: "r-00"}, meta.ScopeFilter{Exact: "r-01"},
		meta.ScopeFilter{Exact: "r-03"}, meta.ScopeFilter{Exact: "r-05"},
		meta.ScopeFilter{Exact: "r-07"},
	)
	for i := 1; i <= 6; i++ {
		name := fmt.Sprintf("r-%02d", i)
		mustCreateRepo(t, s, name, meta.Hosted)
		mustPutManifest(t, s, name, digest("cursor-"+name))
	}

	first, err := s.ListContentNames(ctx(), meta.ListOptions{Visibility: vis, Limit: 1})
	if err != nil {
		t.Fatalf("ListContentNames: %v", err)
	}
	if len(first.Names) != 1 || first.Names[0] != "r-01" || first.NextCursor != "r-01" {
		t.Fatalf("first page = %+v, want [r-01] with cursor r-01", first)
	}

	// Content lands mid-walk: a visible name behind the cursor, a hidden one
	// between the remaining pages, and a visible one past the end.
	for _, name := range []string{"r-00", "r-04x", "r-07"} {
		mustCreateRepo(t, s, name, meta.Hosted)
		mustPutManifest(t, s, name, digest("late-"+name))
	}

	seen := []string{first.Names[0]}
	cursor := first.NextCursor
	for pages := 0; cursor != ""; pages++ {
		if pages > 8 {
			t.Fatal("pagination did not terminate")
		}
		page, err := s.ListContentNames(ctx(), meta.ListOptions{Visibility: vis, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListContentNames: %v", err)
		}
		seen = append(seen, page.Names...)
		cursor = page.NextCursor
	}

	// r-00 was written behind the cursor, so this walk legitimately misses it;
	// r-04x is not visible; r-07 was written ahead and appears.
	want := []string{"r-01", "r-03", "r-05", "r-07"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("stitched pages = %v, want %v: no repeats, no skips of what existed, nothing hidden", seen, want)
	}
}

func testDeletingManifestRemovesItsTags(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)
	d := digest("tagged")
	mustPutManifest(t, s, "repo", d)

	for _, name := range []string{"latest", "v1"} {
		if err := s.PutTag(ctx(), meta.Tag{Repository: "repo", Name: name, Digest: d}); err != nil {
			t.Fatalf("PutTag: %v", err)
		}
	}

	if err := s.DeleteManifest(ctx(), "repo", d); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}

	// A tag pointing at a deleted manifest would resolve to nothing, so the
	// store must not leave one behind.
	for _, name := range []string{"latest", "v1"} {
		if _, err := s.GetTag(ctx(), "repo", name); !errors.Is(err, meta.ErrNotFound) {
			t.Errorf("tag %q survived its manifest: %v", name, err)
		}
	}
}

func testBlobs(t *testing.T, s meta.Store) {
	d := digest("blob")
	blob := meta.Blob{Digest: d, Size: 1024, CreatedAt: testTime}

	if err := s.PutBlob(ctx(), blob); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	// Content-addressed: storing the same digest again is a no-op, not a
	// conflict. Two pushes of the same layer must both succeed.
	if err := s.PutBlob(ctx(), blob); err != nil {
		t.Fatalf("PutBlob (repeat): %v", err)
	}

	got, err := s.GetBlob(ctx(), d)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if got.Size != 1024 {
		t.Errorf("size = %d, want 1024", got.Size)
	}

	requireErrIs(t, s.PutBlob(ctx(), meta.Blob{Size: 1}), meta.ErrInvalid, "PutBlob without a digest")
	requireErrIs(t, s.PutBlob(ctx(), meta.Blob{Digest: digest("neg"), Size: -1}), meta.ErrInvalid, "PutBlob with a negative size")

	if err := s.DeleteBlob(ctx(), d); err != nil {
		t.Fatalf("DeleteBlob: %v", err)
	}
	requireErrIs(t, s.DeleteBlob(ctx(), d), meta.ErrNotFound, "DeleteBlob twice")
	_, err = s.GetBlob(ctx(), d)
	requireErrIs(t, err, meta.ErrNotFound, "GetBlob after delete")
}

func testUploads(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	session := meta.UploadSession{
		ID:          "upload-1",
		Repository:  "repo",
		StartedAt:   testTime,
		LastChunkAt: testTime,
	}
	if err := s.CreateUpload(ctx(), session); err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	requireErrIs(t, s.CreateUpload(ctx(), session), meta.ErrConflict, "CreateUpload twice")
	requireErrIs(t, s.CreateUpload(ctx(), meta.UploadSession{Repository: "repo"}), meta.ErrInvalid, "CreateUpload without an id")
	requireErrIs(t, s.CreateUpload(ctx(), meta.UploadSession{ID: "x", Repository: "ghost"}), meta.ErrNotFound, "CreateUpload in a missing repository")

	later := testTime.Add(time.Minute)
	if err := s.UpdateUpload(ctx(), "upload-1", 4096, later); err != nil {
		t.Fatalf("UpdateUpload: %v", err)
	}

	got, err := s.GetUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("GetUpload: %v", err)
	}
	if got.Bytes != 4096 {
		t.Errorf("bytes = %d, want 4096", got.Bytes)
	}
	if !got.LastChunkAt.Equal(later) {
		t.Errorf("LastChunkAt = %v, want the supplied time %v", got.LastChunkAt, later)
	}

	requireErrIs(t, s.UpdateUpload(ctx(), "ghost", 1, later), meta.ErrNotFound, "UpdateUpload on a missing session")
	requireErrIs(t, s.UpdateUpload(ctx(), "upload-1", -1, later), meta.ErrInvalid, "UpdateUpload with negative bytes")

	if err := s.DeleteUpload(ctx(), "upload-1"); err != nil {
		t.Fatalf("DeleteUpload: %v", err)
	}
	requireErrIs(t, s.DeleteUpload(ctx(), "upload-1"), meta.ErrNotFound, "DeleteUpload twice")
	_, err = s.GetUpload(ctx(), "upload-1")
	requireErrIs(t, err, meta.ErrNotFound, "GetUpload after delete")
}

func testStaleUploads(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	old := testTime
	recent := testTime.Add(2 * time.Hour)

	for _, tc := range []struct {
		id string
		at time.Time
	}{
		{"stale-2", old.Add(time.Minute)},
		{"stale-1", old},
		{"fresh", recent},
	} {
		if err := s.CreateUpload(ctx(), meta.UploadSession{
			ID: tc.id, Repository: "repo", StartedAt: tc.at, LastChunkAt: tc.at,
		}); err != nil {
			t.Fatalf("CreateUpload(%s): %v", tc.id, err)
		}
	}

	cutoff := old.Add(time.Hour)
	stale, err := s.ListStaleUploads(ctx(), cutoff, 0)
	if err != nil {
		t.Fatalf("ListStaleUploads: %v", err)
	}
	if len(stale) != 2 {
		t.Fatalf("got %d stale uploads, want 2 (an active upload must never be reaped)", len(stale))
	}
	if stale[0].ID != "stale-1" || stale[1].ID != "stale-2" {
		t.Errorf("stale uploads = %+v, want them oldest first", stale)
	}

	limited, err := s.ListStaleUploads(ctx(), cutoff, 1)
	if err != nil {
		t.Fatalf("ListStaleUploads(limited): %v", err)
	}
	if len(limited) != 1 || limited[0].ID != "stale-1" {
		t.Errorf("limited = %+v, want just the oldest", limited)
	}
}

// Pull statistics accumulate: a flush adds to what is there and advances the
// last-pulled time, never replacing either. Retention's keep-if-pulled-since
// rule reads both, and a count that reset on every flush would quietly make
// every artifact look unused (§7).
//
// No repository is created here on purpose. These rows are observations, not
// references: a tag that moved or a repository that went away between the pull
// and the flush must still record (R-010).
func testPullStats(t *testing.T, s meta.Store) {
	var (
		first   = testTime
		later   = testTime.Add(time.Hour)
		earlier = testTime.Add(-time.Hour)
		byHash  = string(digest("pulled-by-digest"))
	)

	if err := s.RecordPulls(ctx(), []meta.PullRecord{
		{Repository: "team-a/api", Reference: "latest", At: first, Count: 3},
		{Repository: "team-a/api", Reference: byHash, At: first, Count: 1},
	}); err != nil {
		t.Fatalf("RecordPulls: %v", err)
	}

	requirePullStats(t, s, "team-a/api", "latest", 3, first)
	// A pull by digest is a pull, and it is its own row: the reference the
	// client used is what was recorded.
	requirePullStats(t, s, "team-a/api", byHash, 1, first)

	// A second flush adds to the row rather than replacing it, and the newer
	// observation moves the last-pulled time forward.
	if err := s.RecordPulls(ctx(), []meta.PullRecord{
		{Repository: "team-a/api", Reference: "latest", At: later, Count: 2},
	}); err != nil {
		t.Fatalf("RecordPulls (second batch): %v", err)
	}
	requirePullStats(t, s, "team-a/api", "latest", 5, later)

	// An older observation still counts -- flushes can arrive out of order --
	// but it must not drag the timestamp backwards.
	if err := s.RecordPulls(ctx(), []meta.PullRecord{
		{Repository: "team-a/api", Reference: "latest", At: earlier, Count: 1},
	}); err != nil {
		t.Fatalf("RecordPulls (late batch): %v", err)
	}
	requirePullStats(t, s, "team-a/api", "latest", 6, later)

	_, err := s.GetPullStats(ctx(), "team-a/api", "never-pulled")
	requireErrIs(t, err, meta.ErrNotFound, "GetPullStats for an unpulled reference")

	_, err = s.GetPullStats(ctx(), "ghost", "latest")
	requireErrIs(t, err, meta.ErrNotFound, "GetPullStats in a repository with no statistics")
}

func requirePullStats(t *testing.T, s meta.Store, repo, reference string, count int64, pulled time.Time) {
	t.Helper()

	got, err := s.GetPullStats(ctx(), repo, reference)
	if err != nil {
		t.Fatalf("GetPullStats(%s, %s): %v", repo, reference, err)
	}
	if got.Repository != repo || got.Reference != reference {
		t.Errorf("stats = %+v, want them to identify %s %s", got, repo, reference)
	}
	if got.Count != count {
		t.Errorf("count = %d, want %d", got.Count, count)
	}
	if !got.LastPulledAt.Equal(pulled) {
		t.Errorf("LastPulledAt = %v, want %v", got.LastPulledAt, pulled)
	}
}

// An empty batch is a no-op, not an error and not a transaction: the batcher
// flushes on a timer whether or not anything was pulled (R-010).
func testPullStatsEmptyBatch(t *testing.T, s meta.Store) {
	if err := s.RecordPulls(ctx(), nil); err != nil {
		t.Errorf("RecordPulls(nil): %v, want nil", err)
	}
	if err := s.RecordPulls(ctx(), []meta.PullRecord{}); err != nil {
		t.Errorf("RecordPulls(empty): %v, want nil", err)
	}

	_, err := s.GetPullStats(ctx(), "team-a/api", "latest")
	requireErrIs(t, err, meta.ErrNotFound, "GetPullStats after empty batches")
}

func testPullStatsValidation(t *testing.T, s meta.Store) {
	tests := []struct {
		name   string
		record meta.PullRecord
	}{
		{"empty repository", meta.PullRecord{Reference: "latest", At: testTime, Count: 1}},
		{"empty reference", meta.PullRecord{Repository: "repo", At: testTime, Count: 1}},
		// A record of no pulls is a caller bug, not an empty batch: it would
		// create a row claiming a reference was pulled zero times.
		{"zero count", meta.PullRecord{Repository: "repo", Reference: "latest", At: testTime}},
		{"negative count", meta.PullRecord{Repository: "repo", Reference: "latest", At: testTime, Count: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.RecordPulls(ctx(), []meta.PullRecord{tt.record})
			requireErrIs(t, err, meta.ErrInvalid, "RecordPulls")
		})
	}

	// One bad record rejects the batch. A partially applied flush would leave
	// a total that nothing can reconstruct, because the observations behind it
	// are gone.
	err := s.RecordPulls(ctx(), []meta.PullRecord{
		{Repository: "repo", Reference: "good", At: testTime, Count: 1},
		{Repository: "repo", Reference: "", At: testTime, Count: 1},
	})
	requireErrIs(t, err, meta.ErrInvalid, "RecordPulls with one bad record")

	_, err = s.GetPullStats(ctx(), "repo", "good")
	requireErrIs(t, err, meta.ErrNotFound, "GetPullStats after a rejected batch")
}

// Deleting an entity takes its content with it -- the name itself and every
// name beneath it, since content is keyed by full name and the entity is the
// only row that ever existed for it (ADR 0005). The deletion is immediate
// (Q16): there is no trash can, and GC lag is the only grace window.
//
// The neighbour whose name merely starts the same way is the case that matters
// most: `doomed-not-really/api` must survive `doomed` being deleted, and a
// prefix match written as a LIKE or a plain HasPrefix would take it.
func testDeleteRepositoryRemovesContent(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "doomed", meta.Hosted)
	mustCreateRepo(t, s, "doomed-not-really", meta.Hosted)
	mustCreateRepo(t, s, "survivor", meta.Hosted)
	mustCreateRepo(t, s, "grp", meta.Group)

	d := digest("content")
	mustPutManifest(t, s, "doomed", d)
	mustPutManifest(t, s, "doomed/inner", d)
	mustPutManifest(t, s, "doomed/deep/nested", d)
	mustPutManifest(t, s, "doomed-not-really/api", d)
	mustPutManifest(t, s, "survivor", d)
	for _, repo := range []string{"doomed", "doomed/inner", "doomed-not-really/api"} {
		if err := s.PutTag(ctx(), meta.Tag{Repository: repo, Name: "v1", Digest: d}); err != nil {
			t.Fatalf("PutTag(%q): %v", repo, err)
		}
	}
	if err := s.CreateUpload(ctx(), meta.UploadSession{
		ID: "upload-inner", Repository: "doomed/inner", StartedAt: testTime, LastChunkAt: testTime,
	}); err != nil {
		t.Fatalf("CreateUpload into a remainder: %v", err)
	}
	if err := s.SetGroupMembers(ctx(), "grp", []meta.GroupMember{
		{Repository: "doomed", Position: 1},
		{Repository: "survivor", Position: 2},
	}); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}
	if err := s.CreateUpload(ctx(), meta.UploadSession{
		ID: "upload-1", Repository: "doomed", StartedAt: testTime, LastChunkAt: testTime,
	}); err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	if err := s.DeleteRepository(ctx(), "doomed"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	// Everything under the entity is gone: the bare name and every remainder.
	for _, repo := range []string{"doomed", "doomed/inner", "doomed/deep/nested"} {
		if _, err := s.GetManifest(ctx(), repo, d); !errors.Is(err, meta.ErrNotFound) {
			t.Errorf("manifest in %q survived its entity: %v", repo, err)
		}
	}
	for _, repo := range []string{"doomed", "doomed/inner"} {
		if _, err := s.GetTag(ctx(), repo, "v1"); !errors.Is(err, meta.ErrNotFound) {
			t.Errorf("tag in %q survived its entity: %v", repo, err)
		}
	}
	// The identical digest in another repository is untouched: content is
	// per repository.
	if _, err := s.GetManifest(ctx(), "survivor", d); err != nil {
		t.Errorf("deleting one repository removed another's manifest: %v", err)
	}
	// And the neighbour that merely shares the first characters of the name is
	// a different entity entirely.
	if _, err := s.GetManifest(ctx(), "doomed-not-really/api", d); err != nil {
		t.Errorf("deleting %q reached a neighbouring entity's content: %v", "doomed", err)
	}
	if _, err := s.GetTag(ctx(), "doomed-not-really/api", "v1"); err != nil {
		t.Errorf("deleting %q reached a neighbouring entity's tags: %v", "doomed", err)
	}
	if _, err := s.GetRepository(ctx(), "doomed-not-really"); err != nil {
		t.Errorf("deleting %q reached a neighbouring entity's row: %v", "doomed", err)
	}

	// An upload session outliving its repository would pin its digest against
	// garbage collection forever, and it can never be completed -- including
	// one opened against a name beneath the entity.
	for _, id := range []string{"upload-1", "upload-inner"} {
		if _, err := s.GetUpload(ctx(), id); !errors.Is(err, meta.ErrNotFound) {
			t.Errorf("upload session %q survived its entity: %v", id, err)
		}
	}

	// A group must not keep resolving to a repository that no longer exists.
	members, err := s.ListGroupMembers(ctx(), "grp")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 1 || members[0].Repository != "survivor" {
		t.Errorf("members = %+v, want the deleted repository dropped", members)
	}
}

// Every method must observe context cancellation. A store that ignores it
// keeps working after its caller has given up, which is how a shutdown hangs
// and how a cancelled request still mutates state. The table below is
// exhaustive by construction: MethodNames cross-checks it against the
// interface, so a new method cannot be added without appearing here.
func testContextCancellation(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "repo", meta.Hosted)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, call := range cancellableCalls(cancelled, s) {
		t.Run(call.name, func(t *testing.T) {
			if err := call.fn(); !errors.Is(err, context.Canceled) {
				t.Errorf("%s with a cancelled context = %v, want context.Canceled", call.name, err)
			}
		})
	}
}

// call is one store method invoked with a fixed context.
type call struct {
	name string
	fn   func() error
}

// cancellableCalls invokes every Store method with ctx. Each call is shaped so
// the context check is the first thing it can fail on.
func cancellableCalls(ctx context.Context, s meta.Store) []call {
	d := digest("cancel")
	return []call{
		{"CreateRepository", func() error {
			_, err := s.CreateRepository(ctx, meta.Repository{Name: "c", Type: meta.Hosted})
			return err
		}},
		{"GetRepository", func() error { _, err := s.GetRepository(ctx, "repo"); return err }},
		{"ListRepositories", func() error {
			_, err := s.ListRepositories(ctx, meta.ListOptions{Visibility: meta.Unrestricted()})
			return err
		}},
		{"UpdateRepositoryConfig", func() error {
			_, err := s.UpdateRepositoryConfig(ctx, "repo", []byte(`{}`), 1, "actor", testTime)
			return err
		}},
		{"ListConfigHistory", func() error { _, err := s.ListConfigHistory(ctx, "repo"); return err }},
		{"DeleteRepository", func() error { return s.DeleteRepository(ctx, "repo") }},
		{"SetGroupMembers", func() error { return s.SetGroupMembers(ctx, "repo", nil) }},
		{"ListGroupMembers", func() error { _, err := s.ListGroupMembers(ctx, "repo"); return err }},
		{"PutManifest", func() error {
			return s.PutManifest(ctx, meta.Manifest{Repository: "repo", Digest: d}, nil)
		}},
		{"GetManifest", func() error { _, err := s.GetManifest(ctx, "repo", d); return err }},
		{"DeleteManifest", func() error { return s.DeleteManifest(ctx, "repo", d) }},
		{"ListManifestRefs", func() error { _, err := s.ListManifestRefs(ctx, "repo", d); return err }},
		{"ListIndexParents", func() error { _, err := s.ListIndexParents(ctx, "repo", d); return err }},
		{"ListReferrers", func() error { _, err := s.ListReferrers(ctx, "repo", d, ""); return err }},
		{"PutTag", func() error {
			return s.PutTag(ctx, meta.Tag{Repository: "repo", Name: "t", Digest: d})
		}},
		{"GetTag", func() error { _, err := s.GetTag(ctx, "repo", "t"); return err }},
		{"ListTags", func() error {
			_, err := s.ListTags(ctx, "repo", meta.ListOptions{Visibility: meta.Unrestricted()})
			return err
		}},
		{"ListContentNames", func() error {
			_, err := s.ListContentNames(ctx, meta.ListOptions{Visibility: meta.Unrestricted()})
			return err
		}},
		{"DeleteTag", func() error { return s.DeleteTag(ctx, "repo", "t") }},
		{"PutBlob", func() error { return s.PutBlob(ctx, meta.Blob{Digest: d, Size: 1}) }},
		{"GetBlob", func() error { _, err := s.GetBlob(ctx, d); return err }},
		{"DeleteBlob", func() error { return s.DeleteBlob(ctx, d) }},
		{"CreateUpload", func() error {
			return s.CreateUpload(ctx, meta.UploadSession{ID: "u", Repository: "repo"})
		}},
		{"GetUpload", func() error { _, err := s.GetUpload(ctx, "u"); return err }},
		{"UpdateUpload", func() error { return s.UpdateUpload(ctx, "u", 1, testTime) }},
		{"DeleteUpload", func() error { return s.DeleteUpload(ctx, "u") }},
		{"ListStaleUploads", func() error { _, err := s.ListStaleUploads(ctx, testTime, 0); return err }},
		// A valid, non-empty batch: an empty one is a no-op and would never
		// reach the store's first statement.
		{"RecordPulls", func() error {
			return s.RecordPulls(ctx, []meta.PullRecord{
				{Repository: "repo", Reference: "t", At: testTime, Count: 1},
			})
		}},
		{"GetPullStats", func() error { _, err := s.GetPullStats(ctx, "repo", "t"); return err }},

		{"CreateSubject", func() error {
			return s.CreateSubject(ctx, meta.Subject{ID: "s", Kind: meta.User, Name: "s"})
		}},
		{"GetSubject", func() error { _, err := s.GetSubject(ctx, "s"); return err }},
		{"ListSubjects", func() error { _, err := s.ListSubjects(ctx, meta.ListOptions{}); return err }},
		{"SetSubjectDisabled", func() error { return s.SetSubjectDisabled(ctx, "s", true) }},
		{"DeleteSubject", func() error { return s.DeleteSubject(ctx, "s") }},
		{"CreateGroup", func() error {
			return s.CreateGroup(ctx, meta.SubjectGroup{ID: "g", Name: "g"})
		}},
		{"GetGroup", func() error { _, err := s.GetGroup(ctx, "g"); return err }},
		{"ListGroups", func() error { _, err := s.ListGroups(ctx); return err }},
		{"DeleteGroup", func() error { return s.DeleteGroup(ctx, "g") }},
		{"AddGroupMember", func() error { return s.AddGroupMember(ctx, "g", "s") }},
		{"RemoveGroupMember", func() error { return s.RemoveGroupMember(ctx, "g", "s") }},
		{"ListGroupMemberSubjects", func() error { _, err := s.ListGroupMemberSubjects(ctx, "g"); return err }},
		{"ListSubjectGroups", func() error { _, err := s.ListSubjectGroups(ctx, "s"); return err }},
		{"CreateRole", func() error { return s.CreateRole(ctx, meta.Role{Name: "r"}) }},
		{"GetRole", func() error { _, err := s.GetRole(ctx, "r"); return err }},
		{"ListRoles", func() error { _, err := s.ListRoles(ctx); return err }},
		{"UpdateRoleVerbs", func() error { return s.UpdateRoleVerbs(ctx, "r", nil) }},
		{"PutBuiltinRole", func() error {
			return s.PutBuiltinRole(ctx, meta.Role{Name: "r", Builtin: true, Verbs: []string{"repo:read"}})
		}},
		{"DeleteRole", func() error { return s.DeleteRole(ctx, "r") }},
		{"CreateBinding", func() error {
			return s.CreateBinding(ctx, meta.Binding{
				ID: "b", PrincipalKind: meta.PrincipalSubject, PrincipalID: "s", Role: "r", Scope: "*",
			})
		}},
		{"GetBinding", func() error { _, err := s.GetBinding(ctx, "b"); return err }},
		{"ListBindings", func() error { _, err := s.ListBindings(ctx); return err }},
		{"DeleteBinding", func() error { return s.DeleteBinding(ctx, "b") }},
		{"ListEffectiveBindings", func() error { _, err := s.ListEffectiveBindings(ctx, "s"); return err }},

		{"PutUserCredential", func() error {
			return s.PutUserCredential(ctx, meta.UserCredential{Subject: "s", Hash: "h"})
		}},
		{"GetUserCredential", func() error { _, err := s.GetUserCredential(ctx, "s"); return err }},
		{"DeleteUserCredential", func() error { return s.DeleteUserCredential(ctx, "s") }},
		{"PutRobotCredential", func() error {
			return s.PutRobotCredential(ctx, meta.RobotCredential{
				Subject: "s", SecretHash: []byte("h"), ExpiresAt: testTime.Add(time.Hour),
			})
		}},
		{"GetRobotCredential", func() error { _, err := s.GetRobotCredential(ctx, "s", testTime); return err }},
		{"DeleteRobotCredential", func() error { return s.DeleteRobotCredential(ctx, "s") }},
		{"CreateAccessToken", func() error {
			return s.CreateAccessToken(ctx, meta.AccessToken{ID: "t", Subject: "s", TokenHash: []byte("h")})
		}},
		{"GetAccessTokenByHash", func() error {
			_, err := s.GetAccessTokenByHash(ctx, []byte("h"), testTime)
			return err
		}},
		{"ListAccessTokens", func() error { _, err := s.ListAccessTokens(ctx, "s"); return err }},
		{"TouchAccessToken", func() error { return s.TouchAccessToken(ctx, "t", testTime) }},
		{"DeleteAccessToken", func() error { return s.DeleteAccessToken(ctx, "t") }},
		{"CreateSession", func() error {
			return s.CreateSession(ctx, meta.Session{
				ID: "x", Subject: "s", CSRFToken: "c",
				IdleExpiresAt: testTime, AbsoluteExpiresAt: testTime,
			})
		}},
		{"GetSession", func() error { _, err := s.GetSession(ctx, "x", testTime); return err }},
		{"RefreshSession", func() error { return s.RefreshSession(ctx, "x", testTime) }},
		{"DeleteSession", func() error { return s.DeleteSession(ctx, "x") }},
		{"DeleteSubjectSessions", func() error { _, err := s.DeleteSubjectSessions(ctx, "s"); return err }},
		{"DeleteExpiredSessions", func() error { _, err := s.DeleteExpiredSessions(ctx, testTime); return err }},
	}
}

// MethodNames returns the name of every Store method the contract exercises.
// Implementation-specific suites use it to prove their own tables are complete.
func MethodNames() []string {
	var names []string
	for _, c := range cancellableCalls(context.Background(), nil) {
		names = append(names, c.name)
	}
	return names
}

// Calls exposes the per-method invocations so an implementation can assert
// behaviour the shared contract cannot -- for example that a closed store
// refuses every method.
func Calls(ctx context.Context, s meta.Store) []struct {
	Name string
	Fn   func() error
} {
	inner := cancellableCalls(ctx, s)
	out := make([]struct {
		Name string
		Fn   func() error
	}, len(inner))
	for i, c := range inner {
		out[i].Name = c.name
		out[i].Fn = c.fn
	}
	return out
}

func testCloseIsIdempotent(t *testing.T, s meta.Store) {
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v, want nil", err)
	}
}
