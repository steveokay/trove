package registry_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmem "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
)

// reaperQuiet keeps the error paths from writing to the default logger: the
// tests assert on returned errors, not on log output.
func reaperQuiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// reaperSeed plants one upload session the way a started push leaves it: a row
// in the metadata store and a staging session behind it, idle since last.
func reaperSeed(t *testing.T, s stack, id string, last time.Time) {
	t.Helper()

	ctx := context.Background()
	if err := s.metaDB.CreateUpload(ctx, meta.UploadSession{
		ID: id, Repository: "team-a/api", StartedAt: last, LastChunkAt: last,
	}); err != nil {
		t.Fatalf("CreateUpload %s: %v", id, err)
	}
	if _, err := s.blobs.CreateUpload(ctx, id); err != nil {
		t.Fatalf("staging for %s: %v", id, err)
	}
}

// reaperRowExists reports whether the session row is still there.
func reaperRowExists(t *testing.T, s stack, id string) bool {
	t.Helper()

	_, err := s.metaDB.GetUpload(context.Background(), id)
	switch {
	case err == nil:
		return true
	case errors.Is(err, meta.ErrNotFound):
		return false
	}
	t.Fatalf("GetUpload %s: %v", id, err)
	return false
}

// reaperStagingExists reports whether the staged bytes are still there.
func reaperStagingExists(t *testing.T, s stack, id string) bool {
	t.Helper()

	_, err := s.blobs.OpenUpload(context.Background(), id)
	switch {
	case err == nil:
		return true
	case errors.Is(err, blob.ErrNotFound):
		return false
	}
	t.Fatalf("OpenUpload %s: %v", id, err)
	return false
}

// reaperAt builds a reaper over the fixture's real stores, with its clock
// pinned to at.
func reaperAt(s stack, at time.Time, ttl time.Duration) *registry.UploadReaper {
	return &registry.UploadReaper{
		Meta:  s.metaDB,
		Store: s.blobs,
		TTL:   ttl,
		Now:   func() time.Time { return at },
		Log:   reaperQuiet(),
	}
}

// The boundary, session by session: idle longer than the TTL goes, anything
// else stays whole -- row, staging, and the ability to keep pushing into it.
func TestReaperCollectsOnlyIdleSessions(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	const ttl = 24 * time.Hour

	cases := []struct {
		id       string
		lastAgo  time.Duration
		wantReap bool
	}{
		{id: "reaper-ancient", lastAgo: 72 * time.Hour, wantReap: true},
		{id: "reaper-just-past", lastAgo: ttl + time.Second, wantReap: true},
		{id: "reaper-at-cutoff", lastAgo: ttl, wantReap: false},
		{id: "reaper-recent", lastAgo: time.Hour, wantReap: false},
		{id: "reaper-fresh", lastAgo: 0, wantReap: false},
	}
	want := 0
	for _, tc := range cases {
		reaperSeed(t, s, tc.id, fixedTime.Add(-tc.lastAgo))
		if tc.wantReap {
			want++
		}
	}

	reaped, err := reaperAt(s, fixedTime, ttl).ReapOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapOnce: %v", err)
	}
	if reaped != want {
		t.Fatalf("reaped %d, want %d", reaped, want)
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			gotRow := reaperRowExists(t, s, tc.id)
			gotStaging := reaperStagingExists(t, s, tc.id)
			if tc.wantReap {
				if gotRow || gotStaging {
					t.Fatalf("survived the sweep: row %v, staging %v", gotRow, gotStaging)
				}
				return
			}
			if !gotRow || !gotStaging {
				t.Fatalf("collected an active session: row %v, staging %v", gotRow, gotStaging)
			}
			// Untouched means usable: the client's next chunk still lands.
			rec := s.do(t, http.MethodPatch, "/v2/team-a/api/blobs/uploads/"+tc.id, "carol", layer)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("PATCH after the sweep: %d %s, want 202", rec.Code, rec.Body)
			}
		})
	}
}

// The race the plan names: a client returns to a session the sweep already
// collected. The answer is the spec's upload-unknown, and nothing about the
// session comes back -- no row, no staging -- so the client restarts its push
// rather than resuming into half of one.
func TestReaperReapedSessionAnswersUploadUnknown(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	const id = "reaper-raced"
	reaperSeed(t, s, id, fixedTime.Add(-48*time.Hour))

	if reaped, err := reaperAt(s, fixedTime, 24*time.Hour).ReapOnce(context.Background()); err != nil || reaped != 1 {
		t.Fatalf("ReapOnce = %d, %v; want 1, nil", reaped, err)
	}

	rec := s.do(t, http.MethodPatch, "/v2/team-a/api/blobs/uploads/"+id, "carol", layer)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), registry.CodeBlobUploadUnknown) {
		t.Fatalf("PATCH onto a reaped session: %d %s, want upload-unknown", rec.Code, rec.Body)
	}
	if reaperRowExists(t, s, id) || reaperStagingExists(t, s, id) {
		t.Fatal("the refused chunk resurrected part of the session")
	}
}

// Progress is what protects an upload, and it protects it through the handler:
// a chunk refreshes the activity timestamp, so a session that was minutes from
// collection is not listed at all once its client comes back.
func TestReaperProgressProtectsASession(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	const id = "reaper-resumed"
	// Idle since well past the TTL -- collectable before the client returns.
	reaperSeed(t, s, id, fixedTime.Add(-48*time.Hour))

	// The handler's clock is fixedTime, so the chunk stamps LastChunkAt there.
	rec := s.do(t, http.MethodPatch, "/v2/team-a/api/blobs/uploads/"+id, "carol", layer)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("chunk: %d %s", rec.Code, rec.Body)
	}

	// An hour past the point the original timestamp would have made it stale.
	reaped, err := reaperAt(s, fixedTime.Add(time.Hour), 24*time.Hour).ReapOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapOnce: %v", err)
	}
	if reaped != 0 {
		t.Fatalf("reaped %d, want 0: the refreshed session was collected", reaped)
	}
	if !reaperRowExists(t, s, id) || !reaperStagingExists(t, s, id) {
		t.Fatal("the refreshed session lost its row or its staging")
	}

	row, err := s.metaDB.GetUpload(context.Background(), id)
	if err != nil {
		t.Fatalf("GetUpload: %v", err)
	}
	if !row.LastChunkAt.Equal(fixedTime) {
		t.Fatalf("LastChunkAt = %s, want the chunk's %s", row.LastChunkAt, fixedTime)
	}
}

// The crash window the delete order exists for: staging gone, row still there.
// The next sweep finishes the job instead of reporting a failure -- somebody
// getting there first is the outcome the reaper wanted.
func TestReaperFinishesAnInterruptedCollection(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	ctx := context.Background()
	const id = "reaper-half-done"
	reaperSeed(t, s, id, fixedTime.Add(-48*time.Hour))

	staged, err := s.blobs.OpenUpload(ctx, id)
	if err != nil {
		t.Fatalf("OpenUpload: %v", err)
	}
	if err := staged.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	reaped, err := reaperAt(s, fixedTime, 24*time.Hour).ReapOnce(ctx)
	if err != nil {
		t.Fatalf("ReapOnce over a half-collected session: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("reaped %d, want 1", reaped)
	}
	if reaperRowExists(t, s, id) {
		t.Fatal("the orphaned row survived the retry")
	}
}

// Committed content is outside the reaper's reach by construction: an upload
// session is the only thing it can name, and a commit ends the session. The
// assertion is here anyway, because "by construction" is a claim a test should
// be able to break if the construction ever changes (§4).
func TestReaperNeverTouchesCommittedBlobs(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := layerDigest().String()
	if rec := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/?digest="+digest, "carol", layer); rec.Code != http.StatusCreated {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	reaperSeed(t, s, "reaper-abandoned", fixedTime.Add(-48*time.Hour))

	// Everything the store knows is stale by this clock.
	reaped, err := reaperAt(s, fixedTime.Add(10*365*24*time.Hour), time.Nanosecond).ReapOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapOnce: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("reaped %d, want the one abandoned session", reaped)
	}

	if _, err := s.metaDB.GetBlob(context.Background(), meta.Digest(layerDigest())); err != nil {
		t.Fatalf("the blob row did not survive: %v", err)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/blobs/"+digest, "carol", ""); rec.Code != http.StatusOK || rec.Body.String() != layer {
		t.Fatalf("the blob bytes did not survive: %d %q", rec.Code, rec.Body)
	}
}

// The defaults are the operable ones: no TTL means a day, no clock means the
// real one.
func TestReaperDefaults(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	reaperSeed(t, s, "reaper-two-days-old", time.Now().Add(-48*time.Hour))
	reaperSeed(t, s, "reaper-minutes-old", time.Now().Add(-5*time.Minute))

	reaped, err := (&registry.UploadReaper{Meta: s.metaDB, Store: s.blobs, Log: reaperQuiet()}).
		ReapOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapOnce: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("reaped %d, want 1 under the %s default", reaped, registry.DefaultUploadSessionTTL)
	}
	if reaperRowExists(t, s, "reaper-two-days-old") {
		t.Error("a two-day-old session survived the default TTL")
	}
	if !reaperRowExists(t, s, "reaper-minutes-old") {
		t.Error("a five-minute-old session was collected under the default TTL")
	}
}

var reaperErrDisk = errors.New("reaper: disk on fire")

// reaperFaultyMeta fails the listing, or the delete of one named session, and
// passes everything else through to the real store.
type reaperFaultyMeta struct {
	*metamem.Store
	failList       bool
	failDeleteID   string
	vanishDeleteID string
}

func (f *reaperFaultyMeta) ListStaleUploads(ctx context.Context, before time.Time, limit int) ([]meta.UploadSession, error) {
	if f.failList {
		return nil, reaperErrDisk
	}
	return f.Store.ListStaleUploads(ctx, before, limit)
}

func (f *reaperFaultyMeta) DeleteUpload(ctx context.Context, id string) error {
	switch id {
	case f.failDeleteID:
		return reaperErrDisk
	case f.vanishDeleteID:
		// Somebody committed or cancelled between the listing and the delete.
		return meta.NotFound("upload", id)
	}
	return f.Store.DeleteUpload(ctx, id)
}

// reaperFaultyStore fails to open, or to cancel, one named staging session.
type reaperFaultyStore struct {
	*blobmem.Store
	openErrID   string
	cancelErrID string
}

func (f *reaperFaultyStore) OpenUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if id == f.openErrID {
		return nil, reaperErrDisk
	}
	session, err := f.Store.OpenUpload(ctx, id)
	if err != nil || id != f.cancelErrID {
		return session, err
	}
	return reaperStubbornSession{UploadSession: session}, nil
}

// reaperStubbornSession refuses to let go of its staged bytes.
type reaperStubbornSession struct{ blob.UploadSession }

func (reaperStubbornSession) Cancel(context.Context) error { return reaperErrDisk }

// A row the store has already forgotten is success, not a failure: a commit or
// a client cancel raced the sweep to it and the outcome is the one the reaper
// wanted.
func TestReaperToleratesAVanishedRow(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	const id = "reaper-vanished"
	reaperSeed(t, s, id, fixedTime.Add(-48*time.Hour))

	reaper := reaperAt(s, fixedTime, 24*time.Hour)
	reaper.Meta = &reaperFaultyMeta{Store: s.metaDB, vanishDeleteID: id}

	reaped, err := reaper.ReapOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapOnce over a vanished row: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("reaped %d, want the raced session counted as collected", reaped)
	}
}

// Staging that will not open or will not go is reported, and the row stays put
// so the next sweep tries again. Deleting the row over unreclaimed staging
// would strand bytes nothing could ever list.
func TestReaperStagingFailuresKeepTheRow(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	const (
		unopenable    = "reaper-unopenable"
		uncancellable = "reaper-uncancellable"
	)
	for _, id := range []string{unopenable, uncancellable} {
		reaperSeed(t, s, id, fixedTime.Add(-48*time.Hour))
	}

	reaper := reaperAt(s, fixedTime, 24*time.Hour)
	reaper.Store = &reaperFaultyStore{Store: s.blobs, openErrID: unopenable, cancelErrID: uncancellable}

	reaped, err := reaper.ReapOnce(context.Background())
	if !errors.Is(err, reaperErrDisk) {
		t.Fatalf("ReapOnce error = %v, want the store's", err)
	}
	if reaped != 0 {
		t.Fatalf("reaped %d, want none: neither session's bytes were reclaimed", reaped)
	}
	for _, id := range []string{unopenable, uncancellable} {
		if !reaperRowExists(t, s, id) || !reaperStagingExists(t, s, id) {
			t.Errorf("%s lost its row or staging despite the failure", id)
		}
	}
}

// A store that cannot list has nothing the sweep can do: the error comes back
// rather than being swallowed into a quiet zero.
func TestReaperListFailureIsReturned(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	reaperSeed(t, s, "reaper-unreachable", fixedTime.Add(-48*time.Hour))

	reaper := reaperAt(s, fixedTime, 24*time.Hour)
	reaper.Meta = &reaperFaultyMeta{Store: s.metaDB, failList: true}

	reaped, err := reaper.ReapOnce(context.Background())
	if !errors.Is(err, reaperErrDisk) {
		t.Fatalf("ReapOnce error = %v, want the store's", err)
	}
	if reaped != 0 {
		t.Fatalf("reaped %d without a listing", reaped)
	}
	if !reaperRowExists(t, s, "reaper-unreachable") {
		t.Error("a session went away during a failed sweep")
	}
}

// One session that cannot be collected does not end the sweep. It is reported,
// its neighbours still go, and what is left of it -- a row whose staging is
// already gone -- is exactly the state the next sweep retries.
func TestReaperOneBadSessionDoesNotStopTheSweep(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	const wedged = "reaper-wedged"
	for _, id := range []string{"reaper-first", wedged, "reaper-third"} {
		reaperSeed(t, s, id, fixedTime.Add(-48*time.Hour))
	}

	faulty := &reaperFaultyMeta{Store: s.metaDB, failDeleteID: wedged}
	reaper := reaperAt(s, fixedTime, 24*time.Hour)
	reaper.Meta = faulty

	reaped, err := reaper.ReapOnce(context.Background())
	if !errors.Is(err, reaperErrDisk) {
		t.Fatalf("ReapOnce error = %v, want the wedged session's", err)
	}
	if reaped != 2 {
		t.Fatalf("reaped %d, want the two that could go", reaped)
	}
	for _, id := range []string{"reaper-first", "reaper-third"} {
		if reaperRowExists(t, s, id) || reaperStagingExists(t, s, id) {
			t.Errorf("%s survived a sweep that reported another session's failure", id)
		}
	}
	if !reaperRowExists(t, s, wedged) {
		t.Error("the wedged row went away despite the failed delete")
	}
	if reaperStagingExists(t, s, wedged) {
		t.Error("staging outlived the row: the crash-safe order was inverted")
	}

	// The retry, once the store recovers, finishes it.
	faulty.failDeleteID = ""
	if reaped, err := reaper.ReapOnce(context.Background()); err != nil || reaped != 1 {
		t.Fatalf("retry = %d, %v; want 1, nil", reaped, err)
	}
}

// reaperSignallingMeta reports every listing on a channel, which is how the
// Run test observes sweeps without timing anything.
type reaperSignallingMeta struct {
	*metamem.Store
	swept chan struct{}
	fail  bool
}

func (m *reaperSignallingMeta) ListStaleUploads(ctx context.Context, before time.Time, limit int) ([]meta.UploadSession, error) {
	select {
	case m.swept <- struct{}{}:
	default:
	}
	if m.fail {
		return nil, reaperErrDisk
	}
	return m.Store.ListStaleUploads(ctx, before, limit)
}

// Run sweeps once on the way in and again on every tick, and it stops when its
// context does.
func TestReaperRunSweepsAndStops(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	reaperSeed(t, s, "reaper-run-victim", fixedTime.Add(-48*time.Hour))

	signalling := &reaperSignallingMeta{Store: s.metaDB, swept: make(chan struct{}, 16)}
	reaper := reaperAt(s, fixedTime, 24*time.Hour)
	reaper.Meta = signalling

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		reaper.Run(ctx, time.Millisecond)
	}()

	// The first sweep is the one on entry; the rest are ticks.
	for i := 0; i < 3; i++ {
		select {
		case <-signalling.swept:
		case <-time.After(10 * time.Second):
			t.Fatalf("sweep %d never happened", i)
		}
	}
	if reaperRowExists(t, s, "reaper-run-victim") {
		t.Error("Run swept without collecting the stale session")
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
}

// A failing sweep is reported and the loop keeps its schedule: a store that is
// unwell now may not be at the next tick, and giving up on the reaper would
// mean abandoned uploads accumulate silently.
func TestReaperRunSurvivesAFailingSweep(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	signalling := &reaperSignallingMeta{Store: s.metaDB, swept: make(chan struct{}, 16), fail: true}
	reaper := reaperAt(s, fixedTime, 24*time.Hour)
	reaper.Meta = signalling

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		reaper.Run(ctx, time.Millisecond)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-signalling.swept:
		case <-time.After(10 * time.Second):
			t.Fatalf("sweep %d never happened: Run gave up on a failing store", i)
		}
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
}

// A cancelled context ends a sweep instead of grinding through the store, and
// says so.
func TestReaperCancelledContextEndsTheSweep(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	reaperSeed(t, s, "reaper-untouched", fixedTime.Add(-48*time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reaped, err := reaperAt(s, fixedTime, 24*time.Hour).ReapOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ReapOnce error = %v, want context.Canceled", err)
	}
	if reaped != 0 {
		t.Fatalf("reaped %d after cancellation", reaped)
	}
	if !reaperRowExists(t, s, "reaper-untouched") {
		t.Error("a cancelled sweep still deleted a row")
	}
}
