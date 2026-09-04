package registry_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// The batcher's tests never sleep and never wait on wall time: the flush timer
// is injected as a channel the test sends on, and every completed flush is
// observed through the store it wrote to.

var errPullStore = errors.New("pull statistics store is down")

func pullQuiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// pullSpyMeta stands in for the metadata store: it counts flushes, keeps every
// record it was handed, and can fail once or stall until released.
type pullSpyMeta struct {
	mu      sync.Mutex
	calls   int
	rows    []meta.PullRecord
	failing bool

	// release, when non-nil, holds a flush inside the store until it is
	// closed. It is how a test gets the batcher's goroutine stuck so the queue
	// behind it fills.
	release chan struct{}
	// flushed reports the size of each batch the store accepted. Buffered by
	// every caller, so signalling it never stalls the batcher.
	flushed chan int
}

func (m *pullSpyMeta) RecordPulls(_ context.Context, records []meta.PullRecord) error {
	if m.release != nil {
		<-m.release
	}

	m.mu.Lock()
	m.calls++
	m.rows = append(m.rows, records...)
	failed := m.failing
	m.failing = false
	m.mu.Unlock()

	if m.flushed != nil {
		m.flushed <- len(records)
	}
	if failed {
		return errPullStore
	}
	return nil
}

func (m *pullSpyMeta) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// recorded returns every record the store was handed, and the pulls they
// account for in total.
func (m *pullSpyMeta) recorded() ([]meta.PullRecord, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var total int64
	out := make([]meta.PullRecord, len(m.rows))
	copy(out, m.rows)
	for _, r := range out {
		total += r.Count
	}
	return out, total
}

// pullSpyRecorder is the synchronous half of the seam: it proves which
// requests reach a recorder at all, without a batcher in the way.
type pullSpyRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *pullSpyRecorder) Record(repo, reference string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, repo+" "+reference)
}

func (r *pullSpyRecorder) records() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// pullNotifyStore is the real in-memory store with a completion signal on it,
// so a test can wait for a flush to land rather than poll for its effect.
type pullNotifyStore struct {
	*metamem.Store
	flushed chan int
}

func (s *pullNotifyStore) RecordPulls(ctx context.Context, records []meta.PullRecord) error {
	err := s.Store.RecordPulls(ctx, records)
	s.flushed <- len(records)
	return err
}

// pullBatcher starts a batcher whose only flush trigger is the returned ticks
// channel plus the row bound, and closes it when the test ends.
func pullBatcher(t *testing.T, opts registry.PullBatcherOptions) (*registry.PullBatcher, chan time.Time) {
	t.Helper()

	ticks := make(chan time.Time)
	opts.Ticks = ticks
	if opts.Now == nil {
		opts.Now = func() time.Time { return fixedTime }
	}
	if opts.Log == nil {
		opts.Log = pullQuiet()
	}
	b := registry.NewPullBatcher(opts)
	t.Cleanup(func() {
		if err := b.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return b, ticks
}

// pullTickUntilFlush offers ticks until one finds a non-empty batch. An
// observation and a tick race inside the batcher's select, so the first tick
// may arrive before the observation was folded in; a tick that flushes nothing
// writes nothing, so there is nothing to wait for and another tick follows.
func pullTickUntilFlush(t *testing.T, ticks chan<- time.Time, flushed <-chan int) int {
	t.Helper()

	for {
		select {
		case ticks <- fixedTime:
		case rows := <-flushed:
			return rows
		}
	}
}

// pullStack rebuilds the fixture's routes with a manifest handler that records
// pulls. The stores are the fixture's own, so the seeding helpers still apply.
func pullStack(t *testing.T, recorder registry.PullRecorder) stack {
	t.Helper()

	s := newStack(t)
	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
		Log: pullQuiet(),
	})
	(&registry.Manifests{
		Meta:  s.metaDB,
		Now:   func() time.Time { return fixedTime },
		Pulls: recorder,
		Log:   pullQuiet(),
	}).Register(router)
	s.handler = router
	s.router = router
	return s
}

func TestPullBatcherFlushesWhenTheBatchIsFull(t *testing.T) {
	t.Parallel()

	spy := &pullSpyMeta{flushed: make(chan int, 8)}
	b, _ := pullBatcher(t, registry.PullBatcherOptions{Meta: spy, MaxRows: 3})

	// The bound counts distinct references, so three references reach it.
	for _, reference := range []string{"a", "b", "c"} {
		b.Record("team-a/api", reference)
	}

	if rows := <-spy.flushed; rows != 3 {
		t.Fatalf("flushed %d rows, want 3", rows)
	}
	if got := spy.callCount(); got != 1 {
		t.Errorf("store called %d times, want exactly one transaction per flush", got)
	}
}

func TestPullBatcherFlushesOnTheInterval(t *testing.T) {
	t.Parallel()

	spy := &pullSpyMeta{flushed: make(chan int, 8)}
	// A row bound far out of reach: the only thing that can flush this batch
	// is the clock.
	b, ticks := pullBatcher(t, registry.PullBatcherOptions{Meta: spy, MaxRows: 1_000_000})

	b.Record("team-a/api", "latest")
	if rows := pullTickUntilFlush(t, ticks, spy.flushed); rows != 1 {
		t.Fatalf("flushed %d rows, want 1", rows)
	}
}

func TestPullBatcherFlushesOnClose(t *testing.T) {
	t.Parallel()

	spy := &pullSpyMeta{flushed: make(chan int, 8)}
	b, _ := pullBatcher(t, registry.PullBatcherOptions{Meta: spy, MaxRows: 1_000_000})

	b.Record("team-a/api", "latest")
	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rows := <-spy.flushed; rows != 1 {
		t.Fatalf("flushed %d rows on close, want the pending pull", rows)
	}

	// Closing twice is safe, and the second close has nothing left to write.
	if err := b.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if got := spy.callCount(); got != 1 {
		t.Errorf("store called %d times, want 1", got)
	}
}

// A thousand pulls of one tag is one row with a count of a thousand. Without
// aggregation this is the case that would put a thousand rows through a
// transaction, which is the whole reason the batcher exists.
func TestPullBatcherAggregatesRepeatedPulls(t *testing.T) {
	t.Parallel()

	spy := &pullSpyMeta{flushed: make(chan int, 8)}
	b, _ := pullBatcher(t, registry.PullBatcherOptions{Meta: spy})
	s := pullStack(t, b)
	seedImageBlobs(t, s)
	putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, imageManifest())

	const pulls = 1000
	for i := 0; i < pulls; i++ {
		if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "rita", ""); rec.Code != http.StatusOK {
			t.Fatalf("GET %d: %d %s", i, rec.Code, rec.Body)
		}
	}

	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rows := <-spy.flushed; rows != 1 {
		t.Fatalf("flushed %d rows, want one row for one tag", rows)
	}

	records, total := spy.recorded()
	if len(records) != 1 || records[0].Repository != "team-a/api" || records[0].Reference != "v1" {
		t.Fatalf("records = %+v, want a single row naming the tag", records)
	}
	if total != pulls {
		t.Errorf("count = %d, want %d: every pull counts, even folded into one row", total, pulls)
	}
	if !records[0].At.Equal(fixedTime) {
		t.Errorf("At = %v, want the injected clock's time", records[0].At)
	}
}

// The §9 proof: the pull path adds no database write. N pulls, zero store
// calls, until something asks for a flush.
func TestPullsAddNoStoreCallToTheHotPath(t *testing.T) {
	t.Parallel()

	spy := &pullSpyMeta{flushed: make(chan int, 8)}
	b, _ := pullBatcher(t, registry.PullBatcherOptions{Meta: spy})
	s := pullStack(t, b)
	seedImageBlobs(t, s)
	putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, imageManifest())

	const pulls = 50
	for i := 0; i < pulls; i++ {
		if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "rita", ""); rec.Code != http.StatusOK {
			t.Fatalf("GET %d: %d %s", i, rec.Code, rec.Body)
		}
	}

	// Nothing can have flushed: the batch is far from its row bound and no
	// tick has been offered, so a non-zero count here means a pull wrote.
	if got := spy.callCount(); got != 0 {
		t.Fatalf("%d store calls for %d pulls, want none on the pull path", got, pulls)
	}

	// And the counts were not lost: they were waiting for a flush.
	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-spy.flushed
	if _, total := spy.recorded(); total != pulls {
		t.Errorf("recorded %d pulls after the flush, want %d", total, pulls)
	}
}

func TestPullRecordingCoversGetByTagAndDigestButNotHead(t *testing.T) {
	t.Parallel()

	spy := &pullSpyRecorder{}
	s := pullStack(t, spy)
	seedImageBlobs(t, s)
	payload := imageManifest()
	digest := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, payload)

	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "rita", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET by tag: %d %s", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "rita", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET by digest: %d %s", rec.Code, rec.Body)
	}
	// A HEAD is a probe, not a pull: an existence check must not keep a tag
	// alive against a last-pulled retention rule.
	if rec := s.do(t, http.MethodHead, "/v2/team-a/api/manifests/v1", "rita", ""); rec.Code != http.StatusOK {
		t.Fatalf("HEAD: %d", rec.Code)
	}

	want := []string{"team-a/api v1", "team-a/api " + digest}
	if got := spy.records(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("recorded %v, want %v", got, want)
	}
}

// Nothing that was not served counts: an unknown tag, an unreadable
// repository, and a reference that cannot name anything all record nothing.
func TestFailedPullRecordsNothing(t *testing.T) {
	t.Parallel()

	spy := &pullSpyRecorder{}
	s := pullStack(t, spy)

	tests := []struct {
		name   string
		target string
		as     string
	}{
		{"unknown tag", "/v2/team-a/api/manifests/nope", "rita"},
		{"unreadable repository", "/v2/secret/vault/manifests/v1", "rita"},
		{"unknown repository", "/v2/team-a/ghost/manifests/v1", "rita"},
		{"malformed reference", "/v2/team-a/api/manifests/-not-a-tag", "rita"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := s.do(t, http.MethodGet, tt.target, tt.as, ""); rec.Code == http.StatusOK {
				t.Fatalf("GET %s succeeded unexpectedly", tt.target)
			}
		})
	}

	if got := spy.records(); len(got) != 0 {
		t.Errorf("recorded %v, want nothing: only a served pull counts", got)
	}
}

// A store that refuses a batch loses that batch and nothing else. Retrying
// into a broken store would grow the batch without bound at exactly the moment
// memory is worth least.
func TestPullBatcherDropsARefusedBatch(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	spy := &pullSpyMeta{failing: true, flushed: make(chan int, 8)}
	b, ticks := pullBatcher(t, registry.PullBatcherOptions{
		Meta: spy, MaxRows: 1_000_000,
		Log: slog.New(slog.NewTextHandler(&logged, nil)),
	})

	b.Record("team-a/api", "doomed")
	if rows := pullTickUntilFlush(t, ticks, spy.flushed); rows != 1 {
		t.Fatalf("first flush wrote %d rows, want 1", rows)
	}

	b.Record("team-a/api", "next")
	if rows := pullTickUntilFlush(t, ticks, spy.flushed); rows != 1 {
		t.Fatalf("second flush wrote %d rows, want only the new pull", rows)
	}

	records, _ := spy.recorded()
	if len(records) != 2 || records[0].Reference != "doomed" || records[1].Reference != "next" {
		t.Fatalf("records = %+v, want the refused batch dropped rather than replayed", records)
	}
	if !strings.Contains(logged.String(), "dropped a batch of pull statistics") {
		t.Errorf("log = %q, want the refused batch reported", logged.String())
	}
}

// A full queue drops observations instead of blocking. If Record ever waited,
// this test would deadlock rather than fail an assertion -- which is the
// property under test: a pull must never wait on a statistic.
func TestPullBatcherDropsWhenTheQueueIsFull(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	release := make(chan struct{})
	spy := &pullSpyMeta{release: release, flushed: make(chan int, 256)}
	ticks := make(chan time.Time)
	b := registry.NewPullBatcher(registry.PullBatcherOptions{
		Meta: spy, MaxRows: 1, QueueDepth: 2, Ticks: ticks,
		Now: func() time.Time { return fixedTime },
		Log: slog.New(slog.NewTextHandler(&logged, nil)),
	})

	// The first observation trips the row bound, so the batcher's goroutine is
	// inside the store, waiting on release. Everything offered now has only
	// the queue to sit in.
	b.Record("team-a/api", "first")
	const offered = 100
	for i := 0; i < offered; i++ {
		b.Record("team-a/api", fmt.Sprintf("v%d", i))
	}
	close(release)

	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, total := spy.recorded()
	if total >= offered {
		t.Errorf("recorded %d pulls of %d offered, want the overflow dropped", total, offered+1)
	}
	if !strings.Contains(logged.String(), "dropped pull observations") {
		t.Errorf("log = %q, want the drop count reported", logged.String())
	}
}

// Counts accumulate across flushes: the store upserts, so a reference pulled
// in two separate batches ends with the sum and the later timestamp.
func TestPullCountsAccumulateAcrossFlushes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	inner := metamem.New()
	t.Cleanup(func() { _ = inner.Close() })
	store := &pullNotifyStore{Store: inner, flushed: make(chan int, 8)}

	later := fixedTime.Add(time.Hour)
	at := fixedTime
	b, _ := pullBatcher(t, registry.PullBatcherOptions{
		Meta: store, MaxRows: 1,
		Now: func() time.Time { return at },
	})

	// The row bound is one, so each observation is its own transaction.
	b.Record("team-a/api", "latest")
	<-store.flushed
	at = later
	b.Record("team-a/api", "latest")
	<-store.flushed

	stats, err := inner.GetPullStats(ctx, "team-a/api", "latest")
	if err != nil {
		t.Fatalf("GetPullStats: %v", err)
	}
	if stats.Count != 2 {
		t.Errorf("count = %d, want 2: the second flush adds to the first", stats.Count)
	}
	if !stats.LastPulledAt.Equal(later) {
		t.Errorf("LastPulledAt = %v, want the later pull %v", stats.LastPulledAt, later)
	}
}

// The defaults are what serve gets: its own ticker, wall time, the default
// logger, and the documented bounds. Nothing here waits for the minute to
// elapse -- Close is the other way a batch is written.
func TestPullBatcherDefaults(t *testing.T) {
	t.Parallel()

	spy := &pullSpyMeta{flushed: make(chan int, 8)}
	b := registry.NewPullBatcher(registry.PullBatcherOptions{Meta: spy})

	b.Record("team-a/api", "latest")
	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rows := <-spy.flushed; rows != 1 {
		t.Fatalf("flushed %d rows, want the pending pull", rows)
	}
	records, _ := spy.recorded()
	if records[0].At.IsZero() {
		t.Error("At is zero: the default clock should have stamped the observation")
	}
}

// Shutdown does not hang on a store that has stopped answering: Close reports
// its context's error and leaves the batch to the process ending.
func TestPullBatcherCloseGivesUpWithItsContext(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	spy := &pullSpyMeta{release: release, flushed: make(chan int, 8)}
	ticks := make(chan time.Time)
	b := registry.NewPullBatcher(registry.PullBatcherOptions{
		Meta: spy, MaxRows: 1, Ticks: ticks,
		Now: func() time.Time { return fixedTime }, Log: pullQuiet(),
	})
	// Once released, the goroutine finishes on its own.
	t.Cleanup(func() { close(release) })

	b.Record("team-a/api", "latest")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close with a cancelled context = %v, want context.Canceled", err)
	}
}

// A nil recorder is the disabled case, and it must cost the pull path nothing
// -- including a panic.
func TestPullRecordingIsOptional(t *testing.T) {
	t.Parallel()

	s := pullStack(t, nil)
	seedImageBlobs(t, s)
	putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, imageManifest())

	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "rita", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET with recording disabled: %d %s", rec.Code, rec.Body)
	}
}
