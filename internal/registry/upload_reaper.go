package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// DefaultUploadSessionTTL is how long a session may sit untouched before the
// reaper collects it. A day is generous for a resumable push of a large layer
// over a bad link, and short enough that an abandoned one does not hold its
// staged bytes for a week.
const DefaultUploadSessionTTL = 24 * time.Hour

// uploadReapBatch is how many stale sessions one page of the sweep collects.
// The sweep pages until a short page arrives, so the number only bounds how
// much of the store's answer is held at once.
const uploadReapBatch = 256

// UploadReaperMeta is the slice of the metadata store the reaper needs,
// declared by the consumer (§11). It is deliberately two methods wide: the
// reaper can list abandoned sessions and forget them, and there is no method
// here through which it could reach a manifest, a tag, or a blob row.
type UploadReaperMeta interface {
	// ListStaleUploads returns sessions untouched since the cutoff, oldest
	// first.
	ListStaleUploads(ctx context.Context, before time.Time, limit int) ([]meta.UploadSession, error)

	// DeleteUpload removes a session row.
	DeleteUpload(ctx context.Context, id string) error
}

// UploadReaper collects upload sessions a client walked away from: the row in
// the metadata store and the staged bytes behind it.
//
// It is hosted-side and it never touches committed content (ADR 0009). The
// only thing it can name is an upload session, and a session's bytes are not a
// blob -- they are unverified, they have no digest, and nothing outside the
// session can see them. Once a push commits, its content is a blob row plus
// blob bytes and the session is gone; reclaiming committed storage is garbage
// collection's job, on the other side of a different interface.
//
// An active upload is never touched, and not because the reaper checks: every
// chunk refreshes the session's activity timestamp through UpdateUpload, so a
// session being pushed to simply is not among the ones ListStaleUploads
// returns. The clock that decides is injected (§7), so what counts as
// abandoned is a value the tests set rather than wall time.
type UploadReaper struct {
	// Meta holds the session rows.
	Meta UploadReaperMeta
	// Store holds the staged bytes. It is the hosted store the registry was
	// wired with, the same value the upload handlers write through.
	Store BlobStore
	// TTL is how long a session may be idle before it is collected. Zero
	// means DefaultUploadSessionTTL.
	TTL time.Duration
	// Now supplies the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives what the sweep could not do. Nil falls back to the default
	// logger.
	Log *slog.Logger
}

func (u *UploadReaper) now() time.Time {
	if u.Now == nil {
		return time.Now()
	}
	return u.Now()
}

func (u *UploadReaper) ttl() time.Duration {
	if u.TTL <= 0 {
		return DefaultUploadSessionTTL
	}
	return u.TTL
}

// ReapOnce sweeps every session idle since now minus the TTL and returns how
// many were collected.
//
// A session that cannot be collected is logged and skipped rather than ending
// the sweep -- one wedged row must not keep the rest of an abandoned day's
// uploads on disk -- and every such error comes back joined at the end, so a
// caller still learns the sweep was incomplete. Errors that mean somebody else
// got there first are not failures: a concurrent commit or cancel removing the
// staging directory or the row is exactly the outcome the reaper wanted.
func (u *UploadReaper) ReapOnce(ctx context.Context) (int, error) {
	cutoff := u.now().Add(-u.ttl())
	log := server.Logger(ctx, u.Log)

	var (
		reaped int
		errs   []error
	)
	for {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		batch, err := u.Meta.ListStaleUploads(ctx, cutoff, uploadReapBatch)
		if err != nil {
			errs = append(errs, fmt.Errorf("list stale uploads before %s: %w", cutoff.UTC().Format(time.RFC3339), err))
			break
		}

		collected := 0
		for _, session := range batch {
			if err := u.reap(ctx, session); err != nil {
				log.Error("reap upload session", "id", session.ID, "repo", session.Repository, "error", err)
				errs = append(errs, err)
				continue
			}
			collected++
		}
		reaped += collected

		// A short page is the end of the work. A full page that collected
		// nothing would otherwise be listed again unchanged, forever.
		if len(batch) < uploadReapBatch || collected == 0 {
			break
		}
	}
	return reaped, errors.Join(errs...)
}

// reap discards one session: the staged bytes first, then the row.
//
// The order is the crash-safe one. A crash between the two leaves a row whose
// staging is gone, which the handlers already answer as "upload unknown" -- the
// client restarts its push -- and which the next sweep retries and clears.
// Deleting the row first would invert that: the staged bytes would survive with
// nothing left that could ever list them again.
func (u *UploadReaper) reap(ctx context.Context, session meta.UploadSession) error {
	if err := u.cancelStaging(ctx, session.ID); err != nil {
		return err
	}
	if err := u.Meta.DeleteUpload(ctx, session.ID); err != nil && !errors.Is(err, meta.ErrNotFound) {
		return fmt.Errorf("delete upload row %q: %w", session.ID, err)
	}
	return nil
}

// cancelStaging discards a session's staged bytes. Staging that is already
// gone is success: a commit or a client cancel beat the sweep to it.
func (u *UploadReaper) cancelStaging(ctx context.Context, id string) error {
	staged, err := u.Store.OpenUpload(ctx, id)
	switch {
	case errors.Is(err, blob.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("open upload %q: %w", id, err)
	}
	if err := staged.Cancel(ctx); err != nil && !errors.Is(err, blob.ErrNotFound) {
		return fmt.Errorf("cancel upload %q: %w", id, err)
	}
	return nil
}

// Run sweeps immediately and then on every tick until ctx is done.
//
// This is the interim schedule: P-006 brings a task scheduler with a shared
// run history and a maintenance-mode interlock, and it replaces this loop --
// ReapOnce is the part that survives, because it is the part with the
// behaviour in it. Until then an operator gets a plain ticker, which is enough
// to keep abandoned pushes from accumulating.
func (u *UploadReaper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		reaped, err := u.ReapOnce(ctx)
		log := server.Logger(ctx, u.Log)
		switch {
		case ctx.Err() != nil:
			// Shutdown interrupted the sweep. Whatever it did not collect is
			// still stale next time, so there is nothing to report.
			return
		case err != nil:
			log.Error("stale upload sweep incomplete", "reaped", reaped, "error", err)
		case reaped > 0:
			log.Info("reaped stale upload sessions", "count", reaped)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
