package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// LockFileName is the advisory lock held for the lifetime of a serving
// process. trove is single-node for v1 (ADR 0018) and one process owns the
// data directory; the lock turns a corrupting concurrent start into a clear
// startup error.
const LockFileName = "trove.lock"

// ErrLocked reports that another process holds the data directory.
var ErrLocked = errors.New("data directory is locked by another trove process")

// DataDirLock is an exclusive claim on a data directory.
type DataDirLock struct {
	path string
	file *os.File
}

// AcquireDataDirLock claims dataDir, creating it if necessary. It fails with
// ErrLocked if another process already holds it.
func AcquireDataDirLock(dataDir string) (*DataDirLock, error) {
	if dataDir == "" {
		return nil, errors.New("data directory must not be empty")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating data directory %s: %w", dataDir, err)
	}

	path := filepath.Join(dataDir, LockFileName)
	f, err := lockFile(path)
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}

	// Record the owning PID so an operator can identify the holder. Failure
	// here is not fatal: the lock, not its contents, is what matters.
	if err := f.Truncate(0); err == nil {
		if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
			_ = err
		}
	}

	return &DataDirLock{path: path, file: f}, nil
}

// Path returns the lock file's location.
func (l *DataDirLock) Path() string { return l.path }

// Release drops the lock. It is safe to call more than once.
func (l *DataDirLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return unlockFile(f)
}
