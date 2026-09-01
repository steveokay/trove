package server

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAcquireDataDirLockExcludesASecondHolder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	first, err := AcquireDataDirLock(dir)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	_, err = AcquireDataDirLock(dir)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire error = %v, want ErrLocked", err)
	}

	// After release the directory is claimable again.
	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	second, err := AcquireDataDirLock(dir)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Errorf("release: %v", err)
	}
}

func TestAcquireDataDirLockCreatesTheDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "nested", "data")

	lock, err := AcquireDataDirLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("data directory was not created: %v", err)
	}
	if lock.Path() != filepath.Join(dir, LockFileName) {
		t.Errorf("Path() = %q, want the lock file inside the data dir", lock.Path())
	}
}

func TestLockFileRecordsOwningPID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lock, err := AcquireDataDirLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	data, err := os.ReadFile(lock.Path())
	if err != nil {
		t.Fatalf("reading lock file: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if got != strconv.Itoa(os.Getpid()) {
		t.Errorf("lock file contains %q, want the current pid %d", got, os.Getpid())
	}
}

func TestAcquireDataDirLockRejectsEmptyPath(t *testing.T) {
	t.Parallel()

	if _, err := AcquireDataDirLock(""); err == nil {
		t.Fatal("acquire succeeded with an empty data directory, want an error")
	}
}

func TestAcquireDataDirLockReportsUncreatableDirectory(t *testing.T) {
	t.Parallel()

	// A regular file cannot become a directory, on any platform.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := AcquireDataDirLock(filepath.Join(file, "data"))
	if err == nil {
		t.Fatal("acquire succeeded under a regular file, want an error")
	}
	if errors.Is(err, ErrLocked) {
		t.Errorf("error = %v, want a creation failure rather than ErrLocked", err)
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	lock, err := AcquireDataDirLock(t.TempDir())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Errorf("second release: %v, want nil", err)
	}

	var nilLock *DataDirLock
	if err := nilLock.Release(); err != nil {
		t.Errorf("release on a nil lock: %v, want nil", err)
	}
}
