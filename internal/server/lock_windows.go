//go:build windows

package server

import (
	"errors"
	"os"
	"syscall"
)

// errSharingViolation is ERROR_SHARING_VIOLATION: the file is open elsewhere
// with an incompatible sharing mode. The stdlib syscall package does not
// export it by name on Windows.
const errSharingViolation = syscall.Errno(32)

// lockFile opens the lock file for writing while permitting readers. A second
// process asking for write access is refused, which is the mutual exclusion we
// need; readers are still allowed so an operator (or a test) can read the
// owning PID out of the file while the lock is held, as they can on Unix.
// Windows releases the handle when the process exits, matching flock's crash
// behaviour.
func lockFile(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := syscall.CreateFile(
		p,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, errSharingViolation) || errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func unlockFile(f *os.File) error {
	return f.Close()
}
