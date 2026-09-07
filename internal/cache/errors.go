package cache

import (
	"errors"
	"fmt"
)

// ErrInvalidOptions reports an Evictor, Scheduler, or TouchBatcher that cannot
// be built from what it was given. Callers assert with errors.Is; the message
// names the field.
//
// Everything here is a wiring mistake rather than a runtime condition, which is
// why one sentinel covers all of them: they are all caught at startup, by the
// process refusing to start (§3).
var ErrInvalidOptions = errors.New("cache: invalid options")

// errInvalid builds an ErrInvalidOptions with a reason.
func errInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOptions, fmt.Sprintf(format, args...))
}
