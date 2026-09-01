package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that accepts Go duration strings ("15m", "12h")
// in YAML, environment variables, and flags.
type Duration time.Duration

// String renders the duration in Go's canonical form.
func (d Duration) String() string { return time.Duration(d).String() }

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// ParseDuration parses a Go duration string.
func ParseDuration(s string) (Duration, error) {
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: use a form like 30s, 15m or 12h", s)
	}
	return Duration(v), nil
}

// UnmarshalYAML decodes a duration from a YAML scalar.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\"")
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalYAML renders the duration as a string scalar.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Bytes is a byte quantity that accepts human sizes ("50GB", "512MiB") as well
// as plain byte counts.
type Bytes int64

var byteUnits = []struct {
	suffix string
	factor int64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
	{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000}, {"TB", 1000 * 1000 * 1000 * 1000},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
	{"B", 1},
}

// displayUnits are tried in order when rendering. Decimal units come first so
// a budget written as "50GB" reads back as "50GB" rather than "48828125KiB" --
// 50e9 happens to divide by 1024, and surprising an operator with arithmetic
// they did not ask for is a bad way to display their own configuration.
var displayUnits = []struct {
	suffix string
	factor int64
}{
	{"TB", 1000 * 1000 * 1000 * 1000},
	{"GB", 1000 * 1000 * 1000},
	{"MB", 1000 * 1000},
	{"KB", 1000},
	{"TiB", 1 << 40},
	{"GiB", 1 << 30},
	{"MiB", 1 << 20},
	{"KiB", 1 << 10},
}

// String renders the quantity using the largest unit that divides it exactly,
// so a value round-trips through YAML unchanged.
func (b Bytes) String() string {
	if b == 0 {
		return "0"
	}
	n := int64(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for _, u := range displayUnits {
		if n >= u.factor && n%u.factor == 0 {
			out := strconv.FormatInt(n/u.factor, 10) + u.suffix
			if neg {
				return "-" + out
			}
			return out
		}
	}
	return strconv.FormatInt(int64(b), 10)
}

// Int64 returns the quantity in bytes.
func (b Bytes) Int64() int64 { return int64(b) }

// ParseBytes parses a byte quantity such as "50GB", "512MiB", or "1048576".
func ParseBytes(s string) (Bytes, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("invalid size %q: expected a value like 50GB", s)
	}

	upper := strings.ToUpper(raw)
	for _, u := range byteUnits {
		if !strings.HasSuffix(upper, u.suffix) {
			continue
		}
		num := strings.TrimSpace(upper[:len(upper)-len(u.suffix)])
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q: %q is not a number", s, num)
		}
		return Bytes(v * float64(u.factor)), nil
	}

	v, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: expected a value like 50GB, 512MiB or a byte count", s)
	}
	return Bytes(v), nil
}

// UnmarshalYAML decodes a byte quantity from a YAML string or integer.
func (b *Bytes) UnmarshalYAML(unmarshal func(any) error) error {
	var n int64
	if err := unmarshal(&n); err == nil {
		*b = Bytes(n)
		return nil
	}

	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("size must be a string like \"50GB\" or a byte count")
	}
	v, err := ParseBytes(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// MarshalYAML renders the quantity as a human-readable string.
func (b Bytes) MarshalYAML() (any, error) { return b.String(), nil }
