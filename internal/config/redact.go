package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// RedactedPlaceholder replaces secret values in any rendered configuration.
const RedactedPlaceholder = "<redacted>"

// Redacted returns a copy of the configuration with every field tagged
// `redact:"true"` replaced by RedactedPlaceholder. Use it for anything an
// operator or a support bundle may see (CLAUDE.md §0.6, ADR 0016).
func (c *Config) Redacted() *Config {
	clone := *c
	for _, f := range fieldsOf(&clone) {
		if !f.redact {
			continue
		}
		if f.value.Kind() == reflect.String && f.value.String() != "" {
			f.value.SetString(RedactedPlaceholder)
		}
	}
	return &clone
}

// String renders the configuration as YAML with secrets redacted. It is safe to
// log. There is deliberately no unredacted renderer: a config dump that can
// leak credentials is one careless call away from an incident.
func (c *Config) String() string {
	out, err := yaml.Marshal(c.Redacted())
	if err != nil {
		return fmt.Sprintf("config: unrenderable: %v", err)
	}
	return string(out)
}

// Explain lists every setting with its value and the layer that supplied it,
// secrets redacted. It answers "why is this value what it is?" without a
// restart.
func (c *Config) Explain() string {
	redacted := c.Redacted()
	fields := fieldsOf(redacted)

	width := 0
	for _, f := range fields {
		if len(f.path) > width {
			width = len(f.path)
		}
	}

	var b strings.Builder
	for _, f := range fields {
		fmt.Fprintf(&b, "%-*s  %-24s  %s\n", width, f.path, stringify(f.value), c.Source(f.path))
	}
	return b.String()
}
