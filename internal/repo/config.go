package repo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/reponame"
)

// ErrInvalidConfig reports a configuration that cannot belong to its entity
// type. Callers assert with errors.Is.
var ErrInvalidConfig = errors.New("invalid repository configuration")

// ConfigError names the field that was refused and why.
type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("invalid repository configuration: %s: %s", e.Field, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidConfig) true for this typed error.
func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

func configErr(field, reason string) error { return &ConfigError{Field: field, Reason: reason} }

// Config is a validated, typed repository configuration. Exactly one concrete
// type exists per entity type; the JSON in the metadata store is the wire and
// storage form, and this package owns its shape (ADR 0005).
type Config interface {
	// Validate reports whether the configuration is usable as stored.
	Validate() error
}

// HostedConfig configures a hosted entity. It is empty on purpose: hosted
// behaviour is governed by policies and quotas, which are their own resources
// with their own permissions, not repository config.
type HostedConfig struct{}

// Validate reports no problems: there is nothing to get wrong yet.
func (HostedConfig) Validate() error { return nil }

// GroupConfig configures a group entity. The ordered member list and the
// write target are relational (the group_members table, ADR 0006) rather than
// config, so ordering stays schema-unique and auditable; nothing else exists
// to configure yet.
type GroupConfig struct{}

// Validate reports no problems: there is nothing to get wrong yet.
func (GroupConfig) Validate() error { return nil }

// ProxyConfig configures a proxy entity (ADR 0005, ADR 0008). Zero values
// defer to the deployment-wide defaults in the server configuration; only the
// upstream is required.
type ProxyConfig struct {
	// Upstream is the remote registry's root URL: scheme and host, nothing
	// else. Required.
	Upstream string `json:"upstream"`
	// DefaultNamespace, when set, prefixes single-segment remainders — the
	// Docker Hub behaviour where `nginx` means `library/nginx`. Empty means
	// remainders pass through untouched.
	DefaultNamespace string `json:"default_namespace,omitempty"`
	// Allow and Block are routing rules over remainders, in the binding-scope
	// pattern grammar (one grammar, one fuzzer — ADR 0005). Allow is checked
	// first; DefaultDeny refuses anything no Allow pattern matched (C-010).
	Allow []string `json:"allow,omitempty"`
	Block []string `json:"block,omitempty"`
	// DefaultDeny refuses remainders that match no Allow pattern, turning the
	// proxy from an open relay over one upstream into an allowlist.
	DefaultDeny bool `json:"default_deny,omitempty"`
	// TagTTL and NegativeTTL override the deployment-wide lease TTLs
	// (ADR 0008), as Go durations. Empty means the global setting; "0s" on
	// TagTTL means revalidate every pull.
	TagTTL      string `json:"tag_ttl,omitempty"`
	NegativeTTL string `json:"negative_ttl,omitempty"`
	// OfflineMode overrides the deployment-wide degraded-mode behaviour:
	// "serve-stale" or "strict". Empty means the global setting.
	OfflineMode string `json:"offline_mode,omitempty"`
}

// Validate checks every field the way the edge does: nothing unusable may be
// stored, because config is read back on every request path (ADR 0005).
// Upstream credentials are deliberately not here — they are their own
// resource behind proxy:credentials (C-003), never part of a config document
// that repo:configure can read.
func (c ProxyConfig) Validate() error {
	parsed, err := url.Parse(c.Upstream)
	switch {
	case c.Upstream == "":
		return configErr("upstream", "required: a proxy without an upstream proxies nothing")
	case err != nil:
		return configErr("upstream", err.Error())
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return configErr("upstream", fmt.Sprintf("scheme must be http or https, got %q", parsed.Scheme))
	case parsed.Host == "":
		return configErr("upstream", "must name a host")
	case parsed.User != nil:
		return configErr("upstream", "must not carry credentials: upstream secrets are their own resource (proxy:credentials, ADR 0005)")
	case parsed.Path != "" && parsed.Path != "/":
		return configErr("upstream", "must be the registry root: the /v2/ API prefix and the repository path are added per request")
	case parsed.RawQuery != "" || parsed.Fragment != "":
		return configErr("upstream", "must not carry a query or fragment")
	}

	if c.DefaultNamespace != "" {
		if err := reponame.Validate(c.DefaultNamespace); err != nil {
			return configErr("default_namespace", err.Error())
		}
	}
	for _, field := range []struct {
		name     string
		patterns []string
	}{{"allow", c.Allow}, {"block", c.Block}} {
		for _, pattern := range field.patterns {
			scope, err := authz.ParseScope(pattern)
			if err != nil {
				return configErr(field.name, err.Error())
			}
			if scope.String() == "system" {
				return configErr(field.name, "system is a binding scope, not a routing pattern")
			}
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{{"tag_ttl", c.TagTTL}, {"negative_ttl", c.NegativeTTL}} {
		if field.value == "" {
			continue
		}
		d, err := time.ParseDuration(field.value)
		if err != nil {
			return configErr(field.name, err.Error())
		}
		if d < 0 {
			return configErr(field.name, "must not be negative")
		}
	}
	if c.OfflineMode != "" && c.OfflineMode != "serve-stale" && c.OfflineMode != "strict" {
		return configErr("offline_mode", fmt.Sprintf("must be serve-stale or strict, got %q", c.OfflineMode))
	}
	return nil
}

// ParseConfig decodes and validates a stored or submitted configuration for
// an entity type. Unknown fields are refused — a typo in a config key must be
// an error, not a silently ignored intention. Empty input is the zero
// configuration, valid for hosted and group entities and invalid for a proxy
// (which cannot exist without an upstream).
func ParseConfig(t meta.RepositoryType, raw []byte) (Config, error) {
	decode := func(into Config) (Config, error) {
		if len(raw) != 0 {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(into); err != nil {
				return nil, configErr("config", err.Error())
			}
			// A second document would be silently dropped by a plain Decode.
			if dec.More() {
				return nil, configErr("config", "must be a single JSON document")
			}
		}
		cfg := deref(into)
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	switch t {
	case meta.Hosted:
		return decode(&HostedConfig{})
	case meta.Proxy:
		return decode(&ProxyConfig{})
	case meta.Group:
		return decode(&GroupConfig{})
	default:
		return nil, configErr("type", fmt.Sprintf("unknown repository type %q", t))
	}
}

// deref returns the value a decode target points at, so callers hold the
// config by value and cannot share mutations through the interface.
func deref(c Config) Config {
	switch v := c.(type) {
	case *HostedConfig:
		return *v
	case *ProxyConfig:
		return *v
	case *GroupConfig:
		return *v
	default:
		return c
	}
}
