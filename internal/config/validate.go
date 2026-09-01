package config

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// ValidationError reports one invalid setting, naming both the key and the
// layer that supplied it so an operator knows which file, variable, or flag to
// fix.
type ValidationError struct {
	Key     string
	Source  string
	Message string
}

func (e ValidationError) Error() string {
	if e.Source == "" || e.Source == "default" {
		return fmt.Sprintf("%s: %s", e.Key, e.Message)
	}
	return fmt.Sprintf("%s (from %s): %s", e.Key, e.Source, e.Message)
}

// ValidationErrors is the complete set of problems found in one configuration.
// All problems are reported at once: fixing them one restart at a time is a
// miserable way to bring up a server.
type ValidationErrors []ValidationError

func (errs ValidationErrors) Error() string {
	if len(errs) == 1 {
		return "invalid configuration: " + errs[0].Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration: %d problems:", len(errs))
	for _, e := range errs {
		b.WriteString("\n  - " + e.Error())
	}
	return b.String()
}

// Validate reports every problem with the configuration.
func (c *Config) Validate() error { return c.validate(nil) }

func (c *Config) validate(sources *sourceMap) error {
	v := &validator{cfg: c, sources: sources}

	v.notEmpty("data_dir", c.DataDir)
	v.address("server.address", c.Server.Address)
	v.absoluteURL("server.external_url", c.Server.ExternalURL, true)
	v.positive("server.read_header_timeout", c.Server.ReadHeaderTimeout)
	v.positive("server.shutdown_grace", c.Server.ShutdownGrace)

	v.oneOf("tls.mode", c.TLS.Mode, "off", "acme", "manual")
	switch c.TLS.Mode {
	case "manual":
		v.notEmpty("tls.cert_file", c.TLS.CertFile)
		v.notEmpty("tls.key_file", c.TLS.KeyFile)
	case "acme":
		if len(c.TLS.ACMEDomains) == 0 {
			v.add("tls.acme_domains", "at least one domain is required when tls.mode is acme")
		}
	}

	v.oneOf("database.driver", c.Database.Driver, "sqlite", "postgres")
	if c.Database.Driver == "postgres" {
		v.notEmpty("database.dsn", c.Database.DSN)
	}

	v.oneOf("storage.driver", c.Storage.Driver, "fs", "s3")
	if c.Storage.Driver == "s3" {
		v.notEmpty("storage.s3.endpoint", c.Storage.S3.Endpoint)
		v.notEmpty("storage.s3.bucket", c.Storage.S3.Bucket)
		v.notEmpty("storage.s3.access_key_id", c.Storage.S3.AccessKeyID)
		v.notEmpty("storage.s3.secret_access_key", c.Storage.S3.SecretAccessKey)
	}

	v.nonNegativeBytes("cache.budget", c.Cache.Budget)
	v.nonNegative("cache.tag_ttl", c.Cache.TagTTL)
	v.nonNegative("cache.negative_ttl", c.Cache.NegativeTTL)
	v.oneOf("cache.offline_mode", c.Cache.OfflineMode, "serve-stale", "strict")

	v.durationRange("auth.token_ttl", c.Auth.TokenTTL, time.Minute, time.Hour)
	v.positive("auth.session_idle_ttl", c.Auth.SessionIdleTTL)
	v.positive("auth.session_absolute_ttl", c.Auth.SessionAbsoluteTTL)
	if c.Auth.SessionIdleTTL > c.Auth.SessionAbsoluteTTL {
		v.add("auth.session_idle_ttl", "must not exceed auth.session_absolute_ttl")
	}
	v.positive("auth.robot_default_expiry", c.Auth.RobotDefaultExpiry)

	if c.Scan.Enabled {
		if c.Scan.Concurrency < 1 {
			v.add("scan.concurrency", "must be at least 1 when scanning is enabled")
		}
		if c.Scan.DBUpdateEnabled {
			v.positive("scan.db_update_interval", c.Scan.DBUpdateInterval)
		}
	}

	v.nonNegativeBytes("quota.global_hosted", c.Quota.GlobalHosted)
	if p := c.Quota.SoftThresholdPercent; p < 1 || p > 100 {
		v.add("quota.soft_threshold_percent", fmt.Sprintf("must be between 1 and 100, got %d", p))
	}

	v.positive("webhooks.history_retention", c.Webhooks.HistoryRetention)

	v.oneOf("metrics.exposure", c.Metrics.Exposure, "local", "authed", "open")
	v.oneOf("log.level", c.Log.Level, "debug", "info", "warn", "error")
	v.oneOf("log.format", c.Log.Format, "json", "text")

	if len(v.errs) == 0 {
		return nil
	}
	sort.Slice(v.errs, func(i, j int) bool { return v.errs[i].Key < v.errs[j].Key })
	return v.errs
}

type validator struct {
	cfg     *Config
	sources *sourceMap
	errs    ValidationErrors
}

func (v *validator) add(key, message string) {
	source := "default"
	if v.sources != nil {
		source = v.sources.Source(key)
	}
	v.errs = append(v.errs, ValidationError{Key: key, Source: source, Message: message})
}

func (v *validator) notEmpty(key, value string) {
	if strings.TrimSpace(value) == "" {
		v.add(key, "must not be empty")
	}
}

func (v *validator) oneOf(key, value string, allowed ...string) {
	if slices.Contains(allowed, value) {
		return
	}
	v.add(key, fmt.Sprintf("must be one of %s, got %q", strings.Join(allowed, ", "), value))
}

func (v *validator) positive(key string, d Duration) {
	if d <= 0 {
		v.add(key, fmt.Sprintf("must be greater than zero, got %s", d))
	}
}

func (v *validator) nonNegative(key string, d Duration) {
	if d < 0 {
		v.add(key, fmt.Sprintf("must not be negative, got %s", d))
	}
}

func (v *validator) nonNegativeBytes(key string, b Bytes) {
	if b < 0 {
		v.add(key, fmt.Sprintf("must not be negative, got %s", b))
	}
}

func (v *validator) durationRange(key string, d Duration, minimum, maximum time.Duration) {
	if d.Std() < minimum || d.Std() > maximum {
		v.add(key, fmt.Sprintf("must be between %s and %s, got %s", minimum, maximum, d))
	}
}

func (v *validator) address(key, value string) {
	if strings.TrimSpace(value) == "" {
		v.add(key, "must not be empty")
		return
	}
	if _, _, err := net.SplitHostPort(value); err != nil {
		v.add(key, fmt.Sprintf("must be a host:port address such as :5000, got %q", value))
	}
}

func (v *validator) absoluteURL(key, value string, optional bool) {
	if value == "" {
		if !optional {
			v.add(key, "must not be empty")
		}
		return
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		v.add(key, fmt.Sprintf("must be an absolute http or https URL, got %q", value))
	}
}
