package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	cfg.deriveDefaults()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("shipped defaults must be valid, got: %v", err)
	}
}

func TestValidateCatalog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantKey string
	}{
		{"empty data dir", func(c *Config) { c.DataDir = "  " }, "data_dir"},
		{"address without port", func(c *Config) { c.Server.Address = "localhost" }, "server.address"},
		{"empty address", func(c *Config) { c.Server.Address = "" }, "server.address"},
		{"relative external url", func(c *Config) { c.Server.ExternalURL = "/registry" }, "server.external_url"},
		{"non-http external url", func(c *Config) { c.Server.ExternalURL = "ftp://x.example.com" }, "server.external_url"},
		{"zero read header timeout", func(c *Config) { c.Server.ReadHeaderTimeout = 0 }, "server.read_header_timeout"},
		{"negative shutdown grace", func(c *Config) { c.Server.ShutdownGrace = Duration(-time.Second) }, "server.shutdown_grace"},

		{"unknown tls mode", func(c *Config) { c.TLS.Mode = "maybe" }, "tls.mode"},
		{"manual tls without cert", func(c *Config) { c.TLS.Mode = "manual"; c.TLS.KeyFile = "k.pem" }, "tls.cert_file"},
		{"manual tls without key", func(c *Config) { c.TLS.Mode = "manual"; c.TLS.CertFile = "c.pem" }, "tls.key_file"},
		{"acme without domains", func(c *Config) { c.TLS.Mode = "acme" }, "tls.acme_domains"},

		{"unknown database driver", func(c *Config) { c.Database.Driver = "mysql" }, "database.driver"},
		{"postgres without dsn", func(c *Config) { c.Database.Driver = "postgres"; c.Database.DSN = "" }, "database.dsn"},

		{"unknown storage driver", func(c *Config) { c.Storage.Driver = "tape" }, "storage.driver"},
		{"s3 without endpoint", func(c *Config) { c.Storage.Driver = "s3" }, "storage.s3.endpoint"},
		{"s3 without bucket", func(c *Config) { c.Storage.Driver = "s3" }, "storage.s3.bucket"},
		{"s3 without credentials", func(c *Config) { c.Storage.Driver = "s3" }, "storage.s3.secret_access_key"},

		{"zero manifest cap", func(c *Config) { c.Registry.MaxManifestBytes = 0 }, "registry.max_manifest_bytes"},

		{"negative cache budget", func(c *Config) { c.Cache.Budget = -1 }, "cache.budget"},
		{"negative tag ttl", func(c *Config) { c.Cache.TagTTL = Duration(-time.Minute) }, "cache.tag_ttl"},
		{"negative negative ttl", func(c *Config) { c.Cache.NegativeTTL = Duration(-time.Second) }, "cache.negative_ttl"},
		{"unknown offline mode", func(c *Config) { c.Cache.OfflineMode = "pretend" }, "cache.offline_mode"},

		{"token ttl too short", func(c *Config) { c.Auth.TokenTTL = Duration(30 * time.Second) }, "auth.token_ttl"},
		{"token ttl too long", func(c *Config) { c.Auth.TokenTTL = Duration(2 * time.Hour) }, "auth.token_ttl"},
		{"zero session idle", func(c *Config) { c.Auth.SessionIdleTTL = 0 }, "auth.session_idle_ttl"},
		{"zero session absolute", func(c *Config) { c.Auth.SessionAbsoluteTTL = 0 }, "auth.session_absolute_ttl"},
		{
			name: "idle beyond absolute",
			mutate: func(c *Config) {
				c.Auth.SessionIdleTTL = Duration(48 * time.Hour)
				c.Auth.SessionAbsoluteTTL = Duration(24 * time.Hour)
			},
			wantKey: "auth.session_idle_ttl",
		},
		{"zero robot expiry", func(c *Config) { c.Auth.RobotDefaultExpiry = 0 }, "auth.robot_default_expiry"},

		{"zero scan concurrency", func(c *Config) { c.Scan.Concurrency = 0 }, "scan.concurrency"},
		{"zero db update interval", func(c *Config) { c.Scan.DBUpdateInterval = 0 }, "scan.db_update_interval"},

		{"negative quota", func(c *Config) { c.Quota.GlobalHosted = -1 }, "quota.global_hosted"},
		{"threshold too low", func(c *Config) { c.Quota.SoftThresholdPercent = 0 }, "quota.soft_threshold_percent"},
		{"threshold too high", func(c *Config) { c.Quota.SoftThresholdPercent = 101 }, "quota.soft_threshold_percent"},

		{"zero webhook retention", func(c *Config) { c.Webhooks.HistoryRetention = 0 }, "webhooks.history_retention"},

		{"unknown metrics exposure", func(c *Config) { c.Metrics.Exposure = "public" }, "metrics.exposure"},
		{"unknown log level", func(c *Config) { c.Log.Level = "chatty" }, "log.level"},
		{"unknown log format", func(c *Config) { c.Log.Format = "xml" }, "log.format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := Defaults()
			cfg.deriveDefaults()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error naming %s", tt.wantKey)
			}

			var errs ValidationErrors
			if !errors.As(err, &errs) {
				t.Fatalf("error type = %T, want ValidationErrors", err)
			}
			for _, e := range errs {
				if e.Key == tt.wantKey {
					return
				}
			}
			t.Errorf("errors %v do not mention %s", errs, tt.wantKey)
		})
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	cfg.deriveDefaults()
	cfg.Log.Level = "chatty"
	cfg.Log.Format = "xml"
	cfg.Metrics.Exposure = "public"

	err := cfg.Validate()
	var errs ValidationErrors
	if !errors.As(err, &errs) {
		t.Fatalf("error type = %T, want ValidationErrors", err)
	}
	if len(errs) != 3 {
		t.Errorf("got %d errors, want 3: %v", len(errs), errs)
	}
	if !strings.Contains(err.Error(), "3 problems") {
		t.Errorf("message = %q, want a problem count", err.Error())
	}
}

func TestValidationErrorNamesItsSource(t *testing.T) {
	t.Parallel()

	_, err := Load(harness{
		env: map[string]string{"TROVE_LOG_LEVEL": "chatty"},
	}.options())
	if err == nil {
		t.Fatal("Load succeeded, want a validation error")
	}
	if !strings.Contains(err.Error(), "TROVE_LOG_LEVEL") {
		t.Errorf("error = %v, want it to name the environment variable that set the value", err)
	}

	_, err = Load(harness{
		files: map[string]string{"/etc/trove/trove.yaml": "log:\n  level: chatty\n"},
	}.options())
	if err == nil {
		t.Fatal("Load succeeded, want a validation error")
	}
	if !strings.Contains(err.Error(), "/etc/trove/trove.yaml") {
		t.Errorf("error = %v, want it to name the config file that set the value", err)
	}
}

func TestValidationErrorMessages(t *testing.T) {
	t.Parallel()

	single := ValidationErrors{{Key: "log.level", Source: "default", Message: "bad"}}
	if got := single.Error(); got != "invalid configuration: log.level: bad" {
		t.Errorf("single error = %q", got)
	}

	withSource := ValidationError{Key: "log.level", Source: "env TROVE_LOG_LEVEL", Message: "bad"}
	if got := withSource.Error(); !strings.Contains(got, "from env TROVE_LOG_LEVEL") {
		t.Errorf("error = %q, want the source named", got)
	}

	empty := ValidationError{Key: "k", Message: "bad"}
	if got := empty.Error(); got != "k: bad" {
		t.Errorf("error with no source = %q", got)
	}
}
