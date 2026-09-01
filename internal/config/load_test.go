package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// harness builds Load options backed by in-memory files and environment.
type harness struct {
	files map[string]string
	env   map[string]string
	args  []string
}

func (h harness) options() Options {
	return Options{
		Args: h.args,
		LookupEnv: func(k string) (string, bool) {
			v, ok := h.env[k]
			return v, ok
		},
		ReadFile: func(name string) ([]byte, error) {
			data, ok := h.files[name]
			if !ok {
				return nil, &fs.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
			}
			return []byte(data), nil
		},
	}
}

func mustLoad(t *testing.T, h harness) *Config {
	t.Helper()

	cfg, err := Load(h.options())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{})

	if cfg.Server.Address != ":5000" {
		t.Errorf("server.address = %q, want :5000", cfg.Server.Address)
	}
	if cfg.Cache.TagTTL.Std() != 15*time.Minute {
		t.Errorf("cache.tag_ttl = %v, want 15m (ADR 0008 / Q11)", cfg.Cache.TagTTL)
	}
	if cfg.Cache.NegativeTTL.Std() != time.Minute {
		t.Errorf("cache.negative_ttl = %v, want 60s", cfg.Cache.NegativeTTL)
	}
	if cfg.Cache.Budget.Int64() != 50*1000*1000*1000 {
		t.Errorf("cache.budget = %s, want 50GB", cfg.Cache.Budget)
	}
	if cfg.Policy.GatingEnabled {
		t.Error("policy.gating_enabled = true, want false by default (Q12)")
	}
	if cfg.Metrics.PerRepo {
		t.Error("metrics.per_repo = true, want false by default (E-006)")
	}
	if cfg.Storage.S3.Redirect {
		t.Error("storage.s3.redirect = true, want false by default (ADR 0007)")
	}
	if !cfg.Database.AutoMigrate {
		t.Error("database.auto_migrate = false, want true by default")
	}
	if cfg.Source("server.address") != "default" {
		t.Errorf("source = %q, want default", cfg.Source("server.address"))
	}
}

func TestLoadDerivesPathsFromDataDir(t *testing.T) {
	t.Parallel()

	const dataDir = "/srv/trove"
	cfg := mustLoad(t, harness{args: []string{"-data-dir", dataDir}})

	// Derived paths are local filesystem paths, so they use the host
	// separator: /srv/trove/storage on Linux, \srv\trove\storage on Windows.
	// Build the expectations the same way rather than assuming either.
	for _, tc := range []struct{ name, got, want string }{
		{"storage root", cfg.Storage.FS.Root, filepath.Join(dataDir, "storage")},
		{"sqlite dsn", cfg.Database.DSN, filepath.Join(dataDir, "trove.db")},
		{"secrets key", cfg.Auth.SecretsKeyFile, filepath.Join(dataDir, "keys", "secrets.key")},
		{"signing key", cfg.Auth.TokenSigningKeyFile, filepath.Join(dataDir, "keys", "token-signing.key")},
		{"acme cache", cfg.TLS.ACMECacheDir, filepath.Join(dataDir, "acme")},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestLoadExplicitPathsSurviveDerivation(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{args: []string{
		"-data-dir", "/srv/trove",
		"-storage.fs.root", "/mnt/blobs",
	}})

	if cfg.Storage.FS.Root != "/mnt/blobs" {
		t.Errorf("storage.fs.root = %q, want the explicit /mnt/blobs", cfg.Storage.FS.Root)
	}
}

func TestLoadPrecedence(t *testing.T) {
	t.Parallel()

	const file = "/etc/trove/trove.yaml"

	tests := []struct {
		name       string
		h          harness
		want       string
		wantSource string
	}{
		{
			name:       "defaults only",
			h:          harness{},
			want:       ":5000",
			wantSource: "default",
		},
		{
			name:       "file beats defaults",
			h:          harness{files: map[string]string{file: "server:\n  address: \":6000\"\n"}},
			want:       ":6000",
			wantSource: "file " + file,
		},
		{
			name: "env beats file",
			h: harness{
				files: map[string]string{file: "server:\n  address: \":6000\"\n"},
				env:   map[string]string{"TROVE_SERVER_ADDRESS": ":7000"},
			},
			want:       ":7000",
			wantSource: "env TROVE_SERVER_ADDRESS",
		},
		{
			name: "flag beats env and file",
			h: harness{
				files: map[string]string{file: "server:\n  address: \":6000\"\n"},
				env:   map[string]string{"TROVE_SERVER_ADDRESS": ":7000"},
				args:  []string{"-server.address", ":8000"},
			},
			want:       ":8000",
			wantSource: "flag -server.address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := mustLoad(t, tt.h)
			if cfg.Server.Address != tt.want {
				t.Errorf("server.address = %q, want %q", cfg.Server.Address, tt.want)
			}
			if got := cfg.Source("server.address"); got != tt.wantSource {
				t.Errorf("source = %q, want %q", got, tt.wantSource)
			}
		})
	}
}

func TestLoadPrecedenceAcrossTypes(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{
		env: map[string]string{
			"TROVE_CACHE_BUDGET":          "10GiB",
			"TROVE_CACHE_TAG_TTL":         "1h",
			"TROVE_SCAN_CONCURRENCY":      "4",
			"TROVE_METRICS_PER_REPO":      "true",
			"TROVE_TLS_ACME_DOMAINS":      "a.example.com, b.example.com",
			"TROVE_POLICY_GATING_ENABLED": "true",
		},
	})

	if cfg.Cache.Budget.Int64() != 10<<30 {
		t.Errorf("cache.budget = %s, want 10GiB", cfg.Cache.Budget)
	}
	if cfg.Cache.TagTTL.Std() != time.Hour {
		t.Errorf("cache.tag_ttl = %v, want 1h", cfg.Cache.TagTTL)
	}
	if cfg.Scan.Concurrency != 4 {
		t.Errorf("scan.concurrency = %d, want 4", cfg.Scan.Concurrency)
	}
	if !cfg.Metrics.PerRepo {
		t.Error("metrics.per_repo = false, want true")
	}
	if !cfg.Policy.GatingEnabled {
		t.Error("policy.gating_enabled = false, want true")
	}
	if len(cfg.TLS.ACMEDomains) != 2 || cfg.TLS.ACMEDomains[0] != "a.example.com" {
		t.Errorf("tls.acme_domains = %v, want two trimmed entries", cfg.TLS.ACMEDomains)
	}
}

func TestLoadBooleanFlagNeedsNoValue(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{args: []string{"-policy.gating-enabled"}})
	if !cfg.Policy.GatingEnabled {
		t.Error("policy.gating_enabled = false, want true from a bare bool flag")
	}
}

func TestLoadNoAutoMigrateAlias(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{args: []string{"-no-auto-migrate"}})

	if cfg.Database.AutoMigrate {
		t.Error("database.auto_migrate = true, want false")
	}
	if got := cfg.Source("database.auto_migrate"); got != "flag -no-auto-migrate" {
		t.Errorf("source = %q, want the alias flag", got)
	}
}

func TestLoadConfigFileSelection(t *testing.T) {
	t.Parallel()

	const custom = "/opt/trove.yaml"
	body := "log:\n  level: debug\n"

	t.Run("flag selects the file", func(t *testing.T) {
		t.Parallel()

		cfg := mustLoad(t, harness{
			files: map[string]string{custom: body},
			args:  []string{"-config", custom},
		})
		if cfg.Log.Level != "debug" {
			t.Errorf("log.level = %q, want debug", cfg.Log.Level)
		}
	})

	t.Run("env selects the file", func(t *testing.T) {
		t.Parallel()

		cfg := mustLoad(t, harness{
			files: map[string]string{custom: body},
			env:   map[string]string{"TROVE_CONFIG": custom},
		})
		if cfg.Log.Level != "debug" {
			t.Errorf("log.level = %q, want debug", cfg.Log.Level)
		}
	})

	t.Run("missing default path is not an error", func(t *testing.T) {
		t.Parallel()

		if _, err := Load(harness{}.options()); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	t.Run("missing explicit path is an error", func(t *testing.T) {
		t.Parallel()

		_, err := Load(harness{args: []string{"-config", "/nope.yaml"}}.options())
		if err == nil {
			t.Fatal("Load succeeded, want an error for a missing explicit config file")
		}
		if !strings.Contains(err.Error(), "/nope.yaml") {
			t.Errorf("error = %v, want it to name the file", err)
		}
	})
}

func TestLoadFileErrors(t *testing.T) {
	t.Parallel()

	const path = "/etc/trove/trove.yaml"

	tests := []struct {
		name     string
		body     string
		wantFrag string
	}{
		{"unknown key", "serverr:\n  address: \":6000\"\n", "field serverr not found"},
		{"wrong type", "server:\n  address: [1, 2]\n", "parsing config file"},
		{"bad duration", "cache:\n  tag_ttl: soon\n", "invalid duration"},
		{"bad size", "cache:\n  budget: enormous\n", "invalid size"},
		{"malformed yaml", "server: {\n", "parsing config file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(harness{files: map[string]string{path: tt.body}}.options())
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantFrag) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantFrag)
			}
		})
	}
}

func TestLoadEmptyFileIsValid(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{files: map[string]string{"/etc/trove/trove.yaml": ""}})
	if cfg.Server.Address != ":5000" {
		t.Errorf("server.address = %q, want the default", cfg.Server.Address)
	}
}

func TestLoadUnreadableFileIsAnError(t *testing.T) {
	t.Parallel()

	opts := Options{
		LookupEnv: func(string) (string, bool) { return "", false },
		ReadFile:  func(string) ([]byte, error) { return nil, errors.New("disk on fire") },
	}
	_, err := Load(opts)
	if err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("Load error = %v, want the underlying read failure", err)
	}
}

func TestLoadBadValuesByLayer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		h        harness
		wantFrag string
	}{
		{
			name:     "bad env duration",
			h:        harness{env: map[string]string{"TROVE_CACHE_TAG_TTL": "soon"}},
			wantFrag: "TROVE_CACHE_TAG_TTL",
		},
		{
			name:     "bad env integer",
			h:        harness{env: map[string]string{"TROVE_SCAN_CONCURRENCY": "many"}},
			wantFrag: "invalid integer",
		},
		{
			name:     "bad env boolean",
			h:        harness{env: map[string]string{"TROVE_METRICS_PER_REPO": "yes-please"}},
			wantFrag: "invalid boolean",
		},
		{
			name:     "bad flag size",
			h:        harness{args: []string{"-cache.budget", "loads"}},
			wantFrag: "-cache.budget",
		},
		{
			name:     "unknown flag",
			h:        harness{args: []string{"-nonsense"}},
			wantFrag: "parsing flags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Load(tt.h.options()); err == nil {
				t.Fatal("Load succeeded, want an error")
			} else if !strings.Contains(err.Error(), tt.wantFrag) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantFrag)
			}
		})
	}
}

func TestNameDerivation(t *testing.T) {
	t.Parallel()

	tests := []struct{ path, env, flag string }{
		{"data_dir", "TROVE_DATA_DIR", "data-dir"},
		{"server.address", "TROVE_SERVER_ADDRESS", "server.address"},
		{"cache.tag_ttl", "TROVE_CACHE_TAG_TTL", "cache.tag-ttl"},
		{"storage.s3.secret_access_key", "TROVE_STORAGE_S3_SECRET_ACCESS_KEY", "storage.s3.secret-access-key"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()

			if got := EnvName(tt.path); got != tt.env {
				t.Errorf("EnvName(%q) = %q, want %q", tt.path, got, tt.env)
			}
			if got := FlagName(tt.path); got != tt.flag {
				t.Errorf("FlagName(%q) = %q, want %q", tt.path, got, tt.flag)
			}
		})
	}
}

func TestEveryFieldIsReachableFromEveryLayer(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	for _, f := range fieldsOf(&cfg) {
		if EnvName(f.path) == EnvPrefix {
			t.Errorf("field %q derives an empty environment variable", f.path)
		}
		if FlagName(f.path) == "" {
			t.Errorf("field %q derives an empty flag name", f.path)
		}
	}

	// The walker must reach nested leaves, not stop at the top level.
	var found bool
	for _, f := range fieldsOf(&cfg) {
		if f.path == "storage.s3.secret_access_key" {
			found = true
			if !f.redact {
				t.Error("storage.s3.secret_access_key is not marked redact")
			}
		}
	}
	if !found {
		t.Error("field walker did not reach storage.s3.secret_access_key")
	}
}

func TestSourceOfUnknownPath(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{})
	if got := cfg.Source("not.a.real.key"); got != "default" {
		t.Errorf("Source(unknown) = %q, want default", got)
	}

	var bare Config
	if got := bare.Source("server.address"); got != "default" {
		t.Errorf("Source on a bare config = %q, want default", got)
	}
}
