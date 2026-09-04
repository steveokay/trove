package config

import (
	"path/filepath"
	"time"
)

// gigabyte is the decimal unit used for storage defaults.
const gigabyte = Bytes(1000 * 1000 * 1000)

// Config is the complete runtime configuration. Every field is settable from a
// YAML file, a TROVE_* environment variable, or a flag; see Load for
// precedence. Defaults come from the decision record in CLAUDE.md §13 and the
// ADRs under docs/adr.
type Config struct {
	// DataDir holds blobs, the SQLite database, and key material.
	DataDir string `yaml:"data_dir"`

	Server   Server   `yaml:"server"`
	TLS      TLS      `yaml:"tls"`
	Database Database `yaml:"database"`
	Storage  Storage  `yaml:"storage"`
	Registry Registry `yaml:"registry"`
	Cache    Cache    `yaml:"cache"`
	Auth     Auth     `yaml:"auth"`
	Scan     Scan     `yaml:"scan"`
	Policy   Policy   `yaml:"policy"`
	Quota    Quota    `yaml:"quota"`
	Webhooks Webhooks `yaml:"webhooks"`
	Metrics  Metrics  `yaml:"metrics"`
	Events   Events   `yaml:"events"`
	Log      Log      `yaml:"log"`

	// sources records which layer supplied each value. Unexported so it is
	// invisible to YAML and to the field walker.
	sources *sourceMap
}

// Source reports where the value at a dotted config path came from: "default",
// "file <path>", "env TROVE_X", or "flag -x".
func (c *Config) Source(path string) string {
	if c.sources == nil {
		return "default"
	}
	return c.sources.Source(path)
}

// Server configures the HTTP listener.
type Server struct {
	Address           string   `yaml:"address"`
	ExternalURL       string   `yaml:"external_url"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	ShutdownGrace     Duration `yaml:"shutdown_grace"`
}

// TLS configures transport security. One key switches modes (ADR: PK-004).
type TLS struct {
	Mode         string   `yaml:"mode"` // off | acme | manual
	CertFile     string   `yaml:"cert_file"`
	KeyFile      string   `yaml:"key_file"`
	ACMEEmail    string   `yaml:"acme_email"`
	ACMEDomains  []string `yaml:"acme_domains"`
	ACMECacheDir string   `yaml:"acme_cache_dir"`
}

// Database configures the metadata store (ADR 0006).
type Database struct {
	Driver      string `yaml:"driver"` // sqlite | postgres
	DSN         string `yaml:"dsn" redact:"true"`
	AutoMigrate bool   `yaml:"auto_migrate"`
}

// Storage configures blob storage (ADR 0007).
type Storage struct {
	Driver string    `yaml:"driver"` // fs | s3
	FS     StorageFS `yaml:"fs"`
	S3     StorageS3 `yaml:"s3"`
}

// StorageFS configures the filesystem blob driver.
type StorageFS struct {
	Root string `yaml:"root"`
}

// StorageS3 configures the S3-compatible blob driver.
type StorageS3 struct {
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	Prefix          string `yaml:"prefix"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key" redact:"true"`
	UseSSL          bool   `yaml:"use_ssl"`
	// Redirect serves reads as presigned URLs. Off by default: a redirect
	// bypasses our read-side digest verification (ADR 0007).
	Redirect bool `yaml:"redirect"`
}

// Registry configures the OCI distribution API.
type Registry struct {
	// MaxManifestBytes caps a pushed manifest payload (R-002). Real manifests
	// are kilobytes; the cap keeps an adversarial payload out of memory.
	MaxManifestBytes Bytes `yaml:"max_manifest_bytes"`
	// UploadSessionTTL is how long an upload session may sit idle before the
	// reaper reclaims its row and staged bytes (R-011). Activity refreshes
	// it; an active upload is never reaped.
	UploadSessionTTL Duration `yaml:"upload_session_ttl"`
}

// Cache configures proxy cache semantics (ADR 0008).
type Cache struct {
	Budget      Bytes    `yaml:"budget"`
	TagTTL      Duration `yaml:"tag_ttl"`
	NegativeTTL Duration `yaml:"negative_ttl"`
	OfflineMode string   `yaml:"offline_mode"` // serve-stale | strict
}

// Auth configures identity, tokens, and sessions (ADRs 0004, 0016).
type Auth struct {
	TokenTTL            Duration `yaml:"token_ttl"`
	SessionIdleTTL      Duration `yaml:"session_idle_ttl"`
	SessionAbsoluteTTL  Duration `yaml:"session_absolute_ttl"`
	RobotDefaultExpiry  Duration `yaml:"robot_default_expiry"`
	SecretsKeyFile      string   `yaml:"secrets_key_file"`
	TokenSigningKeyFile string   `yaml:"token_signing_key_file"`
}

// Scan configures vulnerability scanning (ADR 0017).
type Scan struct {
	Enabled          bool     `yaml:"enabled"`
	Concurrency      int      `yaml:"concurrency"`
	DBUpdateEnabled  bool     `yaml:"db_update_enabled"`
	DBUpdateInterval Duration `yaml:"db_update_interval"`
}

// Policy configures pull gating defaults (ADR 0013). Gating is off by default.
type Policy struct {
	GatingEnabled bool `yaml:"gating_enabled"`
}

// Quota configures storage limits (ADR 0014). Zero means unlimited.
type Quota struct {
	GlobalHosted         Bytes `yaml:"global_hosted"`
	SoftThresholdPercent int   `yaml:"soft_threshold_percent"`
}

// Webhooks configures event delivery (ADR 0012).
type Webhooks struct {
	AllowPrivateTargets bool     `yaml:"allow_private_targets"`
	HistoryRetention    Duration `yaml:"history_retention"`
}

// Metrics configures the Prometheus endpoint (ADR 0003 surface 6).
type Metrics struct {
	Exposure string `yaml:"exposure"` // local | authed | open
	PerRepo  bool   `yaml:"per_repo"`
}

// Events configures the event bus (ADR 0012).
type Events struct {
	PersistPulls bool `yaml:"persist_pulls"`
}

// Log configures structured logging.
type Log struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// Defaults returns the configuration used when nothing is set. It is a
// complete, valid configuration except for paths derived from DataDir, which
// Load fills in afterwards.
func Defaults() Config {
	return Config{
		DataDir: "/var/lib/trove",
		Server: Server{
			Address:           ":5000",
			ReadHeaderTimeout: Duration(10 * time.Second),
			ShutdownGrace:     Duration(30 * time.Second),
		},
		TLS: TLS{
			Mode: "off",
		},
		Database: Database{
			Driver:      "sqlite",
			AutoMigrate: true,
		},
		Storage: Storage{
			Driver: "fs",
			S3:     StorageS3{UseSSL: true},
		},
		Registry: Registry{
			MaxManifestBytes: 4 * 1024 * 1024,
			UploadSessionTTL: Duration(24 * time.Hour),
		},
		Cache: Cache{
			Budget:      50 * gigabyte,
			TagTTL:      Duration(15 * time.Minute),
			NegativeTTL: Duration(60 * time.Second),
			OfflineMode: "serve-stale",
		},
		Auth: Auth{
			TokenTTL:           Duration(5 * time.Minute),
			SessionIdleTTL:     Duration(24 * time.Hour),
			SessionAbsoluteTTL: Duration(7 * 24 * time.Hour),
			RobotDefaultExpiry: Duration(90 * 24 * time.Hour),
		},
		Scan: Scan{
			Enabled:          true,
			Concurrency:      1,
			DBUpdateEnabled:  true,
			DBUpdateInterval: Duration(12 * time.Hour),
		},
		Policy: Policy{GatingEnabled: false},
		Quota: Quota{
			GlobalHosted:         0,
			SoftThresholdPercent: 85,
		},
		Webhooks: Webhooks{
			AllowPrivateTargets: false,
			HistoryRetention:    Duration(30 * 24 * time.Hour),
		},
		Metrics: Metrics{Exposure: "local", PerRepo: false},
		Events:  Events{PersistPulls: false},
		Log:     Log{Level: "info", Format: "json"},
	}
}

// deriveDefaults fills in paths that hang off DataDir when the operator has not
// set them explicitly. Done after all layers are applied so that setting
// data_dir alone moves everything with it.
func (c *Config) deriveDefaults() {
	join := func(elem ...string) string { return filepath.Join(append([]string{c.DataDir}, elem...)...) }

	if c.Storage.FS.Root == "" {
		c.Storage.FS.Root = join("storage")
	}
	if c.Database.DSN == "" && c.Database.Driver == "sqlite" {
		c.Database.DSN = join("trove.db")
	}
	if c.Auth.SecretsKeyFile == "" {
		c.Auth.SecretsKeyFile = join("keys", "secrets.key")
	}
	if c.Auth.TokenSigningKeyFile == "" {
		c.Auth.TokenSigningKeyFile = join("keys", "token-signing.key")
	}
	if c.TLS.ACMECacheDir == "" {
		c.TLS.ACMECacheDir = join("acme")
	}
}
