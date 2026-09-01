package config

import (
	"strings"
	"testing"
)

const (
	testDSN    = "postgres://trove:hunter2@db.internal/trove"
	testSecret = "wJalrXUtnFEMI-K7MDENG-EXAMPLEKEY"
)

func configWithSecrets() *Config {
	cfg := Defaults()
	cfg.Database.Driver = "postgres"
	cfg.Database.DSN = testDSN
	cfg.Storage.Driver = "s3"
	cfg.Storage.S3.Endpoint = "s3.example.com"
	cfg.Storage.S3.Bucket = "trove"
	cfg.Storage.S3.AccessKeyID = "AKIAEXAMPLE"
	cfg.Storage.S3.SecretAccessKey = testSecret
	cfg.deriveDefaults()
	return &cfg
}

func TestRedactedReplacesSecrets(t *testing.T) {
	t.Parallel()

	cfg := configWithSecrets()
	red := cfg.Redacted()

	if red.Database.DSN != RedactedPlaceholder {
		t.Errorf("database.dsn = %q, want %q", red.Database.DSN, RedactedPlaceholder)
	}
	if red.Storage.S3.SecretAccessKey != RedactedPlaceholder {
		t.Errorf("s3 secret = %q, want %q", red.Storage.S3.SecretAccessKey, RedactedPlaceholder)
	}

	// Non-secret fields survive, and the original is untouched.
	if red.Storage.S3.AccessKeyID != "AKIAEXAMPLE" {
		t.Errorf("access_key_id = %q, want it preserved", red.Storage.S3.AccessKeyID)
	}
	if cfg.Database.DSN != testDSN {
		t.Error("Redacted mutated the original config")
	}
}

func TestRedactedLeavesEmptySecretsEmpty(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	cfg.deriveDefaults()

	if got := cfg.Redacted().Storage.S3.SecretAccessKey; got != "" {
		t.Errorf("unset secret rendered as %q, want an empty string", got)
	}
}

func TestStringNeverLeaksSecrets(t *testing.T) {
	t.Parallel()

	out := configWithSecrets().String()

	for _, secret := range []string{"hunter2", testSecret} {
		if strings.Contains(out, secret) {
			t.Errorf("rendered config leaked %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, RedactedPlaceholder) {
		t.Errorf("rendered config has no redaction marker:\n%s", out)
	}
	if !strings.Contains(out, "address: :5000") {
		t.Errorf("rendered config is missing ordinary values:\n%s", out)
	}
}

func TestExplainShowsValuesAndSources(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, harness{
		files: map[string]string{"/etc/trove/trove.yaml": "cache:\n  tag_ttl: 1h\n"},
		env:   map[string]string{"TROVE_LOG_LEVEL": "debug"},
		args:  []string{"-server.address", ":9000"},
	})

	out := cfg.Explain()

	for _, want := range []string{
		"server.address",
		":9000",
		"flag -server.address",
		"env TROVE_LOG_LEVEL",
		"file /etc/trove/trove.yaml",
		"default",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Explain() missing %q:\n%s", want, out)
		}
	}
}

func TestExplainRedactsSecrets(t *testing.T) {
	t.Parallel()

	out := configWithSecrets().Explain()

	if strings.Contains(out, "hunter2") || strings.Contains(out, testSecret) {
		t.Errorf("Explain leaked a secret:\n%s", out)
	}
	if !strings.Contains(out, RedactedPlaceholder) {
		t.Errorf("Explain has no redaction marker:\n%s", out)
	}
}

func TestExplainRendersEveryFieldType(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	cfg.TLS.ACMEDomains = []string{"a.example.com", "b.example.com"}
	cfg.deriveDefaults()

	out := cfg.Explain()

	for _, want := range []string{
		"15m0s",                       // Duration
		"50GB",                        // Bytes
		"true",                        // bool
		"1",                           // int
		"a.example.com,b.example.com", // []string
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Explain() missing rendering %q:\n%s", want, out)
		}
	}
}
