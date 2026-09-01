package config

import (
	"os"
	"path/filepath"
	"testing"
)

const examplePath = "../../trove.example.yaml"

// The shipped example is documentation operators copy verbatim. These tests
// stop it drifting from the code: a renamed key or changed default fails here
// rather than in somebody's deployment.

func TestExampleConfigLoads(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("reading %s: %v", examplePath, err)
	}

	cfg, err := Load(Options{
		Args:      []string{"-config", examplePath},
		LookupEnv: func(string) (string, bool) { return "", false },
		ReadFile: func(name string) ([]byte, error) {
			if filepath.Clean(name) != filepath.Clean(examplePath) {
				t.Errorf("unexpected read of %s", name)
			}
			return data, nil
		},
	})
	if err != nil {
		t.Fatalf("the shipped example must load cleanly: %v", err)
	}
	if cfg.Server.Address != ":5000" {
		t.Errorf("server.address = %q, want :5000", cfg.Server.Address)
	}
}

func TestExampleConfigMatchesDefaults(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("reading %s: %v", examplePath, err)
	}

	fromExample, err := Load(Options{
		Args:      []string{"-config", examplePath},
		LookupEnv: func(string) (string, bool) { return "", false },
		ReadFile:  func(string) ([]byte, error) { return data, nil },
	})
	if err != nil {
		t.Fatalf("loading example: %v", err)
	}

	fromDefaults, err := Load(Options{
		LookupEnv: func(string) (string, bool) { return "", false },
		ReadFile:  func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("loading defaults: %v", err)
	}

	// Compare rendered form: it covers every field and reports differences
	// legibly, unlike a struct equality check.
	if got, want := fromExample.String(), fromDefaults.String(); got != want {
		t.Errorf("trove.example.yaml no longer documents the defaults.\n--- example ---\n%s\n--- defaults ---\n%s", got, want)
	}
}
