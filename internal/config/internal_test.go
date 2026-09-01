package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestOptionsFillSuppliesRealDependencies(t *testing.T) {
	t.Parallel()

	var opts Options
	opts.fill()

	if opts.LookupEnv == nil || opts.ReadFile == nil || opts.Output == nil {
		t.Fatal("fill left a dependency nil")
	}

	// The defaults must be the real ones, not stubs that silently do nothing.
	if _, err := opts.ReadFile(os.DevNull); err != nil {
		t.Errorf("default ReadFile could not read %s: %v", os.DevNull, err)
	}
	if _, ok := opts.LookupEnv("TROVE_DEFINITELY_NOT_SET_" + t.Name()); ok {
		t.Error("default LookupEnv reported an unset variable as present")
	}
	if _, err := opts.Output.Write([]byte("discarded")); err != nil {
		t.Errorf("default Output rejected a write: %v", err)
	}
}

func TestSetValueRejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()

	var target struct {
		Ratio   float64
		Numbers []int
	}
	v := reflect.ValueOf(&target).Elem()

	for _, tc := range []struct {
		name  string
		field reflect.Value
	}{
		{"float", v.Field(0)},
		{"non-string slice", v.Field(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := setValue(tc.field, "1"); err == nil {
				t.Error("setValue accepted an unsupported type; it must refuse rather than silently ignore")
			}
		})
	}
}

func TestPresentPathsIgnoresUnparseableYAML(t *testing.T) {
	t.Parallel()

	if got := presentPaths([]byte("this: [is: not: yaml")); got != nil {
		t.Errorf("presentPaths(garbage) = %v, want nil", got)
	}
}

func TestPresentPathsWalksNestedKeys(t *testing.T) {
	t.Parallel()

	got := presentPaths([]byte("server:\n  address: \":1\"\nlog:\n  level: debug\n"))

	want := map[string]bool{"server.address": true, "log.level": true}
	if len(got) != len(want) {
		t.Fatalf("presentPaths = %v, want %d paths", got, len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
	}
}

func TestApplyFlagsRejectsMalformedAliasValue(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	sources := newSourceMap(&cfg)

	err := applyFlags(&cfg, sources, map[string]string{"no-auto-migrate": "perhaps"})
	if err == nil || !strings.Contains(err.Error(), "no-auto-migrate") {
		t.Fatalf("applyFlags error = %v, want it to name the alias flag", err)
	}
}

func TestApplyFlagsIgnoresAliasWhenFalse(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	sources := newSourceMap(&cfg)

	if err := applyFlags(&cfg, sources, map[string]string{"no-auto-migrate": "false"}); err != nil {
		t.Fatalf("applyFlags: %v", err)
	}
	if !cfg.Database.AutoMigrate {
		t.Error("auto_migrate = false; -no-auto-migrate=false must leave it enabled")
	}
	if got := sources.Source("database.auto_migrate"); got != "default" {
		t.Errorf("source = %q, want default when the alias did not apply", got)
	}
}

func TestSourceMapIgnoresUnknownPaths(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	sources := newSourceMap(&cfg)

	sources.set("not.a.key", "file /somewhere.yaml")

	if got := sources.Source("not.a.key"); got != "default" {
		t.Errorf("Source(unknown) = %q, want default", got)
	}
}

func TestAbsoluteURLRejectsUnparseableInput(t *testing.T) {
	t.Parallel()

	v := &validator{}
	v.absoluteURL("server.external_url", "http://[::1", false)

	if len(v.errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(v.errs))
	}
	if v.errs[0].Key != "server.external_url" {
		t.Errorf("key = %q", v.errs[0].Key)
	}
}

func TestAbsoluteURLRequiredWhenNotOptional(t *testing.T) {
	t.Parallel()

	v := &validator{}
	v.absoluteURL("some.url", "", false)

	if len(v.errs) != 1 || !strings.Contains(v.errs[0].Message, "must not be empty") {
		t.Errorf("errs = %v, want a required-field error", v.errs)
	}
}
