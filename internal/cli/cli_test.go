package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/version"
)

func newEnv() (Env, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return Env{Stdout: &out, Stderr: &errOut}, &out, &errOut
}

func TestRunVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantOut  string
		wantErr  bool
		exactOut bool
	}{
		{
			name:    "long form",
			args:    []string{"version"},
			wantOut: "trove ",
		},
		{
			name:     "short form",
			args:     []string{"version", "-short"},
			wantOut:  version.Get().Version + "\n",
			exactOut: true,
		},
		{
			name:    "unknown flag is a usage error",
			args:    []string{"version", "-nope"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env, out, _ := newEnv()
			err := Run(context.Background(), env, tt.args)

			if tt.wantErr {
				if !errors.Is(err, ErrUsage) {
					t.Fatalf("err = %v, want ErrUsage", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.exactOut {
				if out.String() != tt.wantOut {
					t.Errorf("stdout = %q, want %q", out.String(), tt.wantOut)
				}
				return
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tt.wantOut)
			}
		})
	}
}

func TestRunUsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"unknown subcommand", []string{"frobnicate"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env, _, errOut := newEnv()
			err := Run(context.Background(), env, tt.args)

			if !errors.Is(err, ErrUsage) {
				t.Fatalf("err = %v, want ErrUsage", err)
			}
			if !strings.Contains(errOut.String(), "usage: trove") {
				t.Errorf("stderr = %q, want usage text", errOut.String())
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"-h", "--help", "help"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()

			env, out, _ := newEnv()
			if err := Run(context.Background(), env, []string{arg}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := out.String()
			if !strings.Contains(got, "usage: trove") {
				t.Errorf("stdout = %q, want usage text", got)
			}
			for _, c := range commands {
				if !strings.Contains(got, c.name) {
					t.Errorf("help output missing command %q", c.name)
				}
			}
		})
	}
}

// implemented lists commands with real behaviour, which therefore must not be
// asserted to report "not implemented". Each has its own tests.
var implemented = map[string]bool{"version": true, "serve": true}

func TestUnimplementedCommandsReportPlainly(t *testing.T) {
	t.Parallel()

	for _, c := range commands {
		if implemented[c.name] {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			env, out, _ := newEnv()
			err := Run(context.Background(), env, []string{c.name})

			if err == nil {
				t.Fatalf("%s returned nil error; unimplemented commands must fail", c.name)
			}
			if errors.Is(err, ErrUsage) {
				t.Errorf("%s returned ErrUsage; want a not-implemented error", c.name)
			}
			if !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("err = %v, want it to mention 'not implemented'", err)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want nothing written", out.String())
			}
		})
	}
}

func TestCommandTableIsWellFormed(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, len(commands))
	for _, c := range commands {
		if c.name == "" || c.summary == "" || c.run == nil {
			t.Errorf("command %+v has an empty field", c)
		}
		if seen[c.name] {
			t.Errorf("duplicate command %q", c.name)
		}
		seen[c.name] = true
	}
}
