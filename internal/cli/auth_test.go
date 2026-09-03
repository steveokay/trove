package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// explainServer serves the real explain endpoint over a real router, because
// the CLI's contract is "formatting only" (ADR 0015): the way to hold it to
// that is to point it at the code it will really talk to, not at a stub whose
// answers the test invented.
func explainServer(t *testing.T) *httptest.Server {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	// The CLI presents no credentials until the token flow lands (Z-004), so
	// the interesting answers all belong to the anonymous subject: one grant
	// held directly and one carried by a group, exercising both renderings.
	if err := store.CreateGroup(ctx, meta.SubjectGroup{ID: "gid-everyone", Name: "everyone"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := store.AddGroupMember(ctx, "everyone", "anonymous"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	for _, role := range []meta.Role{
		{Name: "developer", Verbs: []string{"repo:read"}},
		{Name: "publisher", Verbs: []string{"repo:read", "repo:write"}},
	} {
		if err := store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole(%q): %v", role.Name, err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-anon", PrincipalKind: meta.PrincipalSubject, PrincipalID: meta.AnonymousSubjectID, Role: "developer", Scope: "public/*"},
		{ID: "b-eve", PrincipalKind: meta.PrincipalGroup, PrincipalID: "gid-everyone", Role: "publisher", Scope: "public/*"},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding(%q): %v", binding.ID, err)
		}
	}

	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
	explain := &server.AuthExplain{Subjects: store, Bindings: store}
	explain.Register(router)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func TestAuthExplainCommand(t *testing.T) {
	t.Parallel()

	srv := explainServer(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "allowed with direct and group grants",
			args: []string{"--verb", "repo:read", "--repo", "public/nginx"},
			want: "allowed repo:read on public/nginx for anonymous\n" +
				"  b-anon: role developer at public/*\n" +
				"  b-eve: role publisher at public/* (via group everyone)\n",
		},
		{
			name: "allowed through a group only",
			args: []string{"--verb", "repo:write", "--repo", "public/nginx"},
			want: "allowed repo:write on public/nginx for anonymous\n" +
				"  b-eve: role publisher at public/* (via group everyone)\n",
		},
		{
			name: "denied names what was asked",
			args: []string{"--verb", "repo:delete", "--repo", "public/nginx"},
			want: "denied repo:delete on public/nginx for anonymous\n" +
				"  no binding grants it\n",
		},
		{
			name: "no repo means the system scope",
			args: []string{"--verb", "user:read"},
			want: "denied user:read on system for anonymous\n" +
				"  no binding grants it\n",
		},
		{
			name: "json passes the response through untouched",
			args: []string{"--verb", "repo:write", "--repo", "public/nginx", "--json"},
			want: `{"subject":{"name":"anonymous","kind":"anonymous","disabled":false},"verb":"repo:write","resource":"public/nginx","allowed":true,"matched":[{"binding":"b-eve","role":"publisher","scope":"public/*","via_group":"everyone"}]}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env, out, _ := newEnv()
			args := append([]string{"auth", "explain", "--server", srv.URL}, tt.args...)
			if err := Run(context.Background(), env, args); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if out.String() != tt.want {
				t.Errorf("stdout:\n got %q\nwant %q", out.String(), tt.want)
			}
		})
	}
}

func TestAuthExplainCommandReportsRefusals(t *testing.T) {
	t.Parallel()

	srv := explainServer(t)
	env, _, _ := newEnv()

	// Anonymous asking about another subject is refused by the server; the
	// CLI relays the problem document's story instead of inventing its own.
	err := Run(context.Background(), env,
		[]string{"auth", "explain", "--server", srv.URL, "--subject", "alice", "--verb", "repo:read"})
	if err == nil {
		t.Fatal("Run succeeded, want the server's refusal surfaced")
	}
	if errors.Is(err, ErrUsage) {
		t.Fatalf("Run = %v, want an operation failure rather than a usage error", err)
	}

	t.Run("a problem's detail is relayed verbatim", func(t *testing.T) {
		t.Parallel()
		env, _, _ := newEnv()
		err := Run(context.Background(), env,
			[]string{"auth", "explain", "--server", srv.URL, "--verb", "repo:frobnicate"})
		if err == nil || !strings.Contains(err.Error(), "repo:frobnicate") {
			t.Errorf("Run = %v, want the server's detail naming the bad verb", err)
		}
	})

	t.Run("a refusal that is not a problem document still reports its status", func(t *testing.T) {
		t.Parallel()
		broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusBadGateway)
		}))
		t.Cleanup(broken.Close)
		env, _, _ := newEnv()
		err := Run(context.Background(), env,
			[]string{"auth", "explain", "--server", broken.URL, "--verb", "repo:read"})
		if err == nil || !strings.Contains(err.Error(), "502") {
			t.Errorf("Run = %v, want the status named", err)
		}
	})

	t.Run("an unreachable server is a plain failure", func(t *testing.T) {
		t.Parallel()
		env, _, _ := newEnv()
		err := Run(context.Background(), env,
			[]string{"auth", "explain", "--server", "http://127.0.0.1:1", "--verb", "repo:read"})
		if err == nil || errors.Is(err, ErrUsage) {
			t.Errorf("Run = %v, want an operation failure", err)
		}
	})

	t.Run("a response that is not the contract is an error", func(t *testing.T) {
		t.Parallel()
		garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		t.Cleanup(garbled.Close)
		env, _, _ := newEnv()
		err := Run(context.Background(), env,
			[]string{"auth", "explain", "--server", garbled.URL, "--verb", "repo:read"})
		if err == nil || !strings.Contains(err.Error(), "could not be parsed") {
			t.Errorf("Run = %v, want a parse failure naming itself", err)
		}
	})
}

func TestAuthExplainCommandUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"missing verb", []string{"auth", "explain", "--server", "http://localhost:0"}},
		{"unparsable server URL", []string{"auth", "explain", "--server", "http://bad host", "--verb", "repo:read"}},
		{"missing server", []string{"auth", "explain", "--verb", "repo:read"}},
		{"unknown flag", []string{"auth", "explain", "--nope"}},
		{"unknown auth subcommand", []string{"auth", "nope"}},
		{"auth without a subcommand", []string{"auth"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env, _, _ := newEnv()
			if err := Run(context.Background(), env, tt.args); !errors.Is(err, ErrUsage) {
				t.Errorf("Run(%v) = %v, want ErrUsage", tt.args, err)
			}
		})
	}
}

// TROVE_TOKEN rides along as a bearer header once set, so the same command
// works unchanged when the token flow lands (Z-004). No t.Parallel: t.Setenv
// forbids it.
func TestAuthExplainCommandSendsTheToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subject":{"name":"anonymous","kind":"anonymous","disabled":false},"verb":"repo:read","resource":"system","allowed":false,"matched":[]}` + "\n"))
	}))
	defer srv.Close()

	t.Setenv("TROVE_TOKEN", "sesame")
	env, _, _ := newEnv()
	if err := Run(context.Background(), env,
		[]string{"auth", "explain", "--server", srv.URL, "--verb", "repo:read"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != "Bearer sesame" {
		t.Errorf("Authorization = %q, want Bearer sesame", got)
	}
}
