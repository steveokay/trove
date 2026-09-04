package proxy

import (
	"fmt"
	"strings"
	"testing"
)

// The challenge parser reads a header an upstream wrote, so it is fed the
// shapes the large registries actually send and the shapes a hostile one
// might. It must never fail to terminate and never invent a scheme.

func TestParseChallenge(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		values  []string
		ok      bool
		scheme  string
		realm   string
		service string
		scope   string
	}{
		{
			name:   "docker hub",
			values: []string{`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`},
			ok:     true, scheme: "bearer",
			realm: "https://auth.docker.io/token", service: "registry.docker.io", scope: "repository:library/nginx:pull",
		},
		{
			name:   "unquoted values",
			values: []string{`Bearer realm=https://auth.example.com/token,service=registry`},
			ok:     true, scheme: "bearer", realm: "https://auth.example.com/token", service: "registry",
		},
		{
			name:   "extra whitespace",
			values: []string{`Bearer   realm = "https://auth.example.com/token" ,  service = "registry" `},
			ok:     true, scheme: "bearer", realm: "https://auth.example.com/token", service: "registry",
		},
		{
			name:   "a comma inside a quoted value",
			values: []string{`Bearer realm="https://auth.example.com/token",scope="repository:a:pull,push"`},
			ok:     true, scheme: "bearer", realm: "https://auth.example.com/token", scope: "repository:a:pull,push",
		},
		{
			name:   "an escaped quote",
			values: []string{`Bearer realm="https://auth.example.com/to\"ken"`},
			ok:     true, scheme: "bearer", realm: `https://auth.example.com/to"ken`,
		},
		{
			name:   "basic",
			values: []string{`Basic realm="Registry Realm"`},
			ok:     true, scheme: "basic", realm: "Registry Realm",
		},
		{
			name:   "bearer wins over basic",
			values: []string{`Basic realm="registry"`, `Bearer realm="https://auth.example.com/token"`},
			ok:     true, scheme: "bearer", realm: "https://auth.example.com/token",
		},
		{
			name:   "two challenges in one header",
			values: []string{`Bearer realm="https://auth.example.com/token", Basic realm="registry"`},
			ok:     true, scheme: "bearer", realm: "https://auth.example.com/token",
		},
		{name: "a scheme we do not speak", values: []string{"Negotiate"}, ok: false},
		{name: "no header at all", values: nil, ok: false},
		{name: "an empty header", values: []string{""}, ok: false},
		{name: "a scheme with no parameters", values: []string{"Bearer"}, ok: true, scheme: "bearer"},
		{name: "an unterminated quote", values: []string{`Bearer realm="https://auth.example.com/token`}, ok: true, scheme: "bearer", realm: "https://auth.example.com/token"},
		{name: "a parameter with no value", values: []string{`Bearer realm`}, ok: true, scheme: "bearer"},
		{name: "case insensitivity", values: []string{`bEaReR ReAlM="x"`}, ok: true, scheme: "bearer", realm: "x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseChallenge(tc.values)
			if ok != tc.ok {
				t.Fatalf("parseChallenge ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if got.scheme != tc.scheme {
				t.Errorf("scheme = %q, want %q", got.scheme, tc.scheme)
			}
			for field, want := range map[string]string{"realm": tc.realm, "service": tc.service, "scope": tc.scope} {
				if got.params[field] != want {
					t.Errorf("%s = %q, want %q", field, got.params[field], want)
				}
			}
		})
	}
}

// TestParseChallengeIsBounded is the hostile-input case: a challenge with
// thousands of parameters must not become thousands of map entries, and the
// scanner must terminate on anything.
func TestParseChallengeIsBounded(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	builder.WriteString("Bearer ")
	for i := range 5000 {
		if i > 0 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `k%d="v"`, i)
	}

	got, ok := parseChallenge([]string{builder.String()})
	if !ok {
		t.Fatal("a long challenge was rejected outright")
	}
	if len(got.params) > maxChallengeParams {
		t.Errorf("parsed %d parameters, want at most %d", len(got.params), maxChallengeParams)
	}
}

func TestScopeForIsPullOnly(t *testing.T) {
	t.Parallel()

	// There is no configuration that makes a proxy writable (§4), so there is
	// no code path here that can ask an upstream for push.
	if got := scopeFor("library/nginx"); got != "repository:library/nginx:pull" {
		t.Errorf("scopeFor = %q", got)
	}
	if strings.Contains(scopeFor("library/nginx"), "push") {
		t.Error("the client asked an upstream for push access")
	}
}

func TestBasicValue(t *testing.T) {
	t.Parallel()

	// The encoding is RFC 7617's, which is what every registry expects.
	if got := basicValue("robot", "hunter2"); got != "cm9ib3Q6aHVudGVyMg==" {
		t.Errorf("basicValue = %q", got)
	}
}
