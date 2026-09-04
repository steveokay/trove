package repo_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
)

// The config validation corpus, per type. Every rejection asserts
// repo.ErrInvalidConfig and names the field, because the admin API relays
// these to an operator fixing a YAML file.
func TestParseConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		typ     meta.RepositoryType
		raw     string
		wantErr string // empty means the parse must succeed
	}{
		{name: "hosted empty", typ: meta.Hosted, raw: ""},
		{name: "hosted empty object", typ: meta.Hosted, raw: "{}"},
		{name: "hosted with a stray field", typ: meta.Hosted, raw: `{"upstream": "x"}`, wantErr: "unknown field"},

		{name: "group empty", typ: meta.Group, raw: ""},
		{name: "group empty object", typ: meta.Group, raw: "{}"},
		{name: "group with members in config", typ: meta.Group, raw: `{"members": ["a"]}`, wantErr: "unknown field"},

		{name: "proxy minimal", typ: meta.Proxy, raw: `{"upstream": "https://registry-1.docker.io"}`},
		{
			name: "proxy fully loaded",
			typ:  meta.Proxy,
			raw: `{"upstream": "https://ghcr.io", "default_namespace": "library",
				"allow": ["library/*", "trove"], "block": ["library/cursed"], "default_deny": true,
				"tag_ttl": "15m", "negative_ttl": "60s", "offline_mode": "strict"}`,
		},
		{name: "proxy without upstream", typ: meta.Proxy, raw: "{}", wantErr: "upstream"},
		{name: "proxy empty raw", typ: meta.Proxy, raw: "", wantErr: "upstream"},
		{name: "proxy ftp upstream", typ: meta.Proxy, raw: `{"upstream": "ftp://host"}`, wantErr: "scheme"},
		{name: "proxy hostless upstream", typ: meta.Proxy, raw: `{"upstream": "https://"}`, wantErr: "host"},
		{
			name: "proxy upstream with credentials", typ: meta.Proxy,
			raw:     `{"upstream": "https://user:pass@ghcr.io"}`,
			wantErr: "credentials",
		},
		{
			name: "proxy upstream with a path", typ: meta.Proxy,
			raw:     `{"upstream": "https://ghcr.io/v2"}`,
			wantErr: "registry root",
		},
		{
			name: "proxy upstream with a query", typ: meta.Proxy,
			raw:     `{"upstream": "https://ghcr.io?x=1"}`,
			wantErr: "query",
		},
		{
			name: "proxy bad default namespace", typ: meta.Proxy,
			raw:     `{"upstream": "https://h", "default_namespace": "UPPER"}`,
			wantErr: "default_namespace",
		},
		{
			name: "proxy bad allow pattern", typ: meta.Proxy,
			raw:     `{"upstream": "https://h", "allow": ["*/middle/*"]}`,
			wantErr: "allow",
		},
		{
			name: "proxy system as a routing pattern", typ: meta.Proxy,
			raw:     `{"upstream": "https://h", "block": ["system"]}`,
			wantErr: "block",
		},
		{
			name: "proxy unparseable ttl", typ: meta.Proxy,
			raw:     `{"upstream": "https://h", "tag_ttl": "soon"}`,
			wantErr: "tag_ttl",
		},
		{
			name: "proxy negative ttl", typ: meta.Proxy,
			raw:     `{"upstream": "https://h", "negative_ttl": "-1s"}`,
			wantErr: "negative",
		},
		{
			name: "proxy unknown offline mode", typ: meta.Proxy,
			raw:     `{"upstream": "https://h", "offline_mode": "pretend"}`,
			wantErr: "offline_mode",
		},
		{
			name: "proxy trailing second document", typ: meta.Proxy,
			raw:     `{"upstream": "https://h"} {"upstream": "https://evil"}`,
			wantErr: "single JSON document",
		},
		{name: "proxy malformed JSON", typ: meta.Proxy, raw: `{"upstream":`, wantErr: "config"},

		{name: "unknown type", typ: meta.RepositoryType("virtual"), raw: "{}", wantErr: "unknown repository type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := repo.ParseConfig(tt.typ, []byte(tt.raw))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseConfig succeeded with %+v, want error containing %q", cfg, tt.wantErr)
				}
				if !errors.Is(err, repo.ErrInvalidConfig) {
					t.Errorf("error %v is not ErrInvalidConfig", err)
				}
				if got := err.Error(); !strings.Contains(got, tt.wantErr) {
					t.Errorf("error %q does not mention %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("a parsed config re-validates: %v", err)
			}
		})
	}
}

// The typed result is the type the entity demands, held by value.
func TestParseConfigReturnsTheRightType(t *testing.T) {
	t.Parallel()

	if cfg, _ := repo.ParseConfig(meta.Hosted, nil); cfg != (repo.HostedConfig{}) {
		t.Errorf("hosted config = %#v", cfg)
	}
	if cfg, _ := repo.ParseConfig(meta.Group, nil); cfg != (repo.GroupConfig{}) {
		t.Errorf("group config = %#v", cfg)
	}
	cfg, err := repo.ParseConfig(meta.Proxy, []byte(`{"upstream": "https://quay.io"}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	proxy, ok := cfg.(repo.ProxyConfig)
	if !ok || proxy.Upstream != "https://quay.io" {
		t.Errorf("proxy config = %#v", cfg)
	}
}
