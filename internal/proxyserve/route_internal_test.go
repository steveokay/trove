package proxyserve

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/repo"
)

// route's defensive branch, tested where it is reachable.
//
// A stored configuration is validated when it is written (C-001), and the
// validation refuses exactly what CompileRoutingRules refuses -- so on the
// serving path this failure cannot happen. It is still handled rather than
// ignored, because route is handed a value rather than a promise, and this
// test is what keeps the handling honest.
func TestRouteReportsRulesItCannotCompile(t *testing.T) {
	t.Parallel()

	s := &Server{}
	_, err := s.route(repo.ProxyConfig{
		Upstream: "https://ghcr.io",
		Allow:    []string{"*/middle/*"},
	}, "owner/app")
	if err == nil {
		t.Fatal("a rule set that cannot compile was accepted")
	}
	if !strings.Contains(err.Error(), "routing rules") {
		t.Errorf("error %q does not say what could not be compiled", err)
	}
}

// The other half of the same guard: a rewritten path the routing grammar will
// not accept as a resource. It cannot arrive from a request either -- the
// router validated the name with the same grammar -- and it must not become an
// upstream request if it ever does.
func TestRouteRefusesAPathTheGrammarRejects(t *testing.T) {
	t.Parallel()

	s := &Server{}
	_, err := s.route(repo.ProxyConfig{Upstream: "https://ghcr.io"}, "NOT A PATH")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Fatalf("error = %v, want ErrContentUnknown", err)
	}
}
