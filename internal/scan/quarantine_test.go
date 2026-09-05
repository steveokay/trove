package scan_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/archtest"
)

// The packages the quarantine rule is about. internal/scan/trivy does not exist
// yet -- S-002 writes it -- which is the point: the boundary is in place before
// the first line of code that could cross it, and a rule matching no package
// passes vacuously by design (archtest.Rules).
const (
	modulePath   = "github.com/steveokay/trove"
	scanPkg      = modulePath + "/internal/scan"
	fakePkg      = modulePath + "/internal/scan/fake"
	adapterPkg   = modulePath + "/internal/scan/trivy"
	vendorPkg    = "github.com/aquasecurity/trivy/pkg/fanal/artifact"
	vendorSister = "github.com/aquasecurity/trivy-db/pkg/types"
	quarantine   = "trivy-is-quarantined"
)

// rule returns the quarantine rule, failing the test if it is missing. A rule
// that is not in the set enforces nothing, and every assertion below would pass
// against an empty Rules().
func rule(t *testing.T) archtest.Rule {
	t.Helper()

	for _, r := range archtest.Rules() {
		if r.Name == quarantine {
			return r
		}
	}
	t.Fatalf("rule %q is not in archtest.Rules(); nothing stops a vendor import", quarantine)
	return archtest.Rule{}
}

// TestVendorQuarantineBites is the half that matters. A boundary test that has
// only ever been seen to pass is indistinguishable from one that cannot fail,
// so this builds graphs that break the rule and insists they are reported.
func TestVendorQuarantineBites(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		importer string
		imported string
	}{
		{name: "the interface package", importer: scanPkg, imported: vendorPkg},
		{name: "the fake", importer: fakePkg, imported: vendorSister},
		{name: "the queue's future neighbours", importer: modulePath + "/internal/policy", imported: vendorPkg},
		{name: "a sibling vendor module", importer: modulePath + "/internal/registry", imported: vendorSister},
		{name: "another engine's library", importer: scanPkg, imported: "github.com/anchore/grype/grype/db"},
	}

	r := rule(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph := archtest.NewGraph(map[string][]string{
				tc.importer: {tc.imported},
				tc.imported: nil,
			})
			violations := graph.Check([]archtest.Rule{r})
			if len(violations) != 1 {
				t.Fatalf("%s importing %s produced %d violations, want 1", tc.importer, tc.imported, len(violations))
			}
			if got := violations[0]; got.From() != tc.importer || got.Forbidden() != tc.imported {
				t.Errorf("violation chain = %s..%s, want %s..%s", got.From(), got.Forbidden(), tc.importer, tc.imported)
			}
			if !strings.Contains(violations[0].Reason, "0017") {
				t.Errorf("the failure does not cite the ADR: %q", violations[0].Reason)
			}
		})
	}
}

// TestVendorQuarantineExemptsTheAdapterOnly is the other half: the rule is
// worthless if the exemption is mistyped, and worse than worthless if the
// exemption is wider than one package.
func TestVendorQuarantineExemptsTheAdapterOnly(t *testing.T) {
	t.Parallel()

	r := rule(t)

	graph := archtest.NewGraph(map[string][]string{
		adapterPkg: {vendorPkg, vendorSister},
		vendorPkg:  nil,
		// A package under the adapter -- its own normalisation helpers -- is
		// covered by the exemption too.
		adapterPkg + "/internal/oci": {vendorPkg},
		vendorSister:                 nil,
	})
	if violations := graph.Check([]archtest.Rule{r}); len(violations) != 0 {
		t.Errorf("the adapter was reported:\n%s", archtest.FormatViolations(violations))
	}

	// Nothing that merely looks like the adapter is exempt.
	for _, impostor := range []string{
		modulePath + "/internal/scan/trivyx",
		modulePath + "/internal/scantrivy",
		modulePath + "/internal/scan",
	} {
		graph := archtest.NewGraph(map[string][]string{impostor: {vendorPkg}, vendorPkg: nil})
		if got := graph.Check([]archtest.Rule{r}); len(got) != 1 {
			t.Errorf("%s got %d violations, want 1: the exemption is wider than one package", impostor, len(got))
		}
	}
}

// TestVendorQuarantineIsDirect pins the mode. A transitive rule here would flag
// the binary's own wiring -- cmd/trove must link the adapter -- and the only way
// to make the suite green again would be to delete the rule.
func TestVendorQuarantineIsDirect(t *testing.T) {
	t.Parallel()

	r := rule(t)
	if r.Mode != archtest.Direct {
		t.Fatalf("rule mode = %s, want direct", r.Mode)
	}

	graph := archtest.NewGraph(map[string][]string{
		modulePath + "/cmd/trove": {adapterPkg},
		adapterPkg:                {vendorPkg},
		vendorPkg:                 nil,
	})
	if violations := graph.Check([]archtest.Rule{r}); len(violations) != 0 {
		t.Errorf("linking the adapter was reported as a violation:\n%s", archtest.FormatViolations(violations))
	}
}

// TestVendorQuarantinePassesVacuouslyToday records the state S-001 leaves the
// repository in: the rule is live, and no package in the module imports a
// vendor scanner because the adapter has not been written yet. When S-002 adds
// it, this test's neighbours above are what keep the exemption honest.
func TestVendorQuarantinePassesVacuouslyToday(t *testing.T) {
	t.Parallel()

	graph, err := archtest.Load(t.Context(), archtest.Options{Patterns: []string{modulePath + "/..."}})
	if err != nil {
		t.Fatalf("loading the module import graph: %v", err)
	}

	packages := graph.Packages()
	if !slices.Contains(packages, scanPkg) || !slices.Contains(packages, fakePkg) {
		t.Fatalf("internal/scan is missing from the loaded graph; the check would pass vacuously for the wrong reason")
	}
	if violations := graph.Check([]archtest.Rule{rule(t)}); len(violations) > 0 {
		t.Fatalf("a vendor scanner is imported outside the adapter:\n\n%s", archtest.FormatViolations(violations))
	}
}
