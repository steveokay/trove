package authz_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
)

// CLAUDE.md §9: every verb needs at least one positive and one negative test.
// A verb with no negative test is an unenforced verb, and it looks exactly
// like an enforced one from the outside.
//
// The allowlist below is what nothing enforces yet. It is a ratchet: a verb
// that acquires tests fails this test until its entry is removed, so it can
// only shrink. When the last entry goes, §9's requirement is met in full and
// this test becomes the thing that keeps it met.
//
// Z-010 took the first three off it -- repo:read, repo:write and gc:run are
// exercised both ways by the handler matrix, which is where a verb is really
// enforced. The rest come off as their handlers land.
func TestEveryVerbHasBothPolarities(t *testing.T) {
	t.Parallel()

	verbtest.AssertVocabularyIsCovered(t, repositoryRoot(t), pendingVerbs)
}

// pendingVerbs are the verbs no test exercises yet, each with the task that
// will wire it up. Entries are removed as those tasks land; adding one back
// requires deleting tests, which is the point.
var pendingVerbs = map[authz.Verb]string{
	authz.RepoList:          "Z-012 permission-filtered listings",
	authz.TagDelete:         "R-003 tag handlers",
	authz.ManifestDelete:    "R-002 manifest handlers",
	authz.ReferrerRead:      "R-005 referrers API",
	authz.RepoCreate:        "C-016 repository admin API",
	authz.RepoConfigure:     "C-016 repository admin API",
	authz.RepoDelete:        "C-016 repository admin API",
	authz.ScanRead:          "S-006 vulnerability queries",
	authz.ScanTrigger:       "S-003 scan queue",
	authz.PolicyRead:        "P-004 dry-run plans",
	authz.PolicyWrite:       "P-002 retention rules",
	authz.PolicyApply:       "P-005 apply path",
	authz.GateOverride:      "S-011 pull gating",
	authz.ProxyRead:         "C-016 repository admin API",
	authz.ProxyWrite:        "C-016 repository admin API",
	authz.ProxyCredentials:  "C-003 upstream credentials",
	authz.QuotaRead:         "P-009 quota accounting",
	authz.QuotaWrite:        "P-009 quota accounting",
	authz.WebhookRead:       "E-002 webhook subscriptions",
	authz.WebhookWrite:      "E-002 webhook subscriptions",
	authz.SearchRead:        "E-010 cross-repo search",
	authz.UserRead:          "Z-014 admin bootstrap",
	authz.UserWrite:         "Z-014 admin bootstrap",
	authz.RoleRead:          "Z-013 effective-permission explainer",
	authz.RoleWrite:         "Z-015 self-lockout prevention",
	authz.AuditRead:         "E-009 audit log",
	authz.SystemMaintenance: "E-008 read-only mode",
}

// repositoryRoot walks up from the test's directory to the module root.
func repositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}
