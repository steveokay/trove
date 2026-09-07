package repo_test

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/hostpattern"
	"github.com/steveokay/trove/internal/repo"
)

// TestPresetsArePinned is the deliberate-edit gate. A preset says which
// registry a deployment will fetch from and which hosts it will send an
// upstream credential to, so changing one must be a change somebody made on
// purpose rather than a line that drifted in a refactor.
func TestPresetsArePinned(t *testing.T) {
	t.Parallel()

	want := []struct {
		name             string
		upstream         string
		defaultNamespace string
		trustedHosts     []string
	}{
		{
			name:             "dockerhub",
			upstream:         "https://registry-1.docker.io",
			defaultNamespace: "library",
			trustedHosts:     []string{"auth.docker.io", "*.docker.com"},
		},
		{
			name:         "gcr",
			upstream:     "https://gcr.io",
			trustedHosts: []string{"storage.googleapis.com"},
		},
		{
			name:         "ghcr",
			upstream:     "https://ghcr.io",
			trustedHosts: []string{"pkg-containers.githubusercontent.com"},
		},
		{
			name:         "k8s",
			upstream:     "https://registry.k8s.io",
			trustedHosts: []string{"*.pkg.dev", "*.googleapis.com", "*.amazonaws.com"},
		},
		{
			name:     "quay",
			upstream: "https://quay.io",
		},
	}

	got := repo.Presets()
	if len(got) != len(want) {
		t.Fatalf("Presets() returned %d entries, want %d", len(got), len(want))
	}
	for i, preset := range got {
		config := preset.Config()
		switch {
		case preset.Name != want[i].name:
			t.Errorf("preset %d is %q, want %q (the list is name-ordered)", i, preset.Name, want[i].name)
		case config.Upstream != want[i].upstream:
			t.Errorf("%s upstream = %q, want %q", preset.Name, config.Upstream, want[i].upstream)
		case config.DefaultNamespace != want[i].defaultNamespace:
			t.Errorf("%s default namespace = %q, want %q",
				preset.Name, config.DefaultNamespace, want[i].defaultNamespace)
		case !slices.Equal(config.TrustedHosts, want[i].trustedHosts):
			t.Errorf("%s trusted hosts = %v, want %v", preset.Name, config.TrustedHosts, want[i].trustedHosts)
		}
	}
}

// TestPresetsValidateLikeOperatorConfiguration is the rule that keeps a shipped
// preset from being a configuration nobody could have written: they go through
// the same validation an operator's document does, with no exemption.
func TestPresetsValidateLikeOperatorConfiguration(t *testing.T) {
	t.Parallel()

	for _, preset := range repo.Presets() {
		t.Run(preset.Name, func(t *testing.T) {
			t.Parallel()

			config := preset.Config()
			if err := config.Validate(); err != nil {
				t.Fatalf("preset config is invalid: %v", err)
			}

			// The name is the entity a deployment would mount it at, so it has
			// to be one the router accepts.
			if err := repo.ValidateEntityName(preset.Name); err != nil {
				t.Errorf("preset name is not a usable entity name: %v", err)
			}
			if preset.Title == "" || preset.Description == "" {
				t.Error("a preset an operator picks from a list needs a title and a description")
			}

			// Every upstream is https. A preset shipping a plaintext upstream
			// would hand an operator a credential-leaking default.
			parsed, err := url.Parse(config.Upstream)
			if err != nil {
				t.Fatalf("upstream does not parse: %v", err)
			}
			if parsed.Scheme != "https" {
				t.Errorf("upstream scheme is %q, want https", parsed.Scheme)
			}

			for _, host := range config.TrustedHosts {
				if err := hostpattern.Validate(host); err != nil {
					t.Errorf("trusted host %q: %v", host, err)
				}
				// A trusted host that is already the upstream's own family is
				// noise: the redirect policy allows the upstream host and its
				// subdomains before it reads this list at all.
				if host == parsed.Hostname() || strings.HasSuffix(host, "."+parsed.Hostname()) {
					t.Errorf("trusted host %q is already inside the upstream's family", host)
				}
			}
		})
	}
}

// TestPresetsShipDisabled is Q7 stated as a test. There is no enabled flag to
// assert on, and that is the point: a preset is inert data, so the assertion is
// that nothing about it names a repository or carries state a boot could act
// on. What makes an install quiet is that this list is never instantiated
// (test/offline proves the boot half).
func TestPresetsShipDisabled(t *testing.T) {
	t.Parallel()

	// Routing rules are empty and default-deny is off: a preset restricts
	// nothing on its own, because restricting is a decision its operator makes
	// about their own deployment, not one five public registries share.
	for _, preset := range repo.Presets() {
		config := preset.Config()
		if len(config.Allow) != 0 || len(config.Block) != 0 || config.DefaultDeny {
			t.Errorf("%s ships routing rules; those belong to the operator (C-010)", preset.Name)
		}
		// Zero TTLs and offline mode mean "use the deployment default", which
		// is what a preset should say: an operator lowering cache.tag_ttl
		// globally must not find five repositories quietly overriding it.
		if config.TagTTL != "" || config.NegativeTTL != "" || config.OfflineMode != "" {
			t.Errorf("%s pins TTLs or offline mode; those come from configuration", preset.Name)
		}
	}
}

func TestPresetByName(t *testing.T) {
	t.Parallel()

	preset, err := repo.PresetByName("dockerhub")
	if err != nil {
		t.Fatalf("PresetByName: %v", err)
	}
	if preset.Config().DefaultNamespace != "library" {
		t.Errorf("dockerhub default namespace = %q, want library", preset.Config().DefaultNamespace)
	}

	_, err = repo.PresetByName("dockerhu")
	if !errors.Is(err, repo.ErrInvalidConfig) {
		t.Fatalf("PresetByName(typo) = %v, want ErrInvalidConfig", err)
	}
	// The caller is usually a person who typed one of five names slightly
	// wrong, so the refusal lists them.
	for _, name := range []string{"dockerhub", "ghcr", "quay", "k8s", "gcr"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the %q preset", err, name)
		}
	}
}

// TestPresetConfigsAreCopies pins the ownership rule: the package's data is not
// reachable through anything it hands out, so one repository's configuration
// cannot change what the next one is created with.
func TestPresetConfigsAreCopies(t *testing.T) {
	t.Parallel()

	first, err := repo.PresetByName("dockerhub")
	if err != nil {
		t.Fatalf("PresetByName: %v", err)
	}
	config := first.Config()
	config.TrustedHosts[0] = "evil.example.com"
	config.TrustedHosts = append(config.TrustedHosts, "also-evil.example.com")
	config.Allow = append(config.Allow, "**")

	second, err := repo.PresetByName("dockerhub")
	if err != nil {
		t.Fatalf("PresetByName: %v", err)
	}
	fresh := second.Config()
	if fresh.TrustedHosts[0] != "auth.docker.io" || len(fresh.TrustedHosts) != 2 {
		t.Errorf("trusted hosts leaked between callers: %v", fresh.TrustedHosts)
	}
	if len(fresh.Allow) != 0 {
		t.Errorf("routing rules leaked between callers: %v", fresh.Allow)
	}

	// Presets() hands out the same isolation.
	all := repo.Presets()
	all[0].Config().TrustedHosts[0] = "evil.example.com"
	if repo.Presets()[0].Config().TrustedHosts[0] != "auth.docker.io" {
		t.Error("Presets() shares its slices with the package")
	}
}
