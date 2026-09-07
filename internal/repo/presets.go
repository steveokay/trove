package repo

import (
	"fmt"
	"slices"
)

// A preset is a proxy configuration for a public registry an operator would
// otherwise have to assemble by hand: the upstream root, the namespace rewrite
// that makes short names work, and the hosts that registry redirects to when it
// serves blobs or issues tokens.
//
// **Presets ship disabled** (Q7). Nothing here creates a repository, opens a
// connection, or is consulted at boot: they are values in the binary, and a
// fresh install proxies nothing until an operator creates a repository from one
// -- which is a `repo:create` plus `repo:configure` action like any other
// (ADR 0005). That is what makes "no phone-home" (§0.6) a property of the
// install rather than of a default somebody has to remember to turn off.
//
// The trusted-host lists are the part worth getting right and the part an
// operator is least likely to know. Every one of these registries authenticates
// or serves content from somewhere other than the host you point at, so a proxy
// configured without them fails partway through the first pull, in the redirect
// policy, with an error that reads like a bug rather than like configuration.

// Preset is a named proxy configuration for a well-known public registry.
type Preset struct {
	// Name identifies the preset and is the entity name the docs suggest.
	// It is a valid entity name, so `trove` can create a repository from a
	// preset without renaming it first.
	Name string

	// Title is what a UI shows -- the registry's own name.
	Title string

	// Description says what the upstream serves, for an operator choosing
	// between five entries in a list.
	Description string

	// config is the proxy configuration itself, unexported so a caller cannot
	// mutate the package's copy. Config returns a deep copy.
	config ProxyConfig
}

// Config returns the preset's proxy configuration.
//
// It is a deep copy: the slices in the returned value share nothing with the
// package's data, so a caller that appends a routing rule to one repository's
// configuration does not change what the next repository is created with.
func (p Preset) Config() ProxyConfig {
	config := p.config
	config.Allow = slices.Clone(p.config.Allow)
	config.Block = slices.Clone(p.config.Block)
	config.TrustedHosts = slices.Clone(p.config.TrustedHosts)
	return config
}

// presets is the shipped set, in name order. Adding one is a deliberate edit:
// a test asserts the list against a pinned table, so a preset cannot change
// which registry it points at without somebody saying so.
var presets = []Preset{
	{
		Name:        "dockerhub",
		Title:       "Docker Hub",
		Description: "The default registry for `docker pull`, including the official `library/` images.",
		config: ProxyConfig{
			Upstream: "https://registry-1.docker.io",
			// Bare names are official images: `nginx` means `library/nginx`.
			// Without this the most common pull on the internet misses.
			DefaultNamespace: "library",
			// Docker Hub issues tokens at auth.docker.io and serves layers
			// from a CDN under docker.com -- a different registrable domain,
			// which is exactly why TrustedHosts exists.
			TrustedHosts: []string{"auth.docker.io", "*.docker.com"},
		},
	},
	{
		Name:        "gcr",
		Title:       "Google Container Registry",
		Description: "Google's older public registry, still serving distroless and GKE images.",
		config: ProxyConfig{
			Upstream:     "https://gcr.io",
			TrustedHosts: []string{"storage.googleapis.com"},
		},
	},
	{
		Name:        "ghcr",
		Title:       "GitHub Container Registry",
		Description: "Images published from GitHub repositories, under `ghcr.io/<owner>/<name>`.",
		config: ProxyConfig{
			Upstream: "https://ghcr.io",
			// Blob downloads redirect to GitHub's package storage.
			TrustedHosts: []string{"pkg-containers.githubusercontent.com"},
		},
	},
	{
		Name:        "k8s",
		Title:       "Kubernetes Registry",
		Description: "The community registry for Kubernetes images (kube-apiserver, etcd, pause).",
		config: ProxyConfig{
			Upstream: "https://registry.k8s.io",
			// registry.k8s.io is a redirector by design: it sends each client
			// to the nearest mirror, which is Artifact Registry or an S3
			// bucket depending on where the request came from. The entries are
			// broad because the mirror set is regional and changes without
			// notice; the operator docs say so, and an operator who would
			// rather pin them can narrow the list.
			TrustedHosts: []string{"*.pkg.dev", "*.googleapis.com", "*.amazonaws.com"},
		},
	},
	{
		Name:        "quay",
		Title:       "Quay.io",
		Description: "Red Hat's public registry: RHEL, OpenShift, Ceph, and community images.",
		config: ProxyConfig{
			Upstream: "https://quay.io",
			// Quay's CDN hosts are subdomains of quay.io, which the redirect
			// policy already treats as the same family, so this list is empty
			// on purpose rather than by omission.
		},
	},
}

// Presets returns every shipped preset, in name order.
//
// The result is safe to keep: each entry's configuration is copied out, so a
// caller cannot reach the package's data through it.
func Presets() []Preset {
	out := make([]Preset, len(presets))
	for i, preset := range presets {
		out[i] = Preset{
			Name:        preset.Name,
			Title:       preset.Title,
			Description: preset.Description,
			config:      preset.Config(),
		}
	}
	return out
}

// PresetByName returns one preset. The error names the presets that do exist,
// because the caller is usually a person who typed one of five names slightly
// wrong.
func PresetByName(name string) (Preset, error) {
	for _, preset := range presets {
		if preset.Name == name {
			return Preset{
				Name:        preset.Name,
				Title:       preset.Title,
				Description: preset.Description,
				config:      preset.Config(),
			}, nil
		}
	}

	names := make([]string, 0, len(presets))
	for _, preset := range presets {
		names = append(names, preset.Name)
	}
	return Preset{}, fmt.Errorf("%w: no preset %q; the presets are %v", ErrInvalidConfig, name, names)
}
