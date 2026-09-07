package registry

import (
	"testing"

	"github.com/steveokay/trove/internal/meta"
)

// The type branch itself, tested from inside the package because a repository
// type the store should never produce cannot be created through it.
func TestDelegatedFailsClosedOnAnUnknownType(t *testing.T) {
	t.Parallel()

	proxy, group := &nopServer{}, &nopServer{}
	servers := ContentServers{Proxy: proxy, Group: group}

	for _, tc := range []struct {
		name      string
		typ       meta.RepositoryType
		want      ContentServer
		delegated bool
	}{
		{name: "hosted is served here", typ: meta.Hosted, want: nil, delegated: false},
		{name: "proxy", typ: meta.Proxy, want: proxy, delegated: true},
		{name: "group", typ: meta.Group, want: group, delegated: true},
		{
			// A type this package does not know is not hosted, so it must not
			// be served from hosted storage; and there is no delegate for it,
			// so it answers as a repository that does not exist. Failing
			// closed is the only safe reading of a value nothing recognises.
			name: "an unknown type", typ: meta.RepositoryType("virtual"), want: nil, delegated: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, delegated := servers.delegated(tc.typ)
			if delegated != tc.delegated {
				t.Errorf("delegated = %t, want %t", delegated, tc.delegated)
			}
			if got != tc.want {
				t.Errorf("delegate = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// nopServer is a distinguishable ContentServer that is never called.
type nopServer struct{ ContentServer }
