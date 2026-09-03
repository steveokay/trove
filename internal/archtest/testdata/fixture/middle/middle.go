// Package middle sits between the decider and storage, so the fixture exercises
// a multi-hop chain rather than a single edge.
package middle

import "example.com/fixture/storage"

// Lookup forwards to storage.
func Lookup(key string) string { return storage.Get(key) }
