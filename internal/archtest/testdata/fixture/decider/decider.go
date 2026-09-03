// Package decider stands in for a decision engine that has grown a storage
// dependency through an intermediary -- the violation a transitive rule catches
// and a direct-import rule would miss.
package decider

import "example.com/fixture/middle"

// Decide reaches storage indirectly.
func Decide(key string) string { return middle.Lookup(key) }
