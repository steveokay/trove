// Package storage stands in for a storage package the decider must not reach.
package storage

// Get stands in for a query.
func Get(key string) string { return key }
