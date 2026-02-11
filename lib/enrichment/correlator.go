package enrichment

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

// ProcessInfo stores cached data about a previously observed process.
type ProcessInfo struct {
	PID            uint32
	Image          string
	CommandLine    string
	User           string
	CurrentDirectory string
}

// Correlator provides an LRU-based cross-event correlation cache for
// parent process lookups.
type Correlator struct {
	cache *lru.Cache[uint32, *ProcessInfo]
}

// NewCorrelator creates a new correlator with the given cache size.
func NewCorrelator(size int) (*Correlator, error) {
	cache, err := lru.New[uint32, *ProcessInfo](size)
	if err != nil {
		return nil, err
	}
	return &Correlator{cache: cache}, nil
}

// Store adds or updates process info in the correlation cache.
func (c *Correlator) Store(pid uint32, info *ProcessInfo) {
	c.cache.Add(pid, info)
}

// Lookup retrieves process info from the cache. Returns nil if not found.
func (c *Correlator) Lookup(pid uint32) *ProcessInfo {
	info, ok := c.cache.Get(pid)
	if !ok {
		return nil
	}
	return info
}

// Len returns the current number of entries in the cache.
func (c *Correlator) Len() int {
	return c.cache.Len()
}
