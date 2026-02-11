package ebpf

import (
	"os/user"
	"strconv"

	lru "github.com/hashicorp/golang-lru/v2"
)

// UserCache provides an LRU cache mapping UID → username string.
type UserCache struct {
	cache *lru.Cache[uint32, string]
}

// NewUserCache creates a new user cache with the given capacity.
func NewUserCache(size int) (*UserCache, error) {
	cache, err := lru.New[uint32, string](size)
	if err != nil {
		return nil, err
	}
	return &UserCache{cache: cache}, nil
}

// Lookup resolves a UID to a username. On cache miss it calls os/user.LookupId.
// Returns the numeric UID as a string if lookup fails.
func (c *UserCache) Lookup(uid uint32) string {
	if name, ok := c.cache.Get(uid); ok {
		return name
	}

	uidStr := strconv.FormatUint(uint64(uid), 10)
	u, err := user.LookupId(uidStr)
	if err != nil {
		c.cache.Add(uid, uidStr)
		return uidStr
	}

	c.cache.Add(uid, u.Username)
	return u.Username
}
