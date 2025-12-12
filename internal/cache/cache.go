// Package cache provides an LRU cache with TTL expiration for SPF results.
package cache

import (
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Result represents a cached SPF check result.
type Result struct {
	Action    string
	Reason    string
	SPFResult string
	CachedAt  time.Time
	ExpiresAt time.Time
}

// Cache is an LRU cache with TTL expiration.
type Cache struct {
	cache   *lru.Cache[string, *Result]
	ttl     time.Duration
	mu      sync.RWMutex
	hits    atomic.Int64
	misses  atomic.Int64
	expired atomic.Int64
	evicted atomic.Int64
}

// Stats holds cache statistics.
type Stats struct {
	Size    int
	MaxSize int
	Hits    int64
	Misses  int64
	Expired int64
	Evicted int64
	HitRate float64
}

// New creates a new cache with the given maximum size and TTL.
func New(maxSize int, ttl time.Duration) (*Cache, error) {
	c := &Cache{
		ttl: ttl,
	}

	// Use atomic increment in eviction callback to avoid deadlock.
	// The callback is called while the LRU internal lock is held,
	// and we must not acquire our mutex here.
	cache, err := lru.NewWithEvict[string, *Result](maxSize, func(key string, value *Result) {
		c.evicted.Add(1)
	})
	if err != nil {
		return nil, err
	}
	c.cache = cache

	return c, nil
}

// Get retrieves a value from the cache.
// Returns nil if not found or expired.
func (c *Cache) Get(key string) *Result {
	c.mu.RLock()
	result, ok := c.cache.Get(key)
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil
	}

	// Check expiration
	if time.Now().After(result.ExpiresAt) {
		// Need write lock to remove
		c.mu.Lock()
		c.cache.Remove(key)
		c.mu.Unlock()
		c.expired.Add(1)
		c.misses.Add(1)
		return nil
	}

	c.hits.Add(1)
	return result
}

// Set stores a value in the cache.
func (c *Cache) Set(key string, result *Result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	result.CachedAt = now
	result.ExpiresAt = now.Add(c.ttl)
	c.cache.Add(key, result)
}

// SetWithTTL stores a value with a custom TTL.
func (c *Cache) SetWithTTL(key string, result *Result, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	result.CachedAt = now
	result.ExpiresAt = now.Add(ttl)
	c.cache.Add(key, result)
}

// Delete removes a key from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Remove(key)
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Purge()
}

// ExpireOld removes all expired entries.
func (c *Cache) ExpireOld() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expired := 0
	keys := c.cache.Keys()

	for _, key := range keys {
		if result, ok := c.cache.Peek(key); ok {
			if now.After(result.ExpiresAt) {
				c.cache.Remove(key)
				expired++
			}
		}
	}

	c.expired.Add(int64(expired))
	return expired
}

// Stats returns cache statistics.
func (c *Cache) Stats() Stats {
	hits := c.hits.Load()
	misses := c.misses.Load()
	expired := c.expired.Load()
	evicted := c.evicted.Load()

	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	c.mu.RLock()
	size := c.cache.Len()
	c.mu.RUnlock()

	return Stats{
		Size:    size,
		MaxSize: size, // LRU doesn't expose max size easily
		Hits:    hits,
		Misses:  misses,
		Expired: expired,
		Evicted: evicted,
		HitRate: hitRate,
	}
}

// ResetStats resets the statistics counters.
func (c *Cache) ResetStats() {
	c.hits.Store(0)
	c.misses.Store(0)
	c.expired.Store(0)
	c.evicted.Store(0)
}
