package shrike

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Default cache configuration.
const (
	// DefaultCacheTTL is the default time-to-live for cached scan results.
	DefaultCacheTTL = 5 * time.Minute

	// DefaultCacheMaxSize is the default maximum number of cached entries.
	DefaultCacheMaxSize = 1000
)

// CacheStats provides read-only cache statistics.
type CacheStats struct {
	Hits    uint64
	Misses  uint64
	Size    int
	MaxSize int
	HitRate float64
}

type cacheEntry struct {
	value     interface{}
	createdAt time.Time
}

// ContentCache is a thread-safe LRU cache with TTL expiry.
// It uses SHA256 content hashes as keys to deduplicate scan requests.
type ContentCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	order   []string // insertion order for LRU eviction
	maxSize int
	ttl     time.Duration
	hits    uint64
	misses  uint64
}

// NewContentCache creates a new content cache.
func NewContentCache(ttl time.Duration, maxSize int) *ContentCache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if maxSize <= 0 {
		maxSize = DefaultCacheMaxSize
	}
	return &ContentCache{
		entries: make(map[string]*cacheEntry, maxSize),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// HashContent computes a SHA256 hash of the content for use as a cache key.
func HashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// Get retrieves a cached value by content hash. Returns nil, false if not found or expired.
func (c *ContentCache) Get(contentHash string) (interface{}, bool) {
	c.mu.RLock()
	entry, exists := c.entries[contentHash]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	// Check TTL
	if time.Since(entry.createdAt) > c.ttl {
		c.mu.Lock()
		delete(c.entries, contentHash)
		c.removeFromOrder(contentHash)
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return entry.value, true
}

// Set stores a value in the cache. Evicts the oldest entry if at capacity.
func (c *ContentCache) Set(contentHash string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry
	if _, exists := c.entries[contentHash]; exists {
		c.entries[contentHash] = &cacheEntry{
			value:     value,
			createdAt: time.Now(),
		}
		return
	}

	// Evict oldest if at capacity
	for len(c.entries) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}

	c.entries[contentHash] = &cacheEntry{
		value:     value,
		createdAt: time.Now(),
	}
	c.order = append(c.order, contentHash)
}

// Stats returns cache statistics.
func (c *ContentCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	return CacheStats{
		Hits:    c.hits,
		Misses:  c.misses,
		Size:    len(c.entries),
		MaxSize: c.maxSize,
		HitRate: hitRate,
	}
}

// Clear removes all entries from the cache.
func (c *ContentCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry, c.maxSize)
	c.order = c.order[:0]
}

func (c *ContentCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}
