package shrike

import (
	"testing"
	"time"
)

func TestContentCache_HitAndMiss(t *testing.T) {
	cache := NewContentCache(5*time.Minute, 100)

	hash := HashContent("hello world")
	cache.Set(hash, "result1")

	val, ok := cache.Get(hash)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if val != "result1" {
		t.Errorf("expected result1, got %v", val)
	}

	_, ok = cache.Get(HashContent("nonexistent"))
	if ok {
		t.Error("expected cache miss for unknown key")
	}
}

func TestContentCache_TTLExpiry(t *testing.T) {
	cache := NewContentCache(50*time.Millisecond, 100)

	hash := HashContent("test")
	cache.Set(hash, "value")

	val, ok := cache.Get(hash)
	if !ok || val != "value" {
		t.Fatal("expected cache hit before TTL")
	}

	time.Sleep(60 * time.Millisecond)

	_, ok = cache.Get(hash)
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestContentCache_LRUEviction(t *testing.T) {
	cache := NewContentCache(5*time.Minute, 3)

	cache.Set("a", "1")
	cache.Set("b", "2")
	cache.Set("c", "3")

	// At capacity — adding "d" should evict "a" (oldest)
	cache.Set("d", "4")

	_, ok := cache.Get("a")
	if ok {
		t.Error("expected 'a' to be evicted")
	}

	val, ok := cache.Get("d")
	if !ok || val != "4" {
		t.Error("expected 'd' to exist")
	}
}

func TestContentCache_UpdateExisting(t *testing.T) {
	cache := NewContentCache(5*time.Minute, 100)

	hash := HashContent("key")
	cache.Set(hash, "v1")
	cache.Set(hash, "v2") // update

	val, ok := cache.Get(hash)
	if !ok || val != "v2" {
		t.Errorf("expected updated value v2, got %v", val)
	}

	stats := cache.Stats()
	if stats.Size != 1 {
		t.Errorf("expected size 1 after update, got %d", stats.Size)
	}
}

func TestContentCache_Stats(t *testing.T) {
	cache := NewContentCache(5*time.Minute, 100)

	hash := HashContent("x")
	cache.Set(hash, "val")

	cache.Get(hash)             // hit
	cache.Get(hash)             // hit
	cache.Get(HashContent("y")) // miss

	stats := cache.Stats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Size != 1 {
		t.Errorf("expected size 1, got %d", stats.Size)
	}
	// HitRate = 2/3 ≈ 0.667
	if stats.HitRate < 0.6 || stats.HitRate > 0.7 {
		t.Errorf("expected hit rate ~0.667, got %f", stats.HitRate)
	}
}

func TestContentCache_Clear(t *testing.T) {
	cache := NewContentCache(5*time.Minute, 100)

	cache.Set("a", "1")
	cache.Set("b", "2")
	cache.Clear()

	stats := cache.Stats()
	if stats.Size != 0 {
		t.Errorf("expected size 0 after clear, got %d", stats.Size)
	}

	_, ok := cache.Get("a")
	if ok {
		t.Error("expected miss after clear")
	}
}

func TestHashContent_Deterministic(t *testing.T) {
	h1 := HashContent("test input")
	h2 := HashContent("test input")

	if h1 != h2 {
		t.Error("hash should be deterministic")
	}

	h3 := HashContent("different input")
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}
}
