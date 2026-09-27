package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestCache(t *testing.T, maxSize int, ttl time.Duration) *Cache {
	t.Helper()
	c, err := New(maxSize, ttl)
	if err != nil {
		t.Fatalf("New(%d, %v) error: %v", maxSize, ttl, err)
	}
	return c
}

func TestGetSet(t *testing.T) {
	c := newTestCache(t, 100, time.Minute)

	r := &Result{Action: "DUNNO", Reason: "SPF pass", SPFResult: "pass"}
	c.Set("key1", r)

	got := c.Get("key1")
	if got == nil {
		t.Fatal("Get(key1) returned nil")
	}
	if got.Action != "DUNNO" {
		t.Errorf("Action = %q, want %q", got.Action, "DUNNO")
	}
	if got.Reason != "SPF pass" {
		t.Errorf("Reason = %q, want %q", got.Reason, "SPF pass")
	}
	if got.SPFResult != "pass" {
		t.Errorf("SPFResult = %q, want %q", got.SPFResult, "pass")
	}
	if got.CachedAt.IsZero() {
		t.Error("CachedAt should be set")
	}
	if got.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
}

func TestGet_Miss(t *testing.T) {
	c := newTestCache(t, 100, time.Minute)

	got := c.Get("nonexistent")
	if got != nil {
		t.Errorf("Get(nonexistent) = %v, want nil", got)
	}
}

func TestGet_Expired(t *testing.T) {
	c := newTestCache(t, 100, 50*time.Millisecond)

	r := &Result{Action: "DUNNO", Reason: "test", SPFResult: "pass"}
	c.Set("key1", r)

	// Should be found immediately
	if c.Get("key1") == nil {
		t.Fatal("Get(key1) returned nil before expiry")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	got := c.Get("key1")
	if got != nil {
		t.Errorf("Get(key1) = %v after expiry, want nil", got)
	}
}

func TestSetWithTTL(t *testing.T) {
	c := newTestCache(t, 100, time.Hour) // long default TTL

	r := &Result{Action: "REJECT", Reason: "test", SPFResult: "fail"}
	c.SetWithTTL("key1", r, 50*time.Millisecond) // short custom TTL

	if c.Get("key1") == nil {
		t.Fatal("Get(key1) returned nil before custom TTL expiry")
	}

	time.Sleep(100 * time.Millisecond)

	if c.Get("key1") != nil {
		t.Error("Get(key1) should be nil after custom TTL expiry")
	}
}

func TestDelete(t *testing.T) {
	c := newTestCache(t, 100, time.Minute)

	c.Set("key1", &Result{Action: "DUNNO", SPFResult: "pass"})
	c.Delete("key1")

	if c.Get("key1") != nil {
		t.Error("Get(key1) should be nil after Delete")
	}
}

func TestClear(t *testing.T) {
	c := newTestCache(t, 100, time.Minute)

	c.Set("key1", &Result{Action: "DUNNO", SPFResult: "pass"})
	c.Set("key2", &Result{Action: "REJECT", SPFResult: "fail"})
	c.Set("key3", &Result{Action: "DEFER", SPFResult: "temperror"})

	c.Clear()

	stats := c.Stats()
	if stats.Size != 0 {
		t.Errorf("Size after Clear = %d, want 0", stats.Size)
	}
}

func TestLRU_Eviction(t *testing.T) {
	c := newTestCache(t, 3, time.Minute)

	c.Set("key1", &Result{Action: "DUNNO", SPFResult: "pass"})
	c.Set("key2", &Result{Action: "DUNNO", SPFResult: "pass"})
	c.Set("key3", &Result{Action: "DUNNO", SPFResult: "pass"})

	// Adding a 4th should evict the oldest (key1)
	c.Set("key4", &Result{Action: "DUNNO", SPFResult: "pass"})

	if c.Get("key1") != nil {
		t.Error("key1 should have been evicted")
	}
	if c.Get("key4") == nil {
		t.Error("key4 should exist")
	}

	stats := c.Stats()
	if stats.Evicted < 1 {
		t.Errorf("Evicted = %d, want >= 1", stats.Evicted)
	}
}

func TestExpireOld(t *testing.T) {
	c := newTestCache(t, 100, 50*time.Millisecond)

	c.Set("key1", &Result{Action: "DUNNO", SPFResult: "pass"})
	c.Set("key2", &Result{Action: "DUNNO", SPFResult: "pass"})

	// Set one with longer TTL
	c.SetWithTTL("key3", &Result{Action: "DUNNO", SPFResult: "pass"}, time.Hour)

	time.Sleep(100 * time.Millisecond)

	expired := c.ExpireOld()
	if expired != 2 {
		t.Errorf("ExpireOld() = %d, want 2", expired)
	}

	// key3 should still be there
	if c.Get("key3") == nil {
		t.Error("key3 should still exist (long TTL)")
	}
}

func TestStats(t *testing.T) {
	c := newTestCache(t, 100, time.Minute)

	// Generate some stats
	c.Set("key1", &Result{Action: "DUNNO", SPFResult: "pass"})
	c.Get("key1")        // hit
	c.Get("key1")        // hit
	c.Get("nonexistent") // miss

	stats := c.Stats()
	if stats.Size != 1 {
		t.Errorf("Size = %d, want 1", stats.Size)
	}
	if stats.Hits != 2 {
		t.Errorf("Hits = %d, want 2", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Misses = %d, want 1", stats.Misses)
	}
	// HitRate = 2/(2+1) * 100 = 66.67
	if stats.HitRate < 66 || stats.HitRate > 67 {
		t.Errorf("HitRate = %f, want ~66.67", stats.HitRate)
	}

	// Test reset
	c.ResetStats()
	stats = c.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("after ResetStats: Hits=%d Misses=%d, want 0,0", stats.Hits, stats.Misses)
	}
}

func TestConcurrency(t *testing.T) {
	c := newTestCache(t, 1000, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", n)
			c.Set(key, &Result{Action: "DUNNO", SPFResult: "pass"})
			c.Get(key)
			c.Get(fmt.Sprintf("miss-%d", n))
		}(i)
	}
	wg.Wait()

	stats := c.Stats()
	if stats.Hits != 100 {
		t.Errorf("Hits = %d, want 100", stats.Hits)
	}
	if stats.Misses != 100 {
		t.Errorf("Misses = %d, want 100", stats.Misses)
	}
}

func BenchmarkGet(b *testing.B) {
	c, _ := New(10000, time.Minute)
	c.Set("bench-key", &Result{Action: "DUNNO", SPFResult: "pass"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get("bench-key")
	}
}

func BenchmarkSet(b *testing.B) {
	c, _ := New(10000, time.Minute)
	r := &Result{Action: "DUNNO", SPFResult: "pass"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(fmt.Sprintf("key-%d", i), r)
	}
}
