/**
 * DNS Correlation Tests.
 *
 * Verifies the functionality of the DNS cache, including addition,
 * resolution, and expiration of entries.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package correlator

import (
	"testing"
	"time"
)

func TestDNSCache_Basic(t *testing.T) {
	// Initialize cache for testing
	cache := NewDNSCache()

	// Add a test record with a short TTL
	domain := "example.com"
	ips := []string{"192.168.1.10", "192.168.1.11"}
	ttl := uint32(2)

	cache.Add(domain, ips, ttl)

	// Verify resolution works for the first IP
	resolved := cache.Resolve("192.168.1.10")
	if resolved != domain {
		t.Errorf("Resolution failed. Expected: %s, Got: %s", domain, resolved)
	} else {
		t.Log("Successfully resolved primary IP.")
	}

	// Verify resolution works for the second IP
	resolved2 := cache.Resolve("192.168.1.11")
	if resolved2 != domain {
		t.Errorf("Resolution failed for secondary IP. Expected: %s, Got: %s", domain, resolved2)
	}
}

func TestDNSCache_Expiration(t *testing.T) {
	cache := NewDNSCache()

	// Add entry with 1 second TTL
	cache.Add("expired.com", []string{"10.0.0.1"}, 1)

	// Verify it exists immediately
	if cache.Resolve("10.0.0.1") != "expired.com" {
		t.Fatal("Cache entry not found immediately after addition.")
	}

	// Wait for TTL expiry
	time.Sleep(2 * time.Second)

	// Verify it is no longer returned
	if cache.Resolve("10.0.0.1") != "" {
		t.Error("Cache entry persisted past TTL.")
	} else {
		t.Log("Cache entry correctly expired.")
	}
}

func TestDNSCache_Cleanup(t *testing.T) {
	cache := NewDNSCache()

	// Add mixed TTL entries
	cache.Add("short.com", []string{"1.1.1.1"}, 1) // 1s TTL
	cache.Add("long.com", []string{"2.2.2.2"}, 10) // 10s TTL

	// Wait for short entry to expire
	time.Sleep(2 * time.Second)

	// Trigger cleanup
	removed := cache.Cleanup()

	// Verify short entry was removed
	if removed != 1 {
		t.Errorf("Cleanup count mismatch. Expected: 1, Got: %d", removed)
	} else {
		t.Log("Cleanup correctly removed expired entry.")
	}

	// Verify long entry remains
	if cache.Resolve("2.2.2.2") != "long.com" {
		t.Error("Cleanup incorrectly removed valid entry.")
	}
}
