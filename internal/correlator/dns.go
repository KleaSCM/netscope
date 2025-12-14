/**
 * DNS Correlation Module.
 *
 * Manages the caching of DNS resolutions to map IP addresses back to
 * their domain names. This enables the system to identify the destination
 * hostname for flows even when the connection is established via IP.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package correlator

import (
	"sync"
	"time"
)

// Represents a cached DNS resolution.
type DNSEntry struct {
	Domain    string
	ExpiresAt time.Time
}

// Manages IP-to-Domain mappings with thread safety.
type DNSCache struct {
	cache map[string]DNSEntry
	mutex sync.RWMutex
}

// Creates a new instance of the DNS cache.
func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: make(map[string]DNSEntry),
	}
}

// Inserts or updates a DNS record in the cache.
func (C *DNSCache) Add(Domain string, IPS []string, TTL uint32) {
	C.mutex.Lock()
	defer C.mutex.Unlock() // Ensure safe concurrent access

	// Default to 5 minutes if no valid TTL is provided
	var effectiveTTL = TTL
	if effectiveTTL == 0 {
		effectiveTTL = 300
	}

	Expiry := time.Now().Add(time.Duration(effectiveTTL) * time.Second)

	for _, IP := range IPS {
		// Store/Update mapping to ensure latest resolution is used
		C.cache[IP] = DNSEntry{
			Domain:    Domain,
			ExpiresAt: Expiry,
		}
	}
}

// Looks up the domain name for a given IP address.
func (C *DNSCache) Resolve(IP string) string {
	C.mutex.RLock()
	defer C.mutex.RUnlock()

	Entry, Exists := C.cache[IP]
	if !Exists {
		return "" // Cache miss
	}

	// Validate expiration to ensure we don't return stale data
	if time.Now().After(Entry.ExpiresAt) {
		return ""
	}

	return Entry.Domain
}

// Removes expired entries from the cache to release memory.
func (C *DNSCache) Cleanup() int {
	C.mutex.Lock()
	defer C.mutex.Unlock()

	Now := time.Now()
	Count := 0

	// Iterate and remove entries that have exceeded their TTL
	for IP, Entry := range C.cache {
		if Now.After(Entry.ExpiresAt) {
			delete(C.cache, IP)
			Count++
		}
	}

	return Count
}
