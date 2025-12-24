/**
 * Reverse DNS Resolver.
 *
 * Provides functionality to resolve IP addresses to hostnames, serving as a fallback
 * when SNI or other metadata is unavailable. Includes caching to minimize network overhead.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */
package enricher

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type DNSResolver struct {
	cache sync.Map
}

var (
	instance *DNSResolver
	once     sync.Once
)

func GetDNSResolver() *DNSResolver {
	once.Do(func() {
		instance = &DNSResolver{}
	})
	return instance
}

func (r *DNSResolver) LookupIP(ip string) string {
	if val, ok := r.cache.Load(ip); ok {
		return val.(string)
	}

	// Private IPs are not resolvable via public DNS.
	if isPrivateIP(ip) {
		return ""
	}

	go r.performLookup(ip)

	return ""
}

func (r *DNSResolver) LookupBlocking(ip string) string {
	if val, ok := r.cache.Load(ip); ok {
		return val.(string)
	}

	if isPrivateIP(ip) {
		return ""
	}

	return r.performLookup(ip)
}

func (r *DNSResolver) performLookup(ip string) string {
	// Timeout prevents hanging the UI if DNS is slow.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var rrr *net.Resolver

	names, err := rrr.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		// Cache negative result to prevent retry storms.
		r.cache.Store(ip, "N/A")
		return ""
	}

	// Remove trailing dot from FQDN.
	hostname := strings.TrimSuffix(names[0], ".")

	r.cache.Store(ip, hostname)
	return hostname
}

// isPrivateIP checks if an IP is private (reused from device.go logic or imported)
// Duplicating small logic here to avoid circular dep if device.go depends on this later.
