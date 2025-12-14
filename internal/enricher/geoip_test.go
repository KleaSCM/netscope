/**
 * GeoIP Service Tests.
 *
 * Verifies the GeoIP service handles initialization and lookups correctly,
 * including graceful degradation when databases are missing.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"testing"
)

func TestGeoIPService_SafeFailures(t *testing.T) {
	// Initialize with empty paths (disabled)
	service, err := NewGeoIPService("", "")
	if err != nil {
		t.Fatalf("Failed to create service with empty paths: %v", err)
	}
	defer service.Close()

	// Perform lookup
	data, err := service.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup returned error for valid IP (should return empty data): %v", err)
	}

	if data == nil {
		t.Fatal("Lookup returned nil data")
	}

	if data.Country != "" || data.City != "" || data.ASN != "" {
		t.Error("Lookup returned data despite missing databases")
	}
}
