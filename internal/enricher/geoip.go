/**
 * GeoIP Enrichment Service.
 *
 * Provides geographical location data context for IP addresses using
 * MaxMind GeoLite2 databases.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// GeoData holds the extracted geographical information.
type GeoData struct {
	Country string
	City    string
	ASN     string
	Org     string
}

// GeoIPService handles IP-to-Location lookups.
type GeoIPService struct {
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
	mu     sync.RWMutex
}

// NewGeoIPService creates a new service instance.
// cityPath and asnPath should be absolute paths to the .mmdb files.
func NewGeoIPService(cityPath, asnPath string) (*GeoIPService, error) {
	service := &GeoIPService{}

	if cityPath != "" {
		db, err := geoip2.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open City DB: %w", err)
		}
		service.cityDB = db
	}

	if asnPath != "" {
		db, err := geoip2.Open(asnPath)
		if err != nil {
			if service.cityDB != nil {
				service.cityDB.Close()
			}
			return nil, fmt.Errorf("failed to open ASN DB: %w", err)
		}
		service.asnDB = db
	}

	return service, nil
}

// Close closes the database readers.
func (s *GeoIPService) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cityDB != nil {
		s.cityDB.Close()
	}
	if s.asnDB != nil {
		s.asnDB.Close()
	}
}

// Lookup retrieves geographical data for a given IP address.
func (s *GeoIPService) Lookup(ipStr string) (*GeoData, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	data := &GeoData{}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cityDB != nil {
		record, err := s.cityDB.City(ip)
		if err == nil {
			data.Country = record.Country.IsoCode
			if len(record.Subdivisions) > 0 {
				data.City = record.Subdivisions[0].Names["en"] // Use subdivision/region as city equivalent if city is empty? Or just City.Names
			}
			// TODO: Add Japanese language support - check Names["ja"] before falling back to "en"
			if record.City.Names["en"] != "" {
				data.City = record.City.Names["en"]
			}
		}
	}

	if s.asnDB != nil {
		record, err := s.asnDB.ASN(ip)
		if err == nil {
			data.ASN = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			data.Org = record.AutonomousSystemOrganization
		}
	}

	return data, nil
}
