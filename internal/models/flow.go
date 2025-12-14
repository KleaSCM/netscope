/**
 * Flow Model.
 *
 * Defines the data structure for a network flow, representing a
 * session or conversation between two endpoints.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package models

import (
	"fmt"
	"time"
)

// Uniquely identifies a network flow (5-tuple keys).
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// Represents a network connection or conversation.
type Flow struct {
	ID          int64 // DB ID
	DeviceID    int64 // Foreign key to Device
	Key         FlowKey
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount uint64
	ByteCount   uint64
	Protocol    string
	DNSQuery    string // If applicable
	TLSSNI      string // If applicable
	DstDomain   string // Correlated domain name
	DstCountry  string // GeoIP Country (ISO code)
	DstCity     string // GeoIP City
	DstASN      string // GeoIP ASN

	// TLS Fingerprinting
	JA3            string // JA3 fingerprint hash
	JA3Application string // Identified application from JA3

	// Runtime Internal
	LastPersisted time.Time `json:"-"` // Not persisted to DB, used for delta tracking
}

// Returns a human-readable string representation of the flow key.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d [%s]", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Protocol)
}
