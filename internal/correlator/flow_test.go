/**
 * Flow Integration Tests.
 *
 * Verifies that the FlowTable correctly integrates with the DNS cache
 * to enrich flow data with domain names.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package correlator

import (
	"testing"
	"time"

	"github.com/kleaSCM/netscope/internal/models"
)

func TestFlowTable_DNSIntegration(t *testing.T) {
	// Create flow table
	ft := NewFlowTable(nil)

	// 1. Create a DNS response packet
	// Represents: example.com -> 1.2.3.4
	dnsPacket := &models.Packet{
		Timestamp: time.Now(),
		Length:    100,
		Layer3:    &models.Layer3{SrcIP: "8.8.8.8", DstIP: "192.168.1.100"},
		Layer4:    &models.Layer4{SrcPort: 53, DstPort: 12345, Protocol: "UDP"},
		DNS: &models.DNS{
			Type:  "Response",
			Query: "example.com",
			Answers: []models.DNSAnswer{
				{Name: "example.com", Type: "A", IP: "1.2.3.4", TTL: 300},
			},
		},
	}

	// Update table to populate cache
	ft.Update(dnsPacket)

	// Verify internal cache state
	resolved := ft.dnsCache.Resolve("1.2.3.4")
	if resolved != "example.com" {
		t.Fatalf("DNS cache failed to populate from packet. Actual: %s", resolved)
	}

	// 2. Create a traffic flow to the resolved IP
	// Represents: 192.168.1.100 -> 1.2.3.4 (TCP)
	flowPacket := &models.Packet{
		Timestamp: time.Now(),
		Length:    500,
		Layer3:    &models.Layer3{SrcIP: "192.168.1.100", DstIP: "1.2.3.4"},
		Layer4:    &models.Layer4{SrcPort: 54321, DstPort: 80, Protocol: "TCP"},
	}

	// Process flow packet
	flow := ft.Update(flowPacket)

	// 3. Verify correlation
	if flow.DstDomain != "example.com" {
		t.Errorf("Flow failed to correlate domain. Expected: example.com, Actual: %s", flow.DstDomain)
	} else {
		t.Log("Flow successfully correlated with cached domain.")
	}
}
