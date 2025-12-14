/**
 * Flow Tracking Module.
 *
 * Tracks network flows by correlating packets into logical conversations.
 * Maintains state for active connections and integrates DNS data for enrichment.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package correlator

import (
	"sync"
	"time"

	"github.com/kleaSCM/netscope/internal/enricher"
	"github.com/kleaSCM/netscope/internal/models"
)

// Manages active network flows.
type FlowTable struct {
	flows    map[models.FlowKey]*models.Flow
	dnsCache *DNSCache
	geoIP    *enricher.GeoIPService
	ja3DB    *enricher.JA3Database
	mu       sync.RWMutex
}

// Creates a new flow table.
func NewFlowTable(geoIP *enricher.GeoIPService) *FlowTable {
	return &FlowTable{
		flows:    make(map[models.FlowKey]*models.Flow),
		dnsCache: NewDNSCache(),
		geoIP:    geoIP,
		ja3DB:    enricher.NewJA3Database(),
	}
}

// Processes a packet and updates the corresponding flow.
func (FT *FlowTable) Update(Packet *models.Packet) *models.Flow {
	if Packet == nil || Packet.Layer3 == nil || Packet.Layer4 == nil {
		return nil
	}

	// Inspect DNS responses to populate the cache for future correlation
	if Packet.DNS != nil && Packet.DNS.Type == "Response" {
		var IPS []string
		for _, Answer := range Packet.DNS.Answers {
			if Answer.IP != "" {
				IPS = append(IPS, Answer.IP)
			}
		}

		if len(IPS) > 0 {
			// Use the TTL from the first answer record to define relevance duration
			FT.dnsCache.Add(Packet.DNS.Query, IPS, Packet.DNS.Answers[0].TTL)
		}
	}

	Key := makeFlowKey(Packet)

	FT.mu.Lock()
	defer FT.mu.Unlock()

	Flow, Exists := FT.flows[Key]
	if !Exists {
		Flow = &models.Flow{
			Key:       Key,
			FirstSeen: Packet.Timestamp,
			Protocol:  Packet.Layer4.Protocol,
		}

		// Attempt to correlate domain name for the new flow
		// Check both source and destination IPs since the flow key canonicalization
		// might obscure which end is the "destination" in a bidirectional sense.
		Domain1 := FT.dnsCache.Resolve(Key.SrcIP)
		Domain2 := FT.dnsCache.Resolve(Key.DstIP)

		if Domain1 != "" {
			Flow.DstDomain = Domain1
		} else if Domain2 != "" {
			Flow.DstDomain = Domain2
		}

		// GeoIP Enrichment
		if FT.geoIP != nil {
			// Try to find location for DstIP first (usually "larger" IP)
			// In a typical detailed implementation, we might want to know distinct src/dst geo
			// But Flow model currently has single DstCountry etc. implying "Remote" info.
			// We check both and prefer the one that yields a result (assuming one is local/private).
			var geo *enricher.GeoData
			var err error

			geo, err = FT.geoIP.Lookup(Key.DstIP)
			if err != nil || geo.Country == "" {
				// Try SrcIP if DstIP failed or yielded no country
				geo, err = FT.geoIP.Lookup(Key.SrcIP)
			}

			if err == nil && geo != nil && geo.Country != "" {
				Flow.DstCountry = geo.Country
				Flow.DstCity = geo.City
				Flow.DstASN = geo.ASN
			}
		}

		FT.flows[Key] = Flow
	}

	// Update stats
	Flow.LastSeen = Packet.Timestamp
	Flow.PacketCount++
	Flow.ByteCount += uint64(Packet.Length)

	// Update enriched info if available
	if Packet.DNS != nil && Flow.DNSQuery == "" {
		Flow.DNSQuery = Packet.DNS.Query
	}
	if Packet.TLS != nil && Flow.TLSSNI == "" {
		Flow.TLSSNI = Packet.TLS.SNI
	}
	if Packet.TLS != nil && Flow.JA3 == "" {
		Flow.JA3 = Packet.TLS.JA3
		// Lookup application from JA3 database
		if Flow.JA3 != "" && FT.ja3DB != nil {
			Flow.JA3Application = FT.ja3DB.Lookup(Flow.JA3)
		}
	}

	return Flow
}

// Returns a list of all current flows.
func (ft *FlowTable) GetActiveFlows() []*models.Flow {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	flows := make([]*models.Flow, 0, len(ft.flows))
	for _, flow := range ft.flows {
		flows = append(flows, flow)
	}
	return flows
}

// Creates a canonical key for the packet (handling bidirectionality).
func makeFlowKey(packet *models.Packet) models.FlowKey {
	srcIP := packet.Layer3.SrcIP
	dstIP := packet.Layer3.DstIP
	srcPort := uint16(packet.Layer4.SrcPort)
	dstPort := uint16(packet.Layer4.DstPort)

	// Determine direction to ensure canonical key for conversation
	// We compare IPs, then Ports to decide which is "Src" in the key
	// This groups A->B and B->A into the same flow key
	swap := false
	if srcIP > dstIP {
		swap = true
	} else if srcIP == dstIP && srcPort > dstPort {
		swap = true
	}

	key := models.FlowKey{
		Protocol: packet.Layer4.Protocol,
	}

	if swap {
		key.SrcIP = dstIP
		key.DstIP = srcIP
		key.SrcPort = dstPort
		key.DstPort = srcPort
	} else {
		key.SrcIP = srcIP
		key.DstIP = dstIP
		key.SrcPort = srcPort
		key.DstPort = dstPort
	}

	return key
}

// Removes flows inactive for longer than timeout.
func (ft *FlowTable) Cleanup(timeout time.Duration) int {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, flow := range ft.flows {
		if now.Sub(flow.LastSeen) > timeout {
			delete(ft.flows, key)
			removed++
		}
	}
	return removed
}
