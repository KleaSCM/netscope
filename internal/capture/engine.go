/**
 * Packet Capture Engine.
 *
 * coordinates the capture, parsing, and analysis of network packets.
 * It manages the lifecycle of the pcap handle and integrates with the
 * correlation engine to build flow data.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package capture

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kleaSCM/netscope/internal/analyzer"
	"github.com/kleaSCM/netscope/internal/correlator"
	"github.com/kleaSCM/netscope/internal/enricher"
	"github.com/kleaSCM/netscope/internal/models"
	"github.com/kleaSCM/netscope/internal/parser"
	"github.com/kleaSCM/netscope/internal/storage"
	"github.com/kleaSCM/netscope/internal/wifi"
)

// Orchestrates the packet capture process, managing the pcap handle and processing pipeline.
type Engine struct {
	interfaceName   string
	handle          *pcap.Handle
	packetSource    *gopacket.PacketSource
	flowTable       *correlator.FlowTable
	geoIP           *enricher.GeoIPService
	deviceTracker   *enricher.DeviceTracker
	sessionTracker  *correlator.SessionTracker
	baselineTracker *analyzer.BaselineTracker
	anomalyDetector *analyzer.AnomalyDetector
	privacyScanner  *analyzer.PrivacyScanner
	wifiScanner     *wifi.Scanner

	// Statistics
	packetsProcessed uint64
	bytesProcessed   uint64

	// Control
	running atomic.Bool
}

// Holds configuration for the capture engine.
type Config struct {
	Interface   string
	SnapLen     int32 // Max bytes to capture per packet
	Promiscuous bool  // Promiscuous mode
	Timeout     time.Duration
	BufferSize  int    // Packet buffer size in MB
	BPFFilter   string // Berkeley Packet Filter
	GeoIPCityDB string // Path to City MMDB
	GeoIPASNDB  string // Path to ASN MMDB
}

// Returns a sensible default configuration (Promiscuous mode, 64k snaplen).
func DefaultConfig(interfaceName string) *Config {
	return &Config{
		Interface:   interfaceName,
		SnapLen:     65536, // Max Ethernet frame size
		Promiscuous: true,
		Timeout:     pcap.BlockForever,
		BufferSize:  32,                              // 32 MB buffer
		BPFFilter:   "",                              // No filter by default
		GeoIPCityDB: "data/geoip/GeoLite2-City.mmdb", // Default path
		GeoIPASNDB:  "data/geoip/GeoLite2-ASN.mmdb",  // Default path
	}
}

// Creates a new capture engine instance with the specified configuration.
func NewEngine(config *Config, store storage.Storage) (*Engine, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Validate interface availability before initializing
	_, err := FindInterface(config.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface error: %w", err)
	}

	// Initialize GeoIP Service
	// We log error but don't fail, as it's an optional enrichment
	geoIP, err := enricher.NewGeoIPService(config.GeoIPCityDB, config.GeoIPASNDB)
	if err != nil {
		log.Printf("Warning: GeoIP initialization failed: %v", err)
	} else {
		log.Println("GeoIP service initialized successfully")
	}

	// Initialize Device Tracker
	tracker := enricher.NewDeviceTracker(store)
	if err := tracker.LoadCache(); err != nil {
		log.Printf("Warning: Failed to load device cache: %v", err)
	}

	engine := &Engine{
		interfaceName:   config.Interface,
		flowTable:       correlator.NewFlowTable(geoIP),
		geoIP:           geoIP,
		deviceTracker:   tracker,
		sessionTracker:  correlator.NewSessionTracker(5 * time.Minute),
		baselineTracker: analyzer.NewBaselineTracker(100),
		anomalyDetector: analyzer.NewAnomalyDetector(),
		privacyScanner:  analyzer.NewPrivacyScanner(),
		wifiScanner:     wifi.NewScanner(),
	}

	// Initialize inactive pcap handle first to safely configure options
	inactive, err := pcap.NewInactiveHandle(config.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive handle: %w", err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(int(config.SnapLen)); err != nil {
		return nil, fmt.Errorf("failed to set snaplen: %w", err)
	}

	if err := inactive.SetPromisc(config.Promiscuous); err != nil {
		return nil, fmt.Errorf("failed to set promiscuous mode: %w", err)
	}

	if err := inactive.SetTimeout(config.Timeout); err != nil {
		return nil, fmt.Errorf("failed to set timeout: %w", err)
	}

	// Optimize kernel buffer size (100MB) to minimize packet drops on high-throughput links
	if config.BufferSize > 0 {
		if err := inactive.SetBufferSize(config.BufferSize * 1024 * 1024); err != nil {
			log.Printf("Warning: failed to set buffer size: %v", err)
		}
	}

	// Begin live capture on the interface
	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate handle: %w", err)
	}

	engine.handle = handle

	// Set kernel-level packet filter
	if config.BPFFilter != "" {
		if err := handle.SetBPFFilter(config.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
		log.Printf("Applied BPF filter: %s", config.BPFFilter)
	}

	// Initialize GoPacket source for decoding
	engine.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

	return engine, nil
}

// Contains basic information about a captured packet for model conversion.
type PacketInfo struct {
	Timestamp      time.Time
	Length         int
	SrcIP          string
	DstIP          string
	SrcPort        uint16
	DstPort        uint16
	Protocol       string
	EthSrcMAC      string
	EthDstMAC      string
	DNSInfo        string          // Human-readable DNS info
	TLSInfo        string          // Human-readable TLS info
	DstDomain      string          // Correlated domain
	DeviceVendor   string          // Source device vendor
	DeviceHostname string          // Source device hostname
	RawPacket      gopacket.Packet // Full packet for additional parsing
	Anomalies      []analyzer.Anomaly
	PrivacyIssues  []analyzer.PrivacyIssue
	WiFiNetwork    *wifi.WiFiNetwork // [NEW]
	WiFiClient     *wifi.WiFiClient  // [NEW]
}

// Begins capturing packets in a blocking loop until the context is canceled.
func (e *Engine) Start(ctx context.Context, handler func(PacketInfo)) error {
	if e.running.Load() {
		return fmt.Errorf("engine already running")
	}

	e.running.Store(true)
	defer e.running.Store(false)

	log.Printf("Starting packet capture on %s", e.interfaceName)
	log.Printf("Capture mode: promiscuous=%v", true)

	packets := e.packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			log.Println("Capture stopped by context")
			return ctx.Err()

		case packet, ok := <-packets:
			if !ok {
				log.Println("Packet channel closed")
				return nil
			}

			if packet == nil {
				continue
			}

			// Process raw packet data
			info := e.extractPacketInfo(packet)
			info.RawPacket = packet // Include full packet for additional parsing

			// Track Device
			if e.deviceTracker != nil {
				device := e.deviceTracker.Track(packet)
				if device != nil {
					info.DeviceVendor = device.Vendor
					info.DeviceHostname = device.Hostname
					if info.DeviceHostname == "" {
						info.DeviceHostname = "Unknown Device"
					}
				}
			}

			// Track flow state and stats
			modelPacket := e.toModelPacket(info)
			flow := e.flowTable.Update(modelPacket)

			if flow != nil {
				if flow.DstDomain != "" {
					info.DstDomain = flow.DstDomain
				} else if flow.TLSSNI != "" {
					info.DstDomain = flow.TLSSNI
				}

				// Track session (groups related flows)
				if e.sessionTracker != nil {
					e.sessionTracker.TrackFlow(flow)
				}

				// Update behavioral baseline
				if e.baselineTracker != nil && info.EthSrcMAC != "" {
					e.baselineTracker.UpdateBaseline(info.EthSrcMAC, flow)

					// Detect Anomalies (Real-time)
					if e.anomalyDetector != nil {
						baseline := e.baselineTracker.GetBaseline(info.EthSrcMAC)
						info.Anomalies = e.anomalyDetector.Detect(flow, baseline)
					}
				}

				// Scan for Privacy Issues (Real-time)
				if e.privacyScanner != nil {
					info.PrivacyIssues = e.privacyScanner.Scan(flow)
				}
			}

			if handler != nil {
				handler(info)
			}

			// Atomic update of performance metrics
			atomic.AddUint64(&e.packetsProcessed, 1)
			atomic.AddUint64(&e.bytesProcessed, uint64(packet.Metadata().Length))
		}
	}
}

// extractPacketInfo extracts basic information from a packet
func (e *Engine) extractPacketInfo(packet gopacket.Packet) PacketInfo {
	info := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		Protocol:  "Unknown",
	}

	// Parse Ethernet header
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		info.EthSrcMAC = eth.SrcMAC.String()
		info.EthDstMAC = eth.DstMAC.String()
	}

	// [NEW] Parse WiFi Layers (if Monitor Mode)
	if e.wifiScanner != nil {
		if net := e.wifiScanner.ParseBeacon(packet); net != nil {
			info.WiFiNetwork = net
			info.Protocol = "802.11 Beacon"
			info.DeviceHostname = "AP: " + net.SSID
		}
		if client := e.wifiScanner.ParseProbeRequest(packet); client != nil {
			info.WiFiClient = client
			info.Protocol = "802.11 Probe"
			info.EthSrcMAC = client.MAC
		}
	}

	// Parse IP (v4/v6) header
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.NextHeader.String()
	}

	// Extract TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.Protocol = "TCP"
	}

	// Extract UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Protocol = "UDP"
	}

	// Handle ICMP
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		info.Protocol = "ICMPv4"
	} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
		info.Protocol = "ICMPv6"
	}

	// Handle ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		info.Protocol = "ARP"
		arp, _ := arpLayer.(*layers.ARP)
		// Extract IPv4 addresses from ARP payload
		info.SrcIP = net.IP(arp.SourceProtAddress).String()
		info.DstIP = net.IP(arp.DstProtAddress).String()
	}

	// Decode DNS layer details
	if parser.IsDNSPacket(packet) {
		query, response, _ := parser.ParseDNS(packet)
		if query != nil {
			info.Protocol = "DNS"
			info.DNSInfo = fmt.Sprintf("Query: %s (%s)", query.QueryName, query.QueryType)
		} else if response != nil {
			info.Protocol = "DNS"
			info.DNSInfo = response.FormatResponse()
		}
	}

	// Analyze TLS handshake metadata
	tlsInfo, _ := parser.ParseTLS(packet)
	if tlsInfo != nil && tlsInfo.Handshake {
		info.Protocol = "TLS" // Override TCP
		if tlsInfo.SNI != "" {
			info.TLSInfo = fmt.Sprintf("Client Hello (SNI: %s)", tlsInfo.SNI)
		} else {
			info.TLSInfo = "Client Hello"
		}
	}

	return info
}

// Stops the capture engine and closes the handle.
func (e *Engine) Stop() {
	if e.handle != nil {
		e.handle.Close()
	}
	if e.geoIP != nil {
		e.geoIP.Close()
	}
	e.running.Store(false)
	log.Println("Capture engine stopped")
}

// Returns current capture statistics including packet drops.
func (e *Engine) Stats() (packetsProcessed, packetsDropped, bytesProcessed uint64) {
	packetsProcessed = atomic.LoadUint64(&e.packetsProcessed)
	bytesProcessed = atomic.LoadUint64(&e.bytesProcessed)

	// Get drop statistics from pcap
	if e.handle != nil {
		stats, err := e.handle.Stats()
		if err == nil {
			packetsDropped = uint64(stats.PacketsDropped)
		}
	}

	return
}

// toModelPacket converts internal PacketInfo to models.Packet for flow tracking
func (e *Engine) toModelPacket(info PacketInfo) *models.Packet {
	p := &models.Packet{
		Timestamp: info.Timestamp,
		Length:    info.Length,
		Layer2: &models.Layer2{
			SrcMAC: info.EthSrcMAC,
			DstMAC: info.EthDstMAC,
		},
		Layer3: &models.Layer3{
			SrcIP:    info.SrcIP,
			DstIP:    info.DstIP,
			Protocol: info.Protocol, // Note: info.Protocol might be "TCP" or "DNS", models.Layer3.Protocol is typically IP proto
		},
		Layer4: &models.Layer4{
			SrcPort:  int(info.SrcPort),
			DstPort:  int(info.DstPort),
			Protocol: info.Protocol, // TODO This needs refinement, simplify for now
		},
	}

	// Add enriched info
	if info.Protocol == "DNS" {
		// info.DNSInfo is just a string summary, we need the structured data
		// Since extractPacketInfo returns a flat PacketInfo struct, we might need to parse it again or store it in PacketInfo
		// To avoid re-parsing, let's assume we can cast the RawPacket layer in a real implementation.
		// For now, we will re-parse it quickly as it's cleaner than polluting PacketInfo with complex structs
		// Or better, let's update PacketInfo to hold the parsed DNS data if available

		if parser.IsDNSPacket(info.RawPacket) {
			query, response, _ := parser.ParseDNS(info.RawPacket)

			if query != nil {
				p.DNS = &models.DNS{
					Query:     query.QueryName,
					Type:      "Query",
					QueryType: query.QueryType,
				}
			} else if response != nil {
				answers := make([]models.DNSAnswer, len(response.Answers))
				for i, a := range response.Answers {
					answers[i] = models.DNSAnswer{
						Name:  a.Name,
						Type:  a.Type,
						IP:    a.IP,
						TTL:   a.TTL,
						CNAME: a.CNAME,
					}
				}

				p.DNS = &models.DNS{
					Query:   response.QueryName,
					Answers: answers,
					Type:    "Response",
					ResCode: response.ResponseCode,
				}
			}
		}
	}

	// Add TLS info
	if info.Protocol == "TLS" {
		tlsInfo, _ := parser.ParseTLS(info.RawPacket)
		if tlsInfo != nil {
			p.TLS = &models.TLS{
				SNI:         tlsInfo.SNI,
				Version:     tlsInfo.Version,
				CipherSuite: tlsInfo.CipherSuite,
				Handshake:   tlsInfo.Handshake,
				JA3:         tlsInfo.JA3,
			}
		}
	}

	return p
}

// Returns the active flows from the flow table for display and analysis.
func (e *Engine) GetActiveFlows() []*models.Flow {
	if e.flowTable == nil {
		return nil
	}
	return e.flowTable.GetActiveFlows()
}

// Returns the session tracker for accessing session data.
func (e *Engine) GetSessionTracker() *correlator.SessionTracker {
	return e.sessionTracker
}

// Returns the baseline tracker for accessing behavioral baselines.
func (e *Engine) GetBaselineTracker() *analyzer.BaselineTracker {
	return e.baselineTracker
}

// IsRunning returns whether the engine is currently capturing
func (e *Engine) IsRunning() bool {
	return e.running.Load()
}
