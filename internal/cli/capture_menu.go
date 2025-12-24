/**
 * Capture Menu Implementation.
 *
 * Provides the interactive UI for configuring and starting packet captures,
 * allowing users to select interfaces, filters, and output modes.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kleaSCM/netscope/internal/capture"
	"github.com/kleaSCM/netscope/internal/enricher"
	"github.com/kleaSCM/netscope/internal/parser"
	"github.com/kleaSCM/netscope/internal/storage"
)

var localDeviceIP string

// Holds configuration for packet capture.
type CaptureConfig struct {
	Interface string
	Filter    string
	Verbose   bool
}

// Displays the capture menu and handles packet capture workflow.
func ShowCaptureMenu(store storage.Storage) error {
	// Interface selection is the first required step
	iface, err := selectInterface()
	if err != nil {
		return err
	}

	// Filter selection allows narrowing down traffic
	filter, err := selectFilter()
	if err != nil {
		return err
	}

	// Output mode determines verbosity
	verbose := selectOutputMode()

	// Confirmation step to prevent accidental starts
	ClearScreen()
	fmt.Print(banner)
	fmt.Println("Capture Configuration:")
	fmt.Println(string(make([]rune, 60)))
	fmt.Printf("  Interface: %s\n", iface.Name)
	if filter != "" {
		fmt.Printf("  Filter:    %s\n", filter)
	} else {
		fmt.Printf("  Filter:    (none - capturing all traffic)\n")
	}
	fmt.Printf("  Mode:      %s\n", map[bool]string{true: "Verbose", false: "Simple"}[verbose])
	fmt.Println()

	if !Confirm("Start capture with these settings?") {
		return nil
	}

	// Begin blocking capture loop
	return startCapture(iface.Name, filter, verbose, store)
}

func selectInterface() (*capture.NetworkInterface, error) {
	interfaces, err := capture.ListInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	// Filter out loopback and down interfaces for display
	validInterfaces := make([]capture.NetworkInterface, 0)
	options := make([]string, 0)

	for _, iface := range interfaces {
		if !iface.IsLoopback {
			validInterfaces = append(validInterfaces, iface)

			// Format option string
			addrs := "no IP"
			if len(iface.Addresses) > 0 {
				addrs = iface.Addresses[0]
			}
			status := ""
			if !iface.IsUp {
				status = " (DOWN)"
			}
			options = append(options, fmt.Sprintf("%s (%s)%s", iface.Name, addrs, status))
		}
	}

	// If no valid interfaces found, fallback to showing all (don't error out)
	if len(validInterfaces) == 0 {
		// Fall through to allow "Show all" option or just return error if truly 0 total interfaces
		if len(interfaces) == 0 {
			return nil, fmt.Errorf("no network interfaces found")
		}
	}

	// Add "Show all interfaces" option
	options = append(options, "Show all interfaces (including loopback/down)")

	// Try to detect and suggest the best interface
	ClearScreen()
	fmt.Println(GetBanner())
	fmt.Println("Select Network Interface:")
	fmt.Println(string(make([]rune, 60)))

	defaultIface, err := capture.GetDefaultInterface()
	if err == nil && defaultIface != nil {
		// Find the index of the recommended interface
		recommendedIdx := -1
		for i, iface := range validInterfaces {
			if iface.Name == defaultIface.Name {
				recommendedIdx = i
				break
			}
		}

		if recommendedIdx >= 0 {
			fmt.Printf("\n💡 Recommended: Option %d - %s\n", recommendedIdx+1, defaultIface.Name)
			if len(defaultIface.Addresses) > 0 {
				fmt.Printf("   IP Address: %s\n", defaultIface.Addresses[0])
			}
			fmt.Println("   This is your active network interface")
			fmt.Println()
		}
	}

	idx, err := Select("", options)
	if err != nil {
		return nil, err
	}

	// If user selected "show all"
	if idx == len(options)-1 {
		return selectInterfaceAll(interfaces)
	}

	return &validInterfaces[idx], nil
}

func selectInterfaceAll(interfaces []capture.NetworkInterface) (*capture.NetworkInterface, error) {
	options := make([]string, 0)

	for _, iface := range interfaces {
		status := "DOWN"
		if iface.IsUp {
			status = "UP"
		}

		addrs := "no IP"
		if len(iface.Addresses) > 0 {
			addrs = iface.Addresses[0]
		}

		flags := ""
		if iface.IsLoopback {
			flags = " [LOOPBACK]"
		}

		options = append(options, fmt.Sprintf("%s (%s) [%s]%s", iface.Name, addrs, status, flags))
	}

	idx, err := Select("Select Network Interface:", options)
	if err != nil {
		return nil, err
	}

	return &interfaces[idx], nil
}

func selectFilter() (string, error) {
	options := []string{
		"All traffic (no filter)",
		"DNS only (udp port 53)",
		"HTTP/HTTPS (tcp port 80 or 443)",
		"HTTPS only (tcp port 443)",
		"HTTP only (tcp port 80)",
		"Custom BPF filter",
	}

	idx, err := Select("Select Traffic Filter:", options)
	if err != nil {
		return "", err
	}

	filters := []string{
		"",
		"udp port 53",
		"tcp port 80 or tcp port 443",
		"tcp port 443",
		"tcp port 80",
		"", // Custom - will prompt
	}

	if idx == 5 {
		// Custom filter
		filter, err := Prompt("Enter BPF filter expression: ")
		if err != nil {
			return "", err
		}
		return filter, nil
	}

	return filters[idx], nil
}

func selectOutputMode() bool {
	options := []string{
		"Simple (one line per packet)",
		"Verbose (detailed packet information)",
	}

	idx, _ := Select("Select Output Mode:", options)
	return idx == 1
}

func startCapture(interfaceName, filter string, verbose bool, store storage.Storage) error {
	ClearScreen()
	fmt.Print(banner)

	// Initialize default configuration
	config := capture.DefaultConfig(interfaceName)
	config.BPFFilter = filter

	// Initialize the packet capture engine
	engine, err := capture.NewEngine(config, store)
	if err != nil {
		return fmt.Errorf("failed to create capture engine: %w", err)
	}
	defer engine.Stop()

	// Ensure clean exit on interrupt signal
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Track statistics to calculate rates
	var lastStats struct {
		packets uint64
		bytes   uint64
	}

	// Get local interface IP for display
	localDeviceIP = ""
	ifaceInfo, err := capture.FindInterface(interfaceName)
	if err == nil && len(ifaceInfo.Addresses) > 0 {
		for _, addr := range ifaceInfo.Addresses {
			if strings.Contains(addr, ".") {
				localDeviceIP = addr
				break
			}
		}
	}
	if verbose {
		fmt.Printf("ℹ️  Local IP detected: %s\n", localDeviceIP)
	}

	// Periodically report stats and save active flows
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				packets, dropped, bytes := engine.Stats()
				packetDelta := packets - lastStats.packets
				bytesDelta := bytes - lastStats.bytes

				fmt.Printf("\n[STATS] Total: %d packets (%s) | Dropped: %d | Rate: %d pkt/s (%s/s)\n",
					packets, formatBytes(bytes), dropped,
					packetDelta/5, formatBytes(bytesDelta/5))

				lastStats.packets = packets
				lastStats.bytes = bytes

				// Persist active flows
			case <-ticker.C:
				if store != nil {
					flows := engine.GetActiveFlows()
					savedCount := 0
					for _, flow := range flows {
						// Optimization: only save flows that have updated since last persist
						if flow.LastSeen.After(flow.LastPersisted) {
							if err := store.SaveFlow(flow); err == nil {
								flow.LastPersisted = time.Now()
								savedCount++
							}
						}
					}
				}
			}
		}
	}()

	// Capture Loop
	packetHandler := func(info capture.PacketInfo) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		engine.Stats() // Update internal stats (not printed here)

		// Specialized parsing for DNS traffic
		if parser.IsDNSPacket(info.RawPacket) {
			query, response, err := parser.ParseDNS(info.RawPacket)
			if err == nil {
				if query != nil {
					printDNSQuery(query, verbose)
				}
				if response != nil {
					printDNSResponse(response, verbose)
				}
			}
			return
		}

		// Regular packet handling
		if verbose {
			printPacketVerbose(info)
		} else {
			printPacketSimple(info)
		}
	}

	// Start capture in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- engine.Start(ctx, packetHandler)
	}()

	fmt.Printf("🚀 Capturing on %s", interfaceName)
	if filter != "" {
		fmt.Printf(" (filter: %s)", filter)
	}
	fmt.Println("\n   Press Ctrl+C to stop")
	fmt.Println()
	fmt.Println(string(make([]rune, 60)))
	fmt.Println()

	// Wait for signal or error
	select {
	case <-sigChan:
		fmt.Println("\n\n🛑 Stopping capture...")
		cancel()

		// Wait a bit for engine to stop
		time.Sleep(200 * time.Millisecond)

		// Print final stats
		packets, dropped, bytes := engine.Stats()
		fmt.Println("\n" + string(make([]rune, 60)))
		fmt.Println("Final Statistics:")
		fmt.Printf("  Packets Captured: %d\n", packets)
		fmt.Printf("  Packets Dropped:  %d\n", dropped)
		fmt.Printf("  Total Bytes:      %s\n", formatBytes(bytes))
		fmt.Println(string(make([]rune, 60)))

		PressEnterToContinue()

	case err := <-errChan:
		if err != nil && err != context.Canceled {
			return fmt.Errorf("capture error: %w", err)
		}
	}

	return nil
}

func printPacketSimple(info capture.PacketInfo) {
	timestamp := info.Timestamp.Format("15:04:05")

	// Resolve Names if missing (Reverse DNS)
	srcName := info.DeviceHostname
	if srcName == "" || strings.HasPrefix(srcName, "Device-") {
		// Try to find a better name via DNS
		dnsName := enricher.GetDNSResolver().LookupIP(info.SrcIP)
		if dnsName != "" && dnsName != "N/A" {
			srcName = dnsName
		}
	}

	dstName := info.DstDomain
	if dstName == "" {
		dstName = enricher.GetDNSResolver().LookupIP(info.DstIP)
		if dstName == "N/A" {
			dstName = ""
		}
	}

	// 1. Friendly Labels
	srcLabel := humanizeLabel(srcName, info.DeviceVendor, info.SrcIP)
	dstLabel := humanizeLabel(dstName, "", info.DstIP)

	// 2. Detect Direction / Type
	direction := "↔"
	if strings.HasPrefix(info.DstIP, "224.") || strings.HasPrefix(info.DstIP, "239.") || info.DstIP == "255.255.255.255" {
		direction = "📢" // Broadcast/Multicast
		dstLabel = "Broadcast/Multicast"
	} else if isPrivateIP(info.SrcIP) && !isPrivateIP(info.DstIP) {
		direction = "📤" // Upload/Request
	} else if !isPrivateIP(info.SrcIP) && isPrivateIP(info.DstIP) {
		direction = "📥" // Download/Response
	}

	// 3. Simplified Output
	if info.SrcIP != "" && info.DstIP != "" {
		// Format: [Time] Dir Proto Source -> Destination (Bytes)
		fmt.Printf("[%s] %s  %-4s  %s  %s  %s  (%d bytes)\n",
			timestamp,
			direction,
			info.Protocol,
			srcLabel,
			"→",
			dstLabel,
			info.Length)
	} else if info.Protocol == "ARP" {
		fmt.Printf("[%s] 🔊 ARP: Who has %s? Tell %s\n", timestamp, info.DstIP, info.SrcIP)
	} else {
		fmt.Printf("[%s] %s (%d bytes)\n", timestamp, info.Protocol, info.Length)
	}

	// Print One-Line Alerts (concise)
	if len(info.PrivacyIssues) > 0 {
		for _, issue := range info.PrivacyIssues {
			fmt.Printf("   🚨 PRIVACY: %s\n", issue.Description)
		}
	}
	if len(info.Anomalies) > 0 {
		for _, anomaly := range info.Anomalies {
			fmt.Printf("   ⚠️  ANOMALY: %s\n", anomaly.Description)
		}
	}
}

func humanizeLabel(name, vendor, ip string) string {
	if name == "" {
		return ip
	}

	// My Device (Identified by local interface IP)
	if ip == localDeviceIP {
		return "My Device (You) 💻"
	}

	if name == "" {
		if vendor != "" {
			return fmt.Sprintf("%s (%s)", vendor, ip)
		}
		return ip
	}

	// Simplify generic device names
	if strings.HasPrefix(name, "Device-") {
		if vendor != "" {
			return fmt.Sprintf("%s Device (%s)", vendor, ip)
		}
		return fmt.Sprintf("Device (%s)", ip)
	}

	// Simplify generic device names
	if strings.HasPrefix(name, "Device-") {
		if vendor != "" {
			return fmt.Sprintf("%s Device", vendor)
		}
		// Generic fallback
		return fmt.Sprintf("Device (%s)", ip)
	}

	// Truncate overly long domains
	if len(name) > 30 {
		return name[:27] + "..."
	}

	return name
}

// Helper to deduce private IPs
func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.")
}

func printPacketVerbose(info capture.PacketInfo) {
	timestamp := info.Timestamp.Format("15:04:05.000000")

	fmt.Println("\n" + string(make([]rune, 60)))
	fmt.Printf("Timestamp: %s\n", timestamp)
	fmt.Printf("Protocol:  %s\n", info.Protocol)
	fmt.Printf("Length:    %d bytes\n", info.Length)

	if info.EthSrcMAC != "" {
		fmt.Printf("Ethernet:  %s → %s\n", info.EthSrcMAC, info.EthDstMAC)
	}

	if info.SrcIP != "" {
		fmt.Printf("IP:        %s → %s\n", info.SrcIP, info.DstIP)
		if info.SrcPort > 0 {
			fmt.Printf("Ports:     %d → %d\n", info.SrcPort, info.DstPort)
		}
	}

	// Print Privacy Alerts
	if len(info.PrivacyIssues) > 0 {
		for _, issue := range info.PrivacyIssues {
			fmt.Printf("⛔ PRIVACY: [%s] %s\n", issue.Type, issue.Description)
		}
	}

	// Print Anomaly Alerts
	if len(info.Anomalies) > 0 {
		for _, anomaly := range info.Anomalies {
			fmt.Printf("⚠️  ANOMALY: [%s] %s\n", anomaly.Type, anomaly.Description)
		}
	}
}

func printDNSQuery(query *parser.DNSQuery, verbose bool) {
	timestamp := query.Timestamp.Format("15:04:05.000")

	if verbose {
		fmt.Println("\n" + string(make([]rune, 60)))
		fmt.Printf("Timestamp: %s\n", timestamp)
		fmt.Printf("Type:      DNS Query\n")
		fmt.Printf("Query:     %s\n", query.QueryName)
		fmt.Printf("Type:      %s\n", query.QueryType)
		fmt.Printf("From:      %s\n", query.SrcIP)
		fmt.Printf("To:        %s\n", query.DstIP)
		fmt.Printf("TX ID:     %d\n", query.TransactionID)
	} else {
		fmt.Printf("[%s] 🔍 %s\n", timestamp, query.FormatQuery())
	}
}

func printDNSResponse(response *parser.DNSResponse, verbose bool) {
	timestamp := response.Timestamp.Format("15:04:05.000")

	if verbose {
		fmt.Println("\n" + string(make([]rune, 60)))
		fmt.Printf("Timestamp: %s\n", timestamp)
		fmt.Print(response.FormatVerbose())
		fmt.Printf("From:      %s\n", response.SrcIP)
		fmt.Printf("To:        %s\n", response.DstIP)
	} else {
		fmt.Printf("[%s] ✅ %s\n", timestamp, response.FormatResponse())
	}
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
