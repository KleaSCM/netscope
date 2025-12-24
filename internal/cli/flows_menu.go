/**
 * Active Flows Menu Implementation.
 *
 * Displays real-time network flows with enriched metadata including
 * applications, traffic classes, and geographic information.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package cli

import (
	"fmt"
	"sort"
	"time"

	"github.com/kleaSCM/netscope/internal/capture"
	"github.com/kleaSCM/netscope/internal/models"
)

// Displays the active flows menu with real-time flow data.
func ShowActiveFlowsMenu(engine *capture.Engine) error {
	if engine == nil {
		ShowMessage("⚠️  Capture engine not initialized. Start a capture first.")
		return nil
	}

	ClearScreen()
	fmt.Println(GetBanner())
	fmt.Println("Active Network Flows")
	fmt.Println(string(make([]rune, 60)))

	flows := engine.GetActiveFlows()

	if len(flows) == 0 {
		fmt.Println("\nNo active flows detected.")
		fmt.Println("Start a packet capture to see live network traffic.")
		PressEnterToContinue()
		return nil
	}

	// Sort flows by last activity (most recent first)
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].LastSeen.After(flows[j].LastSeen)
	})

	// Display summary statistics
	totalBytes := uint64(0)
	totalPackets := uint64(0)
	trafficClasses := make(map[string]int)
	applications := make(map[string]int)

	for _, f := range flows {
		totalBytes += f.ByteCount
		totalPackets += f.PacketCount
		if f.TrafficClass != "" {
			trafficClasses[f.TrafficClass]++
		}
		if f.Application != "" {
			applications[f.Application]++
		}
	}

	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total Flows: %d\n", len(flows))
	fmt.Printf("   Total Packets: %d\n", totalPackets)
	fmt.Printf("   Total Bytes: %s\n\n", formatBytes(totalBytes))

	// Display top applications
	if len(applications) > 0 {
		fmt.Printf("🎯 Top Applications:\n")
		topApps := sortMapByValue(applications, 5)
		for app, count := range topApps {
			fmt.Printf("   %s: %d flows\n", app, count)
		}
		fmt.Println()
	}

	// Display traffic breakdown
	if len(trafficClasses) > 0 {
		fmt.Printf("📦 Traffic Classes:\n")
		for class, count := range trafficClasses {
			fmt.Printf("   %s: %d flows\n", class, count)
		}
		fmt.Println()
	}

	// Display detailed flow table
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("\nDetailed Flows (sorted by recent activity):")

	// Limit display to top 20 most recent
	displayCount := 20
	if len(flows) < displayCount {
		displayCount = len(flows)
	}

	for i := 0; i < displayCount; i++ {
		f := flows[i]
		printFlowDetails(f, i+1)
	}

	if len(flows) > displayCount {
		fmt.Printf("\n... and %d more flows (showing top %d)\n", len(flows)-displayCount, displayCount)
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	PressEnterToContinue()
	return nil
}

func printFlowDetails(f *models.Flow, index int) {
	// Duration of flow
	duration := f.LastSeen.Sub(f.FirstSeen)
	age := time.Since(f.LastSeen)

	fmt.Printf("[%d] ", index)

	// Source and Destination
	src := fmt.Sprintf("%s:%d", f.Key.SrcIP, f.Key.SrcPort)
	dst := fmt.Sprintf("%s:%d", f.Key.DstIP, f.Key.DstPort)

	// Add domain if available
	if f.DstDomain != "" {
		dst = fmt.Sprintf("%s (%s)", f.DstDomain, f.Key.DstIP)
	} else if f.TLSSNI != "" {
		dst = fmt.Sprintf("%s (%s)", f.TLSSNI, f.Key.DstIP)
	}

	fmt.Printf("%s → %s\n", src, dst)

	// Protocol and Application
	fmt.Printf("    Protocol: %s", f.Protocol)
	if f.Application != "" {
		fmt.Printf(" | App: %s", f.Application)
	}
	if f.TrafficClass != "" {
		fmt.Printf(" | Class: %s", f.TrafficClass)
	}
	fmt.Println()

	// Geographic info
	if f.DstCountry != "" {
		fmt.Printf("    Location: %s", f.DstCountry)
		if f.DstCity != "" {
			fmt.Printf(", %s", f.DstCity)
		}
		if f.DstASN != "" {
			fmt.Printf(" (ASN: %s)", f.DstASN)
		}
		fmt.Println()
	}

	// TLS info
	if f.JA3 != "" {
		fmt.Printf("    TLS JA3: %s", f.JA3[:16]+"...")
		if f.JA3Application != "" {
			fmt.Printf(" (%s)", f.JA3Application)
		}
		fmt.Println()
	}

	// Traffic stats
	fmt.Printf("    Stats: %d packets, %s", f.PacketCount, formatBytes(f.ByteCount))
	fmt.Printf(" | Duration: %s | Idle: %s\n", formatDuration(duration), formatDuration(age))

	fmt.Println()
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

// return top N entries from a map sorted by value
func sortMapByValue(m map[string]int, topN int) map[string]int {
	type kv struct {
		Key   string
		Value int
	}

	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make(map[string]int)
	count := topN
	if len(sorted) < count {
		count = len(sorted)
	}

	for i := 0; i < count; i++ {
		result[sorted[i].Key] = sorted[i].Value
	}

	return result
}
