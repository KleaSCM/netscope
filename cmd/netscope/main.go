/**
 * NetScope Main Application Entry Point.
 *
 * Initializes the application, sets up storage, and launches the
 * interactive CLI menu. It serves as the central coordination point
 * for the user interface and backend services.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kleaSCM/netscope/internal/capture"
	"github.com/kleaSCM/netscope/internal/cli"
	"github.com/kleaSCM/netscope/internal/storage"
)

// Boostraps the application and starts the main event loop.
func main() {
	// Root privileges are required for raw socket access (capture)
	if !isRoot() {
		fmt.Println("⚠️  NetScope requires root/administrator privileges for packet capture.")
	}

	// Initialize persistent storage for capture data
	store, err := storage.NewSQLiteStorage("netscope.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Register available CLI operations
	menu := cli.NewMenu("Main Menu:")

	menu.AddOption("List Network Interfaces", handleListInterfaces)
	menu.AddOption("Start Packet Capture", func() error { return handleStartCapture(store) })
	menu.AddOption("Query Data", func() error { return handleQueryData(store) })
	menu.AddOption("WiFi Security 📡", func() error { return cli.ShowWiFiMenu(store) }) // New feature
	menu.AddOption("Capture History", handleCaptureHistory)
	menu.AddOption("Settings", handleSettings)
	menu.AddOption("About", handleAbout)
	menu.AddOption("Exit", func() error { return nil })

	// Start the interactive CLI loop
	if err := menu.Display(); err != nil {
		log.Fatalf("Menu error: %v", err)
	}

	fmt.Println("\n👋 Thanks for using NetScope!")
}

// Displays available network interfaces to the user.
func handleListInterfaces() error {
	cli.ClearScreen()
	fmt.Println(cli.GetBanner())
	fmt.Println("Network Interfaces")
	fmt.Println(string(make([]rune, 60)))

	interfaces, err := capture.ListInterfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	if len(interfaces) == 0 {
		fmt.Println("\nNo network interfaces found")
		cli.PressEnterToContinue()
		return nil
	}

	// Format string data for tabular display
	headers := []string{"#", "Name", "Status", "IP Address", "Type"}
	rows := make([][]string, 0)

	for i, iface := range interfaces {
		status := "DOWN"
		if iface.IsUp {
			status = "UP"
		}

		ipAddr := "None"
		if len(iface.Addresses) > 0 {
			ipAddr = iface.Addresses[0]
			if len(iface.Addresses) > 1 {
				ipAddr += fmt.Sprintf(" (+%d more)", len(iface.Addresses)-1)
			}
		}

		ifaceType := "Ethernet"
		if iface.IsLoopback {
			ifaceType = "Loopback"
		}

		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			iface.Name,
			status,
			ipAddr,
			ifaceType,
		})
	}

	cli.Table(headers, rows)

	// Suggest default
	defaultIface, err := capture.GetDefaultInterface()
	if err == nil {
		fmt.Printf("💡 Recommended for capture: %s\n", defaultIface.Name)
	}

	cli.PressEnterToContinue()
	return nil
}

// Initiates the packet capture workflow.
func handleStartCapture(store storage.Storage) error {
	return cli.ShowCaptureMenu(store)
}

// Launches the data query interface.
func handleQueryData(store storage.Storage) error {
	return cli.ShowQueryMenu(store)
}

// Shows previous capture sessions (placeholder).
func handleCaptureHistory() error {
	cli.ClearScreen()
	fmt.Println(cli.GetBanner())
	fmt.Println("Capture History")
	fmt.Println(string(make([]rune, 60)))
	fmt.Println()
	fmt.Println("🚧 Coming soon in Phase 2!")
	fmt.Println()
	fmt.Println("This feature will show:")
	fmt.Println("  • Previous capture sessions")
	fmt.Println("  • Saved packet captures")
	fmt.Println("  • Capture statistics and summaries")
	fmt.Println()
	cli.PressEnterToContinue()
	return nil
}

// Displays application settings (placeholder).
func handleSettings() error {
	cli.ClearScreen()
	fmt.Println(cli.GetBanner())
	fmt.Println("Settings")
	fmt.Println(string(make([]rune, 60)))
	fmt.Println()
	fmt.Println("🚧 Coming soon!")
	fmt.Println()
	fmt.Println("Future settings:")
	fmt.Println("  • Default capture interface")
	fmt.Println("  • Default filters")
	fmt.Println("  • Output preferences")
	fmt.Println("  • Storage settings")
	fmt.Println("  • Alert configurations")
	fmt.Println()
	cli.PressEnterToContinue()
	return nil
}

// Shows application information and credits.
func handleAbout() error {
	cli.ClearScreen()
	fmt.Println(cli.GetBanner())
	fmt.Println("About NetScope")
	fmt.Println(string(make([]rune, 60)))
	fmt.Println()
	fmt.Println("NetScope v0.1 - Phase 1.2")
	fmt.Println()
	fmt.Println("A network traffic analysis and monitoring platform")
	fmt.Println("built for learning and understanding your network.")
	fmt.Println()
	fmt.Println("Current Features:")
	fmt.Println("  ✅ Real-time packet capture")
	fmt.Println("  ✅ Protocol parsing (Ethernet, IP, TCP, UDP, ICMP, ARP)")
	fmt.Println("  ✅ DNS query and response analysis")
	fmt.Println("  ✅ BPF filtering")
	fmt.Println("  ✅ Interactive CLI")
	fmt.Println()
	fmt.Println("Coming Soon:")
	fmt.Println("  🚧 TLS handshake parsing")
	fmt.Println("  🚧 HTTP request/response parsing")
	fmt.Println("  🚧 Flow tracking and sessions")
	fmt.Println("  🚧 Database storage")
	fmt.Println("  🚧 Web dashboard")
	fmt.Println()
	fmt.Println("Built with Go and gopacket")
	fmt.Println()
	fmt.Println("Ethics: Observation only, respects encryption boundaries")
	fmt.Println()
	cli.PressEnterToContinue()
	return nil
}

// Verifies if the process is running with root privileges.
func isRoot() bool {
	return os.Geteuid() == 0
}
