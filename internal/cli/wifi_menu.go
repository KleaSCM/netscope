/**
 * WiFi Monitor Menu.
 *
 * CLI interface for 802.11 monitor mode features.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package cli

import (
	"fmt"

	"github.com/kleaSCM/netscope/internal/analyzer"
	"github.com/kleaSCM/netscope/internal/storage"
)

func ShowWiFiMenu(store storage.Storage) error {
	menu := NewMenu("WiFi Security Monitor 📡")

	menu.AddOption("Scan for Access Points (APs)", func() error {
		return runAPScan(store)
	})

	menu.AddOption("Monitor Client Probes (Who is nearby?)", func() error {
		return runClientMonitor(store)
	})

	menu.AddOption("Monitor WPA Handshakes (EAPOL)", func() error {
		return runHandshakeMonitor(store)
	})

	menu.AddOption("Back to Main Menu", func() error { return ErrExitMenu })

	return menu.Display()
}

func runAPScan(store storage.Storage) error {
	ClearScreen()
	fmt.Println("📡 Detected Access Points (From Database)")
	fmt.Println("   (Ensure 'Start Packet Capture' is running to find new ones)")
	fmt.Println(string(make([]rune, 80)))

	aps, err := store.ListAccessPoints()
	if err != nil {
		fmt.Printf("Error listing APs: %v\n", err)
	} else {
		if len(aps) == 0 {
			fmt.Println("\n   No APs found yet.")
		} else {
			// Header
			fmt.Printf("\n   %-18s  %-20s  %-4s  %-6s  %-4s  %s\n", "BSSID", "SSID", "CH", "ENC", "SIG", "VENDOR")
			fmt.Println("   " + string(make([]rune, 75)))

			for _, ap := range aps {
				enc := ap.Encryption
				if len(enc) > 6 {
					enc = enc[:6]
				}
				fmt.Printf("   %-18s  %-20s  %-4d  %-6s  %-4d  %s\n",
					ap.BSSID,
					truncate(ap.SSID, 20),
					ap.Channel,
					enc,
					ap.Signal,
					ap.Vendor)
			}
		}

		// Run security analysis to detect rogue APs and other anomalies.
		alerts := analyzer.DetectRogueAPs(aps)
		if len(alerts) > 0 {
			fmt.Println("\n   ⚠️  SECURITY ALERTS DETECTED!")
			fmt.Println("   " + string(make([]rune, 75)))
			for _, alert := range alerts {
				icon := "⚠️"
				if alert.Severity == "CRITICAL" {
					icon = "⛔" // Or 🚨
				}

				fmt.Printf("   %s [%s] %s (%s)\n", icon, alert.Severity, alert.Message, alert.BSSID)
			}
		}
	}

	fmt.Println("\n   [Press Enter to return]")
	PressEnterToContinue()
	return nil
}

func runClientMonitor(store storage.Storage) error {
	ClearScreen()
	fmt.Println("🕵️  WiFi Client Probes (Scanning...)")
	fmt.Println("   (Devices searching for known networks)")
	fmt.Println(string(make([]rune, 80)))

	clients, err := store.ListWiFiClients()
	if err != nil {
		fmt.Printf("Error listing clients: %v\n", err)
	} else {
		if len(clients) == 0 {
			fmt.Println("\n   No probing clients detected yet.")
		} else {
			// Header
			fmt.Printf("\n   %-18s  %-20s  %-25s  %s\n", "MAC ADDRESS", "VENDOR", "PROBED SSIDs", "LAST SEEN")
			fmt.Println("   " + string(make([]rune, 75)))

			for _, c := range clients {
				ssids := ""
				if len(c.ProbedSSIDs) > 0 {
					// Strip brackets from fmt.Sprintf output roughly if needed,
					// or just display as is since we stored it as string "[A B]"
					ssids = truncate(c.ProbedSSIDs[0], 25)
				}

				fmt.Printf("   %-18s  %-20s  %-25s  %s\n",
					c.MAC,
					truncate(c.Vendor, 20),
					ssids,
					c.LastSeen.Format("15:04:05"))
			}
		}
	}

	fmt.Println("\n   [Press Enter to return]")
	PressEnterToContinue()
	return nil
}

func runHandshakeMonitor(store storage.Storage) error {
	ClearScreen()
	fmt.Println("🤝 WPA/WPA2 Handshakes (EAPOL)")
	fmt.Println("   (Captured 4-Way Handshake frames for security auditing)")
	fmt.Println(string(make([]rune, 80)))

	handshakes, err := store.ListHandshakes()
	if err != nil {
		fmt.Printf("Error listing handshakes: %v\n", err)
	} else {
		if len(handshakes) == 0 {
			fmt.Println("\n   No handshakes captured yet.")
		} else {
			// Header
			fmt.Printf("\n   %-18s  %-18s  %-8s  %s\n", "BSSID (Target)", "CLIENT (Victim)", "TYPE", "TIMESTAMP")
			fmt.Println("   " + string(make([]rune, 75)))

			for _, hs := range handshakes {
				typeStr := "Partial"
				if hs.IsFull {
					typeStr = "FULL 🟢"
				}
				fmt.Printf("   %-18s  %-18s  %-8s  %s\n",
					hs.BSSID,
					hs.ClientMAC,
					typeStr,
					hs.Timestamp.Format("15:04:05"))
			}
		}
	}

	fmt.Println("\n   [Press Enter to return]")
	PressEnterToContinue()
	return nil
}

func truncate(s string, l int) string {
	if len(s) > l {
		return s[:l-3] + "..."
	}
	return s
}
