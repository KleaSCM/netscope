/**
 * Installation Verification Tool.
 *
 * Verifies that the necessary libraries and drivers (like Npcap) are
 * installed and that the application has the required permissions to
 * access network interfaces.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

// Checks for library availability and lists visible interfaces to confirm access.
func main() {
	fmt.Println("Verifying Npcap installation...")

	// Check version (loads the DLL)
	version := pcap.Version()
	fmt.Printf("Pcap Version: %s\n", version)

	// Try to list devices
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("❌ Error finding devices: %v\nPossible causes:\n - Npcap is not installed\n - Missing Administrator privileges\n", err)
	}

	fmt.Printf("✅ Success! Found %d network devices.\n", len(devs))
	for i, d := range devs {
		if i >= 5 {
			fmt.Println("... and more")
			break
		}
		fmt.Printf(" - %s (%s)\n", d.Name, d.Description)
	}
}
