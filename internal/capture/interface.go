/**
 * Network Interface Management.
 *
 * Provides functionality to list, filter, and select network interfaces
 * for packet capture. It abstracts OS-specific details to present a
 * unified view of available capture targets.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package capture

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// Aggregates OS-level interface details to allow users to select a valid capture target.
type NetworkInterface struct {
	Name        string
	Description string
	Addresses   []string
	Flags       net.Flags
	IsUp        bool
	IsLoopback  bool
}

// Queries the operating system for all network devices capable of packet capture.
func ListInterfaces() ([]NetworkInterface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}

	interfaces := make([]NetworkInterface, 0, len(devices))

	for _, device := range devices {
		iface := NetworkInterface{
			Name:        device.Name,
			Description: device.Description,
			Addresses:   make([]string, 0, len(device.Addresses)),
		}

		// Collect all associated IP addresses
		for _, addr := range device.Addresses {
			if addr.IP != nil {
				iface.Addresses = append(iface.Addresses, addr.IP.String())
			}
		}

		// Query OS for interface status flags
		netIface, err := net.InterfaceByName(device.Name)
		if err == nil {
			iface.Flags = netIface.Flags
			iface.IsUp = netIface.Flags&net.FlagUp != 0
			iface.IsLoopback = netIface.Flags&net.FlagLoopback != 0
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// Locates a specific interface by its system name to validate user selection.
func FindInterface(name string) (*NetworkInterface, error) {
	interfaces, err := ListInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}

// Applies heuristics to suggest the most likely interface for capturing internet traffic.
func GetDefaultInterface() (*NetworkInterface, error) {
	interfaces, err := ListInterfaces()
	if err != nil {
		return nil, err
	}

	// Prioritize active physical interfaces with connectivity
	for _, iface := range interfaces {
		if !iface.IsLoopback && iface.IsUp && len(iface.Addresses) > 0 {
			return &iface, nil
		}
	}

	// Fallback to any physical interface
	for _, iface := range interfaces {
		if !iface.IsLoopback {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no suitable interface found")
}

// Outputs a formatted list of interfaces to the CLI to aid user selection.
func PrintInterfaces() error {
	interfaces, err := ListInterfaces()
	if err != nil {
		return err
	}

	if len(interfaces) == 0 {
		fmt.Println("No network interfaces found")
		return nil
	}

	fmt.Println("\nAvailable network interfaces:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for i, iface := range interfaces {
		status := "DOWN"
		if iface.IsUp {
			status = "UP"
		}

		fmt.Printf("\n[%d] %s", i+1, iface.Name)
		if iface.Description != "" && iface.Description != iface.Name {
			fmt.Printf(" (%s)", iface.Description)
		}
		fmt.Printf("\n    Status: %s", status)

		if iface.IsLoopback {
			fmt.Print(" [LOOPBACK]")
		}

		if len(iface.Addresses) > 0 {
			fmt.Printf("\n    Addresses:")
			for _, addr := range iface.Addresses {
				fmt.Printf("\n      - %s", addr)
			}
		} else {
			fmt.Printf("\n    Addresses: None")
		}
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Recommend best available interface
	defaultIface, err := GetDefaultInterface()
	if err == nil {
		fmt.Printf("\nRecommended interface: %s\n", defaultIface.Name)
	}

	fmt.Println()
	return nil
}
