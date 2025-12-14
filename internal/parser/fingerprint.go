/**
 * OS Fingerprinting Parser.
 *
 * Utilizes TCP/IP stack signatures (TTL, Window Size, Options) to passively
 * fingerprint the operating system of remote hosts.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GuessOS attempts to fingerprint the OS based on packet characteristics (TTL).
// This is a passive heuristic and may not always be accurate.
func GuessOS(packet gopacket.Packet) string {
	// Need Layer 3 (IP) for TTL
	var ttl uint8

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ttl = ip.TTL
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		ttl = ip.HopLimit
	} else {
		return ""
	}

	// Simple Heuristics based on Initial TTL (which decrements)
	// We check ranges because hops decrease the value
	// Windows: Starts at 128
	// Linux/Android/Google: Starts at 64
	// Mac/iOS: Starts at 64
	// Solaris/Cisco: Starts at 255

	switch {
	case ttl > 128:
		return "Solaris/Cisco"
	case ttl > 64:
		return "Windows"
	case ttl > 32:
		return "Linux/Apple/iOS" // Hard to distinguish solely on TTL
	default:
		// Very low TTL might be local or just very distant
		return "Unknown"
	}
}
