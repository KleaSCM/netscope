/**
 * Transport Layer Parser.
 *
 * Decodes Layer 4 protocols (TCP, UDP), extracting port numbers, flags,
 * and sequence numbers.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kleaSCM/netscope/internal/models"
)

// Extracts Layer 4 information (TCP or UDP).
func ParseTransport(packet gopacket.Packet) *models.Layer4 {
	// Check for TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		flags := []string{}
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}
		if tcp.ECE {
			flags = append(flags, "ECE")
		}
		if tcp.CWR {
			flags = append(flags, "CWR")
		}
		if tcp.NS {
			flags = append(flags, "NS")
		}

		return &models.Layer4{
			SrcPort:  int(tcp.SrcPort),
			DstPort:  int(tcp.DstPort),
			Protocol: "TCP",
			Flags:    flags,
			Seq:      tcp.Seq,
			Ack:      tcp.Ack,
		}
	}

	// Check for UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return &models.Layer4{
			SrcPort:  int(udp.SrcPort),
			DstPort:  int(udp.DstPort),
			Protocol: "UDP",
			Flags:    []string{},
			Seq:      0,
			Ack:      0,
		}
	}

	return nil
}
