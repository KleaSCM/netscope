/**
 * IP Protocol Parser.
 *
 * Handles the extraction of Network Layer (Layer 3) information,
 * supporting both IPv4 and IPv6 addressing schemes.
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

// Extracts Layer 3 information (IPv4 or IPv6).
func ParseIP(packet gopacket.Packet) *models.Layer3 {
	// Check for IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		return &models.Layer3{
			SrcIP:    ipv4.SrcIP.String(),
			DstIP:    ipv4.DstIP.String(),
			Version:  "IPv4",
			Protocol: ipv4.Protocol.String(),
			TTL:      ipv4.TTL,
		}
	}

	// Check for IPv6
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		return &models.Layer3{
			SrcIP:    ipv6.SrcIP.String(),
			DstIP:    ipv6.DstIP.String(),
			Version:  "IPv6",
			Protocol: ipv6.NextHeader.String(),
			TTL:      ipv6.HopLimit,
		}
	}

	return nil
}
