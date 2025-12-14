/**
 * Ethernet Parser.
 *
 * Handles the extraction of Data Link Layer (Layer 2) information,
 * specifically source and destination MAC addresses and EtherType.
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

// Extracts Layer 2 information.
func ParseEthernet(packet gopacket.Packet) *models.Layer2 {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil
	}

	ethernet, _ := ethernetLayer.(*layers.Ethernet)

	return &models.Layer2{
		SrcMAC:    ethernet.SrcMAC.String(),
		DstMAC:    ethernet.DstMAC.String(),
		EtherType: ethernet.EthernetType.String(),
	}
}
