/**
 * Parser Unit Tests.
 *
 * Verifies the correctness of protocol parsing for Ethernet (L2),
 * IP (L3), and TCP/UDP (L4) layers using constructed packets.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package parser

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseEthernet(t *testing.T) {
	// Create a dummy packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			EthernetType: layers.EthernetTypeIPv4,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	l2 := ParseEthernet(packet)
	if l2 == nil {
		t.Fatal("Expected Layer2, got nil")
	}

	if l2.SrcMAC != "00:11:22:33:44:55" {
		t.Errorf("Expected SrcMAC 00:11:22:33:44:55, got %s", l2.SrcMAC)
	}
	if l2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Expected DstMAC aa:bb:cc:dd:ee:ff, got %s", l2.DstMAC)
	}
	if l2.EtherType != "IPv4" {
		t.Errorf("Expected EtherType IPv4, got %s", l2.EtherType)
	}
}

func TestParseIP(t *testing.T) {
	// Create a dummy IPv4 packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.IP{192, 168, 1, 10},
			DstIP:    net.IP{192, 168, 1, 20},
			Protocol: layers.IPProtocolTCP,
			TTL:      64,
			Version:  4,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	l3 := ParseIP(packet)
	if l3 == nil {
		t.Log(packet.Dump())
		t.Fatal("Expected Layer3, got nil")
	}

	if l3.SrcIP != "192.168.1.10" {
		t.Errorf("Expected SrcIP 192.168.1.10, got %s", l3.SrcIP)
	}
	if l3.DstIP != "192.168.1.20" {
		t.Errorf("Expected DstIP 192.168.1.20, got %s", l3.DstIP)
	}
	if l3.Version != "IPv4" {
		t.Errorf("Expected Version IPv4, got %s", l3.Version)
	}
	if l3.Protocol != "TCP" {
		t.Errorf("Expected Protocol TCP, got %s", l3.Protocol)
	}
}

func TestParseTransport(t *testing.T) {
	// Create a dummy TCP packet
	buffer := gopacket.NewSerializeBuffer()
	// Disable ComputeChecksums to avoid complex setup
	opts := gopacket.SerializeOptions{FixLengths: true}

	ipv4 := &layers.IPv4{Protocol: layers.IPProtocolTCP, SrcIP: net.IP{1, 2, 3, 4}, DstIP: net.IP{5, 6, 7, 8}, Version: 4, IHL: 5}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		SYN:     true,
		Seq:     100,
		Ack:     0,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			EthernetType: layers.EthernetTypeIPv4,
		},
		ipv4,
		tcp,
	)
	if err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	l4 := ParseTransport(packet)
	if l4 == nil {
		t.Log(packet.Dump())
		t.Fatal("Expected Layer4, got nil")
	}

	if l4.SrcPort != 12345 {
		t.Errorf("Expected SrcPort 12345, got %d", l4.SrcPort)
	}
	if l4.DstPort != 80 {
		t.Errorf("Expected DstPort 80, got %d", l4.DstPort)
	}
	if l4.Protocol != "TCP" {
		t.Errorf("Expected Protocol TCP, got %s", l4.Protocol)
	}

	hasSyn := false
	for _, flag := range l4.Flags {
		if flag == "SYN" {
			hasSyn = true
			break
		}
	}
	if !hasSyn {
		t.Error("Expected SYN flag, not found")
	}
}
