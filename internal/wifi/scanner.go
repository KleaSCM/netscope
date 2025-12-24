/**
 * WiFi Scanner.
 *
 * logic to parse 802.11 management frames (Beacons, Probes)
 * to extract Access Point and Client information.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package wifi

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kleaSCM/netscope/internal/models"
)

// WiFiNetwork represents a discovered Access Point.
type WiFiNetwork struct {
	SSID       string
	BSSID      string // MAC Address
	Channel    int
	Encryption string // e.g., "WPA2", "Open"
	Signal     int    // RSSI in dBm
	Vendor     string
	LastSeen   string // Timestamp
}

// WiFiClient represents a station probing for networks.
type WiFiClient struct {
	MAC         string
	ProbedSSIDs []string // List of networks this client is looking for
	Signal      int
	Vendor      string
	LastSeen    string
}

// Scanner handles the parsing of WiFi frames.
type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

// ParseBeacon extracts network info from a Beacon frame.
func (s *Scanner) ParseBeacon(packet gopacket.Packet) *WiFiNetwork {
	dot11 := packet.Layer(layers.LayerTypeDot11)
	if dot11 == nil {
		return nil
	}

	// Filter for Management frames (Type 0) and Beacon (Subtype 8).
	// We specifically look for the Beacon layer which guarantees presence of SSID/BSSID fields.
	d11, _ := dot11.(*layers.Dot11)
	if d11.Type != layers.Dot11TypeMgmt || d11.Proto != 0 {
		return nil
	}

	beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon)
	if beaconLayer == nil {
		return nil
	}

	netInfo := &WiFiNetwork{
		BSSID: d11.Address3.String(), // BSSID is usually Addr3 in Mgmt frames
	}

	// Default to Hidden if SSID parsing fails
	netInfo.SSID = "Hidden"

	// Parse Information Elements (IEs)
	// Iterate through layers to find Dot11InformationElement
	for _, layer := range packet.Layers() {
		if info, ok := layer.(*layers.Dot11InformationElement); ok {
			if info.ID == layers.Dot11InformationElementIDSSID {
				netInfo.SSID = string(info.Info)
			}
			if info.ID == layers.Dot11InformationElementIDDSSet {
				if len(info.Info) > 0 {
					netInfo.Channel = int(info.Info[0])
				}
			}
		}
	}

	return netInfo
}

// ParseProbeRequest extracts client probing info.
func (s *Scanner) ParseProbeRequest(packet gopacket.Packet) *WiFiClient {
	dot11 := packet.Layer(layers.LayerTypeDot11)
	if dot11 == nil {
		return nil
	}
	d11, _ := dot11.(*layers.Dot11)

	// Filter for Probe Requests.
	// These frames are crucial for detecting client presence even when they are not associated with an AP.
	if packet.Layer(layers.LayerTypeDot11MgmtProbeReq) == nil {
		return nil
	}

	client := &WiFiClient{
		MAC: d11.Address2.String(), // Address2 is the Source Address in Mgmt frames
	}

	// Extract Probed SSID
	for _, layer := range packet.Layers() {
		if info, ok := layer.(*layers.Dot11InformationElement); ok {
			if info.ID == layers.Dot11InformationElementIDSSID {
				ssid := string(info.Info)
				if ssid != "" {
					client.ProbedSSIDs = append(client.ProbedSSIDs, ssid)
				}
			}
		}
	}

	return client
}

// Inspects 802.11 Data frames for WPA Key material (Type 0x888E).
func (s *Scanner) ParseEAPOL(packet gopacket.Packet) *models.Handshake {
	d11Layer := packet.Layer(layers.LayerTypeDot11)
	if d11Layer == nil {
		return nil
	}
	d11, _ := d11Layer.(*layers.Dot11)

	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return nil
	}

	hs := &models.Handshake{
		BSSID:     d11.Address1.String(),
		ClientMAC: d11.Address2.String(),
		Timestamp: time.Now(),
		IsFull:    false,
	}

	// Normalize addresses based on frame direction (FromDS/ToDS).
	if d11.Flags.ToDS() {
		hs.BSSID = d11.Address1.String()
		hs.ClientMAC = d11.Address2.String()
	} else if d11.Flags.FromDS() {
		hs.BSSID = d11.Address2.String()
		hs.ClientMAC = d11.Address1.String()
	}

	return hs
}
