/**
 * TLS Protocol Parser.
 *
 * Extracts unencrypted metadata from the TLS handshake, specifically the
 * Server Name Indication (SNI), to identify destination domains in encrypted traffic.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package parser

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Holds extracted TLS information.
type TLSInfo struct {
	SNI         string
	Version     string
	CipherSuite string
	Handshake   bool
	JA3         string // JA3 fingerprint hash
}

// Extracts TLS information from a packet.
func ParseTLS(packet gopacket.Packet) (*TLSInfo, error) {
	// TLS is usually over TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil // Not TCP
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 5 {
		return nil, nil // Too short for TLS record header
	}

	// Check for TLS Content Type: Handshake (22)
	contentType := payload[0]
	if contentType != 22 {
		return nil, nil // Not a handshake
	}

	// Check version (major version 3 for SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3)
	// TLS 1.0 = 0x0301, 1.2 = 0x0303
	majorVersion := payload[1]
	if majorVersion != 3 {
		return nil, nil // Not SSL/TLS 3.x
	}

	// Record length
	recordLen := binary.BigEndian.Uint16(payload[3:5])
	if int(recordLen)+5 > len(payload) {
		return nil, nil // Incomplete record
	}

	// Handshake Message
	// Handshake Type (1 byte)
	handshakeType := payload[5]
	if handshakeType != 1 {
		return nil, nil // Not Client Hello
	}

	// Skip Handshake Header (4 bytes: type + 3 bytes length)
	// payload[5] = type
	// payload[6:9] = length
	// payload[9:11] = client version
	// payload[11:43] = random (32 bytes)

	offset := 5 + 4 // Start of ClientHello body
	if offset+2 > len(payload) {
		return nil, nil
	}

	// Client Version
	// clientVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Random
	offset += 32
	if offset > len(payload) {
		return nil, nil
	}

	// Session ID
	if offset+1 > len(payload) {
		return nil, nil
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset > len(payload) {
		return nil, nil
	}

	// Cipher Suites
	if offset+2 > len(payload) {
		return nil, nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset > len(payload) {
		return nil, nil
	}

	// Compression Methods
	if offset+1 > len(payload) {
		return nil, nil
	}
	compMethodsLen := int(payload[offset])
	offset += 1 + compMethodsLen
	if offset > len(payload) {
		return nil, nil
	}

	// Extensions
	if offset+2 > len(payload) {
		return nil, nil
	} // No extensions
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	endOfExtensions := offset + extensionsLen
	if endOfExtensions > len(payload) {
		endOfExtensions = len(payload)
	}

	info := &TLSInfo{
		Handshake: true,
		Version:   "TLS",                // General placeholder, specific version logic is complex with 1.3
		JA3:       CalculateJA3(packet), // Calculate JA3 fingerprint
	}

	// Iterate extensions to find SNI (Type 0)
	for offset+4 <= endOfExtensions {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > endOfExtensions {
			break
		}

		if extType == 0 { // SNI
			// SNI Extension parsing
			// List Length (2 bytes)
			if extLen < 2 {
				break
			}
			// listLen := binary.BigEndian.Uint16(payload[offset : offset+2])

			sniOffset := offset + 2
			sniEnd := offset + extLen

			for sniOffset+3 <= sniEnd {
				nameType := payload[sniOffset]
				nameLen := int(binary.BigEndian.Uint16(payload[sniOffset+1 : sniOffset+3]))
				sniOffset += 3

				if sniOffset+nameLen > sniEnd {
					break
				}

				if nameType == 0 { // Host Name
					info.SNI = string(payload[sniOffset : sniOffset+nameLen])
					return info, nil
				}
				sniOffset += nameLen
			}
		}

		offset += extLen
	}

	return info, nil
}
