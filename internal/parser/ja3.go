/**
 * JA3 TLS Fingerprinting.
 *
 * Implements JA3 fingerprinting to identify TLS clients based on their
 * Client Hello characteristics. JA3 creates an MD5 hash of specific fields
 * to uniquely identify applications regardless of destination.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package parser

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// JA3Data holds the extracted fields used to calculate JA3 fingerprint.
type JA3Data struct {
	SSLVersion           uint16
	CipherSuites         []uint16
	Extensions           []uint16
	EllipticCurves       []uint16
	EllipticCurveFormats []uint8
}

// Computes the JA3 fingerprint from a TLS Client Hello packet.
// Returns the MD5 hash string or empty string if not a valid Client Hello.
func CalculateJA3(packet gopacket.Packet) string {
	data := extractJA3Data(packet)
	if data == nil {
		return ""
	}

	// Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	ja3String := buildJA3String(data)
	if ja3String == "" {
		return ""
	}

	// MD5 hash
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// Parses the Client Hello and extracts JA3-relevant fields needed for fingerprint calculation.
func extractJA3Data(packet gopacket.Packet) *JA3Data {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 43 {
		return nil // Too short for Client Hello
	}

	// Verify TLS Handshake (Content Type 22, Handshake Type 1)
	if payload[0] != 22 || payload[5] != 1 {
		return nil
	}

	data := &JA3Data{}

	// Parse Client Hello
	offset := 9 // Skip TLS record header (5) + handshake header (4)

	// SSL Version (2 bytes)
	if offset+2 > len(payload) {
		return nil
	}
	data.SSLVersion = binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Random (32 bytes)
	offset += 32
	if offset > len(payload) {
		return nil
	}

	// Session ID
	if offset+1 > len(payload) {
		return nil
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset > len(payload) {
		return nil
	}

	// Cipher Suites
	if offset+2 > len(payload) {
		return nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(payload) {
		return nil
	}

	// Extract cipher suites (each is 2 bytes)
	for i := 0; i < cipherSuitesLen; i += 2 {
		if offset+2 > len(payload) {
			break
		}
		cipher := binary.BigEndian.Uint16(payload[offset : offset+2])
		// Filter out GREASE values (0x?A?A pattern)
		if !isGREASE(cipher) {
			data.CipherSuites = append(data.CipherSuites, cipher)
		}
		offset += 2
	}

	// Compression Methods
	if offset+1 > len(payload) {
		return nil
	}
	compMethodsLen := int(payload[offset])
	offset += 1 + compMethodsLen
	if offset > len(payload) {
		return nil
	}

	// Extensions
	if offset+2 > len(payload) {
		return data // No extensions
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	endOfExtensions := offset + extensionsLen
	if endOfExtensions > len(payload) {
		endOfExtensions = len(payload)
	}

	// Parse extensions
	for offset+4 <= endOfExtensions {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > endOfExtensions {
			break
		}

		// Filter out GREASE extensions
		if !isGREASE(extType) {
			data.Extensions = append(data.Extensions, extType)

			// Parse specific extensions for JA3
			switch extType {
			case 10: // supported_groups (elliptic curves)
				data.EllipticCurves = parseEllipticCurves(payload[offset : offset+extLen])
			case 11: // ec_point_formats
				data.EllipticCurveFormats = parseECPointFormats(payload[offset : offset+extLen])
			}
		}

		offset += extLen
	}

	return data
}

// Formats JA3Data into the JA3 string format (comma-separated fields) before hashing.
func buildJA3String(data *JA3Data) string {
	var parts []string

	// SSL Version
	parts = append(parts, strconv.Itoa(int(data.SSLVersion)))

	// Cipher Suites (sorted)
	ciphers := make([]string, len(data.CipherSuites))
	for i, c := range data.CipherSuites {
		ciphers[i] = strconv.Itoa(int(c))
	}
	parts = append(parts, strings.Join(ciphers, "-"))

	// Extensions (in order, not sorted)
	extensions := make([]string, len(data.Extensions))
	for i, e := range data.Extensions {
		extensions[i] = strconv.Itoa(int(e))
	}
	parts = append(parts, strings.Join(extensions, "-"))

	// Elliptic Curves
	curves := make([]string, len(data.EllipticCurves))
	for i, c := range data.EllipticCurves {
		curves[i] = strconv.Itoa(int(c))
	}
	parts = append(parts, strings.Join(curves, "-"))

	// EC Point Formats
	formats := make([]string, len(data.EllipticCurveFormats))
	for i, f := range data.EllipticCurveFormats {
		formats[i] = strconv.Itoa(int(f))
	}
	parts = append(parts, strings.Join(formats, "-"))

	return strings.Join(parts, ",")
}

// Extracts elliptic curve IDs from the supported_groups extension for JA3 calculation.
func parseEllipticCurves(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2

	var curves []uint16
	for offset+2 <= len(data) && offset < 2+listLen {
		curve := binary.BigEndian.Uint16(data[offset : offset+2])
		if !isGREASE(curve) {
			curves = append(curves, curve)
		}
		offset += 2
	}

	return curves
}

// Extracts EC point format IDs from the TLS extension for JA3 fingerprinting.
func parseECPointFormats(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}

	listLen := int(data[0])
	offset := 1

	var formats []uint8
	for offset < len(data) && offset < 1+listLen {
		formats = append(formats, data[offset])
		offset++
	}

	return formats
}

// Checks if a value is a GREASE value (used to prevent ossification).
// GREASE values follow the pattern 0x?A?A where ? is the same nibble.
func isGREASE(value uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	if (value&0x0f0f) == 0x0a0a && ((value>>8)&0xf0) == (value&0xf0) {
		return true
	}
	return false
}
