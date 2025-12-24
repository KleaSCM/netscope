/**
 * WiFi Models.
 *
 * Defines the data structures for 802.11 Access Points, Clients,
 * and security alerts used throughout the specific WiFi modules.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package models

import "time"

// AccessPoint represents a discovered 802.11 Access Point.
type AccessPoint struct {
	ID         int64
	BSSID      string
	SSID       string
	Channel    int
	Encryption string
	Vendor     string
	Signal     int
	FirstSeen  time.Time
	LastSeen   time.Time
}

// WiFiClient represents a station probing for networks.
type WiFiClient struct {
	ID          int64
	MAC         string
	Vendor      string
	ProbedSSIDs []string
	LastSeen    time.Time
}

// RogueAlert represents a security threat detected by the analyzer.
type RogueAlert struct {
	BSSID    string
	SSID     string
	Severity string // "CRITICAL", "WARNING"
	Message  string
}

// Handshake represents a captured WPA/WPA2 4-way handshake (EAPOL).
type Handshake struct {
	ID        int64
	BSSID     string
	ClientMAC string
	IsFull    bool // True if all 4 frames (or generic "capture") are valid
	Timestamp time.Time
}
