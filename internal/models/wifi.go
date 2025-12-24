package models

import "time"

// AccessPoint represents a discovered 802.11 Access Point.
type AccessPoint struct {
	ID         int64
	BSSID      string // MAC Address
	SSID       string
	Channel    int
	Encryption string // e.g., "WPA2", "Open"
	Vendor     string
	Signal     int // RSSI in dBm
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Client represents a device probing for WiFi.
type WiFiClient struct {
	ID          int64
	MAC         string
	Vendor      string
	ProbedSSIDs []string // Store as JSON or comma-separated in DB? JSON is better.
	LastSeen    time.Time
}
