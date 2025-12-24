/**
 * Device Fingerprinting.
 *
 * Analyzes traffic patterns and characteristics to infer device types
 * (e.g., Mobile, IoT, Desktop) and operating systems.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"log"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/kleaSCM/netscope/internal/models"
	"github.com/kleaSCM/netscope/internal/parser"
	"github.com/kleaSCM/netscope/internal/storage"
)

// DeviceTracker maintains real-time state of network devices.
type DeviceTracker struct {
	storage      storage.Storage
	vendorLookup *VendorLookup
	cache        map[string]*models.Device // MAC -> Device
	mu           sync.RWMutex
}

// NewDeviceTracker creates a new tracker instance.
func NewDeviceTracker(store storage.Storage) *DeviceTracker {
	return &DeviceTracker{
		storage:      store,
		vendorLookup: NewVendorLookup(),
		cache:        make(map[string]*models.Device),
	}
}

// Track processes a packet to update device information.
// Returns the device associated with the source MAC.
func (dt *DeviceTracker) Track(packet gopacket.Packet) *models.Device {
	// We primarily track by Source MAC (Layer 2)
	layer2 := parser.ParseEthernet(packet)
	if layer2 == nil {
		return nil
	}

	mac := layer2.SrcMAC

	// Check IP Address (Layer 3) for filtering
	layer3 := parser.ParseIP(packet)
	if layer3 != nil {
		// Filter: Only track private IPs as "Devices"
		// This prevents remote servers from being tracked as local devices
		if !isPrivateIP(layer3.SrcIP) {
			return nil
		}
	}

	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Check cache first
	if device, ok := dt.cache[mac]; ok {
		// Update timestamps and ephemeral data
		device.LastSeen = packet.Metadata().Timestamp

		// Passive OS update (if unknown or we want to refine)
		if device.OSFingerprint == "" || device.OSFingerprint == "Unknown" {
			os := parser.GuessOS(packet)
			if os != "" && os != "Unknown" {
				device.OSFingerprint = os
				// Ideally, persist this change
				dt.persist(device)
			}
		}

		// Update IP if changed or not set
		if layer3 != nil {
			if device.IPAddress != layer3.SrcIP {
				device.IPAddress = layer3.SrcIP
				dt.persist(device)
			}
		}

		return device
	}

	// New Device found
	device := &models.Device{
		MACAddress: mac,
		FirstSeen:  packet.Metadata().Timestamp,
		LastSeen:   packet.Metadata().Timestamp,
		DeviceType: "Unknown", // Default
	}

	// Vendor Lookup
	device.Vendor = dt.vendorLookup.Lookup(mac)

	// OS Fingerprint
	device.OSFingerprint = parser.GuessOS(packet)

	// IP Address
	if layer3 != nil {
		device.IPAddress = layer3.SrcIP
	}

	// Basic Hostname guessing
	if device.Vendor != "" {
		device.Hostname = device.Vendor + "-Device"
	} else {
		shortMac := strings.ReplaceAll(mac, ":", "")
		if len(shortMac) > 4 {
			shortMac = shortMac[len(shortMac)-4:]
		}
		device.Hostname = "Device-" + shortMac
	}

	// Persist to DB
	if err := dt.storage.SaveDevice(device); err != nil {
		log.Printf("Error saving new device %s: %v", mac, err)
	}

	dt.cache[mac] = device
	return device
}

// Helper for private IP check
func isPrivateIP(ip string) bool {
	// Simple string-based check for common private ranges
	// 10.0.0.0/8
	if strings.HasPrefix(ip, "10.") {
		return true
	}
	// 192.168.0.0/16
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}
	// 172.16.0.0/12 block
	if strings.HasPrefix(ip, "172.") {
		return true
	}
	// 169.254.0.0/16 (Link Local)
	if strings.HasPrefix(ip, "169.254.") {
		return true
	}
	// 127.0.0.0/8 (Loopback)
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	// IPv6 Link Local
	if strings.HasPrefix(ip, "fe80:") {
		return true
	}
	// IPv6 ULA
	if strings.HasPrefix(ip, "fc") || strings.HasPrefix(ip, "fd") {
		return true
	}
	return false
}

// Persist updates the device in storage.
func (dt *DeviceTracker) persist(d *models.Device) {
	if err := dt.storage.SaveDevice(d); err != nil {
		log.Printf("Error updating device %s: %v", d.MACAddress, err)
	}
}

// LoadCache populates the memory cache from the database.
func (dt *DeviceTracker) LoadCache() error {
	devices, err := dt.storage.ListDevices()
	if err != nil {
		return err
	}

	dt.mu.Lock()
	defer dt.mu.Unlock()

	for _, d := range devices {
		dt.cache[d.MACAddress] = d
	}
	return nil
}
