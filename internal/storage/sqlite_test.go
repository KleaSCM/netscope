/**
 * SQLite Storage Tests.
 *
 * Verifies the full persistence API (Devices, Flows) against a temporary
 * SQLite database schema.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package storage

import (
	"os"
	"testing"
	"time"

	"github.com/kleaSCM/netscope/internal/models"
)

func TestSQLiteStorage(t *testing.T) {
	// Create temporary DB file
	dbPath := "test_netscope.db"
	defer os.Remove(dbPath)

	store, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// Test Migrate
	if err := store.Migrate(); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	// Test SaveDevice
	device := &models.Device{
		MACAddress: "AA:BB:CC:DD:EE:FF",
		Vendor:     "Test Vendor",
		Hostname:   "test-device",
		IPAddress:  "192.168.1.100",
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}
	if err := store.SaveDevice(device); err != nil {
		t.Fatalf("Failed to save device: %v", err)
	}
	if device.ID == 0 {
		t.Error("Expected device ID to be set")
	}

	// Test GetDeviceByMAC
	fetched, err := store.GetDeviceByMAC("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("Failed to get device: %v", err)
	}
	if fetched == nil {
		t.Fatal("Device not found")
	}
	if fetched.Hostname != "test-device" {
		t.Errorf("Expected hostname test-device, got %s", fetched.Hostname)
	}

	// Test SaveFlow
	flow := &models.Flow{
		DeviceID: device.ID,
		Key: models.FlowKey{
			SrcIP:    "192.168.1.100",
			DstIP:    "8.8.8.8",
			SrcPort:  12345,
			DstPort:  53,
			Protocol: "UDP",
		},
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		PacketCount: 1,
		ByteCount:   100,
		Protocol:    "UDP",
		DNSQuery:    "google.com",
	}
	if err := store.SaveFlow(flow); err != nil {
		t.Fatalf("Failed to save flow: %v", err)
	}
	if flow.ID == 0 {
		t.Error("Expected flow ID to be set")
	}

	// Test ListDevices
	devices, err := store.ListDevices()
	if err != nil {
		t.Fatalf("Failed to list devices: %v", err)
	}
	if len(devices) == 0 {
		t.Error("Expected at least one device")
	}

	// Test GetRecentFlows
	flows, err := store.GetRecentFlows(10)
	if err != nil {
		t.Fatalf("Failed to get recent flows: %v", err)
	}
	if len(flows) == 0 {
		t.Error("Expected at least one flow")
	}
	if flows[0].Key.SrcIP != "192.168.1.100" {
		t.Errorf("Expected SrcIP 192.168.1.100, got %s", flows[0].Key.SrcIP)
	}
}
