/**
 * SQLite Implementation.
 *
 * Implements the Storage interface using SQLite3, suitable for standalone
 * and embedded deployment scenarios.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/kleaSCM/netscope/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// Implements the Storage interface for SQLite.
type SQLiteStorage struct {
	db *sql.DB
}

// Creates a new SQLite storage instance.
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &SQLiteStorage{db: db}, nil
}

// Closes the database connection.
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Applies the schema to the database.
func (s *SQLiteStorage) Migrate() error {
	_, err := s.db.Exec(Schema)
	if err != nil {
		return fmt.Errorf("failed to apply schema: %w", err)
	}
	return nil
}

// Saves or updates a device in the database.
func (s *SQLiteStorage) SaveDevice(d *models.Device) error {
	query := `
	INSERT INTO devices (mac_address, vendor, hostname, ip_address, os_fingerprint, device_type, first_seen, last_seen, user_label)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac_address) DO UPDATE SET
		vendor = excluded.vendor,
		hostname = excluded.hostname,
		ip_address = excluded.ip_address,
		last_seen = excluded.last_seen;
	`
	res, err := s.db.Exec(query, d.MACAddress, d.Vendor, d.Hostname, d.IPAddress, d.OSFingerprint, d.DeviceType, d.FirstSeen, d.LastSeen, d.UserLabel)
	if err != nil {
		return fmt.Errorf("failed to save device: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	d.ID = id
	return nil
}

// Retrieves a device by its MAC address.
func (s *SQLiteStorage) GetDeviceByMAC(mac string) (*models.Device, error) {
	query := `SELECT id, mac_address, vendor, hostname, ip_address, os_fingerprint, device_type, first_seen, last_seen, user_label FROM devices WHERE mac_address = ?`
	row := s.db.QueryRow(query, mac)

	var d models.Device
	err := row.Scan(&d.ID, &d.MACAddress, &d.Vendor, &d.Hostname, &d.IPAddress, &d.OSFingerprint, &d.DeviceType, &d.FirstSeen, &d.LastSeen, &d.UserLabel)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// Saves or updates a flow in the database.
func (s *SQLiteStorage) SaveFlow(f *models.Flow) error {
	// If flow ID is empty, insert. We don't really update flows in real-time db efficiently without ID.
	// But in this system, maybe we assume ID is 0 for new flows.
	// Actually, correlate logic holds *models.Flow in memory.
	// We want to persist it.

	query := `
	INSERT INTO flows (device_id, src_ip, dst_ip, src_port, dst_port, protocol, dst_domain, traffic_type, start_time, end_time, bytes_sent, packets_sent, app_protocol)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	// Insert flow record.
	// Missing: dst_country, city, asn, ja3, etc. Phase 1 doesn't have them all.
	// Also Flow model has Key but DB separates 5-tuple.

	res, err := s.db.Exec(query,
		f.DeviceID,
		f.Key.SrcIP, f.Key.DstIP, f.Key.SrcPort, f.Key.DstPort, f.Key.Protocol,
		f.DNSQuery, // mapping DNSQuery -> dst_domain for simplicity
		"normal",   // traffic_type
		f.FirstSeen, f.LastSeen,
		f.ByteCount, f.PacketCount,
		f.Protocol, // app_protocol (e.g. TCP/UDP, reused)
	)
	if err != nil {
		return fmt.Errorf("failed to save flow: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	f.ID = id
	return nil
}

// Returns all registered devices ordered by last seen.
func (s *SQLiteStorage) ListDevices() ([]*models.Device, error) {
	query := `SELECT id, mac_address, vendor, hostname, ip_address, os_fingerprint, device_type, first_seen, last_seen, user_label FROM devices ORDER BY last_seen DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	defer rows.Close()

	var devices []*models.Device
	for rows.Next() {
		var d models.Device
		if err := rows.Scan(&d.ID, &d.MACAddress, &d.Vendor, &d.Hostname, &d.IPAddress, &d.OSFingerprint, &d.DeviceType, &d.FirstSeen, &d.LastSeen, &d.UserLabel); err != nil {
			return nil, err
		}
		devices = append(devices, &d)
	}
	return devices, nil
}

// Returns the most recent flows up to the specified limit.
func (s *SQLiteStorage) GetRecentFlows(limit int) ([]*models.Flow, error) {
	query := `
	SELECT id, device_id, src_ip, dst_ip, src_port, dst_port, protocol, dst_domain, traffic_type, start_time, end_time, bytes_sent, packets_sent, app_protocol 
	FROM flows 
	ORDER BY start_time DESC 
	LIMIT ?`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent flows: %w", err)
	}
	defer rows.Close()

	var flows []*models.Flow
	for rows.Next() {
		var f models.Flow
		var trafficType string
		// Scan matches columns in query
		err := rows.Scan(
			&f.ID, &f.DeviceID,
			&f.Key.SrcIP, &f.Key.DstIP, &f.Key.SrcPort, &f.Key.DstPort, &f.Key.Protocol,
			&f.DNSQuery,
			&trafficType,
			&f.FirstSeen, &f.LastSeen,
			&f.ByteCount, &f.PacketCount,
			&f.Protocol, // app_protocol
		)

		if err != nil {
			return nil, err
		}
		flows = append(flows, &f)
	}
	return flows, nil
}

// SaveAccessPoint persists or updates a WiFi Access Point.
func (s *SQLiteStorage) SaveAccessPoint(ap *models.AccessPoint) error {
	query := `
	INSERT INTO access_points (bssid, ssid, channel, encryption, vendor, signal, first_seen, last_seen)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(bssid) DO UPDATE SET
		ssid = excluded.ssid,
		channel = excluded.channel,
		encryption = excluded.encryption,
		signal = excluded.signal,
		last_seen = excluded.last_seen;
	`
	_, err := s.db.Exec(query, ap.BSSID, ap.SSID, ap.Channel, ap.Encryption, ap.Vendor, ap.Signal, ap.FirstSeen, ap.LastSeen)
	if err != nil {
		return fmt.Errorf("failed to save AP: %w", err)
	}
	return nil
}

// ListAccessPoints retrieves all discovered APs.
func (s *SQLiteStorage) ListAccessPoints() ([]*models.AccessPoint, error) {
	query := `SELECT id, bssid, ssid, channel, encryption, vendor, signal, first_seen, last_seen FROM access_points ORDER BY last_seen DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list APs: %w", err)
	}
	defer rows.Close()

	var aps []*models.AccessPoint
	for rows.Next() {
		var ap models.AccessPoint
		if err := rows.Scan(&ap.ID, &ap.BSSID, &ap.SSID, &ap.Channel, &ap.Encryption, &ap.Vendor, &ap.Signal, &ap.FirstSeen, &ap.LastSeen); err != nil {
			return nil, err
		}
		aps = append(aps, &ap)
	}
	return aps, nil
}

// SaveWiFiClient persists or updates a WiFi Client probe.
func (s *SQLiteStorage) SaveWiFiClient(client *models.WiFiClient) error {
	// Using JSON serialization for ProbedSSIDs avoids the complexity of a many-to-many
	// relationship table for this simple list.
	ssidsJSON, err := json.Marshal(client.ProbedSSIDs)
	if err != nil {
		// Log error but attempt to save empty list to prevent data loss of the client itself
		ssidsJSON = []byte("[]")
	}

	query := `
	INSERT INTO wifi_clients (mac_address, vendor, probed_ssids, last_seen)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(mac_address) DO UPDATE SET
		probed_ssids = excluded.probed_ssids,
		last_seen = excluded.last_seen;
	`
	_, err = s.db.Exec(query, client.MAC, client.Vendor, string(ssidsJSON), client.LastSeen)
	if err != nil {
		return fmt.Errorf("failed to save WiFi client: %w", err)
	}
	return nil
}

// ListWiFiClients retrieves all discovered WiFi clients.
func (s *SQLiteStorage) ListWiFiClients() ([]*models.WiFiClient, error) {
	query := `SELECT id, mac_address, vendor, probed_ssids, last_seen FROM wifi_clients ORDER BY last_seen DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}
	defer rows.Close()

	var clients []*models.WiFiClient
	for rows.Next() {
		var c models.WiFiClient
		var ssidJSON string

		if err := rows.Scan(&c.ID, &c.MAC, &c.Vendor, &ssidJSON, &c.LastSeen); err != nil {
			return nil, err
		}

		// Unmarshal the JSON array of SSIDs back into the slice.
		// If unmarshalling fails, we default to an empty slice to keep the UI functional.
		if len(ssidJSON) > 0 {
			if err := json.Unmarshal([]byte(ssidJSON), &c.ProbedSSIDs); err != nil {
				c.ProbedSSIDs = []string{}
			}
		}

		clients = append(clients, &c)
	}
	return clients, nil
}

// Note: This only stores the event metadata; raw packet data is handled by the capture engine/pcap.
func (s *SQLiteStorage) SaveHandshake(hs *models.Handshake) error {
	query := `
	INSERT INTO handshakes (bssid, client_mac, is_full, timestamp)
	VALUES (?, ?, ?, ?)
	`
	_, err := s.db.Exec(query, hs.BSSID, hs.ClientMAC, hs.IsFull, hs.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to save handshake: %w", err)
	}
	return nil
}

// Returns handshakes sorted by newest first.
func (s *SQLiteStorage) ListHandshakes() ([]*models.Handshake, error) {
	query := `SELECT id, bssid, client_mac, is_full, timestamp FROM handshakes ORDER BY timestamp DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list handshakes: %w", err)
	}
	defer rows.Close()

	var handshakes []*models.Handshake
	for rows.Next() {
		var hs models.Handshake
		if err := rows.Scan(&hs.ID, &hs.BSSID, &hs.ClientMAC, &hs.IsFull, &hs.Timestamp); err != nil {
			return nil, err
		}
		handshakes = append(handshakes, &hs)
	}
	return handshakes, nil
}
