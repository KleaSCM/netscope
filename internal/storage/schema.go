/**
 * Database Schema.
 *
 * Defines the DDL statements for creating the relational database structure,
 * including tables for devices, flows, DNS entries, and TLS handshakes.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package storage

// Contains the SQL statements to create the database tables.
const Schema = `
-- Devices Table
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac_address TEXT UNIQUE,
    vendor TEXT,
    hostname TEXT,
    ip_address TEXT,
    os_fingerprint TEXT,
    device_type TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    user_label TEXT
);

-- Flows Table
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    device_id INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    dst_domain TEXT,
    dst_country TEXT,
    dst_city TEXT,
    dst_asn TEXT,
    app_protocol TEXT,
    traffic_type TEXT,
    ja3_hash TEXT,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    packets_sent INTEGER,
    packets_received INTEGER,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flows(device_id);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(start_time);
CREATE INDEX IF NOT EXISTS idx_flows_domain ON flows(dst_domain);

-- DNS Queries Table
CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY,
    device_id INTEGER,
    query_domain TEXT,
    query_type TEXT,
    resolved_ips TEXT, -- JSON array
    response_time_ms INTEGER,
    ttl INTEGER,
    timestamp TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(query_domain);
CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_queries(timestamp);

-- TLS Handshakes Table
CREATE TABLE IF NOT EXISTS tls_handshakes (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER,
    sni TEXT,
    ja3_hash TEXT,
    ja3s_hash TEXT,
    cipher_suite TEXT,
    tls_version TEXT,
    cert_common_name TEXT,
    cert_issuer TEXT,
    cert_valid_from TIMESTAMP,
    cert_valid_to TIMESTAMP,
    identified_app TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);

-- Access Points (WiFi)
CREATE TABLE IF NOT EXISTS access_points (
    id INTEGER PRIMARY KEY,
    bssid TEXT UNIQUE,
    ssid TEXT,
    channel INTEGER,
    encryption TEXT,
    vendor TEXT,
    signal INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
);

-- WiFi Clients (Probing)
CREATE TABLE IF NOT EXISTS wifi_clients (
    id INTEGER PRIMARY KEY,
    mac_address TEXT UNIQUE,
    vendor TEXT,
    probed_ssids TEXT, -- JSON array
    last_seen TIMESTAMP
);
`
