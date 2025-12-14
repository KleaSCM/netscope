# NetScope Data Flow Architecture

## Overview
This document details how data flows through the NetScope system from packet capture to storage and analysis.

---

## 1. Packet Capture Flow

```
Network Interface (eth0, wlan0, etc.)
         ↓
   [Promiscuous Mode]
         ↓
    libpcap/gopacket
         ↓
   Ring Buffer (in-memory queue)
         ↓
   Worker Pool (goroutines)
```

**Key Points:**
- Capture runs in promiscuous mode to see all network traffic
- Ring buffer prevents packet loss during processing spikes
- Multiple worker goroutines process packets concurrently
- BPF filters can be applied at kernel level for efficiency

---

## 2. Protocol Parsing Pipeline

### Layer 2: Ethernet
```
Raw Packet Bytes
    ↓
[Ethernet Frame]
    ├─ Source MAC
    ├─ Destination MAC
    ├─ EtherType
    └─ Payload → Next Layer
```

### Layer 3: IP
```
Ethernet Payload
    ↓
[IP Packet Parser]
    ├─ Version (IPv4/IPv6)
    ├─ Source IP
    ├─ Destination IP
    ├─ Protocol (TCP/UDP/ICMP)
    ├─ TTL
    ├─ Flags
    └─ Payload → Next Layer
```

### Layer 4: Transport
```
IP Payload
    ↓
[TCP/UDP Parser]
    ├─ Source Port
    ├─ Destination Port
    ├─ TCP: Flags, Seq, Ack, Window
    ├─ TCP: Options
    └─ Payload → Next Layer
```

### Layer 7: Application
```
Transport Payload
    ↓
[Protocol Detection]
    ├─ Port-based hint
    ├─ Payload inspection
    └─ Route to specific parser
         ↓
    ┌────┴────┬─────────┬────────┬────────┐
    ↓         ↓         ↓        ↓        ↓
  [DNS]    [TLS]     [HTTP]   [DHCP]  [Other]
```

---

## 3. Flow Tracking

### Flow Identification (5-Tuple)
```
Parsed Packet
    ↓
Extract 5-Tuple:
  - Source IP
  - Destination IP
  - Source Port
  - Destination Port
  - Protocol
    ↓
Hash(5-tuple) → Flow ID
    ↓
Flow Table Lookup
    ├─ Existing Flow? → Update
    └─ New Flow? → Create
```

### Flow State Machine
```
[NEW] 
  ↓ (SYN packet)
[SYN_SENT]
  ↓ (SYN-ACK packet)
[ESTABLISHED]
  ↓ (Data transfer)
[ACTIVE]
  ↓ (FIN packet)
[CLOSING]
  ↓ (FIN-ACK)
[CLOSED]
```

---

## 4. DNS Correlation Engine

### DNS Query Tracking
```
DNS Query Packet
    ↓
Extract:
  - Query Domain (e.g., "google.com")
  - Query Type (A, AAAA, CNAME, etc.)
  - Transaction ID
  - Timestamp
    ↓
Store in DNS Cache
```

### DNS Response Processing
```
DNS Response Packet
    ↓
Extract:
  - Resolved IPs
  - TTL
  - Transaction ID
    ↓
Match with Query (by Transaction ID)
    ↓
Create Domain → IP Mapping
    ↓
Store with Expiry (TTL)
```

### Connection Correlation
```
New TCP Connection to IP X
    ↓
Lookup Recent DNS Queries
    ↓
Find: "example.com" → IP X (within TTL)
    ↓
Tag Connection:
  - Domain: "example.com"
  - Resolved At: timestamp
  - Confidence: HIGH
```

**Edge Cases Handled:**
- Multiple IPs for one domain (round-robin DNS)
- Expired DNS cache entries
- Connections without DNS (direct IP usage)
- Reverse DNS lookups for unknown IPs

---

## 5. TLS Analysis Pipeline

### ClientHello Processing
```
TLS ClientHello Packet
    ↓
Extract:
  ├─ SNI (Server Name Indication)
  ├─ Cipher Suites
  ├─ Extensions
  ├─ Supported Versions
  └─ Elliptic Curves
    ↓
Calculate JA3 Hash:
  Hash(Version, Ciphers, Extensions, Curves, Formats)
    ↓
Store Client Fingerprint
```

### ServerHello Processing
```
TLS ServerHello Packet
    ↓
Extract:
  ├─ Selected Cipher Suite
  ├─ Selected Extensions
  └─ Certificate Chain
    ↓
Calculate JA3S Hash:
  Hash(Version, Cipher, Extensions)
    ↓
Extract Certificate Info:
  ├─ Common Name
  ├─ SANs (Subject Alternative Names)
  ├─ Issuer
  ├─ Validity Period
  └─ Fingerprint
    ↓
Store Server Fingerprint
```

### Application Identification
```
JA3 Hash
    ↓
Lookup in Fingerprint Database
    ↓
Match Found?
  ├─ YES → Tag with Application Name
  └─ NO  → Tag as "Unknown (JA3: xxx)"
```

---

## 6. Enrichment Pipeline

### Device Identification
```
MAC Address
    ↓
OUI Lookup (first 3 octets)
    ↓
Vendor Name (e.g., "Apple, Inc.")
    ↓
Combine with:
  ├─ DHCP Hostname
  ├─ mDNS Hostname
  ├─ TCP/IP Fingerprint
  └─ User-Defined Name
    ↓
Device Profile:
  - MAC: aa:bb:cc:dd:ee:ff
  - Vendor: Apple
  - Hostname: "Johns-iPhone"
  - OS: iOS (fingerprinted)
  - Type: Mobile Device
```

### GeoIP Enrichment
```
Destination IP
    ↓
Query GeoIP Database
    ↓
Extract:
  ├─ Country Code
  ├─ Country Name
  ├─ City
  ├─ Latitude/Longitude
  ├─ ASN (Autonomous System)
  ├─ Organization
  └─ Network Name
    ↓
Cache Result (24hr TTL)
```

### Traffic Classification
```
Flow Metadata
    ↓
Feature Extraction:
  ├─ Port Numbers
  ├─ Packet Sizes
  ├─ Inter-Arrival Times
  ├─ Protocol Flags
  └─ Payload Signatures
    ↓
Classification:
  ├─ Port-Based (80=HTTP, 443=HTTPS)
  ├─ DPI Signatures (Netflix, YouTube patterns)
  ├─ ML Model (future)
  └─ Heuristics (streaming, gaming, browsing)
    ↓
Tag: "Video Streaming" / "Web Browsing" / etc.
```

---

## 7. Storage Schema

### Device Table
```sql
CREATE TABLE devices (
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
```

### Flow Table
```sql
CREATE TABLE flows (
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
CREATE INDEX idx_flows_device ON flows(device_id);
CREATE INDEX idx_flows_time ON flows(start_time);
CREATE INDEX idx_flows_domain ON flows(dst_domain);
```

### DNS Table
```sql
CREATE TABLE dns_queries (
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
CREATE INDEX idx_dns_domain ON dns_queries(query_domain);
CREATE INDEX idx_dns_time ON dns_queries(timestamp);
```

### TLS Table
```sql
CREATE TABLE tls_handshakes (
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
```

---

## 8. Analysis Pipeline

### Behavioral Baseline
```
Per Device:
  ↓
Learn Normal Patterns:
  ├─ Typical connection times (morning, evening)
  ├─ Common destinations (domains/IPs)
  ├─ Expected traffic volume
  ├─ Protocol distribution
  └─ Connection frequency
    ↓
Store Baseline Profile
    ↓
Continuously Update (sliding window)
```

### Anomaly Detection
```
New Flow
    ↓
Compare Against Baseline:
  ├─ Unusual destination?
  ├─ Unusual time of day?
  ├─ Unusual traffic volume?
  ├─ Port scanning pattern?
  └─ Beaconing behavior?
    ↓
Calculate Anomaly Score
    ↓
Score > Threshold?
  ├─ YES → Generate Alert
  └─ NO  → Log as Normal
```

### Privacy Leak Detection
```
For Each Device:
  ↓
Analyze Connections:
  ├─ Third-party tracker domains
  ├─ Advertising networks
  ├─ Analytics services
  ├─ Unexpected external connections
  └─ Data sent to unknown destinations
    ↓
Calculate Privacy Score:
  - 100 = Excellent (minimal external contact)
  - 0 = Poor (extensive tracking)
    ↓
Generate Privacy Report
```

---

## 9. Query & Retrieval Flow

### CLI Query Example
```
User: ./netscope query flows --device 192.168.1.50 --last 1h
    ↓
[Query Parser]
    ↓
SQL Generation:
  SELECT * FROM flows f
  JOIN devices d ON f.device_id = d.id
  WHERE d.ip_address = '192.168.1.50'
    AND f.start_time > datetime('now', '-1 hour')
  ORDER BY f.start_time DESC
    ↓
[Database Query]
    ↓
[Result Formatting]
    ↓
Output to Terminal:
  ┌────────────┬─────────────────┬────────┬──────────┐
  │ Time       │ Destination     │ Bytes  │ Protocol │
  ├────────────┼─────────────────┼────────┼──────────┤
  │ 14:32:15   │ google.com      │ 1.2MB  │ HTTPS    │
  │ 14:31:08   │ cloudflare.com  │ 543KB  │ HTTPS    │
  └────────────┴─────────────────┴────────┴──────────┘
```

---

## 10. Real-Time Dashboard Data Flow

```
[Packet Capture] → [Parser] → [Storage]
                                   ↓
                          [Change Detector]
                                   ↓
                           [WebSocket Push]
                                   ↓
                            [Web Dashboard]
                                   ↓
                          [Real-Time Update]
                                   ↓
                         [Visualization Render]
```

**Dashboard Updates:**
- New device detected → Push notification
- Traffic spike → Update bandwidth graph
- Anomaly detected → Alert banner
- Connection established → Update topology
- DNS query → Update activity log

---

## Performance Considerations

### Packet Processing Rate
- **Target**: 1 Gbps sustained traffic
- **Strategy**: Lock-free ring buffer, worker pool
- **Optimization**: Packet filtering at BPF level

### Storage Efficiency
- **Strategy**: Aggregate flows, don't store every packet
- **Retention**: 
  - Full flows: 7 days
  - Aggregated stats: 30 days
  - Alerts/anomalies: 90 days
- **Indexing**: Time-series optimized indexes

### Memory Management
- **Flow Table**: Limited to N active flows (e.g., 100k)
- **DNS Cache**: TTL-based expiry
- **Packet Buffer**: Fixed size ring buffer
- **GeoIP Cache**: In-memory with LRU eviction

---

## Error Handling

### Packet Loss
```
Capture Buffer Full
    ↓
Log: "Dropped N packets at timestamp X"
    ↓
Increment Drop Counter
    ↓
Continue Processing
```

### Parsing Errors
```
Malformed Packet
    ↓
Log: "Parse error: layer Y, reason Z"
    ↓
Store as "Unknown Protocol"
    ↓
Continue Processing
```

### Database Errors
```
Write Failure
    ↓
Retry with Exponential Backoff
    ↓
Still Failing?
  ├─ Log to File (fallback)
  └─ Alert User
```

---

This data flow architecture ensures NetScope can handle high-throughput traffic while maintaining accuracy and providing real-time insights.
