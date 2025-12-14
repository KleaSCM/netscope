# NetScope

**Comprehensive Network Traffic Analysis & Monitoring Platform**

NetScope is a powerful, academic network observatory tool designed to capture, analyze, and visualize network traffic on your own network. Built with Go for performance and maintainability, it provides deep insights into device behavior, traffic patterns, and potential security concerns—all while respecting encryption boundaries.

---

## 🎯 Project Goals

- **Observe & Understand**: Capture and analyze all network traffic metadata
- **Device Intelligence**: Automatically identify and profile devices on your network
- **Privacy Awareness**: Detect what data your devices are sending and where
- **Security Monitoring**: Identify anomalous behavior, rogue devices, and potential threats
- **Educational**: Learn network protocols and traffic analysis in depth
- **Ethical**: No decryption attempts, no hacky MITM attacks—pure observation

---

## ✨ Key Features

### Phase 1: Foundation (Current Focus)
- Real-time packet capture from network interfaces
- Multi-layer protocol parsing (Ethernet → IP → TCP/UDP → Application)
- DNS query tracking and correlation
- TLS handshake analysis (SNI, certificates, JA3 fingerprinting)
- Device identification and tracking
- Efficient storage and querying

### Phase 2: Intelligence
- DNS-to-IP correlation engine
- GeoIP enrichment (country, city, ASN)
- Device fingerprinting (OS detection, vendor identification)
- Application identification via TLS fingerprints
- Traffic classification

### Phase 3: Analysis
- Behavioral baseline establishment
- Anomaly detection (unusual traffic patterns, beaconing, data exfiltration)
- Privacy leak detection (third-party trackers, unexpected connections)
- Session reconstruction and flow analysis

### Phase 4: WiFi Security
- 802.11 frame capture and analysis
- Rogue AP detection
- Evil twin attack detection
- WPA handshake capture (academic purposes)
- Client probing behavior analysis

### Phase 5: Visualization
- Real-time web dashboard
- 3D network topology visualization
- Interactive traffic timeline
- Per-device analytics
- Bandwidth graphs and protocol distribution

### Phase 6: IoT Monitoring
- Automatic IoT device discovery
- Behavioral monitoring and alerting
- Vulnerability scanning
- Traffic blocking integration

### Phase 7: Advanced
- Machine learning for traffic classification
- Intelligent alerting system
- Automated reporting
- Performance optimization
- Multi-interface support

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        NetScope Platform                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┐
│ Network Traffic │ ← Raw packets from interface(s)
└────────┬────────┘
         │
┌────────▼────────┐
│ Capture Engine  │ ← gopacket/libpcap, ring buffer
│  (capture/)     │   promiscuous mode, BPF filters
└────────┬────────┘
         │
┌────────▼────────┐
│ Protocol Parser │ ← Layer 2-7 dissection
│   (parser/)     │   Ethernet, IP, TCP/UDP, DNS,
│                 │   TLS, HTTP, DHCP, mDNS, etc.
└────────┬────────┘
         │
┌────────▼────────┐
│   Correlator    │ ← Link DNS → IPs
│ (correlator/)   │   Track sessions & flows
│                 │   5-tuple flow tracking
└────────┬────────┘
         │
┌────────▼────────┐
│    Enricher     │ ← GeoIP, device fingerprinting
│  (enricher/)    │   JA3/JA4, vendor lookup
│                 │   Application identification
└────────┬────────┘
         │
┌────────▼────────┐
│    Analyzer     │ ← Pattern detection
│  (analyzer/)    │   Anomaly detection
│                 │   Privacy analysis
└────────┬────────┘
         │
┌────────▼────────┐
│  Storage Layer  │ ← SQLite → PostgreSQL
│   (storage/)    │   Time-series optimized
│                 │   Efficient indexing
└────────┬────────┘
         │
         ├─────────────┬─────────────┐
         │             │             │
┌────────▼────────┐ ┌──▼──────┐ ┌───▼────────┐
│   CLI Query     │ │ Web API │ │ Dashboard  │
│   Interface     │ │ (api/)  │ │   (web/)   │
└─────────────────┘ └─────────┘ └────────────┘
```

---

## 📂 Project Structure

```
netscope/
├── cmd/
│   ├── netscope/              # Main CLI application
│   │   └── main.go
│   └── web/                   # Web dashboard server
│       └── main.go
│
├── internal/
│   ├── capture/               # Packet capture engine
│   │   ├── engine.go          # Main capture loop
│   │   ├── interface.go       # Interface selection/config
│   │   └── buffer.go          # Ring buffer implementation
│   │
│   ├── parser/                # Protocol dissection
│   │   ├── ethernet.go        # Layer 2
│   │   ├── ip.go              # IPv4/IPv6
│   │   ├── transport.go       # TCP/UDP
│   │   ├── dns.go             # DNS parsing
│   │   ├── tls.go             # TLS handshake parsing
│   │   ├── http.go            # HTTP/1.1 parsing
│   │   └── fingerprint.go     # JA3/JA4 calculation
│   │
│   ├── correlator/            # Connection correlation
│   │   ├── dns.go             # DNS → IP mapping
│   │   ├── flow.go            # Flow tracking (5-tuple)
│   │   └── session.go         # Session reconstruction
│   │
│   ├── enricher/              # Data enrichment
│   │   ├── geoip.go           # GeoIP lookups
│   │   ├── device.go          # Device fingerprinting
│   │   ├── vendor.go          # MAC OUI lookup
│   │   └── application.go     # App identification
│   │
│   ├── analyzer/              # Traffic analysis
│   │   ├── baseline.go        # Behavioral baseline
│   │   ├── anomaly.go         # Anomaly detection
│   │   ├── privacy.go         # Privacy leak detection
│   │   └── patterns.go        # Pattern matching
│   │
│   ├── storage/               # Database layer
│   │   ├── db.go              # Database interface
│   │   ├── sqlite.go          # SQLite implementation
│   │   ├── postgres.go        # PostgreSQL (future)
│   │   ├── schema.go          # Schema definitions
│   │   └── queries.go         # Common queries
│   │
│   ├── models/                # Data structures
│   │   ├── device.go          # Device model
│   │   ├── flow.go            # Flow/connection model
│   │   ├── packet.go          # Packet metadata
│   │   ├── dns.go             # DNS query model
│   │   └── session.go         # Session model
│   │
│   └── config/                # Configuration
│       ├── config.go          # Config loading/parsing
│       └── defaults.go        # Default values
│
├── pkg/
│   └── api/                   # Public API (future)
│       └── handlers.go
│
├── web/                       # Frontend assets
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── assets/
│   └── templates/
│       └── index.html
│
├── scripts/                   # Utility scripts
│   ├── setup.sh              # Environment setup
│   ├── install.sh            # Installation script
│   └── update_geoip.sh       # GeoIP database updater
│
├── docs/                      # Documentation
│   ├── architecture.md        # Architecture details
│   ├── protocol-parsing.md    # Protocol documentation
│   ├── api.md                 # API documentation
│   └── deployment.md          # Deployment guide
│
├── test/                      # Integration tests
│   ├── capture_test.go
│   ├── parser_test.go
│   └── integration_test.go
│
├── data/                      # Data files (gitignored)
│   ├── geoip/                # GeoIP databases
│   └── fingerprints/         # Known fingerprints DB
│
├── .gitignore
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
└── README.md
```

---

## 🛠️ Technology Stack

### Core
- **Language**: Go 1.21+
- **Packet Capture**: libpcap (Linux/macOS), Npcap (Windows)
- **Protocol Parsing**: gopacket

### Storage
- **Development**: SQLite3
- **Production**: PostgreSQL / TimescaleDB
- **Caching**: (Future) Redis

### Enrichment
- **GeoIP**: MaxMind GeoLite2
- **Fingerprinting**: JA3/JA4 libraries

### Frontend (Phase 5+)
- **Server**: Go net/http or Gin
- **Visualization**: Three.js, D3.js
- **Real-time**: WebSockets

---

## 📋 Development Roadmap

### ✅ Phase 1: Foundation (Weeks 1-5)
**Goal**: Capture, parse, store, query basic traffic data

- [x] Project structure setup
- [ ] Packet capture engine
- [ ] Protocol parser (Layer 2-4)
- [ ] DNS & TLS parsing
- [ ] Flow tracking
- [ ] Database schema & storage
- [ ] Basic CLI query interface

**Milestone**: Can capture traffic, identify devices, track connections, query flows

---

### Phase 2: Correlation & Enrichment (Weeks 6-8)
**Goal**: Understand what devices are connecting to

- [ ] DNS correlation engine
- [ ] GeoIP integration
- [ ] Device fingerprinting
- [ ] JA3/JA4 fingerprinting
- [ ] Application identification
- [ ] Traffic classification

**Milestone**: Every connection shows device → domain → location → app

---

### Phase 3: Behavioral Analysis (Weeks 9-12)
**Goal**: Detect unusual behavior and privacy leaks

- [ ] Session reconstruction
- [ ] Behavioral baseline per device
- [ ] Anomaly detection algorithms
- [ ] Privacy leak detection
- [ ] Pattern matching engine

**Milestone**: Platform alerts on anomalies and privacy concerns

---

### Phase 4: WiFi Security (Weeks 13-15)
**Goal**: Monitor WiFi-specific security

- [ ] 802.11 frame capture
- [ ] AP detection & monitoring
- [ ] Rogue AP detection
- [ ] Client probing analysis
- [ ] WPA handshake capture

**Milestone**: Full WiFi security audit capabilities

---

### Phase 5: Visualization (Weeks 16-20)
**Goal**: Beautiful, interactive dashboard

- [ ] Web server setup
- [ ] Real-time dashboard
- [ ] 3D network topology
- [ ] Timeline view
- [ ] Per-device detail pages
- [ ] Query builder UI

**Milestone**: Production-ready web interface

---

### Phase 6: IoT Monitoring (Weeks 21-24)
**Goal**: Specialized IoT device security

- [ ] IoT device discovery
- [ ] Behavior monitoring
- [ ] Vulnerability scanning
- [ ] Traffic blocking integration

**Milestone**: Comprehensive IoT security monitoring

---

### Phase 7: Advanced Features (Weeks 25+)
**Goal**: ML, alerting, optimization

- [ ] Machine learning integration
- [ ] Intelligent alerting system
- [ ] Automated reporting
- [ ] Performance optimization
- [ ] Multi-interface support

**Milestone**: Enterprise-grade feature set

---

## 🚀 Getting Started

### Prerequisites
```bash
# Linux (Debian/Ubuntu)
sudo apt-get install libpcap-dev build-essential

# macOS
brew install libpcap

# Windows
# Install Npcap from https://npcap.com/
```

### Installation
```bash
# Clone repository
git clone https://github.com/kleaSCM/netscope.git
cd netscope

# Install dependencies
go mod download

# Build
make build

# Run (requires root/admin for packet capture)
sudo ./bin/netscope
```

### Basic Usage
```bash
# List available interfaces
sudo ./netscope interfaces

# Start capture on specific interface
sudo ./netscope capture --interface eth0

# Query devices
./netscope query devices

# Query flows for a device
./netscope query flows --device 192.168.1.100

# Start web dashboard
sudo ./netscope web --port 8080
```

---

## 🔒 Security & Ethics

### What This Tool Does
- ✅ Captures metadata about network traffic
- ✅ Analyzes plaintext protocols (HTTP, DNS, etc.)
- ✅ Observes encrypted traffic patterns (without decryption)
- ✅ Identifies devices and applications
- ✅ Detects anomalies and privacy leaks

### What This Tool Does NOT Do
- ❌ Decrypt TLS/SSL traffic
- ❌ Install fake certificates (MITM attacks)
- ❌ Break encryption algorithms
- ❌ Crack passwords or keys
- ❌ Attack other networks

### Legal Considerations
- **Only use on networks you own or have explicit permission to monitor**
- Packet capture may require root/administrator privileges
- Some jurisdictions have laws about network monitoring
- Capturing others' traffic without consent may be illegal
- This tool is for educational and personal network security purposes only

### Privacy
- All data stays local (no cloud uploads)
- Encrypted traffic payloads are not decrypted or stored
- Metadata is stored securely on your system
- You control all data retention policies

---

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [Protocol Parsing Guide](docs/protocol-parsing.md)
- [API Documentation](docs/api.md)
- [Deployment Guide](docs/deployment.md)
