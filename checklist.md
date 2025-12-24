## Development Roadmap

### Phase 1: Foundation

**Goal**: Capture, parse, store, query basic traffic data

- [x] Project structure setup
- [x] Packet capture engine
- [x] Protocol parser (Layer 2-4)
- [x] DNS & TLS parsing
- [x] Flow tracking
- [x] Database schema & storage
- [x] Basic CLI query interface

**Milestone**: Can capture traffic, identify devices, track connections, query flows

---

### Phase 2: Correlation & Enrichment

**Goal**: Understand what devices are connecting to

- [x] DNS correlation engine
- [x] GeoIP integration
- [x] Device fingerprinting
- [x] JA3/JA4 fingerprinting
- [x] Application identification
- [x] Traffic classification

**Milestone**: Every connection shows device → domain → location → app

---

### Phase 3: Behavioral Analysis

**Goal**: Detect unusual behavior and privacy leaks

- [x] Session reconstruction
- [x] Behavioral baseline per device
- [x] Anomaly detection algorithms
- [x] Privacy leak detection
- [x] Pattern matching engine

**Milestone**: Platform alerts on anomalies and privacy concerns

---

### Phase 4: WiFi Security

**Goal**: Monitor WiFi-specific security

- [ ] 802.11 frame capture
- [ ] AP detection & monitoring
- [ ] Rogue AP detection
- [ ] Client probing analysis
- [ ] WPA handshake capture

**Milestone**: Full WiFi security audit capabilities

---

### Phase 5: Visualization

**Goal**: Beautiful, interactive dashboard

- [ ] Web server setup
- [ ] Real-time dashboard
- [ ] 3D network topology
- [ ] Timeline view
- [ ] Per-device detail pages
- [ ] Query builder UI

**Milestone**: Production-ready web interface

---

### Phase 6: IoT Monitoring

**Goal**: Specialized IoT device security

- [ ] IoT device discovery
- [ ] Behavior monitoring
- [ ] Vulnerability scanning
- [ ] Traffic blocking integration

**Milestone**: Comprehensive IoT security monitoring

---

### Phase 7: Advanced Features

**Goal**: ML, alerting, optimization

- [ ] Machine learning integration
- [ ] Intelligent alerting system
- [ ] Automated reporting
- [ ] Performance optimization
- [ ] Multi-interface support
