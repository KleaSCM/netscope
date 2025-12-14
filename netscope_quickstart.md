# NetScope - Quick Start Guide

Get NetScope up and running in 5 minutes!

---

## Prerequisites

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential golang
```



---

## Installation

### Step 1: Clone or Create Project Structure

```bash
# Create project directory
mkdir -p netscope
cd netscope

# Create directory structure
mkdir -p cmd/netscope
mkdir -p internal/capture
mkdir -p bin
```

### Step 2: Copy Files

Copy these files to your project:
- `go.mod` → project root
- `Makefile` → project root
- `cmd/netscope/main.go` → cmd/netscope/
- `internal/capture/interface.go` → internal/capture/
- `internal/capture/engine.go` → internal/capture/

### Step 3: Install Dependencies

```bash
# Install Go dependencies
make deps

# Or manually:
go mod download
go mod tidy
```

### Step 4: Build

```bash
make build

# Or manually:
go build -o bin/netscope ./cmd/netscope
```

---

## Usage

### List Network Interfaces

```bash
sudo ./bin/netscope interfaces
```

**Output:**
```
╔═══════════════════════════════════════════════════════════╗
║                       NetScope v0.1                       ║
║          Network Traffic Analysis & Monitoring            ║
╚═══════════════════════════════════════════════════════════╝

Available network interfaces:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1] wlan0 (Wireless LAN adapter)
    Status: UP
    Addresses:
      - 192.168.1.50
      - fe80::1234:5678:abcd:ef01

[2] eth0 (Ethernet adapter)
    Status: UP
    Addresses:
      - 192.168.1.100

[3] lo (Loopback)
    Status: UP [LOOPBACK]
    Addresses:
      - 127.0.0.1
      - ::1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Recommended interface: wlan0
```

---

### Start Capturing Packets

#### Basic Capture (All Traffic)

```bash
sudo ./bin/netscope capture --interface wlan0
```

**Output:**
```
🚀 Starting capture on wlan0
   Press Ctrl+C to stop

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[14:32:15.123] 192.168.1.50:54321 → 142.250.80.46:443 (TCP, 66 bytes)
[14:32:15.124] 192.168.1.50:54322 → 1.1.1.1:53 (UDP, 71 bytes)
[14:32:15.156] 192.168.1.50:443 ← 142.250.80.46:12345 (TCP, 1514 bytes)
[14:32:16.001] ARP: aa:bb:cc:dd:ee:ff → ff:ff:ff:ff:ff:ff (42 bytes)

[STATS] Packets: 1247 | Dropped: 0 | Bytes: 1.82 MB
```

#### Capture with Filter (HTTPS Only)

```bash
sudo ./bin/netscope capture --interface wlan0 --filter "tcp port 443"
```

#### Verbose Mode

```bash
sudo ./bin/netscope capture --interface wlan0 --verbose
```

**Verbose Output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Timestamp: 14:32:15.123456
Protocol:  TCP
Length:    66 bytes
Ethernet:  aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66
IP:        192.168.1.50 → 142.250.80.46
Ports:     54321 → 443
```

---

## Common BPF Filters

### Protocol Filters
```bash
# Capture only TCP traffic
--filter "tcp"

# Capture only UDP traffic
--filter "udp"

# Capture DNS queries
--filter "udp port 53"

# Capture HTTP traffic
--filter "tcp port 80"

# Capture HTTPS traffic
--filter "tcp port 443"
```

### IP Address Filters
```bash
# Capture traffic to/from specific IP
--filter "host 192.168.1.100"

# Capture traffic to specific IP
--filter "dst host 192.168.1.100"

# Capture traffic from specific IP
--filter "src host 192.168.1.100"

# Capture traffic to specific subnet
--filter "dst net 192.168.1.0/24"
```

### Port Filters
```bash
# Capture traffic on port 80 or 443
--filter "port 80 or port 443"

# Capture traffic on port range
--filter "portrange 8000-9000"
```

### Complex Filters
```bash
# HTTPS traffic to specific IP
--filter "tcp port 443 and host 192.168.1.100"

# HTTP or HTTPS
--filter "tcp port 80 or tcp port 443"

# Everything except SSH
--filter "not tcp port 22"
```

---

## Stopping Capture

Press `Ctrl+C` to stop capture gracefully. NetScope will display final statistics:

```
🛑 Shutting down gracefully...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Final Statistics:
  Packets Captured: 12,847
  Packets Dropped:  0
  Total Bytes:      18.52 MB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Capture stopped successfully
```

---

## Troubleshooting

### Permission Denied
**Error:** `Operation not permitted` or `You don't have permission`

**Solution:** NetScope requires root privileges for packet capture:
```bash
sudo ./bin/netscope capture --interface wlan0
```

---

### Interface Not Found
**Error:** `interface eth0 not found`

**Solution:** List available interfaces:
```bash
sudo ./bin/netscope interfaces
```

Then use a valid interface name.

---

### libpcap Not Found (Linux)
**Error:** `cannot find -lpcap`

**Solution:** Install libpcap development files:
```bash
sudo apt-get install libpcap-dev
```

---

### No Packets Captured

**Possible causes:**
1. Wrong interface selected
2. No network activity
3. Firewall blocking
4. BPF filter too restrictive

**Solutions:**
- Verify interface is UP: `sudo ./bin/netscope interfaces`
- Try without filter first
- Generate some traffic (open a website)
- Check firewall settings

---

## Makefile Shortcuts

```bash
# Build
make build

# List interfaces quickly
make interfaces

# Start capture quickly (uses default interface)
make capture

# Clean build artifacts
make clean

# Install dependencies
make deps

# Complete setup
make setup
```

---

## Next Steps

Phase 1 is now complete! You have a working packet capture tool.

**What's working:**
- ✅ Interface listing
- ✅ Packet capture
- ✅ Basic protocol parsing (Ethernet, IP, TCP, UDP, ICMP, ARP)
- ✅ BPF filtering
- ✅ Statistics tracking

**Coming next in Phase 1:**
- Protocol parser improvements (DNS, TLS, HTTP)
- Flow tracking (5-tuple sessions)
- Database storage
- Query interface

---

## Getting Help

```bash
# Show help
./bin/netscope help

# Or
make help
```