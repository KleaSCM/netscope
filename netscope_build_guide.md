# NetScope - Build & Run Guide

Interactive CLI version - no more typing long commands!

---

## Prerequisites

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential golang
```

### Windows
1. Install [Go](https://golang.org/dl/) (1.21 or newer)
2. Install [Npcap](https://npcap.com/) (with WinPcap API compatibility enabled)

---

## Project Setup

### 1. Create Directory Structure

**Linux:**
```bash
mkdir -p netscope/cmd/netscope
mkdir -p netscope/internal/{capture,parser,cli}
mkdir -p netscope/bin
cd netscope
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Path netscope\cmd\netscope -Force
New-Item -ItemType Directory -Path netscope\internal\capture -Force
New-Item -ItemType Directory -Path netscope\internal\parser -Force
New-Item -ItemType Directory -Path netscope\internal\cli -Force
New-Item -ItemType Directory -Path netscope\bin -Force
cd netscope
```

### 2. Copy Files

Place these files in your project:
```
netscope/
├── go.mod
├── cmd/netscope/main.go
├── internal/
│   ├── capture/
│   │   ├── interface.go
│   │   └── engine.go
│   ├── parser/
│   │   └── dns.go
│   └── cli/
│       ├── menu.go
│       └── capture_menu.go
```

### 3. Install Dependencies

```bash
go mod download
go mod tidy
```

---

## Building

### Linux
```bash
go build -o bin/netscope ./cmd/netscope
```

### Windows
```powershell
go build -o bin\netscope.exe .\cmd\netscope
```

---

## Running NetScope

### Linux
```bash
sudo ./bin/netscope
```

### Windows
Open PowerShell as Administrator, then:
```powershell
.\bin\netscope.exe
```

---

## Using the Interactive Menu

### Main Menu

When you run NetScope, you'll see:

```
╔═══════════════════════════════════════════════════════════╗
║                       NetScope v0.1                       ║
║          Network Traffic Analysis & Monitoring            ║
╚═══════════════════════════════════════════════════════════╝

Main Menu:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. List Network Interfaces
  2. Start Packet Capture
  3. Capture History
  4. Settings
  5. About
  6. Exit

Select option [1-6]: _
```

### 1. List Network Interfaces

Shows all available network interfaces in a nice table:

```
#  Name   Status  IP Address       Type
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1  eth0   UP      192.168.1.100    Ethernet
2  wlan0  UP      192.168.1.50     Ethernet
3  lo     UP      127.0.0.1        Loopback

💡 Recommended for capture: wlan0
```

### 2. Start Packet Capture

Interactive wizard that guides you through:

#### Step 1: Select Interface
```
Select Network Interface:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. eth0 (192.168.1.100)
  2. wlan0 (192.168.1.50)
  3. Show all interfaces (including loopback/down)

Select [1-3]: 2
```

#### Step 2: Select Filter
```
Select Traffic Filter:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. All traffic (no filter)
  2. DNS only (udp port 53)
  3. HTTP/HTTPS (tcp port 80 or 443)
  4. HTTPS only (tcp port 443)
  5. HTTP only (tcp port 80)
  6. Custom BPF filter

Select [1-6]: 2
```

#### Step 3: Select Output Mode
```
Select Output Mode:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Simple (one line per packet)
  2. Verbose (detailed packet information)

Select [1-2]: 1
```

#### Step 4: Confirm
```
Capture Configuration:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Interface: wlan0
  Filter:    udp port 53
  Mode:      Simple

Start capture with these settings? (y/n): y
```

#### Capturing
```
🚀 Capturing on wlan0 (filter: udp port 53)
   Press Ctrl+C to stop

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[14:32:15.123] 🔍 DNS Query: google.com (A) [ID: 12345]
[14:32:15.156] ✅ DNS Response: google.com → 142.250.80.46 [ID: 12345]
[14:32:16.003] 🔍 DNS Query: github.com (A) [ID: 12346]
[14:32:16.045] ✅ DNS Response: github.com → 140.82.121.4 [ID: 12346]

[STATS] Total: 847 packets (1.24 MB) | Dropped: 0 | Rate: 42 pkt/s (18.5 KB/s)
```

Press `Ctrl+C` to stop:
```
🛑 Stopping capture...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Final Statistics:
  Packets Captured: 847
  Packets Dropped:  0
  Total Bytes:      1.24 MB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press Enter to continue...
```

---

## Example Workflows

### Monitor DNS Traffic
1. Select option `2` (Start Packet Capture)
2. Choose your active interface
3. Select `DNS only` filter
4. Choose Simple mode
5. Watch DNS queries in real-time!

### Capture All HTTPS Traffic
1. Select option `2` (Start Packet Capture)
2. Choose your active interface
3. Select `HTTPS only` filter
4. Choose output mode
5. See all encrypted connections!

### Custom Filter
1. Select option `2` (Start Packet Capture)
2. Choose your interface
3. Select `Custom BPF filter`
4. Enter your filter: `tcp and (port 80 or port 443)`
5. Start capturing!

---

## Output Modes

### Simple Mode
One line per packet, easy to read:
```
[14:32:15.123] 🔍 DNS Query: google.com (A) [ID: 12345]
[14:32:15.156] ✅ DNS Response: google.com → 142.250.80.46 [ID: 12345]
[14:32:15.201] 192.168.1.50:54321 → 142.250.80.46:443 (TCP, 66 bytes)
```

### Verbose Mode
Detailed information per packet:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Timestamp: 14:32:15.123456
Type:      DNS Query
Query:     google.com
Type:      A
From:      192.168.1.50
To:        1.1.1.1
TX ID:     12345
```

---

## Troubleshooting

### Permission Denied (Linux)
**Solution:** Run with `sudo`
```bash
sudo ./bin/netscope
```

### Access Denied (Windows)
**Solution:** Run PowerShell as Administrator
- Right-click PowerShell
- Select "Run as Administrator"
- Navigate to your project and run `.\bin\netscope.exe`

### No Interfaces Found
**Possible causes:**
- Not running as root/administrator
- No network adapters installed
- libpcap/Npcap not installed

**Solutions:**
1. Ensure you're running with elevated privileges
2. Install libpcap (Linux) or Npcap (Windows)
3. Check that network adapters are enabled

### No Packets Captured
**Possible causes:**
- Wrong interface selected
- No network activity
- Filter too restrictive

**Solutions:**
1. Use option 1 to verify interface is UP
2. Generate some traffic (open a website)
3. Try "All traffic" filter first
4. Use the recommended interface from option 1

---

## What's New

### Interactive CLI (Current)
✅ **No more typing long commands!**
- Menu-driven interface
- Step-by-step capture wizard
- Visual interface selection
- Pre-configured filters
- Confirmation dialogs

### Phase 1.2 Features
✅ **DNS Parsing**
- Real-time DNS query monitoring
- DNS response with resolved IPs
- Transaction ID tracking
- TTL information

---

## Coming Soon

**Phase 1.3:**
- TLS handshake parsing (SNI extraction)
- HTTP request/response parsing
- Certificate information

**Phase 2:**
- Flow tracking and session management
- Database storage
- Query interface for historical data

**Phase 3:**
- Behavioral analysis
- Anomaly detection
- Privacy leak detection

---

## Tips

💡 **Start with DNS filtering** when learning - it's the most interesting and easiest to understand

💡 **Use Simple mode** initially, switch to Verbose when you need detail

💡 **Generate traffic** by opening websites in your browser to see captures in action

💡 **Experiment with filters** - the Custom BPF filter option is very powerful
