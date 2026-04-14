# CLAUDE.md — Packet Analyzer & Network Topology Educational GUI

## Git Workflow (read this first)

This project lives in Git and is mirrored to GitHub. **Commit and push regularly as work progresses** — don't let meaningful changes sit uncommitted, and don't batch multiple unrelated changes into one commit. The goal is that every logical step is recoverable and the GitHub remote always reflects current work, so nothing is ever lost and any change can be reverted cleanly.

Rules:
- Commit after each logical unit of work (a new widget wired up, a bug fixed, a refactor landed) rather than at arbitrary intervals.
- Write clean, imperative-mood commit messages that describe *what* changed and *why* when the why isn't obvious from the diff. Examples: `Add sidebar navigation skeleton with five placeholder tabs`, `Fix late-binding closure in sidebar button handlers`, `Move hostname resolution into background QThread`.
- **Do not include AI attribution** (no `Co-Authored-By: Claude`, no "Generated with Claude Code" trailers) in commit messages or PR bodies.
- Push to `origin main` after each commit (or small group of related commits) so the remote stays current.
- Before starting non-trivial work, confirm the working tree is clean (`git status`) so changes can be isolated to their own commits.
- Never force-push `main` or rewrite published history without explicit instruction.

## Project Overview

A Python-based desktop network analyzer and topology visualizer built with PyQt6. The application captures live network traffic using Scapy, decodes packets across all OSI layers, maps discovered devices into an interactive topology graph, and presents everything in an educational GUI designed to make networking concepts tangible.

**Inspiration:** [NetLens by luqezr](https://github.com/luqezr/NetLens) — a Node.js/Python/MongoDB network scanner. This project shares the same spirit (device discovery, topology visualization, packet inspection) but is a self-contained Python desktop application with an educational focus rather than a web-based production monitoring tool.

**Primary goals:**
1. Hands-on learning tool for CompTIA Network+ concepts
2. Portfolio project demonstrating software + networking intersection
3. Real-time packet capture and protocol decoding
4. Interactive network topology visualization
5. Educational OSI layer breakdowns with tooltips explaining each field

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| GUI framework | PyQt6 | Desktop application, sidebar navigation |
| Packet capture | Scapy | Python library, requires Administrator/root |
| Network driver | Npcap | Windows packet capture driver (already installed) |
| Topology graph | PyQt6 + custom canvas OR NetworkX + matplotlib embedded | TBD — see design decisions |
| Data storage | In-memory (Python dicts/dataclasses) | No database — session-based |
| Export | .pcap (Scapy), CSV | Via Scan tab |

**Python version:** 3.x (latest stable)
**OS:** Windows 11 (primary development environment)
**Network interface:** Intel I226-V 2.5GbE (`"Ethernet"` in Scapy)

---

## Current State (What Has Been Built)

The data pipeline (Phase 1) is complete and working:

### Working capture capabilities:
- ARP request/reply parsing
- TCP with flag extraction (SYN, ACK, FIN, RST, PSH)
- UDP broadcasts
- SSDP/UPnP (239.255.255.250)
- mDNS (224.0.0.251)
- STP (Spanning Tree Protocol BPDUs to 01:80:c2:00:00:00)
- ICMPv6 NDP (Neighbor Solicitation/Advertisement)
- IGMP (multicast group management)
- DNS query/response parsing

### Working data extraction:
- Explicit port number extraction for TCP and UDP
- Hostname resolution with DNS cache (async background thread)
- Protocol/service name mapping from (protocol, port) tuples
- IP-to-hostname cache preventing repeated lookups

### Known devices on the home network:
```
192.168.86.1   → Mesh router/gateway (Google/Nest, MAC 9c:3e:53:2b:4a:32)
192.168.86.72  → HolyStar-PC (user's machine, Intel I226-V)
192.168.86.73  → Philips Hue Bridge (ecb5fa3fdc01, model BSB002)
192.168.86.55  → living-room (Apple TV/HomePod sleep proxy)
192.168.86.49  → Downstairs TV (AirPlay capable)
```

### What does NOT exist yet:
- PyQt6 GUI (not started)
- Any visual components
- Topology graph
- Device card views
- OSI layer tree widget
- Real-time packet feed widget
- ARP scanner
- .pcap/.CSV export

---

## Application Architecture

### Folder structure (target):
```
project/
├── CLAUDE.md                   # This file
├── main.py                     # Entry point — launches PyQt6 app
├── capture/
│   ├── __init__.py
│   ├── sniffer.py              # Scapy capture thread
│   ├── decoder.py              # Packet → structured dict decoder
│   └── arp_scanner.py          # Active ARP scan for device discovery
├── models/
│   ├── __init__.py
│   ├── packet.py               # Packet dataclass
│   └── device.py               # Device dataclass
├── ui/
│   ├── __init__.py
│   ├── main_window.py          # QMainWindow with sidebar navigation
│   ├── tabs/
│   │   ├── dashboard.py        # Dashboard tab
│   │   ├── devices.py          # Devices tab
│   │   ├── topology.py         # Topology tab
│   │   ├── packets.py          # Packets tab
│   │   └── scan.py             # Scan tab
│   └── widgets/
│       ├── packet_table.py     # Scrollable live packet feed
│       ├── osi_tree.py         # Expandable OSI layer tree
│       ├── device_card.py      # Individual device card widget
│       └── topology_canvas.py  # Interactive network graph canvas
├── utils/
│   ├── __init__.py
│   ├── dns_resolver.py         # Background DNS resolution thread
│   ├── oui_lookup.py           # MAC vendor lookup
│   └── service_map.py          # Port → service name mapping
└── requirements.txt
```

### Threading model:
```
Main thread (PyQt6 event loop)
├── UI rendering and interaction
└── Receives signals from worker threads via Qt signals/slots

Capture thread (QThread)
├── Scapy sniff() runs here — NEVER on main thread
├── Emits packet_captured signal with decoded packet dict
└── Stopped via threading.Event flag

DNS resolver thread (QThread)
├── Consumes IP address queue
├── Resolves hostnames with timeout
└── Emits hostname_resolved signal back to main thread

ARP scanner thread (QThread — on demand)
├── Sends ARP requests to subnet
├── Collects replies
└── Emits devices_discovered signal
```

**Critical rule:** Scapy's `sniff()` is blocking. It MUST run in a QThread. Never call Scapy functions on the main thread or the GUI will freeze.

---

## UI Design

### Navigation:
Sidebar on the left with five tabs. Active tab highlighted. No top menu bar.

```
┌─────────────────────────────────────────────────────┐
│ [≡]  NetAnalyzer                                    │
├──────────┬──────────────────────────────────────────┤
│          │                                          │
│ Dashboard│         Main content area                │
│ Devices  │         (changes per tab)                │
│ Topology │                                          │
│ Packets  │                                          │
│ Scan     │                                          │
│          │                                          │
└──────────┴──────────────────────────────────────────┘
```

### Tab specifications:

#### Dashboard
- Network summary: total devices, packets captured, bytes seen, active connections
- Mini topology (small, non-interactive preview of the Topology tab)
- Device list preview (top 5-8 devices, most recently active)
- Recent packets live feed (last 15-20 packets, auto-scrolls, stops on manual scroll)
- Refresh rate: ~1 second updates

#### Devices
- Card grid layout — one card per discovered device
- Each card shows: IP, MAC, hostname, vendor (OUI lookup), last seen, open ports, device type icon
- "View Packets →" button on each card — switches to Packets tab with filter pre-applied for that device's IP
- Cards sorted by: most recently active first
- Manual label override field (e.g., rename "192.168.86.73" to "Hue Bridge")

#### Topology
- Full interactive network graph
- Nodes: each discovered device (icon reflects device type)
- Edges: connections observed between devices (weighted by traffic volume)
- WAN boundary: dashed line separating local network from internet traffic
- Gateway node (router) at center
- Click device → highlight all packets involving that device
- Click edge → show traffic summary between those two devices
- Zoom/pan support
- Layout algorithm: force-directed or hierarchical with gateway at root

#### Packets
- Top section: scrollable packet list table
  - Columns: #, Time, Source IP, Dest IP, Protocol, Length, Info (service/description)
  - Color coding by protocol (ARP=yellow, TCP=blue, UDP=green, ICMP=red, DNS=purple)
  - Click row → populate bottom section
- Bottom section: OSI layer detail tree (expandable)
  - Layer 1: Physical (interface, captured length)
  - Layer 2: Ethernet (src MAC, dst MAC, EtherType)
  - Layer 3: IP (src IP, dst IP, TTL, flags, checksum)
  - Layer 4: TCP/UDP (src port, dst port, flags, sequence numbers)
  - Layer 7: Application (protocol name, payload preview)
  - Each field has an ℹ️ tooltip explaining what it means (educational feature)
- Raw hex toggle: shows raw bytes of the packet
- Filter bar: filter by IP, protocol, port

#### Scan
- Interface selector dropdown (auto-detects available interfaces)
- Capture toggle button (Start/Stop)
- ARP scan button (active discovery of subnet)
- Capture filter input (BPF filter string, e.g., "tcp port 443")
- Export buttons: "Export .pcap" and "Export CSV"
- Capture statistics: packets/sec, bytes/sec, drop count

---

## Key Design Decisions

### Why PyQt6 over Tkinter or web-based:
- Native desktop performance for real-time packet feed at high capture rates
- QThread integration for safe multi-threaded UI updates
- Rich widget library (QTreeWidget for OSI layers, QTableWidget for packets)
- Better than Tkinter for complex layouts and styling

### Why in-memory storage over SQLite/MongoDB:
- Session-based tool — data is relevant only while capturing
- Avoids database dependency complexity
- NetLens uses MongoDB for persistent multi-session tracking — not needed here
- If persistence is added later, SQLite is the natural choice (no server required)

### File-based .pcap analysis:
- Development mode: load a pre-captured .pcap file instead of live capture
- Allows GUI development without needing to run as Administrator
- Use `rdpcap()` from Scapy to read .pcap files

### Hostname resolution:
- Two-stage: show raw IP immediately, resolve in background thread
- Cache: dict mapping IP → hostname, persists for session
- Timeout: 2 seconds per resolution attempt
- Never block the packet feed waiting for DNS

### Topology graph implementation options (TBD):
1. **NetworkX + matplotlib embedded in PyQt6** — easier to implement, less interactive
2. **Custom QPainter canvas** — full control, more work, best performance
3. **PyQtGraph** — good for real-time updating graphs
4. **D3.js via PyQt6 QWebEngineView** — most visually impressive, adds complexity

Recommendation: Start with NetworkX + matplotlib for Phase 5, upgrade to PyQtGraph or custom QPainter if performance is insufficient.

---

## Development Phases

### Phase 1 — Data pipeline ✅ COMPLETE
Scapy capture, packet decoding, protocol identification, hostname resolution

### Phase 2 — PyQt6 basic window (NEXT)
- QMainWindow skeleton
- Sidebar navigation with 5 tabs
- Tab switching works
- No content yet — just labeled placeholder widgets

### Phase 3 — Packets tab
- QTableWidget for packet list
- QTreeWidget for OSI layer breakdown
- Wire up to capture thread via Qt signals
- Color coding by protocol
- Filter bar

### Phase 4 — Devices tab
- Device dataclass and device registry dict
- OUI/MAC vendor lookup
- Device card widget
- Cross-tab link to Packets tab with IP filter

### Phase 5 — Topology tab
- NetworkX graph
- Matplotlib FigureCanvasQTAgg embedded in PyQt6
- Force-directed layout
- Node click → highlight packets

### Phase 6 — Dashboard tab
- Stats counters
- Mini topology (non-interactive)
- Recent packets feed (subset of Packets tab)

### Phase 7 — Scan tab
- Interface selector
- Start/Stop capture button
- ARP scanner
- BPF filter input
- Export .pcap and CSV

### Phase 8 — Polish
- Dark theme (QSS stylesheet)
- Device type icons (router, PC, phone, IoT, TV)
- Educational tooltips on all OSI fields
- Performance optimization for high packet rates
- README and GitHub repository setup

---

## Code Conventions

### Signals and slots pattern for threading:
```python
# Worker thread emits signal
class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)  # emits decoded packet dict
    
    def run(self):
        sniff(iface="Ethernet", prn=self._handle_packet, store=False)
    
    def _handle_packet(self, pkt):
        decoded = decode_packet(pkt)
        self.packet_captured.emit(decoded)  # safe cross-thread signal

# Main window connects slot
self.capture_thread.packet_captured.connect(self.on_packet_received)

def on_packet_received(self, packet_dict):
    # This runs on main thread — safe to update UI
    self.packet_table.add_row(packet_dict)
```

### Packet dict structure (standard format throughout app):
```python
{
    "timestamp": float,          # time.time()
    "number": int,               # sequential capture number
    "src_mac": str,              # "aa:bb:cc:dd:ee:ff" or ""
    "dst_mac": str,
    "src_ip": str,               # "192.168.86.72" or ""
    "dst_ip": str,
    "src_port": int | None,
    "dst_port": int | None,
    "protocol": str,             # "TCP", "UDP", "ARP", "ICMP", "ICMPv6", etc.
    "service": str,              # "HTTPS", "DNS", "mDNS", "SSDP", or ""
    "length": int,               # bytes
    "flags": str,                # TCP flags "SA", "F", etc. or ""
    "info": str,                 # human-readable summary line
    "layers": dict,              # full layer breakdown for OSI tree
    "raw_hex": str,              # hex dump string
}
```

### Device dataclass:
```python
@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""             # from OUI lookup
    label: str = ""              # user-assigned label
    first_seen: float = 0.0
    last_seen: float = 0.0
    open_ports: list = field(default_factory=list)
    device_type: str = "unknown" # "router", "pc", "phone", "iot", "tv", "unknown"
    packet_count: int = 0
    byte_count: int = 0
```

### Naming conventions:
- Files: `snake_case.py`
- Classes: `PascalCase`
- Qt widget subclasses: suffix with widget type — `PacketTableWidget`, `OsiTreeWidget`
- Thread classes: suffix with `Thread` — `CaptureThread`, `DnsResolverThread`
- Signals: verb_noun format — `packet_captured`, `hostname_resolved`, `device_discovered`

---

## Running the Application

### Requirements:
```
pip install PyQt6 scapy pyqtgraph networkx matplotlib
```

### Must run as Administrator on Windows:
Scapy requires raw socket access (Npcap). Without Administrator privileges, capture will fail silently or raise PermissionError.

```bash
# Run from elevated terminal
python main.py
```

### Development mode (no admin required):
```bash
# Load from .pcap file instead of live capture
python main.py --file capture.pcap
```

### Interface name:
The Intel I226-V appears as `"Ethernet"` in Scapy on this machine. Interface selection will be exposed in the Scan tab — do not hardcode `"Ethernet"` in anything except test scripts.

---

## Scapy Gotchas on Windows

- `sniff(store=False)` — always use `store=False` to prevent memory buildup during long captures
- `sniff(iface="Ethernet")` — interface name is case-sensitive on Windows
- Npcap must be installed with "WinPcap API compatibility" option checked
- Running without Administrator shows no error but captures 0 packets
- `conf.use_pcap = True` may be needed on some Windows configurations
- IPv6 packets may require `ETH_P_ALL` or `iface` specification

---

## Educational Features (Key Differentiator)

This tool is explicitly designed for learning — not just monitoring. Every technical element should have an educational explanation accessible to a Network+ student.

### OSI layer tooltips (examples):
- **TTL field**: "Time To Live — decremented by 1 at each router hop. When it reaches 0 the packet is discarded. Prevents packets from looping forever."
- **TCP SYN flag**: "Synchronize — sent in the first packet of a TCP three-way handshake to initiate a connection."
- **EtherType 0x0800**: "Indicates the payload is an IPv4 packet. 0x86DD = IPv6, 0x0806 = ARP."
- **Destination MAC ff:ff:ff:ff:ff:ff**: "Broadcast address — this frame is delivered to all devices on the local network segment."

### Protocol color coding rationale (shown in legend):
- ARP = Yellow (discovery/layer 2)
- TCP = Blue (reliable connection)
- UDP = Green (fast/connectionless)
- ICMP = Red (control messages)
- DNS = Purple (name resolution)
- Other = Gray

---

## Differences from NetLens (Inspiration)

| Feature | NetLens | This Project |
|---|---|---|
| Interface | Web (React + Node.js API) | Desktop (PyQt6) |
| Backend | Python scanner + Node.js API | Pure Python |
| Database | MongoDB (persistent) | In-memory (session) |
| Scanning | nmap + scapy | Scapy only |
| CVE detection | Yes (nmap NSE scripts) | No |
| Topology | React Flow / D3.js | NetworkX + matplotlib or custom |
| Auth | Session login | None (local app) |
| Target user | Network admin (production) | Student / learner (educational) |
| OS support | Linux only | Windows primary |
| Installation | System service | Run directly |

The core inspiration taken from NetLens: the five-section dashboard concept (overview, devices, topology, packets/alerts, scan controls) and the idea of combining active scanning with passive capture into one unified view.

---

## Project Name

Working name: **NetScope** or maybe something greek like **Aperio** (NetLens is taken by the inspiration project)
GitHub: `github.com/HolyStarGazer` — repo name TBD