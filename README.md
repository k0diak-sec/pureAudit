# PureAudit

A Python-based home network security auditing tool built by [PureSecure](https://puresecure.cloud).

PureAudit scans local networks to identify connected devices, detect open ports, flag security misconfigurations, and generate actionable audit reports for families and small businesses.

## Features

- **Network Discovery** - Identifies all active devices on the local network via ARP scanning
- **Manufacturer Identification** - Resolves device manufacturers from MAC addresses using the IEEE OUI database (39,000+ entries)
- **Randomized MAC Detection** - Identifies devices using privacy-randomized MAC addresses (common on Apple/Android devices)
- **Port Scanning** - Detects open ports and maps them to known services
- **Vulnerability Flagging** - Flags common security misconfigurations with severity ratings and remediation steps
- **Report Generation** - Outputs human-readable TXT and machine-readable JSON audit reports

## Installation

```bash
git clone https://github.com/k0diak-sec/pureAudit.git
cd pureAudit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Full Security Audit
Network discovery, port scanning across 32 common ports, vulnerability analysis, and report generation.
```bash
sudo venv/bin/python src/main.py --audit --target 192.168.1.0/24
```

### Fast Scan
Network discovery with a targeted 12-port scan optimized for home network assessments.
```bash
sudo venv/bin/python src/main.py --fast --target 192.168.1.0/24
```

### Quick Scan
Device discovery only. No port scanning, no report.
```bash
sudo venv/bin/python src/main.py --scan --target 192.168.1.0/24
```

### Auto-detect Subnet
For standard (non-segmented) home networks.
```bash
sudo venv/bin/python src/main.py --audit
```

### Notes
- `sudo` is required for ARP scanning. Without it, the tool falls back to reading the local ARP table.
- Disable VPN before scanning for accurate local hostname resolution.
- For VLAN-segmented networks (Firewalla, UniFi), always use `--target` with your specific subnet.

## Tech Stack

- Python 3.10+
- Scapy (network packet crafting and ARP discovery)
- Rich (terminal UI and formatted output)
- IEEE OUI Database (manufacturer identification)

## Project Structure

```
pureAudit/
├── LICENSE
├── README.md
├── .gitignore
├── requirements.txt
├── reports/
├── src/
│   ├── main.py
│   ├── networkScanner.py
│   ├── ouiDatabase.py
│   ├── portScanner.py
│   └── reportGenerator.py
├── tests/
│   └── testPortScanner.py
└── utils/
    └── buildOuiDatabase.py
```

## Project Roadmap

- [x] Project structure and scaffolding
- [x] Network discovery module
- [x] Port scanning module
- [x] Vulnerability flagging engine
- [x] Report generator (TXT and JSON)
- [x] CLI interface with Rich
- [x] Unit tests (portScanner)
- [x] PureSecure branding and colors
- [x] MIT License
- [x] README updated (--target as primary usage)
- [x] VLAN/segmented network documentation
- [x] srp() tuning: retry and inter for reliable device discovery
- [x] Add port 4444 (Metasploit/reverse shell) to RISKY_PORTS
- [x] Expand COMMON_PORTS for home network security
- [x] MAC address vendor lookup (OUI database, 39,000+ entries)
- [x] Randomized MAC detection (locally administered bit check)
- [x] Fast scan mode (--fast) with 12-port QUICK_PORTS profile
- [ ] Device-aware vulnerability context (Apple randomized MAC vs known manufacturer UPnP)
- [ ] Fast scan CLI: display hostname and manufacturer, save IP and MAC to file
- [ ] CLI flags: --verbose and --quiet modes
- [ ] Unit tests (networkScanner)
- [ ] Unit tests (reportGenerator)

### Future / V2
- [ ] Service detection via banner grabbing

## About

Built by a Navy veteran and cybersecurity professional passionate about protecting families and seniors from digital threats. PureAudit is the open-source backbone of [PureSecure's](https://puresecure.cloud) home network assessment service.

## License

MIT License
