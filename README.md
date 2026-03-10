# PureAudit 🔒

A Python-based home network security auditing tool built by [PureSecure](https://puresecure.cloud).

PureAudit scans local networks to identify security risks, open ports, and common misconfigurations — helping families and small businesses understand their network exposure.

## Features

- **Network Discovery** — Identifies all active devices on the local network
- **Port Scanning** — Detects open ports and maps them to known services
- **Vulnerability Flagging** — Flags common security misconfigurations (default credentials, open admin panels, unencrypted services)
- **Report Generation** — Outputs a clean, readable security audit report

## Tech Stack

- Python 3.10+
- Scapy (network packet crafting & sniffing)
- python-nmap (port scanning wrapper)
- Rich (terminal UI & formatted output)

## Installation

```bash
git clone https://github.com/k0diak-sec/pureAudit.git
cd pureAudit
pip install -r requirements.txt
```

### Usage

### Full Security Audit
Network discovery, port scanning, vulnerability analysis, and report generation.
```bash
python src/main.py --audit --target 192.168.1.0/24
```

### Quick Scan
Discovery only — no port scan, no report.
```bash
python src/main.py --scan --target 192.168.1.0/24
```

### Auto-detect Subnet
For standard home networks (non-segmented).
```bash
python src/main.py --audit
```

## Project Roadmap

- [x] Project structure & scaffolding
- [x] Network discovery module
- [x] Port scanning module
- [x] Vulnerability flagging engine
- [x] Report generator (TXT & JSON)
- [x] CLI interface with Rich
- [x] Unit tests (portScanner)
- [x] PureSecure branding & colors
- [x] MIT License
- [x] README updated (--target as primary usage)
- [x] VLAN/segmented network documentation
- [x] Add port 4444 (Metasploit/reverse shell) to RISKY_PORTS
- [x] Expand COMMON_PORTS for home network security
- [x] srp() tuning: retry and inter for reliable device discovery
- [ ] MAC address vendor lookup (OUI database)
- [ ] Device-aware vulnerability context (e.g., Apple vs router UPnP)
- [ ] Service detection via banner grabbing
- [ ] CLI flags: --verbose and --quiet modes
- [ ] Color-coded severity in TXT reports
- [ ] Unit tests (networkScanner)
- [ ] Unit tests (reportGenerator)

## About

Built by a U.S. Navy veteran and cybersecurity professional passionate about protecting families and seniors from digital threats. PureAudit is the open-source backbone of [PureSecure's](https://puresecure.cloud/driveway-safety-scan.php) Driveway Safety Scan service.

## License

MIT License
