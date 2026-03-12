# PureAudit

A Python-based home network security auditing tool built by [PureSecure](https://puresecure.cloud).

PureAudit scans local networks to identify security risks, open ports, and common misconfigurations, helping families and small businesses understand their network exposure.

## Features

- **Network Discovery** -- Identifies all active devices on the local network via ARP scanning
- **Manufacturer Identification** -- Resolves device manufacturers from MAC addresses using the IEEE OUI database (39,000+ entries)
- **Randomized MAC Detection** -- Flags devices using locally administered (randomized) MAC addresses
- **Device-Aware Vulnerability Context** -- Differentiates Apple/randomized MAC UPnP from actual security risks
- **Fast Scan Mode** -- 12-port targeted scan with client-facing slim table, optimized for quick demos
- **Full Audit Mode** -- Comprehensive port scan across 30+ common ports
- **Vulnerability Flagging** -- Flags risky open ports with severity ratings and plain-English recommendations
- **Report Generation** -- Outputs human-readable TXT and machine-readable JSON audit reports
- **Verbosity Controls** -- --quiet for clean client demos, --verbose for field debugging

## Tech Stack

- Python 3.10+
- Scapy (network packet crafting and ARP scanning)
- Rich (terminal UI and formatted output)
- IEEE OUI Database (offline manufacturer lookup)

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
Network discovery, port scanning (30+ ports), vulnerability analysis, and report generation.
```bash
sudo venv/bin/python src/main.py --audit --target 192.168.1.0/24
```

### Fast Scan
Network discovery, 12-port targeted scan, vulnerability analysis, and report generation. Client-facing slim table shows hostname and manufacturer only.
```bash
sudo venv/bin/python src/main.py --fast --target 192.168.1.0/24
```

### Quick Scan
Discovery only. No port scan, no report.
```bash
sudo venv/bin/python src/main.py --scan --target 192.168.1.0/24
```

### Single Device Scan
Target a specific IP for faster testing.
```bash
sudo venv/bin/python src/main.py --fast --target 192.168.1.51
```

### Verbosity Flags
Combine with any scan mode.
```bash
# Quiet: banner, table, and summary only
sudo venv/bin/python src/main.py --fast --quiet --target 192.168.1.0/24

# Verbose: show every scan attempt, open port, and flag detail
sudo venv/bin/python src/main.py --fast --verbose --target 192.168.1.0/24
```

### Auto-detect Subnet
For standard home networks (non-segmented). Not recommended for VLAN environments.
```bash
sudo venv/bin/python src/main.py --audit
```

### Notes
- `sudo` is required for ARP scanning. Without it, the tool falls back to reading the ARP table.
- Disable VPN before scanning for accurate local hostname resolution.
- Always run from the project root directory so reports save to the correct location.

## Running Tests

```bash
python -m unittest tests/testPortScanner.py tests/testNetworkScanner.py tests/testReportGenerator.py -v
```

## Project Structure

```
pureAudit/
├── LICENSE
├── README.md
├── .gitignore
├── requirements.txt
├── reports/
│   └── .gitkeep
├── src/
│   ├── main.py
│   ├── networkScanner.py
│   ├── portScanner.py
│   ├── reportGenerator.py
│   └── ouiDatabase.py
├── tests/
│   ├── testPortScanner.py
│   ├── testNetworkScanner.py
│   └── testReportGenerator.py
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
- [x] Unit tests (portScanner, networkScanner, reportGenerator)
- [x] PureSecure branding and colors
- [x] MIT License
- [x] VLAN/segmented network documentation
- [x] srp() tuning: retry and inter for reliable device discovery
- [x] Add port 4444 (Metasploit/reverse shell) to RISKY_PORTS
- [x] Expand COMMON_PORTS for home network security
- [x] MAC address vendor lookup (OUI database, 39,000+ entries)
- [x] Randomized MAC detection (locally administered bit check)
- [x] Fast scan mode (--fast) with 12-port QUICK_PORTS profile
- [x] Device-aware vulnerability context (Apple randomized MAC vs known manufacturer UPnP)
- [x] Fast scan client-facing slim table with full details saved to report
- [x] CLI flags: --verbose and --quiet modes
- [ ] Multi-target scanning (scan specific IPs in a single run)

### Future / V2
- [ ] Service detection via banner grabbing

## About

Built by a Navy veteran and cybersecurity professional passionate about protecting families and seniors from digital threats. PureAudit is the open-source backbone of [PureSecure's](https://puresecure.cloud) home network assessment service.

## License

MIT License
