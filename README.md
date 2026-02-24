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

## Usage

```bash
# Quick scan of local network
python src/main.py --scan

# Full audit with report
python src/main.py --audit --output reports/

# Scan specific subnet
python src/main.py --target 192.168.1.0/24
```

## Project Roadmap

- [x] Project structure & scaffolding
- [ ] Network discovery module
- [ ] Port scanning module
- [ ] Service identification
- [ ] Vulnerability flagging engine
- [ ] Report generator (TXT & JSON)
- [ ] CLI interface with Rich
- [ ] Unit tests

## About

Built by a Navy veteran and cybersecurity professional passionate about protecting families and seniors from digital threats. PureAudit is the open-source backbone of [PureSecure's](https://puresecure.cloud) home network assessment service.

## License

MIT License
