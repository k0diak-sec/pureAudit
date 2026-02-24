#!/usr/bin/env python3
"""
portScanner.py — Port Scanning & Vulnerability Flagging Module
Scans hosts for open ports and flags common security issues.
"""

import socket

from rich.console import Console

console = Console()


# Common ports to scan and their associated services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "Web-Admin",
    49152: "UPnP"
}

# Ports that are risky when exposed on a home network
RISKY_PORTS = {
    21: {
        "severity": "HIGH",
        "reason": "FTP transfers data in plaintext including credentials",
        "recommendation": "Disable FTP. Use SFTP (port 22) instead."
    },
    23: {
        "severity": "CRITICAL",
        "reason": "Telnet is unencrypted and easily intercepted",
        "recommendation": "Disable Telnet immediately. Use SSH instead."
    },
    25: {
        "severity": "MEDIUM",
        "reason": "Open SMTP can be abused for spam relay",
        "recommendation": "Ensure SMTP requires authentication."
    },
    135: {
        "severity": "HIGH",
        "reason": "MS-RPC is a common attack vector for Windows exploits",
        "recommendation": "Block from external access via firewall."
    },
    139: {
        "severity": "HIGH",
        "reason": "NetBIOS exposes file sharing and system information",
        "recommendation": "Disable NetBIOS over TCP/IP if not needed."
    },
    445: {
        "severity": "HIGH",
        "reason": "SMB has been exploited by WannaCry, EternalBlue, etc.",
        "recommendation": "Block SMB from external access. Update to SMBv3."
    },
    1433: {
        "severity": "HIGH",
        "reason": "Exposed database server — risk of data breach",
        "recommendation": "Never expose databases to the network. Use firewall rules."
    },
    1883: {
        "severity": "MEDIUM",
        "reason": "MQTT (IoT protocol) often lacks authentication",
        "recommendation": "Enable authentication and use TLS (port 8883)."
    },
    3306: {
        "severity": "HIGH",
        "reason": "Exposed MySQL database server",
        "recommendation": "Restrict to localhost or use SSH tunneling."
    },
    3389: {
        "severity": "CRITICAL",
        "reason": "RDP is heavily targeted by brute-force and ransomware attacks",
        "recommendation": "Disable RDP or restrict to VPN-only access."
    },
    5432: {
        "severity": "HIGH",
        "reason": "Exposed PostgreSQL database server",
        "recommendation": "Restrict to localhost. Use SSH tunneling for remote access."
    },
    5900: {
        "severity": "CRITICAL",
        "reason": "VNC often lacks encryption and strong authentication",
        "recommendation": "Disable VNC or tunnel through SSH/VPN."
    },
    8080: {
        "severity": "MEDIUM",
        "reason": "HTTP proxy or admin panel may be exposed",
        "recommendation": "Verify what service is running. Restrict access if admin panel."
    },
    9090: {
        "severity": "MEDIUM",
        "reason": "Web admin panels are common brute-force targets",
        "recommendation": "Change default port. Enable strong authentication."
    },
    49152: {
        "severity": "MEDIUM",
        "reason": "UPnP can allow automatic port forwarding by malware",
        "recommendation": "Disable UPnP on your router if not needed."
    }
}


class PortScanner:
    """Scans hosts for open ports and identifies vulnerabilities."""

    def __init__(self, timeout=1.0):
        """
        Initialize the port scanner.

        Args:
            timeout: Socket connection timeout in seconds.
        """
        self.timeout = timeout

    def scanHost(self, ip, ports=None):
        """
        Scan a host for open ports.

        Args:
            ip: Target IP address.
            ports: Dict of port:service pairs to scan.
                   Defaults to COMMON_PORTS.

        Returns:
            List of dicts with keys: port, service, state
        """
        if ports is None:
            ports = COMMON_PORTS

        openPorts = []

        for port, service in ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    openPorts.append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })

            except socket.error:
                continue

        return openPorts

    def flagVulnerabilities(self, openPorts):
        """
        Analyze open ports and flag security risks.

        Args:
            openPorts: List of open port dicts from scanHost().

        Returns:
            List of vulnerability flag dicts.
        """
        flags = []

        for portInfo in openPorts:
            portNum = portInfo["port"]

            if portNum in RISKY_PORTS:
                risk = RISKY_PORTS[portNum]
                flags.append({
                    "port": portNum,
                    "service": portInfo["service"],
                    "severity": risk["severity"],
                    "reason": risk["reason"],
                    "recommendation": risk["recommendation"]
                })

        # Check for HTTP without HTTPS
        httpOpen = any(p["port"] == 80 for p in openPorts)
        httpsOpen = any(p["port"] == 443 for p in openPorts)

        if httpOpen and not httpsOpen:
            flags.append({
                "port": 80,
                "service": "HTTP",
                "severity": "MEDIUM",
                "reason": "HTTP service running without HTTPS counterpart",
                "recommendation": "Enable HTTPS with a valid SSL/TLS certificate."
            })

        return flags

    def getPortSummary(self, openPorts):
        """Return a quick summary string of open ports."""
        if not openPorts:
            return "No open ports detected"

        portList = [f"{p['port']}/{p['service']}" for p in openPorts]
        return f"{len(openPorts)} open: {', '.join(portList)}"
