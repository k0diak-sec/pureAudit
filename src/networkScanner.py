#!/usr/bin/env python3
"""
networkScanner.py — Network Discovery Module
Discovers active devices on the local network using ARP scanning.
"""

import socket
import subprocess
import platform

from rich.console import Console
from rich.table import Table

console = Console()


class NetworkScanner:
    """Scans local network to discover connected devices."""

    def __init__(self, target=None):
        """
        Initialize the network scanner.

        Args:
            target: Target subnet (e.g., '192.168.1.0/24').
                    If None, auto-detects the local subnet.
        """
        self.target = target if target else self._detectSubnet()

    def _detectSubnet(self):
        """Auto-detect the local network subnet."""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            localIp = s.getsockname()[0]
            s.close()

            # Derive subnet (assumes /24)
            octets = localIp.split(".")
            subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            console.print(f"[dim]Auto-detected subnet: {subnet}[/dim]")
            return subnet

        except Exception as e:
            console.print(f"[red]Could not detect subnet: {e}[/red]")
            return "192.168.1.0/24"

    def discoverDevices(self):
        """
        Discover active devices on the network using ARP scan.

        Returns:
            List of dicts with keys: ip, mac, hostname
        """
        console.print(f"[dim]Scanning {self.target}...[/dim]")
        devices = []

        try:
            from scapy.all import ARP, Ether, srp

            # Build ARP request packet
            arpRequest = ARP(pdst=self.target)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arpRequest

            # Send packet and capture responses
            answered, _ = srp(packet, timeout=3, verbose=False)

            for sent, received in answered:
                hostname = self._resolveHostname(received.psrc)
                devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": hostname
                })

        except ImportError:
            console.print("[yellow]Scapy not installed. Falling back to ARP table scan...[/yellow]")
            devices = self._fallbackArpScan()

        except PermissionError:
            console.print("[yellow]Root/admin privileges required for ARP scan. Falling back...[/yellow]")
            devices = self._fallbackArpScan()

        return devices

    def _fallbackArpScan(self):
        """Fallback: parse the system ARP table when Scapy isn't available."""
        devices = []
        try:
            osType = platform.system().lower()

            if osType == "darwin" or osType == "linux":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            elif osType == "windows":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            else:
                return devices

            for line in result.stdout.splitlines():
                if "(" in line and ")" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        hostname = parts[0]
                        ip = parts[1].strip("()")
                        mac = parts[3]

                        if mac != "(incomplete)" and mac != "ff:ff:ff:ff:ff:ff":
                            devices.append({
                                "ip": ip,
                                "mac": mac,
                                "hostname": hostname if hostname != "?" else "Unknown"
                            })

        except Exception as e:
            console.print(f"[red]Fallback scan failed: {e}[/red]")

        return devices

    def _resolveHostname(self, ip):
        """Attempt to resolve an IP address to a hostname."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return "Unknown"

    def displayResults(self, devices):
        """Display discovered devices in a formatted table."""
        table = Table(title="Discovered Devices", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Hostname", style="yellow")

        for idx, device in enumerate(devices, 1):
            table.add_row(
                str(idx),
                device["ip"],
                device["mac"],
                device["hostname"]
            )

        console.print(table)
