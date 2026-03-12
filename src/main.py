#!/usr/bin/env python3
"""
PureAudit — Home Network Security Auditing Tool
Built by PureSecure | https://puresecure.cloud

Usage:
    python main.py --scan                    Quick network discovery
    python main.py --audit --output reports/ Full audit with report
    python main.py --target 192.168.1.0/24   Scan specific subnet
"""

import argparse
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from networkScanner import NetworkScanner
from portScanner import PortScanner
from portScanner import PortScanner, QUICK_PORTS
from reportGenerator import ReportGenerator

console = Console()


def displayBanner():
    """Display the PureAudit startup banner."""
    banner = Text()
    banner.append("╔══════════════════════════════════════╗\n", style="bold #27becf")
    banner.append("║         ", style="bold #27becf")
    banner.append("PureAudit v1.1", style="bold #f25a29")
    banner.append("              ║\n", style="bold #27becf")
    banner.append("║   ", style="bold #27becf")
    banner.append("Home Network Security Scanner", style="bold white")
    banner.append("    ║\n", style="bold #27becf")
    banner.append("║         ", style="bold #27becf")
    banner.append("by PureSecure", style="bold #f25a29")
    banner.append("               ║\n", style="bold #27becf")
    banner.append("╚══════════════════════════════════════╝", style="bold #27becf")
    console.print(Panel(banner, expand=False))


def parseArgs():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PureAudit — Home Network Security Auditing Tool"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="12 Port scan: discover devices, scan 12 common ports, and flag vulnerabilities on the local network fast"
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Quick scan: discover devices on the local network only (no port scanning or vulnerability flagging)"
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Full audit: scan devices, ports, and flag vulnerabilities"
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Target subnet to scan (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="reports/",
        help="Output directory for audit reports"
    )
    return parser.parse_args()

def runFastScan(target, outputDir):
    """Run a fast network discovery, 12-port scan security audit."""
    console.print("\n[bold yellow]🔍 Running Fast Scan...[/bold yellow]\n")
    startTime = datetime.now()

    # Phase 1: Network Discovery
    console.print("[bold #27becf]Phase 1: Network Discovery[/bold #27becf]")
    scanner = NetworkScanner(target)
    devices = scanner.discoverDevices()

    if not devices:
        console.print("[red]No devices found. Audit aborted.[/red]")
        return

    console.print(f"[green]✓ Found {len(devices)} device(s)[/green]\n")

    # Phase 2: Port Scanning
    console.print("[bold #27becf]Phase 2: Port Scanning[/bold #27becf]")
    portScanner = PortScanner()
    scanResults = []

    for device in devices:
        ip = device["ip"]
        console.print(f"  Scanning {ip}...")
        ports = portScanner.scanHost(ip, QUICK_PORTS)
        scanResults.append({
            "ip": ip,
            "mac": device.get("mac", "Unknown"),
            "hostname": device.get("hostname", "Unknown"),
            "manufacturer": device.get("manufacturer", "Unknown"),
            "ports": ports
        })

    console.print(f"[green]✓ Port scan complete[/green]\n")

    # Phase 3: Vulnerability Flagging
    console.print("[bold #27becf]Phase 3: Vulnerability Analysis[/bold #27becf]")
    for result in scanResults:
        result["flags"] = portScanner.flagVulnerabilities(result["ports"], result.get("manufacturer", "Unknown")) 
        totalFlags = sum(len(r["flags"]) for r in scanResults)
    console.print(f"[yellow]⚠ Found {totalFlags} potential issue(s)[/yellow]\n")

    # Phase 4: Report Generation
    console.print("[bold #27becf]Phase 4: Generating Report[/bold #27becf]")
    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()

    report = ReportGenerator(outputDir)
    reportPath = report.generateReport(scanResults, duration)
    console.print(f"[green]✓ Report saved to: {reportPath}[/green]\n")

    # Summary
    scanner.displayClientResults(devices)
    console.print(Panel(
        f"Devices scanned: {len(devices)}\n"
        f"Issues found: {totalFlags}\n"
        f"Duration: {duration:.1f}s\n"
        f"Report: {reportPath}",
        title="[bold #f25a29]PureAudit Summary[/bold #f25a29]",
        expand=False
    ))

def runQuickScan(target):
    """Run a quick network discovery scan."""
    console.print("\n[bold yellow]⚡ Running Quick Scan...[/bold yellow]\n")
    startTime = datetime.now()

    scanner = NetworkScanner(target)
    devices = scanner.discoverDevices()

    if not devices:
        console.print("[red]No devices found. Check your network connection or target subnet.[/red]")
        return []
    
    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()
    console.print(f"[green]✓ Found {len(devices)} device(s) on the network[/green]\n")
    scanner.displayResults(devices)

    return devices


def runFullAudit(target, outputDir):
    """Run a full network security audit."""
    console.print("\n[bold yellow]🔍 Running Full Security Audit...[/bold yellow]\n")
    startTime = datetime.now()

    # Phase 1: Network Discovery
    console.print("[bold #27becf]Phase 1: Network Discovery[/bold #27becf]")
    scanner = NetworkScanner(target)
    devices = scanner.discoverDevices()

    if not devices:
        console.print("[red]No devices found. Audit aborted.[/red]")
        return

    console.print(f"[green]✓ Found {len(devices)} device(s)[/green]\n")

    # Phase 2: Port Scanning
    console.print("[bold #27becf]Phase 2: Port Scanning[/bold #27becf]")
    portScanner = PortScanner()
    scanResults = []

    for device in devices:
        ip = device["ip"]
        console.print(f"  Scanning {ip}...")
        ports = portScanner.scanHost(ip)
        scanResults.append({
            "ip": ip,
            "mac": device.get("mac", "Unknown"),
            "hostname": device.get("hostname", "Unknown"),
            "manufacturer": device.get("manufacturer", "Unknown"),
            "ports": ports
        })

    console.print(f"[green]✓ Port scan complete[/green]\n")

    # Phase 3: Vulnerability Flagging
    console.print("[bold #27becf]Phase 3: Vulnerability Analysis[/bold #27becf]")
    for result in scanResults:
        result["flags"] = portScanner.flagVulnerabilities(result["ports"], result.get("manufacturer", "Unknown"))
        totalFlags = sum(len(r["flags"]) for r in scanResults)
    console.print(f"[yellow]⚠ Found {totalFlags} potential issue(s)[/yellow]\n")

    # Phase 4: Report Generation
    console.print("[bold #27becf]Phase 4: Generating Report[/bold #27becf]")
    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()

    report = ReportGenerator(outputDir)
    reportPath = report.generateReport(scanResults, duration)
    console.print(f"[green]✓ Report saved to: {reportPath}[/green]\n")

    # Summary
    console.print(Panel(
        f"[bold]Audit Complete[/bold]\n"
        f"Devices scanned: {len(devices)}\n"
        f"Issues found: {totalFlags}\n"
        f"Duration: {duration:.1f}s\n"
        f"Report: {reportPath}",
        title="[bold #f25a29]PureAudit Summary[/bold #f25a29]",
        expand=False
    ))


def main():
    """Main entry point for PureAudit."""
    displayBanner()
    args = parseArgs()

    if not args.scan and not args.audit and not args.fast:
        console.print("[yellow]No action specified. Use --scan, --fast, or --audit[/yellow]")
        console.print("Run 'python main.py --help' for usage info.")
        sys.exit(1)

    target = args.target if args.target else None

    if args.fast:
        runFastScan(target, args.output)
    elif args.scan:
        runQuickScan(target)
    elif args.audit:
        runFullAudit(target, args.output)


if __name__ == "__main__":
    main()
