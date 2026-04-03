#!/usr/bin/env python3
"""
PureAudit | Home Network Security Auditing Tool
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
        description="PureAudit | Home Network Security Auditing Tool"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="PureAudit v1.1"
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
    parser.add_argument(
    "--quiet",
    action="store_true",
    help="Minimal output: banner, results table, and summary only"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Detailed output: show every scan attempt and timing info"
    )
    return parser.parse_args()

def runFastScan(target, outputDir, verbosity=1):
    """Run a fast network discovery, 12-port scan security audit."""
    if verbosity > 0:
        console.print("\n[bold yellow]🔍 Running Quick Scan...[/bold yellow]\n")
    startTime = datetime.now()

    # Phase 1: Network Discovery
    if verbosity > 0:
        console.print("[bold #27becf]Phase 1: Network Discovery[/bold #27becf]")
    scanner = NetworkScanner(target)
    devices = scanner.discoverDevices()

    if not devices:
        console.print("[red]No devices found. Audit aborted.[/red]")
        return

    if verbosity > 0:
        console.print(f"[green]✓ Found {len(devices)} device(s)[/green]\n")

    # Phase 2: Port Scanning
    if verbosity > 0:
        console.print("[bold #27becf]Phase 2: Port Scanning[/bold #27becf]")
    portScanner = PortScanner()
    scanResults = []

    for device in devices:
        ip = device["ip"]
        if verbosity >= 1:
            console.print(f"  Scanning {ip}...")
        ports = portScanner.scanHost(ip, QUICK_PORTS)

        # Verbose: show each open port as it's found
        if verbosity == 2:
            for p in ports:
                console.print(f"    [bold red]OPEN[/bold red] {p['port']}/{p['service']}")
            if not ports:
                console.print(f"    [dim]No open ports[/dim]")

        scanResults.append({
            "ip": ip,
            "mac": device.get("mac", "Unknown"),
            "hostname": device.get("hostname", "Unknown"),
            "manufacturer": device.get("manufacturer", "Unknown"),
            "ports": ports
        })

    if verbosity > 0:
        console.print(f"[green]✓ Port scan complete[/green]\n")

    # Phase 3: Vulnerability Flagging
    if verbosity > 0:
        console.print("[bold #27becf]Phase 3: Vulnerability Analysis[/bold #27becf]")
    for result in scanResults:
        result["flags"] = portScanner.flagVulnerabilities(result["ports"], result.get("manufacturer", "Unknown"))

        # Verbose: show each flag as it's found
        if verbosity == 2:
            for flag in result["flags"]:
                console.print(f"    [{flag['severity']}] {flag['port']}/{flag['service']}: {flag['reason']}")

    totalFlags = sum(len(r["flags"]) for r in scanResults)
    if verbosity > 0:
        console.print(f"[yellow]⚠ Found {totalFlags} potential issue(s)[/yellow]\n")

    # Phase 4: Report Generation
    if verbosity > 0:
        console.print("[bold #27becf]Phase 4: Generating Report[/bold #27becf]")
    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()

    report = ReportGenerator(outputDir)
    reportPath = report.generateReport(scanResults, duration)
    if verbosity > 0:
        console.print(f"[green]✓ Report saved to: {reportPath}[/green]\n")

    # Always show the client table and summary
    scanner.displayClientResults(devices)
    console.print(Panel(
        f"[bold]Audit Complete[/bold]\n"
        f"Devices scanned: {len(devices)}\n"
        f"Issues found: {totalFlags}\n"
        f"Duration: {duration:.1f}s\n"
        f"Report: {reportPath}",
        title="[bold #f25a29]PureAudit Summary[/bold #f25a29]",
        expand=False
    ))

def runQuickScan(target, verbosity=1):
    """Run a quick network discovery scan."""
    if verbosity > 0:
        console.print("\n[bold yellow]⚡ Running Quick Scan...[/bold yellow]\n")
    startTime = datetime.now()

    scanner = NetworkScanner(target)
    devices = scanner.discoverDevices()

    if not devices:
        console.print("[red]No devices found. Check your network connection or target subnet.[/red]")
        return []

    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()

    if verbosity > 0:
        console.print(f"[green]✓ Found {len(devices)} device(s) on the network[/green]\n")

    if verbosity == 2:
        for device in devices:
            console.print(f"    {device['ip']} | {device['mac']} | {device['hostname']} | {device.get('manufacturer', 'Unknown')}")
        console.print("")

    scanner.displayResults(devices)

    if verbosity > 0:
        console.print(f"\n[dim]Scan completed in {duration:.1f}s[/dim]")

    return devices


def runFullAudit(target, outputDir, verbosity=1):
    """Run a full network security audit."""
    if verbosity > 0:
        console.print("\n[bold yellow]🔍 Running Full Security Audit...[/bold yellow]\n")
    startTime = datetime.now()

    # Phase 1: Network Discovery
    if verbosity > 0:
        console.print("[bold #27becf]Phase 1: Network Discovery[/bold #27becf]")
    scanner = NetworkScanner(target)
    devices = scanner.discoverDevices()

    if not devices:
        console.print("[red]No devices found. Audit aborted.[/red]")
        return

    if verbosity > 0:
        console.print(f"[green]✓ Found {len(devices)} device(s)[/green]\n")

    if verbosity == 2:
        for device in devices:
            console.print(f"    {device['ip']} | {device['mac']} | {device['hostname']} | {device.get('manufacturer', 'Unknown')}")
        console.print("")

    # Phase 2: Port Scanning
    if verbosity > 0:
        console.print("[bold #27becf]Phase 2: Port Scanning[/bold #27becf]")
    portScanner = PortScanner()
    scanResults = []

    for device in devices:
        ip = device["ip"]
        if verbosity >= 1:
            console.print(f"  Scanning {ip}...")
        ports = portScanner.scanHost(ip)

        if verbosity == 2:
            for p in ports:
                console.print(f"    [bold red]OPEN[/bold red] {p['port']}/{p['service']}")
            if not ports:
                console.print(f"    [dim]No open ports[/dim]")

        scanResults.append({
            "ip": ip,
            "mac": device.get("mac", "Unknown"),
            "hostname": device.get("hostname", "Unknown"),
            "manufacturer": device.get("manufacturer", "Unknown"),
            "ports": ports
        })

    if verbosity > 0:
        console.print(f"[green]✓ Port scan complete[/green]\n")

    # Phase 3: Vulnerability Flagging
    if verbosity > 0:
        console.print("[bold #27becf]Phase 3: Vulnerability Analysis[/bold #27becf]")
    for result in scanResults:
        result["flags"] = portScanner.flagVulnerabilities(result["ports"], result.get("manufacturer", "Unknown"))

        if verbosity == 2:
            for flag in result["flags"]:
                console.print(f"    [{flag['severity']}] {flag['port']}/{flag['service']}: {flag['reason']}")

    totalFlags = sum(len(r["flags"]) for r in scanResults)
    if verbosity > 0:
        console.print(f"[yellow]⚠ Found {totalFlags} potential issue(s)[/yellow]\n")

    # Phase 4: Report Generation
    if verbosity > 0:
        console.print("[bold #27becf]Phase 4: Generating Report[/bold #27becf]")
    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()

    report = ReportGenerator(outputDir)
    reportPath = report.generateReport(scanResults, duration)
    if verbosity > 0:
        console.print(f"[green]✓ Report saved to: {reportPath}[/green]\n")

    # Summary always shows
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

    verbosity = 1
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2

    if args.fast:
        runFastScan(target, args.output, verbosity)
    elif args.scan:
        runQuickScan(target, verbosity)
    elif args.audit:
        runFullAudit(target, args.output, verbosity)

if __name__ == "__main__":
    main()
