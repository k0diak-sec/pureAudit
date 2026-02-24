#!/usr/bin/env python3
"""
testPortScanner.py — Unit tests for the Port Scanner module.
"""

import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from portScanner import PortScanner, RISKY_PORTS, COMMON_PORTS


class TestPortScanner(unittest.TestCase):
    """Test cases for the PortScanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = PortScanner(timeout=0.5)

    def testInitialization(self):
        """Test that scanner initializes with correct timeout."""
        self.assertEqual(self.scanner.timeout, 0.5)

    def testDefaultTimeout(self):
        """Test that default timeout is 1.0 seconds."""
        defaultScanner = PortScanner()
        self.assertEqual(defaultScanner.timeout, 1.0)

    def testFlagVulnerabilitiesWithRiskyPorts(self):
        """Test that risky ports are properly flagged."""
        openPorts = [
            {"port": 23, "service": "Telnet", "state": "open"},
            {"port": 3389, "service": "RDP", "state": "open"},
            {"port": 443, "service": "HTTPS", "state": "open"}
        ]

        flags = self.scanner.flagVulnerabilities(openPorts)

        # Telnet and RDP should be flagged, HTTPS should not
        flaggedPorts = [f["port"] for f in flags]
        self.assertIn(23, flaggedPorts)
        self.assertIn(3389, flaggedPorts)
        self.assertNotIn(443, flaggedPorts)

    def testFlagVulnerabilitiesSeverity(self):
        """Test that severity levels are correctly assigned."""
        openPorts = [
            {"port": 23, "service": "Telnet", "state": "open"}
        ]

        flags = self.scanner.flagVulnerabilities(openPorts)
        self.assertEqual(flags[0]["severity"], "CRITICAL")

    def testFlagHttpWithoutHttps(self):
        """Test that HTTP without HTTPS is flagged."""
        openPorts = [
            {"port": 80, "service": "HTTP", "state": "open"}
        ]

        flags = self.scanner.flagVulnerabilities(openPorts)
        httpFlag = [f for f in flags if f["reason"].startswith("HTTP service")]
        self.assertEqual(len(httpFlag), 1)
        self.assertEqual(httpFlag[0]["severity"], "MEDIUM")

    def testNoFlagHttpWithHttps(self):
        """Test that HTTP with HTTPS present is NOT flagged for missing HTTPS."""
        openPorts = [
            {"port": 80, "service": "HTTP", "state": "open"},
            {"port": 443, "service": "HTTPS", "state": "open"}
        ]

        flags = self.scanner.flagVulnerabilities(openPorts)
        httpFlag = [f for f in flags if "HTTP service" in f.get("reason", "")]
        self.assertEqual(len(httpFlag), 0)

    def testEmptyPortList(self):
        """Test vulnerability flagging with no open ports."""
        flags = self.scanner.flagVulnerabilities([])
        self.assertEqual(len(flags), 0)

    def testGetPortSummaryWithPorts(self):
        """Test port summary string generation."""
        openPorts = [
            {"port": 22, "service": "SSH", "state": "open"},
            {"port": 80, "service": "HTTP", "state": "open"}
        ]
        summary = self.scanner.getPortSummary(openPorts)
        self.assertIn("2 open", summary)
        self.assertIn("22/SSH", summary)

    def testGetPortSummaryEmpty(self):
        """Test port summary with no open ports."""
        summary = self.scanner.getPortSummary([])
        self.assertEqual(summary, "No open ports detected")

    def testAllRiskyPortsHaveRequiredFields(self):
        """Test that all risky port entries have required fields."""
        for port, info in RISKY_PORTS.items():
            self.assertIn("severity", info, f"Port {port} missing severity")
            self.assertIn("reason", info, f"Port {port} missing reason")
            self.assertIn("recommendation", info, f"Port {port} missing recommendation")
            self.assertIn(info["severity"], ["CRITICAL", "HIGH", "MEDIUM"],
                         f"Port {port} has invalid severity: {info['severity']}")


if __name__ == "__main__":
    unittest.main()
