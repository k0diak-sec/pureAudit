#!/usr/bin/env python3
"""
testReportGenerator.py — Unit tests for the Report Generator module.
"""

import unittest
import sys
import os
import json
import shutil
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reportGenerator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test cases for the ReportGenerator class."""

    def setUp(self):
        """Set up test fixtures with a temporary output directory."""
        self.testDir = "test_reports/"
        self.generator = ReportGenerator(self.testDir)
        self.sampleResults = [
            {
                "ip": "192.168.1.1",
                "mac": "20:6d:31:ee:98:6a",
                "hostname": "router.lan",
                "ports": [
                    {"port": 22, "service": "SSH", "state": "open"},
                    {"port": 53, "service": "DNS", "state": "open"}
                ],
                "flags": []
            },
            {
                "ip": "192.168.1.50",
                "mac": "ce:db:9f:0a:6e:1c",
                "hostname": "iphone.lan",
                "ports": [
                    {"port": 49152, "service": "UPnP", "state": "open"}
                ],
                "flags": [
                    {
                        "port": 49152,
                        "service": "UPnP",
                        "severity": "MEDIUM",
                        "reason": "UPnP can allow automatic port forwarding by malware",
                        "recommendation": "Disable UPnP on your router if not needed."
                    }
                ]
            }
        ]
        self.sampleDuration = 120.5

    def tearDown(self):
        """Clean up temporary test reports directory."""
        if os.path.exists(self.testDir):
            shutil.rmtree(self.testDir)

    def testInitializationCreatesDirectory(self):
        """Test that ReportGenerator creates the output directory."""
        self.assertTrue(os.path.exists(self.testDir))

    def testGenerateReportReturnsTxtPath(self):
        """Test that generateReport returns a path to a TXT file."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        self.assertTrue(reportPath.endswith(".txt"))
        self.assertTrue(os.path.exists(reportPath))

    def testGenerateReportCreatesJsonFile(self):
        """Test that generateReport also creates a JSON file."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        jsonPath = reportPath.replace(".txt", ".json")
        self.assertTrue(os.path.exists(jsonPath))

    def testTxtReportContainsPureSecure(self):
        """Test that the TXT report includes PureSecure branding."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        with open(reportPath, "r") as f:
            content = f.read()
        self.assertIn("PureSecure", content)
        self.assertIn("puresecure.cloud", content)

    def testTxtReportContainsDeviceInfo(self):
        """Test that the TXT report includes device IPs and MACs."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        with open(reportPath, "r") as f:
            content = f.read()
        self.assertIn("192.168.1.1", content)
        self.assertIn("192.168.1.50", content)
        self.assertIn("20:6d:31:ee:98:6a", content)

    def testTxtReportContainsSeverity(self):
        """Test that the TXT report includes severity flags."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        with open(reportPath, "r") as f:
            content = f.read()
        self.assertIn("MEDIUM", content)
        self.assertIn("UPnP", content)

    def testTxtReportContainsSummary(self):
        """Test that the TXT report includes the summary section."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        with open(reportPath, "r") as f:
            content = f.read()
        self.assertIn("Devices:    2 discovered", content)
        self.assertIn("Issues:     1 flagged", content)
        self.assertIn("120.5 seconds", content)

    def testJsonReportIsValidJson(self):
        """Test that the JSON report is valid parseable JSON."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        jsonPath = reportPath.replace(".txt", ".json")
        with open(jsonPath, "r") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)

    def testJsonReportStructure(self):
        """Test that the JSON report has the expected top-level keys."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        jsonPath = reportPath.replace(".txt", ".json")
        with open(jsonPath, "r") as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("summary", data)
        self.assertIn("devices", data)

    def testJsonReportMetadata(self):
        """Test that the JSON metadata contains correct info."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        jsonPath = reportPath.replace(".txt", ".json")
        with open(jsonPath, "r") as f:
            data = json.load(f)
        metadata = data["metadata"]
        self.assertEqual(metadata["tool"], "PureAudit v1.1")
        self.assertEqual(metadata["generatedBy"], "PureSecure")
        self.assertEqual(metadata["durationSeconds"], 120.5)

    def testJsonReportSummaryAccuracy(self):
        """Test that the JSON summary counts are accurate."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        jsonPath = reportPath.replace(".txt", ".json")
        with open(jsonPath, "r") as f:
            data = json.load(f)
        summary = data["summary"]
        self.assertEqual(summary["totalDevices"], 2)
        self.assertEqual(summary["totalOpenPorts"], 3)
        self.assertEqual(summary["totalIssues"], 1)

    def testJsonReportDeviceCount(self):
        """Test that the JSON report contains the correct number of devices."""
        reportPath = self.generator.generateReport(self.sampleResults, self.sampleDuration)
        jsonPath = reportPath.replace(".txt", ".json")
        with open(jsonPath, "r") as f:
            data = json.load(f)
        self.assertEqual(len(data["devices"]), 2)

    def testGenerateReportEmptyResults(self):
        """Test that report generation handles empty scan results."""
        reportPath = self.generator.generateReport([], 0.0)
        self.assertTrue(os.path.exists(reportPath))
        with open(reportPath, "r") as f:
            content = f.read()
        self.assertIn("Devices:    0 discovered", content)

    def testGenerateReportNoFlags(self):
        """Test report with devices but no security flags."""
        cleanResults = [
            {
                "ip": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "hostname": "clean-device.lan",
                "ports": [{"port": 443, "service": "HTTPS", "state": "open"}],
                "flags": []
            }
        ]
        reportPath = self.generator.generateReport(cleanResults, 30.0)
        with open(reportPath, "r") as f:
            content = f.read()
        self.assertIn("looking good!", content)


if __name__ == "__main__":
    unittest.main()
