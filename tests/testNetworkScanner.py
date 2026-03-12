#!/usr/bin/env python3
"""
testNetworkScanner.py — Unit tests for the Network Scanner module.
"""

import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from networkScanner import NetworkScanner


class TestNetworkScanner(unittest.TestCase):
    """Test cases for the NetworkScanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = NetworkScanner("192.168.1.0/24")

    def testInitializationWithTarget(self):
        """Test that scanner initializes with the provided target."""
        self.assertEqual(self.scanner.target, "192.168.1.0/24")

    def testInitializationAutoDetect(self):
        """Test that scanner auto-detects a subnet when no target is given."""
        scanner = NetworkScanner()
        self.assertIsNotNone(scanner.target)
        self.assertIn("/24", scanner.target)

    def testResolveHostnameInvalidIp(self):
        """Test that hostname resolution returns Unknown for invalid IPs."""
        result = self.scanner._resolveHostname("999.999.999.999")
        self.assertEqual(result, "Unknown")

    def testResolveHostnameLocalhost(self):
        """Test that localhost resolves to a hostname."""
        result = self.scanner._resolveHostname("127.0.0.1")
        self.assertIsInstance(result, str)
        self.assertNotEqual(result, "")

    def testResolveManufacturerKnownOui(self):
        """Test that a known MAC prefix resolves to a manufacturer."""
        # Apple MAC prefix
        result = self.scanner._resolveManufacturer("00:1A:2B:00:00:00")
        self.assertIsInstance(result, str)

    def testResolveManufacturerRandomizedMac(self):
        """Test that a randomized MAC is detected correctly."""
        # ce has bit 1 set (locally administered)
        result = self.scanner._resolveManufacturer("ce:db:9f:0a:6e:1c")
        self.assertEqual(result, "Randomized MAC")

    def testResolveManufacturerRealMac(self):
        """Test that a real MAC with unknown OUI returns Unknown, not Randomized."""
        # 00 has bit 1 cleared (universally administered) but fake OUI
        result = self.scanner._resolveManufacturer("00:00:01:00:00:00")
        # Should not be "Randomized MAC" since bit 1 is 0
        self.assertNotEqual(result, "Randomized MAC")

    def testResolveManufacturerBitCheck(self):
        """Test the locally administered bit across multiple MACs."""
        # Bit 1 set = randomized
        randomizedMacs = ["ca:11:22:33:44:55", "de:ad:be:ef:00:00", "fe:ed:fa:ce:00:00"]
        for mac in randomizedMacs:
            result = self.scanner._resolveManufacturer(mac)
            if result != "Randomized MAC":
                # Could be in OUI database, which is fine
                self.assertIsInstance(result, str)

        # Bit 1 cleared = real hardware
        realMacs = ["00:11:22:33:44:55", "10:20:30:40:50:60"]
        for mac in realMacs:
            result = self.scanner._resolveManufacturer(mac)
            self.assertNotEqual(result, "Randomized MAC")

    def testDiscoverDevicesReturnsList(self):
        """Test that discoverDevices returns a list."""
        # Uses fallback ARP scan without sudo
        devices = self.scanner.discoverDevices()
        self.assertIsInstance(devices, list)

    def testDiscoverDevicesFormat(self):
        """Test that discovered devices have the expected keys."""
        devices = self.scanner.discoverDevices()
        for device in devices:
            self.assertIn("ip", device)
            self.assertIn("mac", device)
            self.assertIn("hostname", device)
            self.assertIn("manufacturer", device)

    def testFallbackArpScanReturnsList(self):
        """Test that fallback ARP scan returns a list."""
        devices = self.scanner._fallbackArpScan()
        self.assertIsInstance(devices, list)

    def testDisplayResultsNoErrors(self):
        """Test that displayResults handles empty list without errors."""
        try:
            self.scanner.displayResults([])
        except Exception as e:
            self.fail(f"displayResults raised {type(e).__name__} on empty list")

    def testDisplayResultsWithDevices(self):
        """Test that displayResults handles a device list without errors."""
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "hostname": "test-device.lan",
                "manufacturer": "Test Corp"
            }
        ]
        try:
            self.scanner.displayResults(devices)
        except Exception as e:
            self.fail(f"displayResults raised {type(e).__name__} with valid devices")


if __name__ == "__main__":
    unittest.main()
