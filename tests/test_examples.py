"""Safety tests for the beginner examples."""

from __future__ import annotations

import argparse
import sys
import unittest
from unittest.mock import patch

from examples import nmap_scanner, sequential_scanner, threaded_queue_scanner


class SocketExampleValidationTests(unittest.TestCase):
    def test_sequential_example_rejects_unsafe_timeout_and_scope(self) -> None:
        for value in ("nan", "inf", "0", "30.1"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                sequential_scanner.timeout_seconds(value)
        with self.assertRaises(ValueError):
            sequential_scanner.validate_range(
                sequential_scanner.ipv4("198.51.100.1"),
                sequential_scanner.ipv4("198.51.100.2"),
            )

    def test_queue_example_rejects_unsafe_limits_and_scope(self) -> None:
        for value in ("nan", "inf", "0", "30.1"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                threaded_queue_scanner.timeout_seconds(value)
        for value in ("0", "257"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                threaded_queue_scanner.worker_count(value)
        for value in ("0", "65536", "not-a-port"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                threaded_queue_scanner.port_number(value)
        with self.assertRaises(ValueError):
            threaded_queue_scanner.validate_range(
                threaded_queue_scanner.ipv4("224.0.0.1"),
                threaded_queue_scanner.ipv4("224.0.0.2"),
            )


class NmapExampleValidationTests(unittest.TestCase):
    def test_nmap_example_reports_missing_python_wrapper(self) -> None:
        with (
            patch.dict(sys.modules, {"nmap": None}),
            self.assertRaisesRegex(RuntimeError, "python-nmap is not installed"),
        ):
            nmap_scanner.run_nmap("127.0.0.1", 80)

    def test_nmap_target_accepts_local_ipv4_host_and_cidr(self) -> None:
        self.assertEqual(nmap_scanner.local_target("192.168.1.10"), "192.168.1.10")
        self.assertEqual(nmap_scanner.local_target("192.168.1.0/24"), "192.168.1.0/24")

    def test_nmap_target_rejects_option_injection_public_and_oversized_targets(
        self,
    ) -> None:
        for value in (
            "192.168.1.10 --script default",
            "198.51.100.1",
            "10.0.0.0/7",
            "::1",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                nmap_scanner.local_target(value)

    def test_nmap_hostname_display_removes_terminal_control_characters(self) -> None:
        unsafe = "printer\x1b[31m.local\nnext"
        self.assertEqual(
            nmap_scanner.safe_display(unsafe),
            "printer?[31m.local?next",
        )


if __name__ == "__main__":
    unittest.main()
