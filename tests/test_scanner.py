"""Tests for the standard-library TCP range scanner."""

from __future__ import annotations

import argparse
import ast
import csv
import errno
import io
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import scanner


class ValidationTests(unittest.TestCase):
    def test_parse_ipv4_accepts_ipv4_boundaries(self) -> None:
        self.assertEqual(str(scanner.parse_ipv4("0.0.0.0")), "0.0.0.0")
        self.assertEqual(str(scanner.parse_ipv4("255.255.255.255")), "255.255.255.255")

    def test_parse_ipv4_rejects_invalid_and_ipv6_values(self) -> None:
        for value in ("192.168.1.999", "not-an-ip", "::1"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                scanner.parse_ipv4(value)

    def test_parse_port_accepts_boundaries_and_rejects_invalid_values(self) -> None:
        self.assertEqual(scanner.parse_port("1"), 1)
        self.assertEqual(scanner.parse_port("65535"), 65535)
        for value in ("0", "65536", "eighty"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                scanner.parse_port(value)

    def test_positive_worker_and_timeout_parsers(self) -> None:
        self.assertEqual(scanner.parse_positive_int("4"), 4)
        self.assertEqual(scanner.parse_positive_float("0.25"), 0.25)
        for function, value in (
            (scanner.parse_positive_int, "0"),
            (scanner.parse_positive_int, "-1"),
            (scanner.parse_positive_int, str(scanner.MAX_WORKERS + 1)),
            (scanner.parse_positive_float, "0"),
            (scanner.parse_positive_float, "-0.1"),
            (scanner.parse_positive_float, "fast"),
            (scanner.parse_positive_float, "nan"),
            (scanner.parse_positive_float, "inf"),
            (scanner.parse_positive_float, "30.1"),
        ):
            with (
                self.subTest(function=function.__name__, value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                function(value)

    def test_parse_csv_path_requires_csv_extension(self) -> None:
        self.assertEqual(scanner.parse_csv_path("results.csv"), Path("results.csv"))
        for value in ("scanner.py", "results.xlsx", "no-extension"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                scanner.parse_csv_path(value)

    def test_validate_range_accepts_ordered_range_and_rejects_reversed_range(
        self,
    ) -> None:
        start = scanner.parse_ipv4("192.168.1.1")
        end = scanner.parse_ipv4("192.168.1.10")
        self.assertEqual(scanner.validate_range(start, end), 10)
        with self.assertRaises(ValueError):
            scanner.validate_range(end, start)

    def test_validate_range_rejects_excessively_large_scan(self) -> None:
        with self.assertRaises(ValueError):
            scanner.validate_range(
                scanner.parse_ipv4("10.0.0.0"),
                scanner.parse_ipv4("10.1.0.0"),
            )

    def test_validate_range_rejects_non_local_scope(self) -> None:
        with self.assertRaises(ValueError):
            scanner.validate_range(
                scanner.parse_ipv4("198.51.100.1"),
                scanner.parse_ipv4("198.51.100.10"),
            )
        with self.assertRaises(ValueError):
            scanner.validate_range(
                scanner.parse_ipv4("224.0.0.1"),
                scanner.parse_ipv4("224.0.0.2"),
            )


class SingleAddressScanTests(unittest.TestCase):
    @staticmethod
    def socket_context(connect_result: int = 0) -> tuple[MagicMock, MagicMock]:
        socket_factory = MagicMock()
        socket_instance = socket_factory.return_value.__enter__.return_value
        socket_instance.connect_ex.return_value = connect_result
        return socket_factory, socket_instance

    def test_open_port_includes_reverse_dns_and_utc_timestamp(self) -> None:
        socket_factory, socket_instance = self.socket_context(0)
        with (
            patch("scanner.socket.socket", socket_factory),
            patch("scanner.lookup_hostname", return_value="webserver.local"),
        ):
            result = scanner.scan_one("192.168.1.10", 80, 0.5)

        socket_instance.settimeout.assert_called_once_with(0.5)
        socket_instance.connect_ex.assert_called_once_with(("192.168.1.10", 80))
        self.assertEqual(result.state, "open")
        self.assertEqual(result.hostname, "webserver.local")
        self.assertTrue(result.timestamp.endswith("Z"))
        self.assertEqual(result.error, "")

    def test_connection_refused_is_closed_not_offline(self) -> None:
        socket_factory, _ = self.socket_context(errno.ECONNREFUSED)
        with patch("scanner.socket.socket", socket_factory):
            result = scanner.scan_one("192.168.1.11", 80, 0.5)
        self.assertEqual(result.state, "closed")
        self.assertEqual(result.hostname, "Unknown")

    def test_unreachable_return_code_is_error(self) -> None:
        socket_factory, _ = self.socket_context(errno.EHOSTUNREACH)
        with patch("scanner.socket.socket", socket_factory):
            result = scanner.scan_one("192.168.1.12", 80, 0.5)
        self.assertEqual(result.state, "error")
        self.assertTrue(result.error)

    def test_socket_exception_is_error(self) -> None:
        socket_factory = MagicMock(side_effect=OSError("network unavailable"))
        with patch("scanner.socket.socket", socket_factory):
            result = scanner.scan_one("192.168.1.13", 80, 0.5)
        self.assertEqual(result.state, "error")
        self.assertIn("network unavailable", result.error)

    def test_reverse_dns_failure_returns_unknown(self) -> None:
        with patch("scanner.socket.gethostbyaddr", side_effect=socket.herror):
            self.assertEqual(scanner.lookup_hostname("192.168.1.10"), "Unknown")

    def test_reverse_dns_lookup_has_a_time_limit(self) -> None:
        def slow_lookup(ip: str) -> tuple[str, list[str], list[str]]:
            del ip
            time.sleep(0.2)
            return ("late.local", [], [])

        started = time.perf_counter()
        with (
            patch("scanner.socket.gethostbyaddr", side_effect=slow_lookup),
            patch("scanner.REVERSE_DNS_TIMEOUT", 0.01),
        ):
            hostname = scanner.lookup_hostname("192.168.1.10")
        self.assertEqual(hostname, "Unknown")
        self.assertLess(time.perf_counter() - started, 0.15)

    def test_reverse_dns_skips_lookup_when_capacity_is_full(self) -> None:
        with (
            patch.object(scanner.REVERSE_DNS_SLOTS, "acquire", return_value=False),
            patch("scanner.socket.gethostbyaddr") as resolver,
        ):
            hostname = scanner.lookup_hostname("192.168.1.10")
        self.assertEqual(hostname, "Unknown")
        resolver.assert_not_called()

    def test_real_loopback_listener_is_detected_as_open(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def accept_once() -> None:
            connection, _ = listener.accept()
            connection.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        result = scanner.scan_one("127.0.0.1", port, 1.0)
        thread.join(2)
        self.assertEqual(result.state, "open")
        self.assertFalse(thread.is_alive())


class RangeAndCsvTests(unittest.TestCase):
    def test_scan_range_is_inclusive_and_sorted_numerically(self) -> None:
        def fake_scan(ip: str, port: int, timeout: float) -> scanner.ScanResult:
            del timeout
            return scanner.ScanResult(
                ip, port, "closed", "Unknown", "2025-01-01T00:00:00Z"
            )

        with patch("scanner.scan_one", side_effect=fake_scan):
            results = scanner.scan_range(
                scanner.parse_ipv4("192.168.1.2"),
                scanner.parse_ipv4("192.168.1.10"),
                port=80,
                workers=3,
                timeout=0.1,
            )

        self.assertEqual(len(results), 9)
        self.assertEqual(results[0].ip, "192.168.1.2")
        self.assertEqual(results[-1].ip, "192.168.1.10")

    def test_scan_range_cancels_pending_work_on_keyboard_interrupt(self) -> None:
        executor = MagicMock()
        submitted_futures: list[MagicMock] = []

        def submit(*args: object) -> MagicMock:
            del args
            future = MagicMock()
            submitted_futures.append(future)
            return future

        def interrupt(pending: object) -> object:
            self.assertEqual(len(tuple(pending)), 2)
            self.assertEqual(len(submitted_futures), 2)
            raise KeyboardInterrupt

        executor.submit.side_effect = submit
        with (
            patch("scanner.ThreadPoolExecutor", return_value=executor),
            patch("scanner.as_completed", side_effect=interrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            scanner.scan_range(
                scanner.parse_ipv4("127.0.0.1"),
                scanner.parse_ipv4("127.0.0.10"),
                port=80,
                workers=2,
                timeout=0.1,
            )
        for future in submitted_futures:
            future.cancel.assert_called_once()
        executor.shutdown.assert_called_once_with(wait=True, cancel_futures=True)

    def test_write_csv_defaults_to_open_rows_with_exact_columns(self) -> None:
        rows = (
            scanner.ScanResult(
                "192.168.1.10", 80, "open", "=unsafe", "2025-01-01T00:00:00Z"
            ),
            scanner.ScanResult(
                "192.168.1.2", 80, "closed", "Unknown", "2025-01-01T00:00:01Z"
            ),
            scanner.ScanResult(
                "192.168.1.3", 80, "error", "Unknown", "2025-01-01T00:00:02Z", "timeout"
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.csv"
            written = scanner.write_csv(rows, output)
            with output.open(newline="", encoding="utf-8") as handle:
                csv_rows = list(csv.reader(handle))

        self.assertEqual(written, 1)
        self.assertEqual(
            csv_rows[0], ["IP Address", "Port", "State", "Hostname", "Timestamp"]
        )
        self.assertEqual(csv_rows[1][0:3], ["192.168.1.10", "80", "open"])
        self.assertEqual(csv_rows[1][3], "'=unsafe")
        self.assertEqual(rows[0].hostname, "=unsafe")

    def test_safe_csv_cell_neutralizes_formula_and_control_prefixes(self) -> None:
        for value in ("=cmd", "+cmd", "-cmd", "@cmd", "\t=cmd", "\r=cmd", "  =cmd"):
            with self.subTest(value=value):
                self.assertTrue(scanner.safe_csv_cell(value).startswith("'"))
        self.assertEqual(scanner.safe_csv_cell("webserver.local"), "webserver.local")

    def test_write_csv_creates_header_only_file_when_no_ports_are_open(self) -> None:
        rows = (
            scanner.ScanResult(
                "127.0.0.1", 80, "closed", "Unknown", "2025-01-01T00:00:00Z"
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.csv"
            written = scanner.write_csv(rows, output)
            lines = output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(written, 0)
        self.assertEqual(len(lines), 1)

    def test_interrupted_csv_write_preserves_existing_destination(self) -> None:
        rows = (
            scanner.ScanResult(
                "127.0.0.1", 80, "open", "localhost", "2025-01-01T00:00:00Z"
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.csv"
            output.write_text("original\n", encoding="utf-8")
            writer = MagicMock()
            writer.writerows.side_effect = KeyboardInterrupt
            with (
                patch("scanner.csv.writer", return_value=writer),
                self.assertRaises(KeyboardInterrupt),
            ):
                scanner.write_csv(rows, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])


class CliTests(unittest.TestCase):
    def test_main_prints_required_summary(self) -> None:
        fake_results = [
            scanner.ScanResult(
                "127.0.0.1", 80, "open", "localhost", "2025-01-01T00:00:00Z"
            ),
            scanner.ScanResult(
                "127.0.0.2", 80, "error", "Unknown", "2025-01-01T00:00:01Z", "timeout"
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.csv"
            stream = io.StringIO()
            with (
                patch("scanner.scan_range", return_value=fake_results),
                patch("scanner.perf_counter", side_effect=(10.0, 11.25)),
                redirect_stdout(stream),
            ):
                code = scanner.main(
                    [
                        "--start",
                        "127.0.0.1",
                        "--end",
                        "127.0.0.2",
                        "--port",
                        "80",
                        "--output",
                        str(output),
                    ]
                )

        text = stream.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Addresses scanned: 2", text)
        self.assertIn("Open ports found: 1", text)
        self.assertIn("Errors: 1", text)
        self.assertIn("Elapsed time: 1.25 seconds", text)
        self.assertIn("Output file:", text)
        self.assertNotIn("offline", text.lower())

    def test_main_rejects_reversed_range_readably(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            scanner.main(
                ["--start", "192.168.1.10", "--end", "192.168.1.1", "--port", "80"]
            )
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("start IP must not be greater", stderr.getvalue())

    def test_main_handles_keyboard_interrupt_without_traceback(self) -> None:
        stream = io.StringIO()
        with (
            patch("scanner.scan_range", side_effect=KeyboardInterrupt),
            redirect_stdout(stream),
        ):
            code = scanner.main(
                ["--start", "127.0.0.1", "--end", "127.0.0.1", "--port", "80"]
            )
        self.assertEqual(code, 130)
        self.assertIn("Scan interrupted", stream.getvalue())
        self.assertNotIn("Traceback", stream.getvalue())

    def test_main_handles_keyboard_interrupt_during_csv_write(self) -> None:
        result = [
            scanner.ScanResult(
                "127.0.0.1", 80, "open", "localhost", "2025-01-01T00:00:00Z"
            )
        ]
        stream = io.StringIO()
        with (
            patch("scanner.scan_range", return_value=result),
            patch("scanner.write_csv", side_effect=KeyboardInterrupt),
            redirect_stdout(stream),
        ):
            code = scanner.main(
                ["--start", "127.0.0.1", "--end", "127.0.0.1", "--port", "80"]
            )
        self.assertEqual(code, 130)
        self.assertIn("interrupted while writing CSV", stream.getvalue())

    def test_main_reports_output_write_error(self) -> None:
        result = [
            scanner.ScanResult(
                "127.0.0.1", 80, "closed", "Unknown", "2025-01-01T00:00:00Z"
            )
        ]
        stderr = io.StringIO()
        stdout = io.StringIO()
        with (
            patch("scanner.scan_range", return_value=result),
            patch("scanner.write_csv", side_effect=OSError("permission denied")),
            redirect_stderr(stderr),
            redirect_stdout(stdout),
        ):
            code = scanner.main(
                ["--start", "127.0.0.1", "--end", "127.0.0.1", "--port", "80"]
            )
        self.assertEqual(code, 1)
        self.assertIn("Could not write CSV", stderr.getvalue())

    def test_help_runs_without_site_packages(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "scanner.py", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for option in (
            "--start",
            "--end",
            "--port",
            "--workers",
            "--timeout",
            "--output",
        ):
            self.assertIn(option, completed.stdout)

    def test_invalid_ip_and_port_are_readable_cli_errors(self) -> None:
        cases = (
            (
                ["--start", "bad-ip", "--end", "127.0.0.1", "--port", "80"],
                "invalid IPv4 address",
            ),
            (
                ["--start", "127.0.0.1", "--end", "127.0.0.1", "--port", "70000"],
                "between 1 and 65535",
            ),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    [sys.executable, "scanner.py", *arguments],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn(expected, completed.stderr)

    def test_main_scanner_imports_only_standard_library_modules(self) -> None:
        tree = ast.parse(Path("scanner.py").read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        non_standard = imported - sys.stdlib_module_names - {"__future__"}
        self.assertEqual(non_standard, set())


if __name__ == "__main__":
    unittest.main()
