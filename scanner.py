#!/usr/bin/env python3
"""Concurrent IPv4 TCP port scanner using only the Python standard library."""

from __future__ import annotations

import argparse
import csv
import errno
import ipaddress
import math
import os
import queue
import socket
import sys
import tempfile
import threading
from collections.abc import Iterable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Literal

DEFAULT_WORKERS = 40
DEFAULT_TIMEOUT = 0.6
DEFAULT_OUTPUT = "scan_results.csv"
MAX_ADDRESSES = 65_536
MAX_WORKERS = 256
MAX_TIMEOUT = 30.0
REVERSE_DNS_TIMEOUT = 1.0
REVERSE_DNS_CAPACITY = 8
UNKNOWN_HOSTNAME = "Unknown"
CSV_HEADERS = ("IP Address", "Port", "State", "Hostname", "Timestamp")
ALLOWED_LOCAL_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)

# A refused TCP connection is evidence that the port is closed. Timeouts,
# unreachable networks, and other failures are errors, not proof of a closed port.
CLOSED_ERROR_CODES = frozenset(
    {
        errno.ECONNREFUSED,
        getattr(errno, "WSAECONNREFUSED", 10061),
    }
)
REVERSE_DNS_SLOTS = threading.BoundedSemaphore(REVERSE_DNS_CAPACITY)
PortState = Literal["open", "closed", "error"]


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Immutable result for one IPv4 address and TCP port."""

    ip: str
    port: int
    state: PortState
    hostname: str
    timestamp: str
    error: str = ""


def parse_ipv4(value: str) -> ipaddress.IPv4Address:
    """Convert a command-line value to an IPv4 address."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IPv4 address: {value}") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise argparse.ArgumentTypeError(f"IPv4 address required, received: {value}")
    return address


def parse_port(value: str) -> int:
    """Validate a TCP port number from the command line."""

    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def parse_positive_int(value: str) -> int:
    """Validate a positive integer command-line value."""

    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    if number > MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"value must not exceed {MAX_WORKERS}")
    return number


def parse_positive_float(value: str) -> float:
    """Validate a positive floating-point command-line value."""

    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError(
            "value must be a finite number greater than zero"
        )
    if number > MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"value must not exceed {MAX_TIMEOUT:g} seconds"
        )
    return number


def parse_csv_path(value: str) -> Path:
    """Require a CSV filename so source files cannot be selected accidentally."""

    path = Path(value)
    if path.suffix.lower() != ".csv":
        raise argparse.ArgumentTypeError("output path must use the .csv extension")
    return path


def validate_range(start: ipaddress.IPv4Address, end: ipaddress.IPv4Address) -> int:
    """Validate range order and return the inclusive address count."""

    if start > end:
        raise ValueError("start IP must not be greater than end IP")
    if not all(
        any(address in network for network in ALLOWED_LOCAL_NETWORKS)
        for address in (start, end)
    ):
        raise ValueError(
            "scan range must stay within private, loopback, or IPv4 link-local space"
        )
    address_count = int(end) - int(start) + 1
    if address_count > MAX_ADDRESSES:
        raise ValueError(
            f"range contains {address_count:,} addresses; maximum is {MAX_ADDRESSES:,}"
        )
    return address_count


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Check whether one TCP port is reachable across an inclusive local IPv4 range. "
            "Only open-port results are exported by default."
        )
    )
    parser.add_argument(
        "--start", required=True, type=parse_ipv4, help="first IPv4 address"
    )
    parser.add_argument(
        "--end", required=True, type=parse_ipv4, help="last IPv4 address"
    )
    parser.add_argument(
        "--port", required=True, type=parse_port, help="TCP port (1-65535)"
    )
    parser.add_argument(
        "--workers",
        type=parse_positive_int,
        default=DEFAULT_WORKERS,
        help=f"concurrent worker threads, maximum {MAX_WORKERS} (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--timeout",
        type=parse_positive_float,
        default=DEFAULT_TIMEOUT,
        help=(
            f"connection timeout in seconds, maximum {MAX_TIMEOUT:g} "
            f"(default: {DEFAULT_TIMEOUT})"
        ),
    )
    parser.add_argument(
        "--output",
        type=parse_csv_path,
        default=Path(DEFAULT_OUTPUT),
        help=f"CSV output path (default: {DEFAULT_OUTPUT})",
    )
    return parser


def utc_timestamp() -> str:
    """Return an ISO 8601 UTC timestamp ending in Z."""

    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def lookup_hostname(ip: str) -> str:
    """Return the reverse-DNS name for an address, or ``Unknown``."""

    if not REVERSE_DNS_SLOTS.acquire(blocking=False):
        return UNKNOWN_HOSTNAME
    result_queue: queue.SimpleQueue[str] = queue.SimpleQueue()

    def resolve() -> None:
        try:
            try:
                result_queue.put(socket.gethostbyaddr(ip)[0] or UNKNOWN_HOSTNAME)
            except (socket.herror, socket.gaierror, OSError):
                result_queue.put(UNKNOWN_HOSTNAME)
        finally:
            REVERSE_DNS_SLOTS.release()

    resolver = threading.Thread(target=resolve, name="reverse-dns", daemon=True)
    try:
        resolver.start()
    except RuntimeError:
        REVERSE_DNS_SLOTS.release()
        return UNKNOWN_HOSTNAME
    resolver.join(REVERSE_DNS_TIMEOUT)
    if resolver.is_alive() or result_queue.empty():
        return UNKNOWN_HOSTNAME
    return result_queue.get()


def socket_error_message(return_code: int) -> str:
    """Create a readable message for a nonzero ``connect_ex`` return code."""

    try:
        message = os.strerror(return_code)
    except ValueError:
        message = "socket connection failed"
    return f"socket error {return_code}: {message}"


def scan_one(ip: str, port: int, timeout: float) -> ScanResult:
    """Check one IPv4 address and classify the target TCP port."""

    timestamp = utc_timestamp()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            return_code = client.connect_ex((ip, port))
    except (OSError, ValueError, OverflowError) as exc:
        return ScanResult(ip, port, "error", UNKNOWN_HOSTNAME, timestamp, str(exc))

    if return_code == 0:
        return ScanResult(ip, port, "open", lookup_hostname(ip), timestamp)
    if return_code in CLOSED_ERROR_CODES:
        return ScanResult(ip, port, "closed", UNKNOWN_HOSTNAME, timestamp)
    return ScanResult(
        ip,
        port,
        "error",
        UNKNOWN_HOSTNAME,
        timestamp,
        socket_error_message(return_code),
    )


def iter_ip_range(
    start: ipaddress.IPv4Address, end: ipaddress.IPv4Address
) -> Iterable[str]:
    """Yield every IPv4 address in an inclusive range."""

    for numeric_ip in range(int(start), int(end) + 1):
        yield str(ipaddress.IPv4Address(numeric_ip))


def sort_results(results: Iterable[ScanResult]) -> list[ScanResult]:
    """Return a new list sorted by numeric IPv4 value."""

    return sorted(results, key=lambda result: int(ipaddress.IPv4Address(result.ip)))


def scan_range(
    start: ipaddress.IPv4Address,
    end: ipaddress.IPv4Address,
    port: int,
    workers: int,
    timeout: float,
) -> list[ScanResult]:
    """Scan an inclusive IPv4 range concurrently."""

    address_count = validate_range(start, end)
    effective_workers = min(workers, address_count, MAX_WORKERS)
    executor = ThreadPoolExecutor(
        max_workers=effective_workers, thread_name_prefix="tcp-scan"
    )
    future_to_ip: dict[Future[ScanResult], str] = {}
    results: list[ScanResult] = []
    cancel_pending = True
    addresses = iter(iter_ip_range(start, end))

    def submit_next() -> bool:
        try:
            ip = next(addresses)
        except StopIteration:
            return False
        future_to_ip[executor.submit(scan_one, ip, port, timeout)] = ip
        return True

    try:
        for _ in range(effective_workers):
            if not submit_next():
                break

        while future_to_ip:
            future = next(as_completed(tuple(future_to_ip)))
            ip = future_to_ip.pop(future)
            try:
                results.append(future.result())
            except Exception as exc:  # Defensive boundary around worker failures.
                results.append(
                    ScanResult(
                        ip, port, "error", UNKNOWN_HOSTNAME, utc_timestamp(), str(exc)
                    )
                )
            submit_next()
        cancel_pending = False
    finally:
        if cancel_pending:
            for future in future_to_ip:
                future.cancel()
        executor.shutdown(wait=True, cancel_futures=cancel_pending)

    return sort_results(results)


def safe_csv_cell(value: str) -> str:
    """Prevent spreadsheet software from interpreting text as a formula."""

    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(
        ("\t", "\r", "\n")
    ):
        return f"'{value}"
    return value


def write_csv(
    results: Iterable[ScanResult], output_path: Path, open_only: bool = True
) -> int:
    """Write sorted scan results and return the number of data rows written."""

    selected = [result for result in results if not open_only or result.state == "open"]
    selected = sort_results(selected)

    if output_path.is_symlink():
        raise OSError("refusing to overwrite a symbolic-link output path")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            writer = csv.writer(handle)
            writer.writerow(CSV_HEADERS)
            writer.writerows(
                (
                    result.ip,
                    result.port,
                    result.state,
                    safe_csv_cell(result.hostname),
                    result.timestamp,
                )
                for result in selected
            )
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return len(selected)


def print_summary(
    results: Sequence[ScanResult], elapsed: float, output_path: Path
) -> None:
    """Print the required scan summary."""

    open_count = sum(result.state == "open" for result in results)
    error_count = sum(result.state == "error" for result in results)
    print("\nScan summary")
    print("------------")
    print(f"Addresses scanned: {len(results)}")
    print(f"Open ports found: {open_count}")
    print(f"Errors: {error_count}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    print(f"Output file: {output_path}")
    if open_count == 0:
        print(
            "No open TCP ports were found. A host may still be active on other ports."
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line scanner and return a process exit code."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        address_count = validate_range(arguments.start, arguments.end)
    except ValueError as exc:
        parser.error(str(exc))

    print(
        f"Scanning {address_count} address(es) from {arguments.start} to {arguments.end} "
        f"for TCP port {arguments.port}..."
    )
    started = perf_counter()
    try:
        results = scan_range(
            arguments.start,
            arguments.end,
            arguments.port,
            arguments.workers,
            arguments.timeout,
        )
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Pending work was cancelled.")
        return 130
    except (OSError, RuntimeError) as exc:
        print(f"Error: Scan could not start or complete: {exc}", file=sys.stderr)
        return 1

    elapsed = perf_counter() - started
    try:
        write_csv(results, arguments.output)
    except KeyboardInterrupt:
        print("\nScan interrupted while writing CSV output.")
        return 130
    except OSError as exc:
        print(f"Error: Could not write CSV output: {exc}", file=sys.stderr)
        return 1

    print_summary(results, elapsed, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
