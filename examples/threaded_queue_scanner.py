#!/usr/bin/env python3
"""Educational example using ``threading`` and ``Queue``."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import math
import socket
import sys
import threading
from queue import Queue

Result = tuple[str, str]
STOP = object()
MAX_ADDRESSES = 65_536
MAX_WORKERS = 256
MAX_TIMEOUT = 30.0
LOCAL_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)


def ipv4(value: str) -> ipaddress.IPv4Address:
    """Parse a command-line IPv4 address."""

    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IPv4 address: {value}") from exc


def timeout_seconds(value: str) -> float:
    """Parse a finite socket timeout within the example's safety limit."""

    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            "timeout must be greater than 0 and at most 30 seconds"
        )
    return timeout


def port_number(value: str) -> int:
    """Parse and validate a TCP port number."""

    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def worker_count(value: str) -> int:
    """Parse a worker count within the example's safety limit."""

    try:
        workers = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be an integer") from exc
    if not 1 <= workers <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"workers must be between 1 and {MAX_WORKERS}")
    return workers


def validate_range(start: ipaddress.IPv4Address, end: ipaddress.IPv4Address) -> int:
    """Validate local IPv4 scope and return the inclusive address count."""

    if start > end:
        raise ValueError("start IP must not be greater than end IP")
    if not all(any(ip in network for network in LOCAL_NETWORKS) for ip in (start, end)):
        raise ValueError("range must be private, loopback, or IPv4 link-local")
    count = int(end) - int(start) + 1
    if count > MAX_ADDRESSES:
        raise ValueError(f"range must not exceed {MAX_ADDRESSES:,} addresses")
    return count


def check_port(ip: str, port: int, timeout: float) -> str:
    """Classify one TCP connection attempt as open, closed, or error."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            code = client.connect_ex((ip, port))
    except (OSError, ValueError, OverflowError):
        return "error"
    if code == 0:
        return "open"
    if code in {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", 10061)}:
        return "closed"
    return "error"


def scan_range(
    start: ipaddress.IPv4Address,
    end: ipaddress.IPv4Address,
    port: int,
    workers: int,
    timeout: float,
) -> list[Result]:
    """Scan an inclusive IPv4 range with a bounded queue of worker threads."""

    address_count = validate_range(start, end)
    effective_workers = min(workers, address_count, MAX_WORKERS)
    jobs: Queue[str | object] = Queue(maxsize=effective_workers * 2)
    results: list[Result] = []
    result_lock = threading.Lock()

    def worker() -> None:
        """Process queued addresses until the sentinel is received."""

        while True:
            item = jobs.get()
            try:
                if item is STOP:
                    return
                ip = str(item)
                state = check_port(ip, port, timeout)
                with result_lock:
                    results.append((ip, state))
            finally:
                jobs.task_done()

    threads: list[threading.Thread] = []
    try:
        for _ in range(effective_workers):
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            threads.append(thread)
    except RuntimeError as exc:
        for _ in threads:
            jobs.put(STOP)
        jobs.join()
        for thread in threads:
            thread.join()
        raise RuntimeError("could not start worker threads") from exc
    for number in range(int(start), int(end) + 1):
        jobs.put(str(ipaddress.IPv4Address(number)))
    jobs.join()
    for _ in threads:
        jobs.put(STOP)
    jobs.join()
    for thread in threads:
        thread.join()
    return sorted(results, key=lambda item: int(ipaddress.IPv4Address(item[0])))


def main() -> int:
    """Run the queue-based command-line example."""

    parser = argparse.ArgumentParser(
        description="Queue-based educational TCP port scanner"
    )
    parser.add_argument("--start", required=True, type=ipv4)
    parser.add_argument("--end", required=True, type=ipv4)
    parser.add_argument("--port", type=port_number, default=80)
    parser.add_argument("--workers", type=worker_count, default=20)
    parser.add_argument("--timeout", type=timeout_seconds, default=0.6)
    args = parser.parse_args()

    try:
        validate_range(args.start, args.end)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        results = scan_range(
            args.start, args.end, args.port, args.workers, args.timeout
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for ip, state in results:
        print(f"{ip:<15} TCP/{args.port}: {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
