#!/usr/bin/env python3
"""Beginner example: scan an IPv4 range one address at a time."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import math
import socket

MAX_ADDRESSES = 65_536
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


def port_number(value: str) -> int:
    """Parse and validate a TCP port number."""

    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


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
    """Return open, closed, or error for one TCP connection attempt."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            result = client.connect_ex((ip, port))
    except (OSError, ValueError, OverflowError):
        return "error"
    if result == 0:
        return "open"
    if result in {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", 10061)}:
        return "closed"
    return "error"


def main() -> int:
    """Run the sequential command-line example."""

    parser = argparse.ArgumentParser(
        description="Sequential educational TCP port scanner"
    )
    parser.add_argument("--start", required=True, type=ipv4)
    parser.add_argument("--end", required=True, type=ipv4)
    parser.add_argument("--port", required=True, type=port_number)
    parser.add_argument("--timeout", type=timeout_seconds, default=0.6)
    args = parser.parse_args()

    try:
        validate_range(args.start, args.end)
    except ValueError as exc:
        parser.error(str(exc))

    for number in range(int(args.start), int(args.end) + 1):
        ip = str(ipaddress.IPv4Address(number))
        print(f"{ip:<15} TCP/{args.port}: {check_port(ip, args.port, args.timeout)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
