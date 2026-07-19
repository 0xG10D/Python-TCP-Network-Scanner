#!/usr/bin/env python3
"""Optional Nmap example. Requires python-nmap and the Nmap executable."""

from __future__ import annotations

import argparse
import ipaddress
import sys

MAX_ADDRESSES = 65_536
NMAP_TIMEOUT = 30
LOCAL_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)


def port_number(value: str) -> int:
    """Parse and validate a TCP port number."""

    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def local_target(value: str) -> str:
    """Accept one local IPv4 address or CIDR without extra Nmap options."""

    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            normalized = str(network)
        else:
            address = ipaddress.ip_address(value)
            network = ipaddress.ip_network(f"{address}/32", strict=False)
            normalized = str(address)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "target must be one IPv4 address or CIDR"
        ) from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise argparse.ArgumentTypeError("target must use IPv4")
    if network.num_addresses > MAX_ADDRESSES:
        raise argparse.ArgumentTypeError(
            f"target must not exceed {MAX_ADDRESSES:,} addresses"
        )
    if not all(
        any(address in allowed for allowed in LOCAL_NETWORKS)
        for address in (network.network_address, network.broadcast_address)
    ):
        raise argparse.ArgumentTypeError(
            "target must be private, loopback, or IPv4 link-local"
        )
    return normalized


def safe_display(value: str) -> str:
    """Replace terminal control characters with visible placeholders."""

    return "".join(character if character.isprintable() else "?" for character in value)


def run_nmap(target: str, port: int) -> list[tuple[str, str, str]]:
    """Return IP, port state, and hostname rows from Nmap."""

    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap is not installed. Run: pip install -r requirements-optional.txt"
        ) from exc

    try:
        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=target,
            ports=str(port),
            arguments="-sT -Pn",
            timeout=NMAP_TIMEOUT,
        )
    except nmap.PortScannerTimeout as exc:
        raise RuntimeError(
            f"Nmap exceeded the {NMAP_TIMEOUT}-second time limit."
        ) from exc
    except (nmap.PortScannerError, FileNotFoundError) as exc:
        raise RuntimeError(
            "Nmap executable is unavailable. Install Nmap and ensure it is on PATH."
        ) from exc

    rows = []
    for host in scanner.all_hosts():
        port_state = scanner[host].get("tcp", {}).get(port, {}).get("state", "unknown")
        hostname = scanner[host].hostname() or "Unknown"
        rows.append((host, port_state, hostname))
    return rows


def main() -> int:
    """Run the optional Nmap command-line example."""

    parser = argparse.ArgumentParser(
        description="Optional Nmap TCP scanner. Scan only systems you are authorized to test."
    )
    parser.add_argument(
        "--target",
        required=True,
        type=local_target,
        help="authorized local IPv4 address or CIDR, for example 192.168.1.0/24",
    )
    parser.add_argument("--port", type=port_number, default=80)
    args = parser.parse_args()

    try:
        rows = run_nmap(args.target, args.port)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    for ip, state, hostname in rows:
        print(
            f"{ip:<15} TCP/{args.port}: {state:<10} hostname: {safe_display(hostname)}"
        )
    if not rows:
        print(
            "Nmap returned no host records. This does not prove that the targets are offline."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
