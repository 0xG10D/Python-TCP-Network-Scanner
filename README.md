<<<<<<< HEAD
# Python-TCP-Network-Scanner
=======
# Python TCP Port 80 Network Scanner

## Overview

This beginner-friendly Python project checks whether a selected TCP port is reachable across an inclusive local IPv4 range. The primary learning scenario uses TCP port 80, which is commonly associated with HTTP.

An `open` result means the TCP connection succeeded. It does **not** prove that the host is fully online, healthy, or running a valid website. A `closed` or unreachable port also does **not** prove that the host is offline; the device may be active on another port or protected by a firewall.

## Educational purpose

The project demonstrates IPv4 validation, TCP sockets, concurrent work, reverse DNS, error handling, command-line interfaces, CSV export, and responsible network-testing terminology. It is designed for diploma-level students who want a clear progression from a sequential scanner to a structured command-line workflow.

## Features

- Standard-library-only main scanner
- Inclusive, configurable IPv4 start and end addresses
- Configurable TCP port, worker count, timeout, and output path
- Concurrent scanning with `ThreadPoolExecutor`
- Numeric IP sorting
- Reverse-DNS lookup for open-port results
- Accurate `open`, `closed`, and `error` labels
- UTC ISO 8601 timestamps
- Open-port-only CSV export by default
- Header-only CSV output when no open port is found
- Clean `Ctrl+C` handling
- Input and scan-size validation
- CSV-formula protection for discovered hostnames
- Optional sequential, queue/thread, and Nmap learning examples

## Repository structure

```text
.
|-- scanner.py
|-- README.md
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- CODE_OF_CONDUCT.md
|-- SECURITY.md
|-- requirements.txt
|-- requirements-optional.txt
|-- requirements-dev.txt
|-- LICENSE
|-- .gitignore
|-- pseudocode.md
|-- .github/
|   `-- workflows/
|       `-- tests.yml
|-- examples/
|   |-- sequential_scanner.py
|   |-- threaded_queue_scanner.py
|   `-- nmap_scanner.py
|-- sample-output/
|   `-- scan_results.example.csv
|-- docs/
|   |-- project-evolution.md
|   |-- testing.md
|   `-- releases/
|       `-- v1.0.0.md
|-- tests/
|   |-- test_examples.py
|   `-- test_scanner.py
`-- archive/
    `-- original-files/
        `-- README.md
```

The local archive preserves historical work and may contain old hardcoded values or private scan metadata. Its contents are Git-ignored except for the warning README and must not be executed or published without review.

Project policies and release history are available in [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), the [MIT License](LICENSE), and the [v1.0.0 release notes](docs/releases/v1.0.0.md).

## Requirements

- Python 3.10 through 3.13
- Permission to scan the selected systems and network
- No external package is required for `scanner.py`

Optional Nmap example requirements:

- Nmap executable installed and available on `PATH`
- `python-nmap`, listed in `requirements-optional.txt`

## Installation

Clone or download the project, open a terminal in its directory, and create a virtual environment.

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python --version
```

No package installation is required for the main scanner. To run the optional Nmap example:

```powershell
python -m pip install -r requirements-optional.txt
```

If PowerShell blocks virtual-environment activation, run the environment's Python directly without changing the execution policy:

```powershell
.venv\Scripts\python.exe --version
.venv\Scripts\python.exe scanner.py --start 192.168.1.1 --end 192.168.1.254 --port 80
```

### Linux or Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 --version
```

For the optional Nmap example on Kali or Debian-based Linux:

```bash
sudo apt update
sudo apt install nmap
python3 -m pip install -r requirements-optional.txt
```

## Usage

Scan TCP port 80 across a common private `/24` range:

```powershell
python scanner.py --start 192.168.1.1 --end 192.168.1.254 --port 80
```

Use custom concurrency, timeout, and output settings:

```powershell
python scanner.py --start 192.168.1.1 --end 192.168.1.10 --port 80 --workers 20 --timeout 1.0 --output my_scan.csv
```

Linux and Kali use the same options:

```bash
python3 scanner.py --start 192.168.1.1 --end 192.168.1.254 --port 80
```

Display built-in help:

```powershell
python scanner.py --help
```

## Command-line arguments

| Argument | Required | Description | Default |
|---|---:|---|---|
| `--start` | Yes | First IPv4 address in the inclusive range | None |
| `--end` | Yes | Last IPv4 address in the inclusive range | None |
| `--port` | Yes | TCP port from 1 through 65535 | None |
| `--workers` | No | Concurrent worker threads, from 1 through 256 | `40` |
| `--timeout` | No | Finite connection timeout, up to 30 seconds | `0.6` |
| `--output` | No | Destination path ending in `.csv` | `scan_results.csv` |

The main scanner accepts RFC 1918 private, loopback, and IPv4 link-local ranges. It limits one run to 65,536 addresses. These guardrails reduce accidental public or oversized scans and memory pressure.

## Example terminal output

```text
Scanning 10 address(es) from 192.168.1.1 to 192.168.1.10 for TCP port 80...

Scan summary
------------
Addresses scanned: 10
Open ports found: 1
Errors: 0
Elapsed time: 0.82 seconds
Output file: scan_results.csv
```

The elapsed time and output path will be different on your computer.

## How the scanner works

1. `argparse` reads the command-line options.
2. `ipaddress` verifies that both endpoints are valid IPv4 addresses.
3. The program generates every address from `--start` through `--end`.
4. `ThreadPoolExecutor` runs multiple TCP connection attempts concurrently while keeping only the configured worker count in flight.
5. Each attempt is classified as `open`, `closed`, or `error`.
6. Open-port results receive a best-effort, time-limited reverse-DNS lookup with a fixed concurrency cap.
7. Results are sorted by numeric IP value.
8. Open results are written to CSV and a summary is printed.

Reverse DNS may query your configured DNS server and may expose the address being looked up. It can also fail even when the TCP port is open; the scanner then records `Unknown`.

## TCP port scanning explained

A TCP connect scan tries to complete the normal TCP connection process:

- `open`: the connection succeeded, so the service accepted a TCP connection on that port.
- `closed`: the target explicitly refused the connection.
- `error`: the attempt timed out, the network was unreachable, or another socket problem occurred.

This project does not send an HTTP request or verify web content. An open TCP port 80 only means that a TCP service is reachable there.

## A closed port does not mean the host is offline

Port state and host availability are different questions. A laptop can be active while port 80 is closed. A firewall can silently drop the connection. A web service may use port 443, 8080, or another port. Use wording such as "TCP port 80 is open," "HTTP service may be reachable," or "port 80 was not reachable."

## CSV output format

The CSV columns are:

```text
IP Address,Port,State,Hostname,Timestamp
```

By default, only `open` results are exported. If no open port is found, the scanner still creates a CSV containing the header row. Hostnames beginning with spreadsheet formula characters are prefixed safely. An existing CSV at the selected path is replaced only after the new file is written successfully; symbolic-link output paths are refused. See `sample-output/scan_results.example.csv` for fictional data.

Real scan output can contain internal IP addresses, reverse-DNS names, and current timestamps. Treat it as sensitive operational data, review it before sharing, and do not commit it by accident.

## Running the educational examples

Sequential scanner:

```text
python examples/sequential_scanner.py --start 192.168.1.1 --end 192.168.1.10 --port 80
```

Queue/thread scanner:

```text
python examples/threaded_queue_scanner.py --start 192.168.1.1 --end 192.168.1.10 --port 80
```

Optional Nmap scanner:

```text
python examples/nmap_scanner.py --target 192.168.1.0/24 --port 80
```

The Nmap example is independent from the main scanner. Installing `python-nmap` without installing the Nmap executable is not enough. On Linux, use `python3` in these commands if `python` does not select Python 3.

## Testing

Install the pinned development tool and run the core local checks:

```text
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m compileall -q scanner.py examples tests
python -m ruff check --select E4,E7,E9,F,I,UP,B,SIM,RUF scanner.py examples tests
python -m ruff format --check scanner.py examples tests
```

Use `python3` on Linux when required. Tests create loopback listeners only; they do not scan external targets. See [docs/testing.md](docs/testing.md) for test boundaries and CI coverage.

## Troubleshooting

### `python` is not recognized on Windows

Install Python from the official Python distribution or Microsoft Store, enable the option to add Python to `PATH`, then reopen PowerShell. You can also try `py scanner.py ...`.

### Permission denied when writing CSV

Close the CSV in Excel, choose a writable output directory, or provide another filename with `--output`.

### No open ports are found

This can be a valid result. Confirm the IP range, port number, firewall rules, and service configuration. Do not conclude that every host is offline.

### Many results are `error`

Increase `--timeout`, reduce `--workers`, verify routing, and check whether a firewall is dropping packets.

### Nmap example says the executable is unavailable

Install Nmap and confirm `nmap --version` works in the same terminal. Then install `python-nmap` from `requirements-optional.txt`.

### `Ctrl+C` takes a moment

Pending tasks are cancelled, but a small number of already-running socket calls may finish their configured timeout before Python exits.

## Ethical-use warning

Scan only networks and systems that you own or have explicit written permission to test. Port scanning can trigger monitoring alerts, violate acceptable-use policies, or disrupt fragile systems. Start with a tiny range, use conservative worker counts, document authorization, and follow your institution's rules of engagement.

This project is for authorized education and defensive testing. The operator is responsible for legal and ethical use.

## Limitations

- IPv4 only
- TCP connect scanning only
- One port per run
- No HTTP request, banner detection, TLS check, or vulnerability test
- Reverse DNS may be slow, missing, or privacy-sensitive
- Results depend on routing, firewalls, timeout values, and operating-system socket codes
- Running connection attempts cannot be forcefully killed; they end at the socket timeout
- Private, loopback, and IPv4 link-local target ranges only
- Maximum 65,536 addresses, 256 workers, and a 30-second socket timeout per run
- CSV export includes only open-port results by default

## Future improvements

- Add an explicit option to export all states
- Add progress reporting without cluttering terminal output
- Add multiple-port input with safe limits
- Add optional JSON output
- Add structured logging
- Add IPv6 support as a separate learning module
- Add HTTP response verification after a port is confirmed open

## Credits

Created by Muhammad Irfan Shah and project contributors as an educational Python network-programming mini project. The cleaned edition preserves the original learning journey while establishing a safer, testable, and GitHub-ready baseline.

Licensed under the MIT License.
>>>>>>> b116ca6 (Release Python TCP Network Scanner v1.0.0)
