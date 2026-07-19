# Testing Guide

The test suite uses Python's standard `unittest` framework and sends automated
scan traffic only to loopback listeners created by the tests. It covers input
validation, port-state classification, bounded concurrency, reverse DNS, CSV
safety, interruption handling, summaries, and the educational examples.

## Run the tests

Windows PowerShell:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q scanner.py examples tests
python -m ruff check --select E4,E7,E9,F,I,UP,B,SIM,RUF scanner.py examples tests
python -m ruff format --check scanner.py examples tests
```

Linux or Kali Linux:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scanner.py examples tests
python3 -m ruff check --select E4,E7,E9,F,I,UP,B,SIM,RUF scanner.py examples tests
python3 -m ruff format --check scanner.py examples tests
```

Install `requirements-dev.txt` before running Ruff. The main test suite does not
require `python-nmap`, `openpyxl`, or the Nmap executable.

## Test boundaries

- No automated test scans a non-loopback target.
- The optional Nmap integration is validated for input, safe display, and
  graceful missing-wrapper failure, but CI does not launch Nmap.
- Socket error codes vary by operating system; common Windows and POSIX
  connection-refused codes are covered.
- Running socket calls and reverse-DNS threads finish at their bounded timeouts;
  Python cannot forcibly terminate them.

The GitHub Actions test matrix runs compilation, unit tests, and help checks on
Windows and Linux with Python 3.10, 3.11, 3.12, and 3.13. A separate Ubuntu job
uses Python 3.13 for Ruff linting and formatting checks.
