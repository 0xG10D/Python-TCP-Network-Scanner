# Project Evolution

This project developed through several implementations. Each stage solved a new problem and exposed a new limitation. The archived originals are preserved for comparison, but they may contain historical network details and should not be executed without review.

## 1. Sequential socket scanner

**Purpose:** Introduce TCP sockets by checking port 80 on one IPv4 address at a time.

**Improvements:** The program made the connection process visible and used a timeout so one address would not block forever.

**Limitations:** Sequential scanning becomes slow across a full range. Early wording treated port 80 as proof that a host was `Online` or `Offline`, which is technically inaccurate.

**Lesson learned:** A port scan describes a service endpoint, not the complete status of a device. Connection refused, timeout, and unreachable-network conditions should not all be given the same label.

## 2. Excel export version

**Purpose:** Save scan results in a format that students could filter and present in Microsoft Excel.

**Improvements:** Results became reusable after the program ended, and a table structure made analysis easier.

**Limitations:** The version required `openpyxl`, hardcoded its range and hostname, scanned on import, and still used misleading `Online`/`Offline` labels. Excel output also added dependency and file-locking problems.

**Lesson learned:** Export is useful, but the core scanner should stay independent from presentation libraries. CSV is simpler, portable, and supported by Python's standard library.

## 3. Threaded socket scanner

**Purpose:** Reduce scan time by using worker threads and a shared `Queue`.

**Improvements:** Multiple addresses could be checked while other connections waited on network timeouts. A lock protected shared result data.

**Limitations:** The historical version assumed a `/24`, used a high fixed thread count, converted all socket exceptions to `Offline`, and could deadlock if a worker failed before `task_done()`.

**Lesson learned:** Concurrency needs lifecycle management. Every queued item needs guaranteed cleanup, shared data needs protection, and worker failures need explicit `error` results.

## 4. Nmap-based scanner

**Purpose:** Explore a professional network-scanning engine through the `python-nmap` wrapper.

**Improvements:** Nmap provided richer port states and mature target handling. The scanner could report host and port information discovered by Nmap.

**Limitations:** `python-nmap` is only a wrapper; the Nmap executable must also be installed. Automatic subnet detection and `-Pn` scanning could produce noisy, unintended scans. The version also depended on `openpyxl` for Excel export.

**Lesson learned:** External tools add capability and operational prerequisites. A learning project should fail clearly when either the Python package or executable is missing.

## 5. Nmap fallback implementation

**Purpose:** Continue scanning when the Python wrapper was unavailable by running the Nmap executable and parsing XML.

**Improvements:** The fallback demonstrated executable discovery, argument-list subprocess calls, XML parsing, and two integration strategies.

**Limitations:** The two historical fallback files were exact duplicates. The subprocess had no timeout, the filenames contained spelling mistakes, and automatic `/24` scanning still widened scope without explicit user input.

**Lesson learned:** Fallbacks increase maintenance and test scope. Duplicate implementations should be consolidated, and external processes need time limits and trusted executable paths.

## 6. Final cleaned CLI scanner

**Purpose:** Deliver one clear, dependency-free scanner suitable for GitHub and junior students.

**Improvements:** `scanner.py` adds `argparse`, IPv4 and port validation, ordered range checks, configurable workers and timeout, a scan-size guardrail, `ThreadPoolExecutor`, immutable results, reverse DNS, numeric sorting, timestamps, safe CSV output, a required summary, and clean interruption handling. It exports only open-port results by default.

**Limitations:** It checks one IPv4 TCP port per run and does not prove host availability, identify the application protocol, scan UDP, or test vulnerabilities. Already-running threads can finish only when their socket timeout ends.

**Lesson learned:** The strongest implementation is not the one with the most dependencies. It is the one with a precise scope, accurate terminology, validated inputs, predictable output, tests, and clear operational boundaries.

The cleaned examples intentionally repeat a small amount of validation and socket logic. Each file is designed to run independently so beginners can study one concurrency model without importing the main scanner.
