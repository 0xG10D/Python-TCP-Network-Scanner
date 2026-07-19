# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) and the structure
recommended by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

No changes yet.

## [1.0.0] - 2026-07-19

### Added

- Standard-library CLI scanner with validated local IPv4 ranges and TCP ports.
- Bounded concurrent scanning, numeric IP sorting, reverse DNS, UTC timestamps,
  and open-result CSV export.
- Accurate `open`, `closed`, and `error` port-state terminology.
- Sequential socket, queue/thread, and optional Nmap teaching examples.
- Unit and loopback integration tests for validation, scanning, CSV safety,
  interruption handling, and command-line behavior.
- Beginner documentation, project-evolution notes, pseudocode, governance files,
  release notes, and Windows/Linux continuous integration.

### Security

- Limited targets to private, loopback, and IPv4 link-local space.
- Limited scan size, worker count, socket timeout, and reverse-DNS concurrency.
- Neutralized spreadsheet-formula prefixes in discovered hostnames.
- Used atomic CSV replacement and rejected symbolic-link destinations.
- Excluded local historical originals and arbitrary scan-result CSV files from
  publication.
