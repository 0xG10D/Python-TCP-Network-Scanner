# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `1.0.x` | Yes |
| Earlier development snapshots | No |

## Reporting a vulnerability

Please report vulnerabilities privately. After the repository is created on
GitHub, use **Security > Report a vulnerability**. The repository owner must
enable GitHub private vulnerability reporting before publication. Until that
channel is enabled, do not publish exploit details, credentials, private network
data, or identifying scan output in a public issue.

Include a concise description, affected version, reproduction steps using
loopback or fictional data, likely impact, and any suggested mitigation. You
should receive an acknowledgement within 7 days and a status update within 14
days. Complex reports may take longer to resolve.

## Security scope

Relevant reports include unsafe target validation, command injection, terminal
escape injection, CSV formula injection, unsafe file replacement, unintended
data disclosure, denial-of-service conditions, or dependency compromise in an
optional example.

The scanner's normal network observations, differences caused by firewalls,
and absence of a service on a selected port are not vulnerabilities. Never test
a report against a system without authorization.

## Operational safety

- Use only private, loopback, or IPv4 link-local targets you are authorized to
  scan.
- Treat generated CSV files and reverse-DNS names as sensitive operational data.
- Review optional dependencies and keep Nmap updated separately from this
  project.
- Archived original files are local historical material and are excluded from
  the public repository.
