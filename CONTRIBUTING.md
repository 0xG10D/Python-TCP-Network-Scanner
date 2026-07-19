# Contributing

Thank you for helping improve this educational project. Keep changes focused,
beginner-friendly, safe, and portable across Windows and Linux.

## Before contributing

- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Report security concerns using [SECURITY.md](SECURITY.md), not a public issue.
- Scan only systems you own or have explicit permission to test.
- Never commit real scan results, internal hostnames, credentials, or private
  network documentation.
- Open an issue before proposing a major feature or a change to safety limits.

## Development setup

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Linux or Kali Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

`scanner.py` must remain standard-library-only. Install
`requirements-optional.txt` only when working on the Nmap example.

## Development workflow

1. Write or update a test that demonstrates the required behavior.
2. Run it and confirm the expected failure.
3. Make the smallest implementation change that passes the test.
4. Refactor for clarity, then run the full verification suite.

```text
python -m unittest discover -s tests -v
python -m compileall -q scanner.py examples tests
python -m ruff check --select E4,E7,E9,F,I,UP,B,SIM,RUF scanner.py examples tests
python -m ruff format --check scanner.py examples tests
```

Use `python3` on systems where `python` does not select Python 3.

## Code and documentation standards

- Follow PEP 8 and use clear names, type hints, and concise docstrings.
- Keep functions focused and handle failures with readable messages.
- Preserve the immutable `ScanResult` model and validated input boundaries.
- Use `open`, `closed`, and `error` for port states. Never claim a host is
  offline only because a port is closed or unreachable.
- Keep examples independently runnable, even when that requires small amounts
  of deliberate validation duplication.
- Use fictional private addresses and hostnames in documentation and fixtures.
- Add no runtime dependency without a clear educational need.

## Pull requests

Explain the problem, the approach, security or privacy impact, and the commands
you ran. Keep each pull request to one coherent change. Conventional commit
subjects such as `fix: handle interrupted export` are encouraged.
