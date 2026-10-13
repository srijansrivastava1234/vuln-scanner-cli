# VulnScanner CLI

An automated web security auditing engine and CLI tool designed to inspect defensive HTTP headers, analyze cookie security configurations, probe TLS/SSL certificates, and compute defensive security posture grades.

---

## Features

- **Two-Stage TLS/SSL Probe**:
  - Validates certificate chains using Python standard TLS verification.
  - Automatically falls back to an unverified connection upon handshake failure to extract X.509 metadata (`cryptography.x509`), expiration dates, and CA issuer identities even on expired or untrusted certificates.
- **Directive-Level Header Auditing**:
  - Checks for presence and configuration of `Strict-Transport-Security` (HSTS), `X-Content-Type-Options`, `Content-Security-Policy` (CSP), `X-Frame-Options`, and `Referrer-Policy`.
  - Flags weak configurations (e.g., `max-age=0`, `'unsafe-inline'`, wildcard sources).
  - Content-Type aware: exempts headless/API JSON responses from HTML-specific framing and CSP rules.
- **Raw Cookie Auditing**:
  - Inspects `Set-Cookie` directives directly to prevent dropped flags during cookie jar parsing.
  - Audits `Secure`, `HttpOnly`, and `SameSite` flags.
- **Fail-Safe Scoring**:
  - Calibrated 0–100 score and letter grades (`A+` to `F`).
  - Emits explicit `UNREACHABLE` / `HTTP_FAILED` states rather than generating misleading grades on network failures.
- **Rich Terminal UI & CI/CD Export**:
  - Formatted terminal output using `rich`.
  - Export machine-readable reports via `--json`.

---

## Installation

```bash
git clone https://github.com/srijansrivastava1234/vuln-scanner-cli.git
cd vuln-scanner-cli
python -m venv venv
.\venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

---

## Usage

### Interactive Terminal Audit
```bash
python cli.py google.com
```

### Audit an Expired or Staging Endpoint
```bash
python cli.py expired.badssl.com
```

### JSON Export for CI/CD Pipelines
```bash
python cli.py github.com --json report.json
```

### CI/CD Security Gate with Policy Threshold
Break the pipeline (exit code `1`) if the target fails security policy:
```bash
# Fail if grade is F:
python cli.py yoursite.com --fail-grade F

# Strict mode (fail if grade is C or worse):
python cli.py yoursite.com --fail-grade C
```

**Exit Codes:**
- `0`: Scan passed and met security grade threshold.
- `1`: Security posture fell below threshold policy (`--fail-grade`).
- `2`: Target unreachable or operational connection error.

---

## Testing

Run the test suite with `pytest`:

```bash
pytest
```
