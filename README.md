# PQC CBOM Scanner

**Cryptographic Bill of Materials Generator for Quantum Readiness Assessment**

Built for the **PNB Cybersecurity Hackathon 2025-26** — Theme: *Quantum-Proof Systems*

**Live demo: [http://13.60.194.23:5000/](http://13.60.194.23:5000/)**

---

## What it does

Connects to public-facing HTTPS servers, performs a full TLS handshake analysis, and produces a structured **Cryptographic Bill of Materials (CBOM)** — a complete inventory of every cryptographic primitive in use. Each host is then assessed against NIST's post-quantum cryptography standards and assigned one of four labels:

| Label | Meaning |
|---|---|
| ✦ **Fully Quantum Safe** | ML-KEM key exchange + ML-DSA certificate + AES-256 symmetric |
| ◈ **PQC Ready** | PQC key exchange in use, certificate migration pending |
| ◇ **Not PQC Ready** | Classical cryptography only — vulnerable to future quantum attacks |
| ✖ **Critical** | Broken or deprecated cipher suite detected |

Optionally, **subfinder** can enumerate active subdomains before scanning, giving a portfolio-wide view in one run.

Output: a coloured terminal report, a machine-readable `cbom.json`, and an interactive HTML dashboard.

---

## What gets analysed

| Component | What is checked |
|---|---|
| **TLS version** | 1.0 / 1.1 / 1.2 / 1.3 |
| **Key exchange** | X25519, ECDH, X25519Kyber768 (hybrid), ML-KEM (pure) |
| **Bulk cipher** | AES-128, AES-256, ChaCha20, 3DES, RC4 |
| **Hash / MAC** | SHA-256, SHA-384, SHA-512 |
| **Certificate key** | RSA, ECDSA, ML-DSA, SLH-DSA |
| **Certificate expiry** | Warning at < 30 days, error if expired |

---

## Project structure

```
.
├── scan.sh               # CLI scanner — TLS handshake analyser + CBOM emitter
├── generate_report.py    # HTML dashboard generator (reads CBOM JSON)
├── app.py                # Web GUI (Flask) — browser-based frontend
├── Dockerfile            # Production image (gunicorn + subfinder bundled)
├── requirements.txt      # Python dependencies (flask, gunicorn)
├── bin/                  # Place subfinder binary here (see setup)
└── output/               # Auto-created — scan results written here
```

---

## Requirements

### System tools
```bash
# Required
openssl       # 1.1.1+ recommended, 3.x for PQC key exchange detection
python3       # 3.8+
timeout       # part of coreutils

# Install on Ubuntu/Debian if missing
sudo apt update && sudo apt install openssl coreutils python3 python3-pip -y
```

### Python dependencies
```bash
pip install -r requirements.txt
```

### subfinder (optional — for subdomain discovery)

```bash
# Linux x86_64
curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.13.0/subfinder_2.13.0_linux_amd64.zip \
  -o /tmp/sf.zip && unzip -o /tmp/sf.zip subfinder -d bin/ && chmod +x bin/subfinder
```

Check [releases](https://github.com/projectdiscovery/subfinder/releases) for other platforms.
The scanner also uses a system-installed `subfinder` if `bin/subfinder` is absent.

---

## Quick start

### Run locally

```bash
git clone <repo-url> && cd quantumCheck
pip install -r requirements.txt
python3 app.py
# Open http://localhost:5000
```

### Run with Docker

```bash
docker build -t pqc-cbom .
docker run -p 5000:5000 pqc-cbom
# Open http://localhost:5000
```

---

## CLI usage

```
Usage:
  ./scan.sh <hostname> [options]
  ./scan.sh -f <file> [options]

Options:
  -f <file>       File with one host per line (supports host:port)
  --subdomains    Enumerate active subdomains via subfinder before scanning
  --report        Generate HTML dashboard after scanning
  --json          Output raw JSON only (no terminal colours)
  -h              Show help

Examples:
  ./scan.sh google.com
  ./scan.sh api.example-bank.com:8443
  ./scan.sh antaragni.in --subdomains --report
  ./scan.sh -f domains.txt --json > results.json
```

---

## References

- [NIST Post-Quantum Cryptography Standardisation](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 — ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [FIPS 204 — ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [FIPS 205 — SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)
- [subfinder](https://github.com/projectdiscovery/subfinder)

---

*Built for the PNB Cybersecurity Hackathon 2025-26 — "Quantum-Ready Cybersecurity for Future-Safe Banking"*
