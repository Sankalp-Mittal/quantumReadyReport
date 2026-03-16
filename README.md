# PQC CBOM Scanner

**Cryptographic Bill of Materials Generator for Quantum Readiness Assessment**

Built for the **PNB Cybersecurity Hackathon 2025-26** — Theme: *Quantum-Proof Systems*

---

## What it does

PQC CBOM Scanner connects to public-facing web servers and APIs, performs a full TLS handshake analysis, and produces a structured **Cryptographic Bill of Materials (CBOM)** — a complete inventory of every cryptographic primitive in use. It then assesses each component against NIST's post-quantum cryptography standards and assigns one of three labels:

| Label | Meaning |
|---|---|
| ✦ **Fully Quantum Safe** | ML-KEM key exchange + ML-DSA certificate + AES-256 symmetric |
| ◈ **PQC Ready** | PQC key exchange in use, certificate migration pending |
| ◇ **Not PQC Ready** | Classical cryptography only — vulnerable to future quantum attacks |
| ✖ **Critical** | Broken or deprecated cipher suite detected |

The output is a coloured terminal report, a machine-readable `cbom.json` file, and an interactive HTML dashboard.

---

## Background: Why this matters

Modern TLS uses RSA and ECDSA for authentication, and ECDHE for key exchange. Both rely on mathematical problems (integer factorisation and elliptic curve discrete logarithm) that a sufficiently powerful quantum computer running **Shor's algorithm** can solve efficiently.

This enables **Harvest Now, Decrypt Later (HNDL)** attacks — adversaries intercept and store encrypted traffic today, then decrypt it once Cryptographically Relevant Quantum Computers (CRQCs) become available. Banking data encrypted today may be exposed within the decade.

NIST finalised three post-quantum signature standards in August 2024:
- **ML-DSA** (FIPS 204) — replaces RSA/ECDSA in certificates
- **SLH-DSA** (FIPS 205) — hash-based alternative signature scheme
- **FN-DSA** (FIPS 206) — compact lattice-based signatures

And one key encapsulation standard:
- **ML-KEM** (FIPS 203) — replaces ECDHE for key exchange

---

## Project structure

```
.
├── scan.sh               # Main scanner — TLS handshake analyser + CBOM emitter
├── generate_report.py    # HTML dashboard generator (reads CBOM JSON)
├── domains.txt           # Target hosts (edit with your own)
└── output/               # Auto-created — scan results written here
    ├── cbom_YYYYMMDD_HHMMSS.json
    └── pqc_report_YYYYMMDD_HHMMSS.html
```

---

## Requirements

```bash
# Required
openssl       # version 1.1.1+ recommended, 3.x for PQC key exchange detection
coreutils     # provides the timeout command
python3       # version 3.7+ for report generation

# Check versions
openssl version
python3 --version

# Install on Ubuntu/Debian if missing
sudo apt update && sudo apt install openssl coreutils python3 -y
```

No Python packages beyond the standard library are required.

---

## Quick start

```bash
# 1. Clone or download the files into a directory
mkdir pqc-scanner && cd pqc-scanner
# place scan.sh, generate_report.py, domains.txt here

# 2. Make the scanner executable
chmod +x scan.sh

# 3. Scan a single host
./scan.sh google.com

# 4. Scan a list of hosts and generate an HTML report
./scan.sh -f domains.txt --report
```

The HTML report opens in any browser — it is fully self-contained with no external dependencies.

---

## Usage

### Single host

```bash
./scan.sh <hostname>
./scan.sh <hostname>:<port>    # custom port
```

Examples:

```bash
./scan.sh pingala.iitk.ac.in
./scan.sh api.example-bank.com:8443
```

### Multiple hosts from a file

```bash
./scan.sh -f domains.txt
./scan.sh -f domains.txt --report
```

### JSON output only (for scripting / CI pipelines)

```bash
./scan.sh google.com --json
./scan.sh -f domains.txt --json > results.json
```

### All options

```
Usage:
  ./scan.sh <hostname> [options]
  ./scan.sh -f <file> [options]

Options:
  -f <file>    File with one host per line (supports host:port)
  --json       Output raw JSON only, no terminal colours
  --report     Generate HTML dashboard after scanning
  -h           Show help
```

---

## domains.txt format

```bash
# Lines starting with # are comments and are ignored
# One host per line — plain hostname or host:port

google.com
cloudflare.com
api.example-bank.com:8443
internal-vpn.example-bank.com:4433
```

---

## What gets analysed

For each host the scanner inspects:

| Component | What is checked | Quantum threat |
|---|---|---|
| **TLS version** | 1.0 / 1.1 / 1.2 / 1.3 | Older versions have additional weaknesses |
| **Key exchange** | X25519, ECDH, X25519Kyber768, ML-KEM | ECDH/X25519 broken by Shor's algorithm |
| **Bulk cipher** | AES-128, AES-256, ChaCha20, 3DES | AES-256 safe; AES-128 weakened by Grover's; 3DES broken |
| **Hash / MAC** | SHA-256, SHA-384, SHA-512 | SHA-384+ safe; Grover halves collision resistance |
| **Certificate key** | RSA, ECDSA, ML-DSA | RSA/ECDSA broken by Shor's algorithm |
| **Certificate chain** | Depth, issuer, expiry | Entire chain must use PQC for full safety |
| **Signing algorithm** | sha256WithRSAEncryption, ecdsa, ml-dsa | See certificate key |
| **Certificate expiry** | Days remaining | Warning at < 30 days, error if expired |

---

## CBOM JSON output

Each scan produces a CBOM JSON file in `output/`. The structure follows an asset-centric inventory model:

```json
{
  "cbom_version": "1.0",
  "generator": "PQC CBOM Scanner v1.0.0",
  "scan_start": "2026-03-16T10:00:00Z",
  "scan_end":   "2026-03-16T10:02:30Z",
  "total_hosts": 3,
  "assets": [
    {
      "host": "example.com",
      "port": 443,
      "service_type": "https",
      "scan_time": "2026-03-16T10:00:05Z",
      "connection": {
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "enc_algorithm": "AES_256",
        "hash_algorithm": "SHA384",
        "verify": "0 (ok)"
      },
      "key_exchange": {
        "algorithm": "X25519, 253 bits",
        "classification": "classical"
      },
      "certificate": {
        "subject": "CN=example.com",
        "issuer": "C=US, O=DigiCert Inc, CN=...",
        "key_type": "RSA",
        "key_bits": 2048,
        "not_before": "Jan 01 00:00:00 2026",
        "not_after":  "Jan 01 23:59:59 2027",
        "days_until_expiry": 291,
        "chain_depth": 3,
        "classification": "rsa"
      },
      "symmetric": { "classification": "safe" },
      "quantum_assessment": {
        "label": "NOT_PQC_READY",
        "key_exchange_safe": false,
        "certificate_safe": false,
        "symmetric_safe": true,
        "vulnerabilities": [
          "Key exchange vulnerable to Shor's algorithm",
          "RSA certificate broken by Shor's algorithm"
        ]
      },
      "recommendations": [
        "Enable X25519Kyber768 hybrid key exchange in TLS 1.3 configuration",
        "Plan migration to ML-DSA certificate — target 2027 deadline per NIST guidance"
      ]
    }
  ]
}
```

---

## HTML dashboard

Generated by `generate_report.py` — run automatically with `--report` flag, or manually:

```bash
python3 generate_report.py output/cbom_20260316_100000.json
# → output/pqc_report_20260316_100012.html
```

The dashboard includes:

- **Stats bar** — total assets, count per label, percentage breakdown
- **Progress bar** — visual portfolio health at a glance
- **Filter buttons** — show only Quantum Safe / PQC Ready / Not Ready / Critical assets
- **Per-asset cards** — full CBOM details, quantum dot indicators, vulnerabilities list, and remediation steps
- **Certificate expiry warnings** — highlighted in amber (< 30 days) or red (expired)

The HTML file is fully self-contained — no internet connection required to view it.

---

## Quantum label logic

```
Key exchange = pqc_hybrid OR pqc_pure
    AND
Certificate = ML-DSA / SLH-DSA / FN-DSA
    AND
Symmetric = AES-256 or ChaCha20
         ↓
  ✦ FULLY QUANTUM SAFE

─────────────────────────────────────────

Key exchange = pqc_hybrid OR pqc_pure
    AND
Symmetric = AES-256 or ChaCha20
(certificate still classical)
         ↓
  ◈ PQC READY

─────────────────────────────────────────

Key exchange = classical (X25519, ECDH, RSA)
    OR
Symmetric = AES-128 / broken
         ↓
  ◇ NOT PQC READY

─────────────────────────────────────────

Symmetric = 3DES / RC4 / DES
         ↓
  ✖ CRITICAL
```

---

## Remediation guide

### For NOT PQC READY servers

**Step 1 — Enable PQC key exchange (do this now)**

Nginx:
```nginx
ssl_ecdh_curve X25519Kyber768:X25519:P-256;
```

Apache (OpenSSL 3.x + liboqs):
```apache
SSLOpenSSLConfCmd Curves X25519Kyber768:X25519
```

HAProxy:
```
bind *:443 ssl curves X25519Kyber768:X25519
```

**Step 2 — Upgrade symmetric cipher preference**
```nginx
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
```

**Step 3 — Plan certificate migration (2026–2028 target)**

Once CA/Browser Forum and major browser trust stores add PQC root CAs, migrate certificates to ML-DSA using a hybrid approach (classical + PQC key in one certificate) for backward compatibility.

---

## Limitations

- Only scans publicly reachable HTTPS endpoints. Internal services behind firewalls will show as connection errors.
- TLS-based VPN detection (ports 1194, 4433) requires the target to respond with a TLS handshake — raw DTLS/IPSec is not analysed.
- PQC certificate detection depends on OpenSSL recognising the algorithm name in the handshake output. Very new algorithms may show as `unknown`.
- The scanner performs a passive read-only TLS handshake — it does not attempt authentication, send requests, or interact with the application layer.
- Certificate transparency logs and OCSP/CRL status are not checked in this version.

---

## References

- [NIST Post-Quantum Cryptography Standardisation](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 — ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [FIPS 204 — ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [FIPS 205 — SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)
- [Cloudflare PQC deployment blog](https://blog.cloudflare.com/post-quantum-cryptography-ga/)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)

---

## Hackathon context

This tool was built for the **PNB Cybersecurity Hackathon 2025-26**, problem statement: *"Develop a software scanner to validate deployment of Quantum proof cipher and create cryptographic bill of material inventory for public facing applications."*

It directly addresses all stated outcomes:

- ✅ Crypto inventory discovery (TLS Certificate, TLS-based VPN, APIs)
- ✅ Cryptographic controls: cipher suite, key exchange, TLS version, certificate details
- ✅ Quantum-safe algorithm recommendations with actionable remediation steps
- ✅ Automatic `Fully Quantum Safe` / `PQC Ready` label for compliant assets
- ✅ Machine-readable CBOM JSON for integration into existing security toolchains

---

*"Quantum-Ready Cybersecurity for Future-Safe Banking"*
