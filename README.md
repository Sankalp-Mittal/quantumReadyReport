# PQC CBOM Scanner

**Cryptographic Bill of Materials Generator for Quantum Readiness Assessment**

Built for the **PNB Cybersecurity Hackathon 2025-26** — Theme: *Quantum-Proof Systems*

---

## What it does

PQC CBOM Scanner connects to public-facing web servers, performs a full TLS handshake analysis, and produces a structured **Cryptographic Bill of Materials (CBOM)** — a complete inventory of every cryptographic primitive in use. It then assesses each component against NIST's post-quantum cryptography standards and assigns one of four labels:

| Label | Meaning |
|---|---|
| ✦ **Fully Quantum Safe** | ML-KEM key exchange + ML-DSA certificate + AES-256 symmetric |
| ◈ **PQC Ready** | PQC key exchange in use, certificate migration pending |
| ◇ **Not PQC Ready** | Classical cryptography only — vulnerable to future quantum attacks |
| ✖ **Critical** | Broken or deprecated cipher suite detected |

Optionally, **subfinder** can enumerate active subdomains before scanning, giving a portfolio-wide view of an organisation's TLS posture in one run.

Output: a coloured terminal report, a machine-readable `cbom.json` file, and an interactive HTML dashboard that groups subdomains under their parent domain.

---

## Background

Modern TLS uses RSA and ECDSA for authentication and ECDHE for key exchange — both rely on mathematical problems that a sufficiently powerful quantum computer running **Shor's algorithm** can solve efficiently.

This enables **Harvest Now, Decrypt Later (HNDL)** attacks — adversaries store encrypted traffic today and decrypt it once Cryptographically Relevant Quantum Computers (CRQCs) become available. Banking data encrypted today may be exposed within the decade.

NIST finalised post-quantum standards in 2024:
- **ML-KEM** (FIPS 203) — replaces ECDHE for key exchange
- **ML-DSA** (FIPS 204) — replaces RSA/ECDSA in certificates
- **SLH-DSA** (FIPS 205) — hash-based alternative signature scheme
- **FN-DSA** (FIPS 206) — compact lattice-based signatures

---

## Project structure

```
.
├── scan.sh               # CLI scanner — TLS handshake analyser + CBOM emitter
├── generate_report.py    # HTML dashboard generator (reads CBOM JSON)
├── app.py                # Web GUI (Flask) — browser-based frontend for the scanner
├── requirements.txt      # Python dependencies (flask)
├── bin/                  # Place subfinder binary here (see setup below)
│   └── .gitkeep
└── output/               # Auto-created — scan results written here
    └── .gitkeep
```

---

## Requirements

### System tools
```bash
# Required
openssl       # 1.1.1+ recommended, 3.x for PQC key exchange detection
python3       # 3.8+
timeout       # part of coreutils

# Check
openssl version
python3 --version

# Install on Ubuntu/Debian if missing
sudo apt update && sudo apt install openssl coreutils python3 python3-pip -y
```

### Python dependencies
```bash
pip install -r requirements.txt
```

### subfinder (optional — for subdomain discovery)

Download the pre-built binary and place it in `bin/`:

```bash
# Linux x86_64
curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.13.0/subfinder_2.13.0_linux_amd64.zip \
  -o /tmp/sf.zip && unzip -o /tmp/sf.zip subfinder -d bin/ && chmod +x bin/subfinder

# macOS arm64
curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.13.0/subfinder_2.13.0_macos_arm64.zip \
  -o /tmp/sf.zip && unzip -o /tmp/sf.zip subfinder -d bin/ && chmod +x bin/subfinder
```

Check [releases](https://github.com/projectdiscovery/subfinder/releases) for other platforms.
The scanner will also use a system-installed `subfinder` if `bin/subfinder` is absent.

---

## Quick start

### Run locally

```bash
git clone <repo-url> && cd quantumCheck
pip install -r requirements.txt
python3 app.py
# Open http://localhost:5000
```

### Deploy on AWS (Docker)

See the [Deployment — AWS](#deployment--aws) section below.

### CLI

```bash
chmod +x scan.sh

# Single host
./scan.sh google.com

# Multiple hosts
./scan.sh google.com cloudflare.com github.com

# With subdomain discovery + report
./scan.sh antaragni.in --subdomains --report
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
  ./scan.sh pingala.iitk.ac.in
  ./scan.sh api.example-bank.com:8443
  ./scan.sh antaragni.in --subdomains --report
  ./scan.sh -f domains.txt --json > results.json
```

### Host file format

```
# Lines starting with # are comments
google.com
cloudflare.com
api.example-bank.com:8443
```

---

## Terminal output

When scanning multiple hosts the output is structured in three phases:

1. **Progress** — one line per host as it scans, with an inline label
2. **Summary table** — counts per label across all scanned hosts
3. **Full detail** — per-host breakdown (TLS, quantum analysis, certificate, recommendations)

---

## What gets analysed

| Component | What is checked | Quantum threat |
|---|---|---|
| **TLS version** | 1.0 / 1.1 / 1.2 / 1.3 | Older versions have additional weaknesses |
| **Key exchange** | X25519, ECDH, X25519Kyber768, ML-KEM | ECDH/X25519 broken by Shor's algorithm |
| **Bulk cipher** | AES-128, AES-256, ChaCha20, 3DES | AES-256 safe; AES-128 weakened by Grover's; 3DES broken |
| **Hash / MAC** | SHA-256, SHA-384, SHA-512 | SHA-384+ safe; Grover halves collision resistance |
| **Certificate key** | RSA, ECDSA, ML-DSA | RSA/ECDSA broken by Shor's algorithm |
| **Certificate chain** | Depth, issuer, expiry | Entire chain must use PQC for full safety |
| **Certificate expiry** | Days remaining | Warning at < 30 days, error if expired |

---

## CBOM JSON output

Each scan writes a CBOM JSON file to `output/`. Structure:

```json
{
  "cbom_version": "1.0",
  "generator": "PQC CBOM Scanner v1.0.0",
  "scan_start": "2026-03-18T10:00:00Z",
  "scan_end":   "2026-03-18T10:02:30Z",
  "total_hosts": 3,
  "assets": [
    {
      "host": "example.com",
      "port": 443,
      "scan_time": "2026-03-18T10:00:05Z",
      "connection": {
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "enc_algorithm": "AES_256",
        "hash_algorithm": "SHA384",
        "verify": "0 (ok)"
      },
      "key_exchange": { "algorithm": "X25519, 253 bits", "classification": "classical" },
      "certificate": {
        "subject": "CN=example.com",
        "key_type": "RSA", "key_bits": 2048,
        "days_until_expiry": 291,
        "classification": "rsa"
      },
      "symmetric": { "classification": "safe" },
      "quantum_assessment": {
        "label": "NOT_PQC_READY",
        "key_exchange_safe": false,
        "certificate_safe": false,
        "symmetric_safe": true,
        "vulnerabilities": ["Key exchange vulnerable to Shor's algorithm"]
      },
      "recommendations": ["Enable X25519Kyber768 hybrid key exchange"]
    }
  ]
}
```

---

## HTML report

Generated by `generate_report.py` — run automatically with `--report`, or manually:

```bash
python3 generate_report.py output/cbom_20260318_100000.json
```

Features:
- **Stats bar** — total assets, count and % per label
- **Progress bar** — visual portfolio health at a glance
- **Filter buttons** — show only assets matching a specific label
- **Domain grouping** — subdomains are collapsed under their parent domain with a **View N subdomains** button; each subdomain shows a compact row with label, TLS, cipher, key exchange, cert type, and expiry
- **Per-asset cards** — full CBOM details, quantum dot indicators, vulnerabilities, remediation steps
- **Certificate expiry warnings** — amber (< 30 days) or red (expired)
- Fully self-contained HTML — no internet connection required to view

---

## Quantum label logic

```
Key exchange  = pqc_hybrid OR pqc_pure
    AND Certificate = ML-DSA / SLH-DSA / FN-DSA
    AND Symmetric   = AES-256 or ChaCha20
             ↓
      ✦ FULLY QUANTUM SAFE

────────────────────────────────────────
Key exchange  = pqc_hybrid OR pqc_pure
    AND Symmetric = AES-256 or ChaCha20
    (certificate still classical)
             ↓
      ◈ PQC READY

────────────────────────────────────────
Key exchange  = classical (X25519, ECDH, RSA)
    OR Symmetric = AES-128
             ↓
      ◇ NOT PQC READY

────────────────────────────────────────
Symmetric = 3DES / RC4 / DES
             ↓
      ✖ CRITICAL
```

---

## Remediation guide

### Step 1 — Enable PQC key exchange (do this now)

**Nginx:**
```nginx
ssl_ecdh_curve X25519Kyber768:X25519:P-256;
```

**Apache** (OpenSSL 3.x + liboqs):
```apache
SSLOpenSSLConfCmd Curves X25519Kyber768:X25519
```

**HAProxy:**
```
bind *:443 ssl curves X25519Kyber768:X25519
```

### Step 2 — Upgrade symmetric cipher preference
```nginx
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
```

### Step 3 — Plan certificate migration (2026–2028 target)

Once CA/Browser Forum trust stores include PQC root CAs, migrate to ML-DSA using hybrid certificates (classical + PQC key) for backward compatibility.

---

## Deployment — AWS

The project ships with a `Dockerfile` that bundles everything (OpenSSL, subfinder, Python deps). Any AWS service that runs Docker containers will work.

### Option A — EC2 (free tier, simplest)

**1. Launch an instance**
- AMI: Ubuntu 22.04 LTS
- Type: `t2.micro` (free tier eligible)
- Security group inbound rules:

| Port | Source | Purpose |
|---|---|---|
| 22 | Your IP | SSH |
| 5000 | 0.0.0.0/0 | Web app |

**2. Install Docker and run the app**

```bash
# SSH in
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>

# Install Docker
sudo apt update && sudo apt install -y docker.io
sudo usermod -aG docker ubuntu
newgrp docker

# Clone and build
git clone https://github.com/sankalp-mittal/quantumCheck.git
cd quantumCheck
docker build -t pqc-scanner .

# Run (restarts automatically on crash)
docker run -d \
  --name pqc-scanner \
  --restart unless-stopped \
  -p 5000:5000 \
  -e PORT=5000 \
  -e REPORT_TTL=3600 \
  pqc-scanner
```

App is live at **http://\<EC2_PUBLIC_IP\>:5000**

**Useful commands:**
```bash
docker logs -f pqc-scanner   # live logs
docker restart pqc-scanner   # restart
docker stop pqc-scanner      # stop
```

---

### Option B — Elastic Beanstalk (managed, auto-scaling)

**1. Install the EB CLI**
```bash
pip install awsebcli
```

**2. Initialise and deploy**
```bash
cd quantumCheck
eb init -p docker pqc-scanner --region ap-south-1
eb create pqc-scanner-env
eb open
```

Elastic Beanstalk builds the `Dockerfile` automatically and provisions a load-balanced environment. Set environment variables under **Configuration → Software → Environment properties**:

| Key | Value |
|---|---|
| `PORT` | `8080` |
| `REPORT_TTL` | `3600` |

---

### Option C — ECS Fargate (production-grade)

**1. Push image to ECR**
```bash
aws ecr create-repository --repository-name pqc-scanner --region ap-south-1
aws ecr get-login-password --region ap-south-1 \
  | docker login --username AWS --password-stdin \
    <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com

docker build -t pqc-scanner .
docker tag pqc-scanner:latest \
  <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/pqc-scanner:latest
docker push \
  <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/pqc-scanner:latest
```

**2. Create ECS cluster + Fargate task + service** via the AWS Console or CLI, setting:
- Container port: `5000`
- Environment variable `PORT=5000`
- Environment variable `REPORT_TTL=3600`

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Port the server listens on |
| `REPORT_TTL` | `3600` | Seconds before an in-memory report is evicted |

---

## Limitations

- Only scans publicly reachable HTTPS endpoints.
- Subdomain discovery with `--subdomains` requires `bin/subfinder` or a system-installed `subfinder`.
- PQC certificate detection depends on OpenSSL recognising the algorithm name. Very new algorithms may show as `unknown`.
- The scanner performs a passive read-only TLS handshake — it does not authenticate, send HTTP requests, or interact with the application layer.
- Certificate transparency logs and OCSP/CRL status are not checked.

---

## References

- [NIST Post-Quantum Cryptography Standardisation](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 — ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [FIPS 204 — ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [FIPS 205 — SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [Cloudflare PQC deployment](https://blog.cloudflare.com/post-quantum-cryptography-ga/)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)

---

## Hackathon context

Built for the **PNB Cybersecurity Hackathon 2025-26**, problem statement: *"Develop a software scanner to validate deployment of Quantum proof cipher and create cryptographic bill of material inventory for public facing applications."*

Outcomes addressed:
- ✅ Crypto inventory discovery — TLS certificates, APIs, optional subdomain enumeration
- ✅ Cryptographic controls — cipher suite, key exchange, TLS version, certificate details
- ✅ Quantum-safe algorithm recommendations with actionable remediation steps
- ✅ Automatic quantum readiness labelling (Fully Safe / PQC Ready / Not Ready / Critical)
- ✅ Machine-readable CBOM JSON for integration into existing security toolchains
- ✅ Interactive HTML dashboard with domain grouping and subdomain drill-down
- ✅ Web GUI for non-CLI users

---

*"Quantum-Ready Cybersecurity for Future-Safe Banking"*
