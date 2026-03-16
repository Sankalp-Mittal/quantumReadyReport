#!/usr/bin/env bash
# tls_quantum_report.sh — TLS quantum security analyser
# Usage: ./tls_quantum_report.sh <hostname> [port]

set -euo pipefail

HOST="${1:-}"
PORT="${2:-443}"

if [[ -z "$HOST" ]]; then
  echo "Usage: $0 <hostname> [port]"
  echo "Example: $0 pingala.iitk.ac.in"
  echo "         $0 example.com 8443"
  exit 1
fi

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
TICK="${GREEN}✔${RESET}"; CROSS="${RED}✘${RESET}"; WARN="${YELLOW}⚠${RESET}"

# ── Dependency check ───────────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
  echo -e "${RED}Error: openssl is not installed.${RESET}"
  exit 1
fi

echo
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  TLS Quantum Security Report${RESET}"
echo -e "${BOLD}  Target : ${HOST}:${PORT}${RESET}"
echo -e "${BOLD}  Date   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo

# ── Run TLS handshake and capture full output ──────────────────────────────────
RAW=$(echo Q | openssl s_client -connect "${HOST}:${PORT}" \
  -showcerts 2>/dev/null) || {
  echo -e "${RED}Error: Could not connect to ${HOST}:${PORT}${RESET}"
  echo -e "${DIM}Check that the host is reachable and the port is correct.${RESET}"
  exit 1
}

# ── Parse fields ───────────────────────────────────────────────────────────────
TLS_VERSION=$(echo "$RAW"  | grep -oP "(?<=New, )[^,]+" | head -1 || true)
CIPHER=$(echo "$RAW"       | grep -oP "(?<=Cipher is ).*"  | head -1 || true)
KEY_BITS=$(echo "$RAW"     | grep -oP "Server public key is \K[0-9]+" | head -1 || true)
TEMP_KEY=$(echo "$RAW"     | grep -oP "(?<=Peer Temp Key: ).*" | head -1 || true)
# TLS 1.3 reports key exchange group differently
if [[ -z "$TEMP_KEY" ]]; then
  TEMP_KEY=$(echo "$RAW"   | grep -oP "(?<=Negotiated TLS1\.3 group: ).*" | head -1 || true)
fi
SIGN_DIGEST=$(echo "$RAW"  | grep -oP "(?<=Peer signing digest: ).*" | head -1 || true)
SIGN_TYPE=$(echo "$RAW"    | grep -oP "(?<=Peer signature type: ).*" | head -1 || true)
VERIFY=$(echo "$RAW"       | grep -oP "(?<=Verify return code: ).*"  | head -1 || true)
SUBJECT=$(echo "$RAW"      | grep "subject=" | head -1 | sed 's/^[[:space:]]*//' || true)
ISSUER=$(echo "$RAW"       | grep "issuer="  | head -1 | sed 's/^[[:space:]]*//' || true)
CERT_ALGO=$(echo "$RAW"    | grep -oP "(?<=sigalg: ).*" | head -1 || true)
CERT_KEY_TYPE=$(echo "$RAW"| grep -oP "(?<=PKEY: )[^;]+" | head -1 || true)
NOT_BEFORE=$(echo "$RAW"   | grep -oP "(?<=NotBefore: ).*?(?= GMT)" | head -1 || true)
NOT_AFTER=$(echo "$RAW"    | grep -oP "(?<=NotAfter: ).*?(?= GMT)"  | head -1 || true)

# ── Quantum assessment helpers ─────────────────────────────────────────────────
quantum_status_key_exchange() {
  local key="${1:-}"
  case "$key" in
    X25519Kyber*|ML-KEM*|kyber*|*MLKEM*|X25519MLKEM*)
      echo "safe" ;;
    X25519|X25519,*|ECDH*|P-256|P-256,*|P-384|P-384,*|secp*)
      echo "vulnerable" ;;
    *)
      echo "unknown" ;;
  esac
}

quantum_status_cert() {
  local algo="${1:-}"
  case "$algo" in
    *RSA*|*rsa*|*ECDSA*|*ecdsa*|*EC*)
      echo "vulnerable" ;;
    *ML-DSA*|*dilithium*|*Dilithium*|*SLH-DSA*|*sphincs*)
      echo "safe" ;;
    *)
      echo "unknown" ;;
  esac
}

quantum_status_symmetric() {
  local cipher="${1:-}"
  if echo "$cipher" | grep -qiE "AES.256|CHACHA20"; then
    echo "safe"
  elif echo "$cipher" | grep -qiE "AES.128"; then
    echo "marginal"
  else
    echo "unknown"
  fi
}

status_icon() {
  case "$1" in
    safe)      echo -e "${TICK} ${GREEN}Quantum-safe${RESET}" ;;
    vulnerable)echo -e "${CROSS} ${RED}Vulnerable (Shor's algorithm)${RESET}" ;;
    marginal)  echo -e "${WARN} ${YELLOW}Marginal (Grover weakens to 64-bit)${RESET}" ;;
    *)         echo -e "${WARN} ${YELLOW}Unknown — check manually${RESET}" ;;
  esac
}

# ── Section 1: Connection info ─────────────────────────────────────────────────
echo -e "${BOLD}[ 1 ] Connection${RESET}"
echo -e "  Protocol    : ${CYAN}${TLS_VERSION:-unknown}${RESET}"
echo -e "  Cipher suite: ${CYAN}${CIPHER:-unknown}${RESET}"
echo -e "  Cert verify : ${VERIFY:-unknown}"
echo

# ── Section 2: Quantum analysis ───────────────────────────────────────────────
echo -e "${BOLD}[ 2 ] Quantum Security Analysis${RESET}"
echo -e "  ${DIM}────────────────────────────────────────────────${RESET}"

# 2a. Key exchange
KE_STATUS=$(quantum_status_key_exchange "$TEMP_KEY")
echo -e "  Key exchange  : ${CYAN}${TEMP_KEY:-unknown}${RESET}"
echo -e "  Assessment    : $(status_icon "$KE_STATUS")"
if [[ "$KE_STATUS" == "vulnerable" ]]; then
  echo -e "  ${DIM}→ Elliptic curve discrete log broken by Shor's algorithm${RESET}"
  echo -e "  ${DIM}→ Replacement: ML-KEM-768 (Kyber) hybrid with X25519${RESET}"
fi
echo

# 2b. Bulk encryption (parse from cipher)
ENC_ALGO=$(echo "$CIPHER" | grep -oP "AES_\d+|CHACHA20" | head -1 || true)
HASH_ALGO=$(echo "$CIPHER" | grep -oP "SHA\d+" | head -1 || true)
SYM_STATUS=$(quantum_status_symmetric "$CIPHER")
echo -e "  Bulk cipher   : ${CYAN}${ENC_ALGO:-unknown}${RESET}"
echo -e "  Assessment    : $(status_icon "$SYM_STATUS")"
if [[ "$SYM_STATUS" == "safe" ]]; then
  echo -e "  ${DIM}→ Grover's algorithm halves key length: 256-bit → ~128-bit effective. Still safe.${RESET}"
fi
echo

# 2c. Hash
echo -e "  Hash / MAC    : ${CYAN}${HASH_ALGO:-unknown}${RESET}"
if echo "${HASH_ALGO:-}" | grep -qiE "SHA.?(384|512|256)"; then
  echo -e "  Assessment    : $(status_icon "safe")"
  echo -e "  ${DIM}→ Grover weakens to half — ${HASH_ALGO} remains safe at this size.${RESET}"
else
  echo -e "  Assessment    : $(status_icon "unknown")"
fi
echo

# 2d. Certificate
CERT_STATUS=$(quantum_status_cert "${CERT_KEY_TYPE:-}${CERT_ALGO:-}${SIGN_TYPE:-}")
echo -e "  Certificate   : ${CYAN}${CERT_KEY_TYPE:-unknown} ${KEY_BITS:+(${KEY_BITS}-bit)}${RESET}"
echo -e "  Signing algo  : ${CYAN}${CERT_ALGO:-${SIGN_TYPE:-unknown}}${RESET}"
echo -e "  Assessment    : $(status_icon "$CERT_STATUS")"
if [[ "$CERT_STATUS" == "vulnerable" ]]; then
  echo -e "  ${DIM}→ RSA/ECDSA private key recoverable with Shor's algorithm${RESET}"
  echo -e "  ${DIM}→ Replacement: ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) certificate${RESET}"
fi
echo

# ── Section 3: Certificate details ────────────────────────────────────────────
echo -e "${BOLD}[ 3 ] Certificate Details${RESET}"
echo -e "  ${SUBJECT:-subject: unknown}"
echo -e "  ${ISSUER:-issuer: unknown}"
echo -e "  Valid from : ${NOT_BEFORE:-unknown}"
echo -e "  Valid until: ${NOT_AFTER:-unknown}"
echo

# Check expiry
if [[ -n "$NOT_AFTER" ]]; then
  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || date -j -f "%b %d %T %Y" "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
  if (( DAYS_LEFT < 0 )); then
    echo -e "  ${CROSS} ${RED}Certificate has EXPIRED${RESET}"
  elif (( DAYS_LEFT < 30 )); then
    echo -e "  ${WARN} ${YELLOW}Certificate expires in ${DAYS_LEFT} days — renew soon!${RESET}"
  else
    echo -e "  ${TICK} Certificate valid for ${DAYS_LEFT} more days"
  fi
  echo
fi

# ── Section 4: Overall verdict ────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Overall Verdict${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"

VULN_COUNT=0
[[ "$KE_STATUS"   == "vulnerable" ]] && (( VULN_COUNT++ )) || true
[[ "$CERT_STATUS" == "vulnerable" ]] && (( VULN_COUNT++ )) || true
[[ "$SYM_STATUS"  == "vulnerable" ]] && (( VULN_COUNT++ )) || true

if (( VULN_COUNT == 0 )); then
  echo -e "  ${TICK} ${GREEN}${BOLD}QUANTUM-SAFE${RESET} — No classical-only primitives detected."
elif (( VULN_COUNT == 1 )); then
  echo -e "  ${WARN} ${YELLOW}${BOLD}PARTIALLY VULNERABLE${RESET} — ${VULN_COUNT} component needs upgrading."
else
  echo -e "  ${CROSS} ${RED}${BOLD}NOT QUANTUM-SAFE${RESET} — ${VULN_COUNT} components are vulnerable."
fi

echo
echo -e "${DIM}  Note: 'vulnerable' means a cryptographically relevant quantum"
echo -e "  computer running Shor's algorithm could break the handshake."
echo -e "  No such computer exists publicly yet (as of 2026).${RESET}"
echo
