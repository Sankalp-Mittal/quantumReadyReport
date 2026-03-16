#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  PQC Scanner — Cryptographic Bill of Materials (CBOM) Generator
#  Usage:
#    ./scan.sh example.com              # single host
#    ./scan.sh -f domains.txt           # file of hosts
#    ./scan.sh example.com --json       # JSON only
#    ./scan.sh -f domains.txt --report  # full HTML report
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "$OUTPUT_DIR"

# ── Colours ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ── Parse args ─────────────────────────────────────────────────────
HOSTS=()
JSON_ONLY=false
GENERATE_REPORT=false
INPUT_FILE=""

usage() {
  echo -e "${BOLD}PQC CBOM Scanner v${VERSION}${RESET}"
  echo
  echo "Usage:"
  echo "  $0 <hostname> [options]"
  echo "  $0 -f <file> [options]"
  echo
  echo "Options:"
  echo "  -f <file>    File containing one host per line"
  echo "  --json       Output JSON only (no colour terminal output)"
  echo "  --report     Generate HTML report after scanning"
  echo "  -h           Show this help"
  echo
  echo "Examples:"
  echo "  $0 google.com"
  echo "  $0 -f domains.txt --report"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    -f) INPUT_FILE="$2"; shift 2 ;;
    --json) JSON_ONLY=true; shift ;;
    --report) GENERATE_REPORT=true; shift ;;
    -*) echo "Unknown option: $1"; usage ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done

if [[ -n "$INPUT_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=$(echo "$line" | tr -d '[:space:]')
    [[ -z "$line" || "$line" == \#* ]] && continue
    HOSTS+=("$line")
  done < "$INPUT_FILE"
fi

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  echo -e "${RED}Error: No hosts specified.${RESET}"
  usage
fi

# ── Dependency check ───────────────────────────────────────────────
check_deps() {
  local missing=()
  for cmd in openssl timeout; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}Missing dependencies: ${missing[*]}${RESET}"
    echo "Install with: sudo apt install openssl coreutils"
    exit 1
  fi
}
check_deps

# ── PQC knowledge base ─────────────────────────────────────────────
# Key exchange classification
classify_kex() {
  local kex="${1:-}"
  if echo "$kex" | grep -qiE "Kyber|ML-KEM|mlkem|X25519Kyber|x25519kyber|MLKEM|X25519MLKEM"; then
    echo "pqc_hybrid"
  elif echo "$kex" | grep -qiE "^X25519$|ECDH.*P-256|ECDH.*P-384|secp|prime256"; then
    echo "classical"
  elif echo "$kex" | grep -qiE "ML-KEM|CRYSTALS|NTRU|SABER|McEliece|FrodoKEM"; then
    echo "pqc_pure"
  elif [[ -z "$kex" ]]; then
    echo "unknown"
  else
    echo "classical"
  fi
}

# Certificate classification
classify_cert() {
  local algo="${1:-}" keytype="${2:-}"
  local combined="${algo}${keytype}"
  if echo "$combined" | grep -qiE "ML-DSA|Dilithium|SLH-DSA|SPHINCS|FN-DSA|FALCON|pqc"; then
    echo "pqc"
  elif echo "$combined" | grep -qiE "RSA|rsa"; then
    echo "rsa"
  elif echo "$combined" | grep -qiE "EC|ECDSA|ecdsa"; then
    echo "ecdsa"
  else
    echo "unknown"
  fi
}

# Symmetric cipher classification
classify_symmetric() {
  local cipher="${1:-}"
  if echo "$cipher" | grep -qiE "AES.?256|CHACHA20"; then
    echo "safe"
  elif echo "$cipher" | grep -qiE "AES.?128"; then
    echo "marginal"
  elif echo "$cipher" | grep -qiE "3DES|RC4|DES"; then
    echo "broken"
  else
    echo "unknown"
  fi
}

# Overall quantum label
compute_label() {
  local kex_class="$1" cert_class="$2" sym_class="$3"
  if [[ "$kex_class" == "pqc_pure" && "$cert_class" == "pqc" && "$sym_class" == "safe" ]]; then
    echo "FULLY_QUANTUM_SAFE"
  elif [[ ("$kex_class" == "pqc_hybrid" || "$kex_class" == "pqc_pure") && "$sym_class" == "safe" ]]; then
    echo "PQC_READY"
  elif [[ "$sym_class" == "broken" ]]; then
    echo "CRITICAL"
  else
    echo "NOT_PQC_READY"
  fi
}

# Recommendations per label
get_recommendations() {
  local label="$1" kex_class="$2" cert_class="$3"
  local recs=()
  case "$label" in
    FULLY_QUANTUM_SAFE)
      recs+=("Maintain ML-KEM key exchange and ML-DSA certificate on renewal")
      recs+=("Monitor NIST PQC standard updates for algorithm deprecation notices")
      ;;
    PQC_READY)
      recs+=("Upgrade certificate from RSA/ECDSA to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)")
      recs+=("Ensure CA/Browser Forum approves PQC root CAs before deploying PQC certificates")
      recs+=("Consider hybrid certificates (classical + PQC) for backward compatibility")
      ;;
    NOT_PQC_READY)
      if [[ "$kex_class" == "classical" ]]; then
        recs+=("Enable X25519Kyber768 hybrid key exchange in TLS 1.3 configuration")
        recs+=("For nginx: ssl_ecdh_curve X25519Kyber768:X25519; in ssl config block")
        recs+=("For Apache: SSLOpenSSLConfCmd Curves X25519Kyber768:X25519")
      fi
      if [[ "$cert_class" != "pqc" ]]; then
        recs+=("Plan migration to ML-DSA certificate — target 2027 deadline per NIST guidance")
        recs+=("Current RSA/ECDSA certificates are vulnerable to Shor's algorithm on CRQCs")
      fi
      recs+=("Implement Harvest-Now-Decrypt-Later (HNDL) mitigations immediately via PQC key exchange")
      ;;
    CRITICAL)
      recs+=("URGENT: Disable weak ciphers (3DES, RC4, DES) immediately")
      recs+=("Upgrade to TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305")
      recs+=("Apply all NOT_PQC_READY recommendations after fixing critical issues")
      ;;
  esac
  printf '%s\n' "${recs[@]}"
}

# ── Port scanner ───────────────────────────────────────────────────
COMMON_TLS_PORTS=(443 8443 4433 8080 8880)
VPN_PORTS=(1194 1723 500 4500)

scan_port() {
  local host="$1" port="$2"
  timeout 8 openssl s_client \
    -connect "${host}:${port}" \
    -servername "${host}" \
    -showcerts \
    -msg \
    2>/dev/null </dev/null || true
}

# ── Single host scanner ────────────────────────────────────────────
scan_host() {
  local host="$1"
  local port="${2:-443}"
  local service_type="${3:-https}"

  local raw
  raw=$(scan_port "$host" "$port")

  if [[ -z "$raw" ]] || ! echo "$raw" | grep -q "CONNECTED"; then
    echo "{\"error\": \"connection_failed\"}"
    return
  fi

  # Parse fields
  local tls_version cipher key_bits temp_key sign_type cert_algo
  local subject issuer not_before not_after verify chain_depth

  tls_version=$(echo "$raw" | grep -oP "(?<=New, )[^,]+" | head -1 || echo "unknown")
  cipher=$(echo "$raw"      | grep -oP "(?<=Cipher is ).*" | head -1 || echo "unknown")
  key_bits=$(echo "$raw"    | grep -oP "Server public key is \K[0-9]+" | head -1 || echo "0")
  temp_key=$(echo "$raw"    | grep -oP "(?<=Negotiated TLS1\.3 group: ).*" | head -1 || true)
  [[ -z "$temp_key" ]] && \
    temp_key=$(echo "$raw" | grep -oP "(?<=(Peer|Server) Temp Key: )[^,]+" | head -1 | xargs || true)
  [[ -z "$temp_key" ]] && temp_key="unknown"
  sign_type=$(echo "$raw"   | grep -oP "(?<=Peer signature type: ).*" | head -1 || echo "unknown")
  cert_algo=$(echo "$raw"   | grep -oP "(?<=sigalg: ).*" | head -1 || echo "unknown")
  subject=$(echo "$raw"     | grep "subject=" | head -1 | sed 's/.*subject=//' | tr -d '\n' || echo "unknown")
  issuer=$(echo "$raw"      | grep "issuer="  | head -1 | sed 's/.*issuer=//' | tr -d '\n' || echo "unknown")
  not_before=$(echo "$raw"  | grep -oP "(?<=NotBefore: ).*?(?= GMT)" | head -1 || echo "unknown")
  not_after=$(echo "$raw"   | grep -oP "(?<=NotAfter: ).*?(?= GMT)"  | head -1 || echo "unknown")
  verify=$(echo "$raw"      | grep -oP "(?<=Verify return code: ).*" | head -1 || echo "unknown")
  chain_depth=$(echo "$raw" | grep -c "s:CN=" || echo "0")

  # Extract cipher components
  local enc_algo hash_algo
  enc_algo=$(echo "$cipher" | grep -oP "AES_\d+_\w+|CHACHA20_POLY1305|3DES|RC4" | head -1 || echo "unknown")
  hash_algo=$(echo "$cipher" | grep -oP "SHA\d+" | head -1 || echo "unknown")

  # Classify
  local kex_class cert_class sym_class
  kex_class=$(classify_kex "$temp_key")
  cert_class=$(classify_cert "$cert_algo" "$sign_type")
  sym_class=$(classify_symmetric "$cipher")

  # Label
  local label
  label=$(compute_label "$kex_class" "$cert_class" "$sym_class")

  # Certificate expiry
  local days_left=9999
  if [[ "$not_after" != "unknown" ]]; then
    local expiry_epoch now_epoch
    expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  fi

  # Recommendations
  local recs_json=""
  while IFS= read -r rec; do
    [[ -z "$rec" ]] && continue
    recs_json+="\"$(echo "$rec" | sed 's/"/\\"/g')\","
  done < <(get_recommendations "$label" "$kex_class" "$cert_class")
  recs_json="[${recs_json%,}]"

  # Vulnerabilities list
  local vulns_json="["
  [[ "$kex_class" == "classical" ]] && vulns_json+="\"Key exchange vulnerable to Shor's algorithm\","
  [[ "$cert_class" == "rsa" ]]      && vulns_json+="\"RSA certificate broken by Shor's algorithm\","
  [[ "$cert_class" == "ecdsa" ]]    && vulns_json+="\"ECDSA certificate broken by Shor's algorithm\","
  [[ "$sym_class" == "marginal" ]]  && vulns_json+="\"AES-128 weakened to 64-bit effective by Grover's algorithm\","
  [[ "$sym_class" == "broken" ]]    && vulns_json+="\"Broken symmetric cipher in use — immediate action required\","
  [[ "$days_left" -lt 30 ]]         && vulns_json+="\"Certificate expires in ${days_left} days\","
  vulns_json="${vulns_json%,}]"

  # Emit JSON
  cat <<EOF
{
  "host": "${host}",
  "port": ${port},
  "service_type": "${service_type}",
  "scan_time": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "connection": {
    "tls_version": "${tls_version}",
    "cipher_suite": "${cipher}",
    "enc_algorithm": "${enc_algo}",
    "hash_algorithm": "${hash_algo}",
    "verify": "${verify}"
  },
  "key_exchange": {
    "algorithm": "${temp_key}",
    "classification": "${kex_class}"
  },
  "certificate": {
    "subject": "${subject}",
    "issuer": "${issuer}",
    "key_type": "${cert_algo}",
    "key_bits": ${key_bits},
    "signing_algorithm": "${sign_type}",
    "not_before": "${not_before}",
    "not_after": "${not_after}",
    "days_until_expiry": ${days_left},
    "chain_depth": ${chain_depth},
    "classification": "${cert_class}"
  },
  "symmetric": {
    "classification": "${sym_class}"
  },
  "quantum_assessment": {
    "label": "${label}",
    "key_exchange_safe": $([ "$kex_class" != "classical" ] && echo true || echo false),
    "certificate_safe": $([ "$cert_class" == "pqc" ] && echo true || echo false),
    "symmetric_safe": $([ "$sym_class" == "safe" ] && echo true || echo false),
    "vulnerabilities": ${vulns_json}
  },
  "recommendations": ${recs_json}
}
EOF
}

# ── Terminal pretty-print ──────────────────────────────────────────
label_colour() {
  case "$1" in
    FULLY_QUANTUM_SAFE) echo -e "${GREEN}${BOLD}" ;;
    PQC_READY)          echo -e "${CYAN}${BOLD}" ;;
    NOT_PQC_READY)      echo -e "${YELLOW}${BOLD}" ;;
    CRITICAL)           echo -e "${RED}${BOLD}" ;;
    *)                  echo -e "${DIM}" ;;
  esac
}

label_icon() {
  case "$1" in
    FULLY_QUANTUM_SAFE) echo "✦ FULLY QUANTUM SAFE" ;;
    PQC_READY)          echo "◈ PQC READY" ;;
    NOT_PQC_READY)      echo "◇ NOT PQC READY" ;;
    CRITICAL)           echo "✖ CRITICAL" ;;
    *)                  echo "? UNKNOWN" ;;
  esac
}

print_host_report() {
  local json="$1"

  local host tls cipher kex kex_class cert_type cert_bits cert_class
  local sym_class label not_after days_left subject issuer verify vulns recs

  host=$(echo "$json"       | grep -oP '(?<="host": ")[^"]+')
  port=$(echo "$json"       | grep -oP '(?<="port": )\d+' | head -1)
  tls=$(echo "$json"        | grep -oP '(?<="tls_version": ")[^"]+')
  cipher=$(echo "$json"     | grep -oP '(?<="cipher_suite": ")[^"]+')
  kex=$(echo "$json"        | grep -oP '(?<="algorithm": ")[^"]+' | head -1)
  kex_class=$(echo "$json"  | grep -oP '(?<="classification": ")[^"]+' | head -1)
  cert_type=$(echo "$json"  | grep -oP '(?<="key_type": ")[^"]+')
  cert_bits=$(echo "$json"  | grep -oP '(?<="key_bits": )\d+')
  cert_class=$(echo "$json" | grep -oP '(?<="classification": ")[^"]+' | tail -1)
  sym_class=$(echo "$json"  | grep -oP '(?<="classification": ")[^"]+' | sed -n '3p')
  label=$(echo "$json"      | grep -oP '(?<="label": ")[^"]+')
  not_after=$(echo "$json"  | grep -oP '(?<="not_after": ")[^"]+')
  days_left=$(echo "$json"  | grep -oP '(?<="days_until_expiry": )-?\d+')
  subject=$(echo "$json"    | grep -oP '(?<="subject": ")[^"]+')
  issuer=$(echo "$json"     | grep -oP '(?<="issuer": ")[^"]+')
  verify=$(echo "$json"     | grep -oP '(?<="verify": ")[^"]+')

  local lc
  lc=$(label_colour "$label")

  echo
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  ${host}:${port}${RESET}"
  echo -e "${lc}  $(label_icon "$label")${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"

  echo
  echo -e "${BOLD}Connection${RESET}"
  echo -e "  TLS version  : ${CYAN}${tls}${RESET}"
  echo -e "  Cipher suite : ${CYAN}${cipher}${RESET}"
  echo -e "  Cert verify  : ${verify}"

  echo
  echo -e "${BOLD}Quantum Analysis${RESET}"

  # Key exchange
  local kex_icon="${CROSS} ${RED}Vulnerable${RESET}"
  local kex_display="$kex"
  [[ "$kex" == "unknown" || -z "$kex" ]] && kex_display="Not detected (classical assumed)"
  [[ "$kex_class" == "pqc_hybrid" ]] && kex_icon="${TICK} ${GREEN}PQC Hybrid${RESET}"
  [[ "$kex_class" == "pqc_pure"   ]] && kex_icon="${TICK} ${GREEN}PQC Pure${RESET}"
  [[ "$kex_class" == "unknown"    ]] && kex_icon="${WARN} ${YELLOW}Not detected${RESET}"
  echo -e "  Key exchange : ${CYAN}${kex_display}${RESET}  →  ${kex_icon}"

  # Certificate
  local cert_icon="${CROSS} ${RED}Vulnerable${RESET}"
  [[ "$cert_class" == "pqc" ]] && cert_icon="${TICK} ${GREEN}PQC${RESET}"
  echo -e "  Certificate  : ${CYAN}${cert_type} (${cert_bits}-bit)${RESET}  →  ${cert_icon}"

  # Symmetric (data encryption)
  local sym_algo sym_icon sym_note
  sym_algo=$(echo "$cipher" | grep -oP "AES_\d+|CHACHA20" | head -1 || echo "?")
  sym_icon="${WARN} ${YELLOW}Marginal${RESET}"
  sym_note=""
  [[ "$sym_class" == "safe"    ]] && sym_icon="${TICK} ${GREEN}Safe${RESET}"    && sym_note=" (AES-256/ChaCha20 survive quantum)"
  [[ "$sym_class" == "marginal" ]] && sym_note=" (AES-128 weakened to ~64-bit by Grover's)"
  [[ "$sym_class" == "broken"  ]] && sym_icon="${CROSS} ${RED}Broken${RESET}"   && sym_note=" (3DES/RC4 — broken even classically)"
  [[ "$sym_class" == "unknown" ]] && sym_icon="${WARN} ${YELLOW}Not detected${RESET}"
  echo -e "  Data encrypt : ${CYAN}${sym_algo}${RESET}  →  ${sym_icon}${DIM}${sym_note}${RESET}"

  echo
  echo -e "${BOLD}Certificate Details${RESET}"
  echo -e "  Subject      : ${DIM}${subject}${RESET}"
  echo -e "  Issuer       : ${DIM}${issuer}${RESET}"
  echo -e "  Expires      : ${not_after} (${days_left} days)"
  if (( days_left < 0 )); then
    echo -e "  ${RED}${BOLD}  EXPIRED${RESET}"
  elif (( days_left < 30 )); then
    echo -e "  ${YELLOW}  Expiring soon — renew immediately${RESET}"
  fi

  echo
  echo -e "${BOLD}Recommendations${RESET}"
  local i=1
  while IFS= read -r rec; do
    [[ -z "$rec" ]] && continue
    echo -e "  ${i}. ${rec}"
    (( i++ ))
  done < <(echo "$json" | grep -oP '(?<="recommendations": \[)[^\]]+' | tr ',' '\n' | grep -oP '(?<=")[^"]+')
  echo
}

# ── Main scan loop ─────────────────────────────────────────────────
CBOM_ENTRIES=()
SCAN_START=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

$JSON_ONLY || {
  echo
  echo -e "${BOLD}${MAGENTA}"
  echo "  ██████╗  ██████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗ "
  echo "  ██╔══██╗██╔═══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗"
  echo "  ██████╔╝██║   ██║██║  ██║    ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝"
  echo "  ██╔═══╝ ██║▄▄ ██║██║  ██║    ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗"
  echo "  ██║     ╚██████╔╝██████╔╝    ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║"
  echo "  ╚═╝      ╚══▀▀═╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝"
  echo -e "${RESET}"
  echo -e "${DIM}  Cryptographic Bill of Materials — PQC Readiness Scanner v${VERSION}${RESET}"
  echo -e "${DIM}  Scanning ${#HOSTS[@]} host(s) — $(date -u '+%Y-%m-%d %H:%M UTC')${RESET}"
}

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
TICK="${GREEN}✔${RESET}"; CROSS="${RED}✘${RESET}"; WARN="${YELLOW}⚠${RESET}"

for host_entry in "${HOSTS[@]}"; do
  # Strip URL scheme and path — only the TLS layer matters, not the HTTP path
  local_entry="$host_entry"
  # Determine default port from scheme before stripping it
  port="443"
  if echo "$local_entry" | grep -qiE "^https://"; then
    port="443"
    local_entry="${local_entry#https://}"
    local_entry="${local_entry#http*://}"
  elif echo "$local_entry" | grep -qiE "^http://"; then
    port="80"
    local_entry="${local_entry#http://}"
  fi
  # Strip path, query string, fragment
  local_entry="${local_entry%%/*}"
  local_entry="${local_entry%%\?*}"
  local_entry="${local_entry%%#*}"
  # Support explicit host:port syntax (overrides scheme-derived port)
  if echo "$local_entry" | grep -qP ":\d+$"; then
    host="${local_entry%:*}"
    port="${local_entry##*:}"
  else
    host="$local_entry"
  fi

  $JSON_ONLY || echo -e "${DIM}  Scanning ${host}:${port}...${RESET}"

  result=$(scan_host "$host" "$port" "https")

  if echo "$result" | grep -q '"error"'; then
    $JSON_ONLY || echo -e "  ${RED}✘ Could not connect to ${host}:${port}${RESET}"
    result="{\"host\":\"${host}\",\"port\":${port},\"error\":\"connection_failed\",\"scan_time\":\"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}"
  else
    $JSON_ONLY || print_host_report "$result"
  fi

  CBOM_ENTRIES+=("$result")
done

# ── Write CBOM JSON ────────────────────────────────────────────────
CBOM_FILE="${OUTPUT_DIR}/cbom_$(date +%Y%m%d_%H%M%S).json"
{
  echo "{"
  echo "  \"cbom_version\": \"1.0\","
  echo "  \"generator\": \"PQC CBOM Scanner v${VERSION}\","
  echo "  \"scan_start\": \"${SCAN_START}\","
  echo "  \"scan_end\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
  echo "  \"total_hosts\": ${#CBOM_ENTRIES[@]},"
  echo "  \"assets\": ["
  local_sep=""
  for entry in "${CBOM_ENTRIES[@]}"; do
    echo "    ${local_sep}${entry}"
    local_sep=","
  done
  echo "  ]"
  echo "}"
} > "$CBOM_FILE"

$JSON_ONLY && cat "$CBOM_FILE" && exit 0

echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  CBOM saved: ${CBOM_FILE}${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo

# ── Optionally HTML report ───────────────────────────────
if $GENERATE_REPORT; then
  REPORT_SCRIPT="${SCRIPT_DIR}/generate_report.py"
  if [[ -f "$REPORT_SCRIPT" ]]; then
    echo -e "${DIM}Generating HTML report...${RESET}"
    python3 "$REPORT_SCRIPT" "$CBOM_FILE"
  else
    echo -e "${YELLOW}Report generator not found. Run generate_report.py manually.${RESET}"
  fi
fi

echo -e "${DIM}  Tip: run with --report to generate an HTML dashboard${RESET}"
echo
