#!/usr/bin/env bash
# ============================================================================
#  SecuToolkit — one-shot orchestrator
#  ---------------------------------------------------------------------------
#  Usage:
#     ./run_audit.sh example.com                     # full audit (top 100 ports)
#     ./run_audit.sh example.com "80,443,8080"       # custom ports
#  LEGAL: authorized testing only.
# ============================================================================
set -e

HOST="${1:?Usage: ./run_audit.sh <host> [ports]}"
PORTS="${2:-}"

cd "$(dirname "$0")"

echo "═══════════════════════════════════════════════════════════"
echo "  SecuToolkit — Rust RapidScan + Python SecuAudit"
echo "  Target: $HOST"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "→ [1/2] Compiling & running Rust port scanner…"
if [ ! -x ./rust/port_scanner ]; then
  rustc -O ./rust/port_scanner.rs -o ./rust/port_scanner
fi
if [ -n "$PORTS" ]; then
  ./rust/port_scanner "$HOST" "$PORTS"
else
  ./rust/port_scanner "$HOST" --top 100
fi

echo ""
echo "→ [2/2] Running Python web security audit…"
python3 ./python/web_security_audit.py --url "https://$HOST" \
       --out "./report_${HOST}.html" --json "./results_${HOST}.json"

echo ""
echo "✓ Done! Open ./report_${HOST}.html in a browser."
