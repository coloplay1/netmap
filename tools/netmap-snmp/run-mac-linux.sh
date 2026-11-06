#!/bin/sh
# netmap-snmp launcher for macOS / Linux
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then exec python3 netmap_snmp.py "$@"; fi
echo "找不到 python3，請先安裝 Python 3。"
exit 1
