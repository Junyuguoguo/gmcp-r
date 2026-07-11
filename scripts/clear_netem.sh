#!/bin/bash
# scripts/clear_netem.sh
#
# Remove all tc/netem rules from a network interface.
# Usage: sudo ./scripts/clear_netem.sh [interface]

set -euo pipefail

IFACE="${1:-lo}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (use sudo)."
    exit 1
fi

echo "[NETEM] Clearing tc rules on '${IFACE}' ..."

tc qdisc del dev "${IFACE}" root 2>/dev/null && \
    echo "[NETEM] Rules cleared." || \
    echo "[NETEM] No rules to clear (already clean)."

echo "[NETEM] Current state:"
tc qdisc show dev "${IFACE}"
