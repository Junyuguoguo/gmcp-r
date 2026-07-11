#!/bin/bash
# scripts/apply_netem.sh
#
# Apply tc/netem rules to a network interface.
# Usage: sudo ./scripts/apply_netem.sh <condition> [interface]
#
# Conditions:
#   control     - No impairment
#   mild        - Light loss + moderate delay (good WiFi)
#   mobile      - Mobile 4G-like (moderate loss + jitter)
#   poor        - Poor connectivity (high loss + delay)
#   severe      - Severe degradation (satellite-like)
#   loss_heavy  - Heavy packet loss (congested network)

set -euo pipefail

# Ensure cleanup on exit
cleanup() {
    echo "[NETEM] Cleaning up tc rules on ${IFACE} ..."
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
}
trap cleanup EXIT

CONDITION="${1:-}"
IFACE="${2:-lo}"

if [[ -z "${CONDITION}" ]]; then
    echo "Usage: sudo $0 <condition> [interface]"
    echo ""
    echo "Conditions: control, mild, mobile, poor, severe, loss_heavy"
    echo ""
    echo "Default interface: lo"
    exit 1
fi

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (use sudo)."
    exit 1
fi

# Clear existing rules
tc qdisc del dev "${IFACE}" root 2>/dev/null || true
sleep 0.1

echo "[NETEM] Applying condition '${CONDITION}' on interface '${IFACE}'"

case "${CONDITION}" in
    control)
        echo "[NETEM] No impairment (baseline)"
        # No tc rules — clean pipe
        ;;
    mild)
        echo "[NETEM] loss=1% delay=30ms jitter=10ms"
        tc qdisc add dev "${IFACE}" root netem delay 30ms 10ms loss 1%
        ;;
    mobile)
        echo "[NETEM] loss=2% delay=60ms jitter=30ms reorder=5%"
        tc qdisc add dev "${IFACE}" root netem delay 60ms 30ms loss 2% reorder 5%
        ;;
    poor)
        echo "[NETEM] loss=5% delay=100ms jitter=50ms reorder=5%"
        tc qdisc add dev "${IFACE}" root netem delay 100ms 50ms loss 5% reorder 5%
        ;;
    severe)
        echo "[NETEM] loss=10% delay=200ms jitter=80ms reorder=10%"
        tc qdisc add dev "${IFACE}" root netem delay 200ms 80ms loss 10% reorder 10%
        ;;
    loss_heavy)
        echo "[NETEM] loss=20% delay=50ms jitter=20ms reorder=5%"
        tc qdisc add dev "${IFACE}" root netem delay 50ms 20ms loss 20% reorder 5%
        ;;
    *)
        echo "[ERROR] Unknown condition: ${CONDITION}"
        echo "        Valid: control, mild, mobile, poor, severe, loss_heavy"
        exit 1
        ;;
esac

echo "[NETEM] Active rules:"
tc qdisc show dev "${IFACE}"
echo ""
echo "[NETEM] Condition '${CONDITION}' applied. Press Ctrl+C to clean up."

# Keep running until interrupted (trap will clean up)
if [[ "${CONDITION}" != "control" ]]; then
    echo "[NETEM] Keeping alive ... (Ctrl+C to stop and clean up)"
    # Wait forever — cleanup trap handles exit
    while true; do sleep 3600; done
fi
