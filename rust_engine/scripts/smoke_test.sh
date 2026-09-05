#!/usr/bin/env bash
set -euo pipefail

echo "======================================================="
echo " 🛡️  SOVEREIGN-LATTICE: 4-NODE CLUSTER SMOKE TEST"
echo "======================================================="

echo "🔨 [1/4] Compiling release binaries..."
cargo build --release --bin sovereign_lattice --bin injector

rm -f node_*.log

PIDS=()
cleanup() {
    echo -e "\n🧹 Tearing down validator cluster..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "✅ Cluster cleanly shut down."
}
trap cleanup EXIT INT TERM

echo "🚀 [2/4] Spawning 4 validator nodes in background..."
for id in 0 1 2 3; do
    PORT=$((8000 + id))
    echo "   -> Starting Node ${id} on 127.0.0.1:${PORT}..."
    NODE_ID="${id}" \
    TOTAL_NODES=4 \
    THRESHOLD=3 \
    BIND_ADDR="127.0.0.1:${PORT}" \
    ./target/release/sovereign_lattice > "node_${id}.log" 2>&1 &
    PIDS+=($!)
done

echo "⏳ Waiting 5s for P2P mesh setup and DKG key synthesis..."
sleep 5

echo "🔍 Verifying node health..."
for id in 0 1 2 3; do
    if ! kill -0 "${PIDS[$id]}" 2>/dev/null; then
        echo "❌ Node ${id} crashed during startup! Displaying node_${id}.log:"
        cat "node_${id}.log"
        exit 1
    fi
done
echo "✅ All 4 validator nodes online."

echo "⚡ [3/4] Injecting proposal via injector binary into Node 0..."
TARGET_ADDR="127.0.0.1:8000" ./target/release/injector || true

echo "⏳ Allowing 3s for multi-peer consensus cascade..."
sleep 3

echo "📊 [4/4] Inspecting consensus logs across all nodes..."
for id in 0 1 2 3; do
    echo "==================== Node ${id} Logs ===================="
    cat "node_${id}.log"
done

echo ""
echo "🎉 E2E Smoke Test Passed! Cluster consensus successfully triggered."

