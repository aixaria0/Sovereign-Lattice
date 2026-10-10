#!/usr/bin/env bash
set -euo pipefail

CXP_DIGEST="${CXP_DIGEST:-8fe0c9456f4c9a64f47aa0e265d3e18972128f7979dc251ac4decdab1ba19dde}"
if [[ ! "${CXP_DIGEST}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "invalid CXP_DIGEST: expected 64 hex chars" >&2
    exit 2
fi
CXP_DIGEST="${CXP_DIGEST,,}"

printf '%s\n' "======================================================="
printf '%s\n' " SOVEREIGN-LATTICE: 4-NODE CXP PBFT FINALITY TEST"
printf '%s\n' "======================================================="
printf 'Bound CXP digest: %s\n' "${CXP_DIGEST}"

printf '%s\n' "[1/4] Compiling release validator binary..."
cargo build --release --bin sovereign_lattice

rm -f node_*.log consensus_wal_node_*.log
rm -rf artifacts
mkdir -p artifacts

PIDS=()
cleanup() {
    printf '%s\n' "Tearing down validator cluster..."
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

printf '%s\n' "[2/4] Spawning four independent validator processes..."
for id in 0 1 2 3; do
    PORT=$((8000 + id))
    if [[ "${id}" -eq 0 ]]; then
        NODE_ID="${id}" \
        TOTAL_NODES=4 \
        THRESHOLD=3 \
        BIND_ADDR="127.0.0.1:${PORT}" \
        WAL_PATH="consensus_wal_node_${id}.log" \
        AUTO_PROPOSE_DIGEST_HEX="${CXP_DIGEST}" \
        ./target/release/sovereign_lattice > "node_${id}.log" 2>&1 &
    else
        NODE_ID="${id}" \
        TOTAL_NODES=4 \
        THRESHOLD=3 \
        BIND_ADDR="127.0.0.1:${PORT}" \
        WAL_PATH="consensus_wal_node_${id}.log" \
        ./target/release/sovereign_lattice > "node_${id}.log" 2>&1 &
    fi
    PIDS+=("$!")
done

printf '%s\n' "[3/4] Waiting for DKG-authenticated proposal and PBFT commit..."
committed=0
for _ in $(seq 1 30); do
    alive=1
    for index in 0 1 2 3; do
        if ! kill -0 "${PIDS[$index]}" 2>/dev/null; then
            alive=0
            break
        fi
    done
    if [[ "${alive}" -eq 0 ]]; then
        break
    fi

    committed=1
    for id in 0 1 2 3; do
        if ! grep -Eq "CXP_FINALITY .*digest=${CXP_DIGEST} .*quorum=3 .*scope=LOCAL_4_PROCESS_LOOPBACK_PBFT" "node_${id}.log"; then
            committed=0
            break
        fi
    done
    if [[ "${committed}" -eq 1 ]]; then
        break
    fi
    sleep 0.5
done

if [[ "${committed}" -ne 1 ]]; then
    echo "PBFT cluster did not produce a 3-of-4 commit observation on all four replicas." >&2
    for id in 0 1 2 3; do
        echo "==================== Node ${id} Logs ====================" >&2
        cat "node_${id}.log" >&2 || true
    done
    exit 1
fi

if ! grep -Eq "CXP_PROPOSAL leader=0 .*digest=${CXP_DIGEST} .*scope=LOCAL_4_PROCESS_LOOPBACK_PBFT" node_0.log; then
    echo "Leader did not record the DKG-authenticated bound proposal." >&2
    cat node_0.log >&2
    exit 1
fi

for id in 0 1 2 3; do
    if ! grep -q "DKG SUCCESS" "node_${id}.log"; then
        echo "Node ${id} did not complete DKG." >&2
        exit 1
    fi
done

cat > artifacts/sovereign-cxp-cluster-finality.json <<EOF
{
  "schema": "sovereign-cxp-cluster-finality/v1",
  "status": "CONFIRMED",
  "scope": "LOCAL_4_PROCESS_LOOPBACK_PBFT",
  "digest_sha256": "${CXP_DIGEST}",
  "total_nodes": 4,
  "fault_tolerance": 1,
  "quorum_size": 3,
  "node_commit_observations": 4,
  "process_independence": "CONFIRMED",
  "network_transport": "LOOPBACK_TCP_CONFIRMED",
  "dkg": "CONFIRMED",
  "local_cluster_finality": "CONFIRMED",
  "host_independence": "UNKNOWN",
  "organizational_independence": "UNKNOWN",
  "cross_host_finality": "UNKNOWN",
  "global_finality": "UNKNOWN"
}
EOF

printf '%s\n' "[4/4] Verified DKG + network PBFT commit on all four validator processes."
cat artifacts/sovereign-cxp-cluster-finality.json
