#!/bin/bash
# Quick check for known Bug Candidates
# Run: cd gosh_dark_dex_halo2_circuit && ./Pruvendo/fuzz/check_known_bc.sh
#
# Just verifies if BC crashes still occur (no extended fuzzing needed)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

FUZZ_DIR="Pruvendo/fuzz"

# Known BC targets with expected crash
BC_TARGETS=(
    "fuzz_proving_key_bytes:BC-001:halo2curves panic on corrupted bytes"
    "fuzz_verifier_bytes:BC-001/BC-003:halo2curves/halo2_proofs panic"
)

echo "=== Checking Known Bug Candidates ==="
echo "Date: $(date)"
echo ""

for entry in "${BC_TARGETS[@]}"; do
    IFS=':' read -r target bc_id description <<< "$entry"
    
    echo "--- $target ($bc_id) ---"
    echo "Expected: $description"
    
    # Run just 1000 iterations to trigger crash
    if timeout 30 cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- -max_total_time=5 2>&1 | tail -10; then
        echo "STATUS: ✅ FIXED (no crash)"
    else
        echo "STATUS: ⚠️  STILL CRASHES ($bc_id confirmed)"
    fi
    echo ""
done

echo "=== Done ==="

