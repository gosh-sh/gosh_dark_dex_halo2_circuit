#!/bin/bash
# Quick smoke test for fuzz targets
# Run: cd gosh_dark_dex_halo2_circuit && ./Pruvendo/fuzz/quick_smoke_test.sh
#
# Tests each target for 5 seconds to ensure no immediate crashes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

FUZZ_DIR="Pruvendo/fuzz"
TIME_PER_TARGET=5

# Get all targets
TARGETS=$(cargo +nightly fuzz list --fuzz-dir "$FUZZ_DIR" 2>/dev/null)

# Exclude known BC targets (upstream bugs that cause panics on corrupted input)
# BC-001: fuzz_proving_key_bytes, fuzz_verifier_bytes, fuzz_verify_with_vk_bytes
# BC-003/BC-005: fuzz_read_kzg_params
EXCLUDE="fuzz_proving_key_bytes fuzz_verifier_bytes fuzz_verify_with_vk_bytes fuzz_read_kzg_params"

echo "=== Quick Smoke Test ==="
echo "Date: $(date)"
echo "Time per target: ${TIME_PER_TARGET}s"
echo ""

PASSED=0
FAILED=0

for target in $TARGETS; do
    # Skip excluded targets
    if echo "$EXCLUDE" | grep -qw "$target"; then
        echo "[$target] SKIPPED (known BC)"
        continue
    fi
    
    printf "[$target] "
    if cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- -max_total_time=$TIME_PER_TARGET 2>&1 | grep -q "Done"; then
        echo "✅ PASS"
        ((PASSED++))
    else
        echo "❌ FAIL"
        ((FAILED++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

