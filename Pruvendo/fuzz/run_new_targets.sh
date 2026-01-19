#!/bin/bash
# Overnight fuzzing for NEW targets only
# Run: cd gosh_dark_dex_halo2_circuit && ./Pruvendo/fuzz/run_new_targets.sh
#
# These targets have NOT been through overnight fuzzing yet.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="fuzz_new_targets_$TIMESTAMP.log"
FUZZ_DIR="Pruvendo/fuzz"
TIME_PER_TARGET=${1:-600}  # Default 10 min, can override: ./run_new_targets.sh 1800

# NEW targets (poseidon_instead_of_ecc specific, not yet fuzzed overnight)
NEW_TARGETS=(
    fuzz_commitment_binding
    fuzz_digest_binding
    fuzz_sk_hiding
    fuzz_zero_padding_security
)

echo "=== Overnight Fuzzing: NEW Targets ===" | tee "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "Targets: ${#NEW_TARGETS[@]}" | tee -a "$LOG_FILE"
echo "Time per target: ${TIME_PER_TARGET}s" | tee -a "$LOG_FILE"
echo "Estimated total time: $((${#NEW_TARGETS[@]} * TIME_PER_TARGET / 60)) minutes" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

PASSED=0
FAILED=0

for target in "${NEW_TARGETS[@]}"; do
    echo "=== [$((PASSED + FAILED + 1))/${#NEW_TARGETS[@]}] $target ===" | tee -a "$LOG_FILE"
    echo "Start: $(date)" | tee -a "$LOG_FILE"
    
    if cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- -max_total_time=$TIME_PER_TARGET 2>&1 | tee -a "$LOG_FILE" | tail -5; then
        echo "RESULT: PASS" | tee -a "$LOG_FILE"
        ((PASSED++))
    else
        echo "RESULT: FAIL" | tee -a "$LOG_FILE"
        ((FAILED++))
    fi
    echo "" | tee -a "$LOG_FILE"
done

echo "=== SUMMARY ===" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Passed: $PASSED / ${#NEW_TARGETS[@]}" | tee -a "$LOG_FILE"
echo "Failed: $FAILED" | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"

