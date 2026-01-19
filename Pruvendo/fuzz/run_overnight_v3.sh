#!/bin/bash
# Overnight fuzzing script v3 for poseidon_instead_of_ecc architecture
# Run: cd gosh_dark_dex_halo2_circuit && ./Pruvendo/fuzz/run_overnight_v3.sh
#
# 30 fuzz targets × 600 seconds each = ~5 hours total

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="fuzz_overnight_v3_$TIMESTAMP.log"
FUZZ_DIR="Pruvendo/fuzz"
TIME_PER_TARGET=600  # 10 minutes per target

# Stable targets (28 - excluding 2 known BC crashes)
STABLE_TARGETS=(
    fuzz_commitment_binding
    fuzz_completeness
    fuzz_determinism
    fuzz_digest_binding
    fuzz_digest_collision
    fuzz_digest_preimage
    fuzz_double_spend_attack
    fuzz_edge_cases
    fuzz_field_wrap
    fuzz_multikey_digest
    fuzz_poseidon_algebraic
    fuzz_poseidon_consistency
    fuzz_poseidon_gadget_consistency
    fuzz_poseidon_preimage
    fuzz_proof_malleability
    fuzz_proof_mutations
    fuzz_proof_replay
    fuzz_prover_error_paths
    fuzz_public_input_mismatch
    fuzz_sk_hiding
    fuzz_soundness
    fuzz_soundness_extended
    fuzz_structured_proof
    fuzz_sum_binding
    fuzz_token_binding
    fuzz_verifier_negative
    fuzz_witness_manipulation
    fuzz_zero_padding_security
)

# Known BC targets (will crash due to upstream issues)
BC_TARGETS=(
    fuzz_proving_key_bytes   # BC-001: halo2curves panic
    fuzz_verifier_bytes      # BC-001/BC-003: halo2curves panic
)

echo "=== Overnight Fuzzing v3 (poseidon_instead_of_ecc) ===" | tee "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "Targets: ${#STABLE_TARGETS[@]} stable, ${#BC_TARGETS[@]} known BC" | tee -a "$LOG_FILE"
echo "Time per target: ${TIME_PER_TARGET}s" | tee -a "$LOG_FILE"
echo "Estimated total time: $((${#STABLE_TARGETS[@]} * TIME_PER_TARGET / 60)) minutes" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

TOTAL_PASSED=0
TOTAL_FAILED=0

for target in "${STABLE_TARGETS[@]}"; do
    echo "=== [$((TOTAL_PASSED + TOTAL_FAILED + 1))/${#STABLE_TARGETS[@]}] $target ===" | tee -a "$LOG_FILE"
    echo "Start: $(date)" | tee -a "$LOG_FILE"
    
    if cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- -max_total_time=$TIME_PER_TARGET 2>&1 | tee -a "$LOG_FILE" | tail -5; then
        echo "RESULT: PASS" | tee -a "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "RESULT: FAIL" | tee -a "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
    echo "" | tee -a "$LOG_FILE"
done

echo "=== SUMMARY ===" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Passed: $TOTAL_PASSED / ${#STABLE_TARGETS[@]}" | tee -a "$LOG_FILE"
echo "Failed: $TOTAL_FAILED" | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"

