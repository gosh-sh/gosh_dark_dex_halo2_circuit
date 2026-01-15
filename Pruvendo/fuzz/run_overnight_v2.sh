#!/bin/bash
# Overnight Fuzzing Script v2 - NEW + RETRY targets
# Created: 2026-01-15
#
# This script includes:
# - 16 NEW targets (added after first overnight run)
# - 4 RETRY targets (crashed in v1, need re-testing)
#
# Categories:
# - Deep protocol analysis (6 targets)
# - Component audits: Poseidon, FpChip, scalar_multiply (4 targets)
# - P1+P2 testing plan completion (3 targets)
# - Edge case testing (3 targets)
# - RETRY: Crashed in v1 overnight run (4 targets)

set -e

# Configuration
FUZZ_TIME=${1:-600}  # Default: 10 minutes per target
FUZZ_DIR="Pruvendo/fuzz"
LOG_FILE="fuzz_overnight_v2_$(date +%Y%m%d_%H%M%S).log"

# ============================================
# RETRY targets - crashed in v1, need re-testing
# ============================================
# These crashed in the first overnight run:
# - fuzz_multikey_digest: BC-007 deposit_sum collision (expected behavior)
# - fuzz_digest_collision: BC-007 same issue
# - fuzz_proving_key_bytes: BC-005 upstream halo2_proofs panic on malformed data
# - fuzz_verifier_bytes: BC-001 upstream halo2curves panic on short input
RETRY_TARGETS=(
    "fuzz_multikey_digest"
    "fuzz_digest_collision"
    "fuzz_proving_key_bytes"
    "fuzz_verifier_bytes"
)

# ============================================
# NEW targets (16 total) - not run in v1
# ============================================
NEW_TARGETS=(
    # Deep protocol analysis targets
    "fuzz_constraint_bypass"
    "fuzz_public_input_mismatch"
    "fuzz_weak_generator"
    "fuzz_digest_preimage"
    "fuzz_cross_keypair_attack"
    "fuzz_limb_reconstruction"

    # Component audit targets (Poseidon, FpChip)
    "fuzz_poseidon_gadget_consistency"
    "fuzz_poseidon_algebraic"
    "fuzz_scalar_multiply_verification"
    "fuzz_limb_overflow_attack"

    # P1+P2 testing plan targets
    "fuzz_prover_error_paths"
    "fuzz_verifier_negative"
    "fuzz_proof_malleability"

    # Edge case testing targets
    "fuzz_scalar_edge_cases"
    "fuzz_double_spend_attack"
    "fuzz_range_check_bypass"
)

# Combine all targets
TARGETS=("${RETRY_TARGETS[@]}" "${NEW_TARGETS[@]}")

echo "=== Overnight Fuzzing v2: NEW + RETRY Targets ===" | tee "$LOG_FILE"
echo "RETRY targets (4): ${RETRY_TARGETS[*]}" | tee -a "$LOG_FILE"
echo "NEW targets (16): see log for details" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "Time per target: ${FUZZ_TIME}s" | tee -a "$LOG_FILE"
echo "Total targets: ${#TARGETS[@]}" | tee -a "$LOG_FILE"
echo "Estimated time: $(( ${#TARGETS[@]} * FUZZ_TIME / 60 )) minutes" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

PASSED=0
FAILED=0
CRASHED=0

for target in "${TARGETS[@]}"; do
    echo "----------------------------------------" | tee -a "$LOG_FILE"
    echo "[$(date +%H:%M:%S)] Running: $target" | tee -a "$LOG_FILE"
    
    # Run fuzzer
    if timeout $((FUZZ_TIME + 30)) cargo +nightly fuzz run "$target" \
        --fuzz-dir "$FUZZ_DIR" \
        -- -max_total_time="$FUZZ_TIME" 2>&1 | tee -a "$LOG_FILE" | tail -5; then
        
        # Check for crashes
        CRASH_DIR="$FUZZ_DIR/artifacts/$target"
        if [ -d "$CRASH_DIR" ] && [ "$(ls -A "$CRASH_DIR"/crash-* 2>/dev/null)" ]; then
            echo "⚠️  CRASH FOUND in $target" | tee -a "$LOG_FILE"
            ((CRASHED++))
        else
            echo "✅ PASSED: $target" | tee -a "$LOG_FILE"
            ((PASSED++))
        fi
    else
        echo "❌ FAILED: $target (timeout or error)" | tee -a "$LOG_FILE"
        ((FAILED++))
    fi
done

echo "" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "=== SUMMARY ===" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Total: ${#TARGETS[@]}" | tee -a "$LOG_FILE"
echo "Passed: $PASSED" | tee -a "$LOG_FILE"
echo "Crashed: $CRASHED" | tee -a "$LOG_FILE"
echo "Failed: $FAILED" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# List all crashes found
echo "=== CRASHES ===" | tee -a "$LOG_FILE"
find "$FUZZ_DIR/artifacts" -name 'crash-*' -newer "$LOG_FILE" 2>/dev/null | tee -a "$LOG_FILE" || echo "No new crashes" | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"

