#!/bin/bash
# Overnight Fuzzing Script - STABLE v2
# Created: 2026-01-16
# 
# This script includes all targets that passed overnight testing:
# - Original stable targets (20 from v1)
# - Transient targets now confirmed stable (2)
# - New targets confirmed stable (16)
#
# Total: 38 stable targets
# Known crashing targets (4) are in run_overnight_known_crashes.sh

set -e

# Configuration
FUZZ_TIME=${1:-600}  # Default: 10 minutes per target
FUZZ_DIR="Pruvendo/fuzz"
LOG_FILE="fuzz_stable_v2_$(date +%Y%m%d_%H%M%S).log"

# ============================================
# STABLE v1 targets (20) - original stable
# ============================================
STABLE_V1_TARGETS=(
    # Fast targets
    "fuzz_key_sum_collision"
    "fuzz_deposit_sum_collision"
    "fuzz_field_wrap"
    "fuzz_poseidon_consistency"
    "fuzz_limb_overflow"
    # Medium targets
    "fuzz_soundness"
    "fuzz_soundness_extended"
    "fuzz_completeness"
    "fuzz_determinism"
    "fuzz_token_binding"
    "fuzz_sum_binding"
    "fuzz_edge_cases"
    "fuzz_vault_rand_binding"
    "fuzz_vault_zero_binding"
    "fuzz_poseidon_preimage"
    "fuzz_negated_y"
    "fuzz_ec_coordinate_manipulation"
    "fuzz_witness_manipulation"
    # Heavy targets
    "fuzz_proof_replay"
    "fuzz_ec_invalid_points"
)

# ============================================
# TRANSIENT targets - now confirmed stable after 5h run
# ============================================
TRANSIENT_NOW_STABLE=(
    "fuzz_proof_mutations"
    "fuzz_structured_proof"
)

# ============================================
# NEW targets (16) - confirmed stable on 2026-01-16
# ============================================
NEW_STABLE_TARGETS=(
    "fuzz_constraint_bypass"
    "fuzz_public_input_mismatch"
    "fuzz_weak_generator"
    "fuzz_digest_preimage"
    "fuzz_cross_keypair_attack"
    "fuzz_limb_reconstruction"
    "fuzz_poseidon_gadget_consistency"
    "fuzz_poseidon_algebraic"
    "fuzz_scalar_multiply_verification"
    "fuzz_limb_overflow_attack"
    "fuzz_prover_error_paths"
    "fuzz_verifier_negative"
    "fuzz_proof_malleability"
    "fuzz_scalar_edge_cases"
    "fuzz_double_spend_attack"
    "fuzz_range_check_bypass"
)

# Combine all targets (38 total)
TARGETS=("${STABLE_V1_TARGETS[@]}" "${TRANSIENT_NOW_STABLE[@]}" "${NEW_STABLE_TARGETS[@]}")

echo "=== Overnight Fuzzing: STABLE v2 (all confirmed stable) ===" | tee "$LOG_FILE"
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

