#!/bin/bash
# Overnight Fuzzing Script v2 - NEW + TRANSIENT targets
# Created: 2026-01-15
# Updated: 2026-01-16
#
# This script includes:
# - 16 NEW targets (added after first overnight run)
# - 2 TRANSIENT targets (crashed in v1, need long-run verification)
#
# NOTE: Known crashing targets (BC-001, BC-005, BC-007) in run_overnight_known_crashes.sh

set -e

# Configuration
FUZZ_TIME=${1:-600}  # Default: 10 minutes per target
FUZZ_DIR="Pruvendo/fuzz"
LOG_FILE="fuzz_overnight_v2_$(date +%Y%m%d_%H%M%S).log"

# ============================================
# TRANSIENT targets - crashed in v1 overnight, need long-run verification
# ============================================
# Crash files don't reproduce on short runs, but crashed during 5-hour overnight.
# Possible causes: OOM, timeout, race condition. Need to verify on long runs.
TRANSIENT_TARGETS=(
    "fuzz_proof_mutations"
    "fuzz_structured_proof"
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

# Combine all targets (18 total: 2 transient + 16 new)
TARGETS=("${TRANSIENT_TARGETS[@]}" "${NEW_TARGETS[@]}")

echo "=== Overnight Fuzzing v2: NEW + TRANSIENT Targets ===" | tee "$LOG_FILE"
echo "TRANSIENT targets (2): ${TRANSIENT_TARGETS[*]}" | tee -a "$LOG_FILE"
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

