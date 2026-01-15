#!/bin/bash
# Overnight Fuzzing Script - KNOWN CRASHING targets
# Created: 2026-01-16
# 
# These targets have KNOWN crashes due to documented bug candidates:
# - BC-007: deposit_sum collision (fuzz_multikey_digest, fuzz_digest_collision)
# - BC-005: upstream halo2_proofs panic (fuzz_proving_key_bytes)
# - BC-001: upstream halo2curves panic (fuzz_verifier_bytes)
#
# Running these will produce crashes - this is EXPECTED BEHAVIOR.
# Use this script only to:
# 1. Verify crashes are still reproducible
# 2. Check if upstream fixes resolve the issues
# 3. Collect more crash samples for analysis

set -e

# Configuration
FUZZ_TIME=${1:-60}  # Default: 1 minute (short, since we expect crashes)
FUZZ_DIR="Pruvendo/fuzz"
LOG_FILE="fuzz_known_crashes_$(date +%Y%m%d_%H%M%S).log"

# Known crashing targets with their BC references
TARGETS=(
    # BC-007: deposit_sum collision - mathematically expected, not exploitable
    "fuzz_multikey_digest"      # BC-007
    "fuzz_digest_collision"     # BC-007
    
    # BC-005: upstream halo2_proofs panic on malformed VK
    "fuzz_proving_key_bytes"    # BC-005
    
    # BC-001: upstream halo2curves panic on short input
    "fuzz_verifier_bytes"       # BC-001
)

echo "=== Known Crashing Targets (expected behavior) ===" | tee "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "Time per target: ${FUZZ_TIME}s" | tee -a "$LOG_FILE"
echo "Total targets: ${#TARGETS[@]}" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "⚠️  WARNING: These targets are EXPECTED to crash!" | tee -a "$LOG_FILE"
echo "   BC-007: fuzz_multikey_digest, fuzz_digest_collision" | tee -a "$LOG_FILE"
echo "   BC-005: fuzz_proving_key_bytes" | tee -a "$LOG_FILE"
echo "   BC-001: fuzz_verifier_bytes" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

CRASHED=0

for target in "${TARGETS[@]}"; do
    echo "----------------------------------------" | tee -a "$LOG_FILE"
    echo "[$(date +%H:%M:%S)] Running: $target" | tee -a "$LOG_FILE"
    
    # Run fuzzer (expect crashes)
    timeout $((FUZZ_TIME + 30)) cargo +nightly fuzz run "$target" \
        --fuzz-dir "$FUZZ_DIR" \
        -- -max_total_time="$FUZZ_TIME" 2>&1 | tee -a "$LOG_FILE" | tail -5 || true
    
    # Check for crashes
    CRASH_DIR="$FUZZ_DIR/artifacts/$target"
    CRASH_COUNT=$(find "$CRASH_DIR" -name 'crash-*' 2>/dev/null | wc -l | tr -d ' ')
    
    if [ "$CRASH_COUNT" -gt 0 ]; then
        echo "⚠️  CRASH (expected): $target - $CRASH_COUNT crash files" | tee -a "$LOG_FILE"
        ((CRASHED++))
    else
        echo "❓ NO CRASH: $target (unexpected - maybe fixed?)" | tee -a "$LOG_FILE"
    fi
done

echo "" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "=== SUMMARY ===" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Total: ${#TARGETS[@]}" | tee -a "$LOG_FILE"
echo "Crashed (expected): $CRASHED" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"

