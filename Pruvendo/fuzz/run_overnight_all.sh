#!/bin/bash
#
# Overnight Fuzzing Script - ALL TARGETS (poseidon_instead_of_ecc)
# Запускает все 39 fuzz targets для ночного прогона
#
# Использование:
#   ./Pruvendo/fuzz/run_overnight_all.sh [time_per_target_seconds]
#
# По умолчанию: 600 секунд (10 минут) на каждый target
# Для ночного запуска: ./run_overnight_all.sh 900 (15 мин на target = ~10 часов)
#
# ИСКЛЮЧЕНЫ (known BC - upstream panics):
#   - fuzz_proving_key_bytes (BC-001: upstream halo2curves panic)
#   - fuzz_verifier_bytes (BC-005: upstream halo2_proofs panic)
#   - fuzz_read_kzg_params (BC-003/BC-005: upstream panic)
#   - fuzz_verify_with_vk_bytes (BC-001: upstream panic)

set -e

TIME_PER_TARGET=${1:-600}  # 10 минут по умолчанию

# Known BC targets - skip these (upstream panics)
EXCLUDE_TARGETS=(
    "fuzz_proving_key_bytes"
    "fuzz_verifier_bytes"
    "fuzz_read_kzg_params"
    "fuzz_verify_with_vk_bytes"
)

# Get all targets
ALL_TARGETS=$(cargo +nightly fuzz list --fuzz-dir Pruvendo/fuzz 2>/dev/null)

# Filter out excluded targets
TARGETS=()
for target in $ALL_TARGETS; do
    skip=false
    for excluded in "${EXCLUDE_TARGETS[@]}"; do
        if [ "$target" == "$excluded" ]; then
            skip=true
            break
        fi
    done
    if [ "$skip" == "false" ]; then
        TARGETS+=("$target")
    fi
done

TOTAL_TARGETS=${#TARGETS[@]}
ESTIMATED_TIME=$((TOTAL_TARGETS * TIME_PER_TARGET / 60))

echo "=============================================="
echo "DarkDex Overnight Fuzzing - ALL TARGETS"
echo "=============================================="
echo "Total targets: $TOTAL_TARGETS (excluded: ${#EXCLUDE_TARGETS[@]} known BC)"
echo "Time per target: ${TIME_PER_TARGET}s"
echo "Estimated total time: ~${ESTIMATED_TIME} minutes"
echo "Start time: $(date)"
echo "=============================================="

RESULTS_FILE="Pruvendo/fuzz/overnight_all_$(date +%Y%m%d_%H%M%S).log"
echo "Results will be saved to: $RESULTS_FILE"
echo ""

run_target() {
    local target=$1
    local timeout=$2
    local index=$3
    local total=$4
    
    echo "----------------------------------------------"
    echo "[$index/$total] [$(date +%H:%M:%S)] Running: $target (${timeout}s)"
    echo "----------------------------------------------"
    
    START=$(date +%s)
    
    set +e
    OUTPUT=$(cargo +nightly fuzz run "$target" --fuzz-dir Pruvendo/fuzz -- -max_total_time="$timeout" 2>&1)
    EXITCODE=$?
    set -e
    
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    # Extract runs count
    RUNS=$(echo "$OUTPUT" | grep -oE '#[0-9]+\s+DONE' | grep -oE '[0-9]+' | tail -1)
    RUNS=${RUNS:-0}
    
    # Check for crashes
    CRASHES=$(find Pruvendo/fuzz/artifacts/"$target"/ -name 'crash-*' 2>/dev/null | wc -l | tr -d ' ')
    
    STATUS="OK"
    if [ "$EXITCODE" -ne 0 ]; then
        STATUS="CRASH"
    fi
    
    echo "[$target] Runs: $RUNS, Crashes: $CRASHES, Time: ${ELAPSED}s, Status: $STATUS"
    echo "$target,$RUNS,$CRASHES,$ELAPSED,$STATUS" >> "$RESULTS_FILE"
}

echo "target,runs,crashes,time_sec,status" > "$RESULTS_FILE"

INDEX=0
for target in "${TARGETS[@]}"; do
    INDEX=$((INDEX + 1))
    run_target "$target" "$TIME_PER_TARGET" "$INDEX" "$TOTAL_TARGETS"
done

echo ""
echo "=============================================="
echo "Fuzzing completed at $(date)"
echo "Results saved to: $RESULTS_FILE"
echo "=============================================="

# Summary
echo ""
echo "=== SUMMARY ==="
TOTAL_CRASHES=$(find Pruvendo/fuzz/artifacts/ -name 'crash-*' 2>/dev/null | wc -l | tr -d ' ')
echo "Total crash files: $TOTAL_CRASHES"

if [ "$TOTAL_CRASHES" -gt 0 ]; then
    echo ""
    echo "Crash files by target:"
    for target in "${TARGETS[@]}"; do
        COUNT=$(find Pruvendo/fuzz/artifacts/"$target"/ -name 'crash-*' 2>/dev/null | wc -l | tr -d ' ')
        if [ "$COUNT" -gt 0 ]; then
            echo "  $target: $COUNT"
        fi
    done
fi

echo ""
echo "=== EXCLUDED (known BC) ==="
for excluded in "${EXCLUDE_TARGETS[@]}"; do
    echo "  - $excluded"
done

