#!/bin/bash
#
# Overnight Fuzzing Script - STABLE TARGETS (v1 - original)
# Запускает проверенные стабильные fuzz targets
#
# Использование:
#   ./Pruvendo/fuzz/run_overnight.sh [time_per_target_seconds]
#
# По умолчанию: 300 секунд (5 минут) на каждый target
# Для ночного запуска рекомендуется: ./run_overnight.sh 3600 (1 час на target)
#
# ВНИМАНИЕ: Исключены 4 targets, которые упали в первом ночном прогоне:
#   - fuzz_multikey_digest (crash - BC-007 deposit_sum collision)
#   - fuzz_digest_collision (crash - BC-007 deposit_sum collision)
#   - fuzz_proving_key_bytes (crash - BC-005 upstream halo2_proofs panic)
#   - fuzz_verifier_bytes (crash - BC-001 upstream halo2curves panic)
# Эти targets находятся в run_overnight_v2.sh для повторного тестирования.

set -e

TIME_PER_TARGET=${1:-300}  # 5 минут по умолчанию

# Лёгкие targets (без полного circuit, быстрые)
# ИСКЛЮЧЕНЫ: fuzz_multikey_digest, fuzz_digest_collision
FAST_TARGETS=(
    "fuzz_key_sum_collision"
    "fuzz_deposit_sum_collision"
    "fuzz_field_wrap"
    "fuzz_poseidon_consistency"
    "fuzz_limb_overflow"
)

# Средние targets (используют MockProver)
MEDIUM_TARGETS=(
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
)

# Тяжёлые targets (полный prover/verifier)
# ИСКЛЮЧЕНЫ: fuzz_proving_key_bytes, fuzz_verifier_bytes
HEAVY_TARGETS=(
    "fuzz_proof_mutations"
    "fuzz_structured_proof"
    "fuzz_proof_replay"
    "fuzz_ec_invalid_points"
)

echo "=============================================="
echo "DarkDex Overnight Fuzzing"
echo "Time per target: ${TIME_PER_TARGET}s"
echo "Start time: $(date)"
echo "=============================================="

RESULTS_FILE="Pruvendo/fuzz/overnight_results_$(date +%Y%m%d_%H%M%S).log"
echo "Results will be saved to: $RESULTS_FILE"
echo ""

run_target() {
    local target=$1
    local timeout=$2
    echo "----------------------------------------------"
    echo "[$(date +%H:%M:%S)] Running: $target (${timeout}s)"
    echo "----------------------------------------------"
    
    START=$(date +%s)
    
    # Запускаем фаззинг и собираем результат
    set +e
    OUTPUT=$(cargo +nightly fuzz run "$target" --fuzz-dir Pruvendo/fuzz -- -max_total_time="$timeout" 2>&1)
    EXITCODE=$?
    set -e
    
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    # Извлекаем количество runs
    RUNS=$(echo "$OUTPUT" | grep -oE '#[0-9]+\s+DONE' | grep -oE '[0-9]+' | tail -1)
    RUNS=${RUNS:-0}
    
    # Проверяем на crashes
    CRASHES=$(find Pruvendo/fuzz/artifacts/"$target"/ -name 'crash-*' 2>/dev/null | wc -l | tr -d ' ')
    
    STATUS="OK"
    if [ "$EXITCODE" -ne 0 ]; then
        STATUS="CRASH"
    fi
    
    echo "[$target] Runs: $RUNS, Crashes: $CRASHES, Time: ${ELAPSED}s, Status: $STATUS"
    echo "$target,$RUNS,$CRASHES,$ELAPSED,$STATUS" >> "$RESULTS_FILE"
}

echo "target,runs,crashes,time_sec,status" > "$RESULTS_FILE"

echo ""
echo "=== FAST TARGETS ==="
for target in "${FAST_TARGETS[@]}"; do
    run_target "$target" "$TIME_PER_TARGET"
done

echo ""
echo "=== MEDIUM TARGETS ==="
for target in "${MEDIUM_TARGETS[@]}"; do
    run_target "$target" "$TIME_PER_TARGET"
done

echo ""
echo "=== HEAVY TARGETS ==="
for target in "${HEAVY_TARGETS[@]}"; do
    run_target "$target" "$TIME_PER_TARGET"
done

echo ""
echo "=============================================="
echo "Fuzzing completed at $(date)"
echo "Results saved to: $RESULTS_FILE"
echo "=============================================="

# Summary
echo ""
echo "=== SUMMARY ==="
echo "Total crashes found:"
find Pruvendo/fuzz/artifacts/ -name 'crash-*' 2>/dev/null | wc -l
echo ""
echo "Crash files:"
find Pruvendo/fuzz/artifacts/ -name 'crash-*' 2>/dev/null || echo "No crashes found"

