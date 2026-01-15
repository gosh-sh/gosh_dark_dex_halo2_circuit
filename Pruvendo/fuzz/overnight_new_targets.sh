#!/bin/bash
# Overnight fuzzing script for NEW targets only (2026-01-15)
# Запускает только 6 новых глубоких targets, не повторяя вчерашние 26

set -e

# Конфигурация
FUZZ_TIME=800           # секунд на каждый target (~13 минут)
FUZZ_DIR="Pruvendo/fuzz"
LOG_FILE="Pruvendo/fuzz/overnight_results_$(date +%Y%m%d_%H%M%S).log"
PARALLEL_JOBS=2         # Параллельные jobs (осторожно с памятью)

# Только НОВЫЕ targets (не запускались вчера ночью)
NEW_TARGETS=(
    "fuzz_constraint_bypass"      # pk ≠ sk*g bypass атаки
    "fuzz_public_input_mismatch"  # Манипуляция public inputs  
    "fuzz_weak_generator"         # Слабые generators
    "fuzz_digest_preimage"        # Poseidon collision
    "fuzz_cross_keypair_attack"   # Cross-keypair атаки
    "fuzz_limb_reconstruction"    # key_data_sum collision
)

echo "=== Overnight Fuzzing (NEW TARGETS ONLY) ===" | tee $LOG_FILE
echo "Start time: $(date)" | tee -a $LOG_FILE
echo "Fuzz time per target: ${FUZZ_TIME}s" | tee -a $LOG_FILE
echo "Total targets: ${#NEW_TARGETS[@]}" | tee -a $LOG_FILE
echo "Estimated total time: $(( ${#NEW_TARGETS[@]} * FUZZ_TIME / 60 )) minutes" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Функция запуска одного target
run_fuzz_target() {
    local target=$1
    local start_time=$(date +%s)
    
    echo "[$(date +%H:%M:%S)] Starting: $target" | tee -a $LOG_FILE
    
    # Запуск с таймаутом
    timeout $((FUZZ_TIME + 60)) cargo +nightly fuzz run $target \
        --fuzz-dir $FUZZ_DIR \
        -- -max_total_time=$FUZZ_TIME 2>&1 | tee -a "${LOG_FILE}.${target}.detail"
    
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Проверка на crash
    local crashes=$(ls -1 ${FUZZ_DIR}/artifacts/${target}/ 2>/dev/null | wc -l | tr -d ' ')
    
    if [ $exit_code -eq 0 ]; then
        echo "[$(date +%H:%M:%S)] DONE: $target (${duration}s, $crashes crashes)" | tee -a $LOG_FILE
    else
        echo "[$(date +%H:%M:%S)] FAILED: $target (exit=$exit_code, ${duration}s, $crashes crashes)" | tee -a $LOG_FILE
    fi
    
    # Краткая статистика
    grep -E "DONE|runs in|cov:|ft:" "${LOG_FILE}.${target}.detail" | tail -3 >> $LOG_FILE 2>/dev/null || true
    echo "" | tee -a $LOG_FILE
}

# Сборка всех targets
echo "Building all fuzz targets..." | tee -a $LOG_FILE
cargo +nightly fuzz build --fuzz-dir $FUZZ_DIR 2>&1 | tail -5 | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Запуск каждого target последовательно (безопаснее для памяти)
for target in "${NEW_TARGETS[@]}"; do
    run_fuzz_target "$target"
done

# Финальный отчёт
echo "" | tee -a $LOG_FILE
echo "=== FINAL SUMMARY ===" | tee -a $LOG_FILE
echo "End time: $(date)" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Подсчёт crashes
echo "Crashes found:" | tee -a $LOG_FILE
for target in "${NEW_TARGETS[@]}"; do
    local crashes=$(ls -1 ${FUZZ_DIR}/artifacts/${target}/ 2>/dev/null | grep -v "^\." | wc -l | tr -d ' ')
    if [ "$crashes" -gt 0 ]; then
        echo "  $target: $crashes crashes" | tee -a $LOG_FILE
        ls -la ${FUZZ_DIR}/artifacts/${target}/ | tee -a $LOG_FILE
    fi
done

echo "" | tee -a $LOG_FILE
echo "Log saved to: $LOG_FILE" | tee -a $LOG_FILE
echo "Done!" | tee -a $LOG_FILE

