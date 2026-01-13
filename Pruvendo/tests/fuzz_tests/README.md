# Fuzz Tests для DarkDEX Halo2 Circuit

Coverage-guided fuzzing с проверкой свойств ZKP схемы.

**ВАЖНО:** Fuzz targets находятся в `Pruvendo/fuzz/` (симлинк `/fuzz/` → `Pruvendo/fuzz/`).
Эта директория содержит только документацию.

## Требования

```bash
# Требуется nightly Rust
rustup install nightly

# Установка cargo-fuzz
cargo install cargo-fuzz
```

## Fuzz Targets

| Target | Свойство | Что ищет |
|--------|----------|----------|
| `fuzz_soundness` | Soundness | pk ≠ sk*G должен быть ОТКЛОНЁН |
| `fuzz_completeness` | Completeness | pk = sk*G должен быть ПРИНЯТ |
| `fuzz_determinism` | Determinism | Одинаковые входы → одинаковый результат |
| `fuzz_verifier_bytes` | Robustness | Паники при malformed input |

## Запуск

**Запускать из корня проекта!**

```bash
cd /path/to/gosh_dark_dex_halo2_circuit

# Запуск конкретного target (Ctrl+C для остановки)
cargo +nightly fuzz run fuzz_soundness

# Запуск с ограничением времени (5 минут)
cargo +nightly fuzz run fuzz_soundness -- -max_total_time=300

# Запуск с несколькими потоками
cargo +nightly fuzz run fuzz_soundness -- -jobs=4 -workers=4

# Проверка robustness (быстрый, не требует MockProver)
cargo +nightly fuzz run fuzz_verifier_bytes
```

## Найденные баги

### 2024-12-26: Panic в halo2curves при десериализации

**Target:** `fuzz_verifier_bytes`
**Входные данные:** `[0, 0, 0, 0, 0, 0, 0, 10]`
**Ошибка:** `unwrap()` на `Err` в `halo2curves/src/bn256/fq.rs:133`

Это баг в зависимости halo2curves - функция десериализации паникует
на malformed input вместо возврата ошибки.

## Интерпретация результатов

### Успешный запуск (без багов)
```
#12345  DONE   cov: 1234 ft: 567 corp: 89/12Kb exec/s: 100
```

### Найден баг
```
SUMMARY: libFuzzer: deadly signal
Artifact: crash-abc123...
```

Контрпример сохраняется в `fuzz/artifacts/fuzz_<target>/crash-...`

## Воспроизведение краша

```bash
# Посмотреть входные данные
xxd fuzz/artifacts/fuzz_verifier_bytes/crash-abc123

# Воспроизвести
cargo +nightly fuzz run fuzz_verifier_bytes fuzz/artifacts/fuzz_verifier_bytes/crash-abc123
```

## Corpus

Fuzzer сохраняет интересные входы в `fuzz/corpus/fuzz_<target>/`.
Corpus накапливается между запусками для лучшего покрытия.

## Рекомендации

1. **Начните с `fuzz_verifier_bytes`** — быстрый, не требует MockProver
2. **Для property-тестов** (`fuzz_soundness`, `fuzz_completeness`) — долгие кампании (часы)
3. **MockProver медленный** — ~1 exec/sec, но coverage-guided находит edge cases
4. **Запускайте на мощной машине** — больше CPU = больше покрытие

