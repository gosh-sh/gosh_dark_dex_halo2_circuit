# Bug Candidate Tracking - Отслеживание потенциальных проблем

## Статус ночного фаззинга (15.01.2026)

**Запущено**: 26 fuzz targets, 5 часов (03:20 - 08:24)

| Target | Runs | Статус | Направление |
|--------|------|--------|-------------|
| fuzz_soundness | 177 | ✅ OK | Базовый soundness |
| fuzz_soundness_extended | 122 | ✅ OK | Расширенный soundness |
| fuzz_completeness | 146 | ✅ OK | Completeness |
| fuzz_determinism | 42 | ✅ OK | Детерминизм |
| fuzz_token_binding | 90 | ✅ OK | Token binding |
| fuzz_sum_binding | 84 | ✅ OK | Sum binding |
| fuzz_vault_rand_binding | 112 | ✅ OK | Vault binding |
| fuzz_vault_zero_binding | 84 | ✅ OK | Vault = 0 |
| fuzz_edge_cases | 101 | ✅ OK | Edge cases |
| fuzz_poseidon_preimage | 106 | ✅ OK | Preimage |
| fuzz_poseidon_consistency | 3.7M | ✅ OK | Hash consistency |
| fuzz_digest_collision | 1 | ⚠️ BC-007 | Collision (не эксплуатируется) |
| fuzz_deposit_sum_collision | 224M | ✅ OK | deposit_sum collisions |
| fuzz_key_sum_collision | 695K | ✅ OK | key_sum collisions |
| fuzz_multikey_digest | 1 | ⚠️ = BC-007 | Multi-key digest |
| fuzz_limb_overflow | 4.1K | ✅ OK | Limb overflow |
| fuzz_field_wrap | 1.1M | ✅ OK | Field wrap |
| fuzz_ec_invalid_points | 9.7K | ✅ OK | Invalid EC points |
| fuzz_ec_coordinate_manipulation | 5.1K | ✅ OK | Coordinate манипуляции |
| fuzz_negated_y | 3K | ✅ OK | -y coordinates |
| fuzz_witness_manipulation | 4.2K | ✅ OK | Witness манипуляции |
| fuzz_proof_mutations | 30K | ✅ OK | Proof mutations |
| fuzz_structured_proof | 53M | ✅ OK | Structured mutations |
| fuzz_proof_replay | 58 | ✅ OK | Proof replay |
| fuzz_proving_key_bytes | 3 | ⚠️ BC-005 | Corrupted PK (upstream) |
| fuzz_verifier_bytes | 3 | ⚠️ BC-001 | Corrupted VK (upstream) |

---

## Быстрый старт

```bash
# Запустить все 116 property тестов:
cd Pruvendo/tests/property_tests
cargo test --release

# Актуальные BC (upstream issues):
# BC-001: corrupted VK bytes - halo2curves
# BC-003/BC-005: corrupted KZG params - halo2_proofs
# BC-006: non-canonical field elements - informational
```

> **ПРИМЕЧАНИЕ:** После рефакторинга `poseidon_instead_of_ecc` тесты для закрытых BC (BC-002, BC-004, BC-007) были удалены.

## Список Bug Candidates (актуальный статус на 2026-01-21)

> **ВАЖНО**: После рефакторинга `poseidon_instead_of_ecc` многие BC были закрыты!
> Circuit больше не использует ECC операции, vault_rand_val убран.

| ID | Название | Severity | Текущий статус | Последняя верификация |
|----|----------|----------|----------------|----------------------|
| BC-001 | Panic при corrupted VK bytes | Medium | ⚠️ Актуален (upstream halo2curves) | ✅ 2026-01-21: воспроизводится |
| ~~BC-002~~ | ~~Panic при g = identity point~~ | ~~Medium~~ | ❌ **CLOSED** - ECC убран из circuit | N/A |
| BC-003 | shl_overflow при corrupted KZG header | Medium | ⚠️ Актуален (upstream halo2_proofs) | ✅ 2026-01-21: воспроизводится |
| ~~BC-004~~ | ~~shl_overflow в commitment.rs (limbs)~~ | ~~Medium~~ | ❌ **CLOSED** - limbs decomposition убран | N/A |
| BC-005 | shl_overflow в domain.rs | Medium | Дубликат BC-003 (upstream) | = BC-003 |
| BC-006 | Non-canonical field elements | Low | ✅ NOT A SOUNDNESS ISSUE | Informational |
| ~~BC-007~~ | ~~deposit_sum/vault_rand_val коллизии~~ | ~~Low~~ | ❌ **CLOSED** - vault_rand_val убран | N/A |
| ~~BC-008~~ | ~~Split с одинаковыми amounts~~ | ~~Low~~ | ❌ NOT A BUG (model artifact) | N/A |
| BC-009 | Timing side-channel в verifier | Medium | ✅ **ACCEPT** (недостижимая атака) | ✅ 2026-01-21: проанализировано |

### Результаты верификации 2026-01-21

```
BC-001: test_vk_corrupted_single_byte
  → panic at halo2curves "called Result::unwrap() on Err"
  → REPRODUCED (upstream issue)

BC-003: test_params_corrupted_k_value
  → panic "capacity overflow" при попытке аллокации с corrupted k
  → REPRODUCED (upstream issue)

BC-003: test_read_params_corrupted_file
  → panic at halo2curves/bn256/fq.rs "UnexpectedEof"
  → REPRODUCED (upstream issue)

BC-006: Non-canonical field elements
  → Elements are reduced during arithmetic operations
  → NOT A SOUNDNESS ISSUE (informational)
```

**Тесты для воспроизведения:**
```bash
cd Pruvendo/tests/property_tests
cargo test --release -- --nocapture corrupted
```

## Детали каждого Bug Candidate

### BC-001: Panic при corrupted VK bytes
- **Тесты:** `test_corrupted_vk_bytes_header`, `test_corrupted_vk_bytes_middle`
- **Воспроизведение:** `cargo test test_corrupted_vk --release -- --ignored --nocapture`
- **Причина:** halo2curves не обрабатывает gracefully corrupted данные
- **Рекомендация:** Валидировать VK перед использованием

### ~~BC-002~~: Panic при g = identity point (CLOSED)
- **Статус:** ❌ **CLOSED** после рефакторинга `poseidon_instead_of_ecc`
- **Причина закрытия:** Circuit больше не использует ECC операции
- **Было:** subtle crate не поддерживал identity point
- **Теперь:** EccChip, scalar_multiply и все EC операции убраны из circuit

### BC-003: OOM/panic при corrupted KZG header
- **Тест:** `test_corrupted_kzg_header_bc003`
- **Воспроизведение:** `cargo test bc003 --release -- --ignored --nocapture`
- **Причина:** Corrupted size в header приводит к попытке выделить петабайты памяти
- **Рекомендация:** Валидировать размеры перед аллокацией

### ~~BC-004~~: shl_overflow в commitment.rs (CLOSED)
- **Статус:** ❌ **CLOSED** после рефакторинга `poseidon_instead_of_ecc`
- **Причина закрытия:** Limbs decomposition больше не используется в circuit
- **Примечание:** BC-003/BC-005 (corrupted KZG params) остаётся актуальным - это upstream issue

### BC-005/BC-003: shl_overflow в halo2_proofs (upstream)
- **Статус:** ⚠️ Актуален - upstream issue в halo2_proofs
- **Причина:** Corrupted KZG params вызывают overflow при shift операциях
- **Рекомендация:** Валидировать KZG params перед использованием

### BC-006: Non-canonical field elements
- **Статус:** ✅ Informational - NOT a soundness issue
- **Причина:** Elements are reduced during arithmetic operations
- **Рекомендация:** Low priority

### ~~BC-007~~: deposit_sum collision (CLOSED)
- **Статус:** ❌ **CLOSED** после рефакторинга
- **Причина закрытия:** `vault_rand_val` убран из circuit
- **Было:** `deposit_sum = token + sum + vault` - возможны коллизии
- **Теперь:** `digest = Poseidon(sk_commitment, sum, token, sk)` - коллизии невозможны благодаря sk

### ~~BC-008~~: Split с одинаковыми amounts (NOT A BUG)
- **Найден:** Model checking 21.01.2026
- **Первоначально:** В упрощённой Quint модели `split(100, 100)` создавал одну ноту вместо двух
- **Причина модельного артефакта:**
  - Модель использовала `Digest = {owner, token, amount}` без nonce
  - Два депозита с одинаковыми параметрами имели одинаковый digest
  - `Set.union({dig_1}).union({dig_2})` при `dig_1 == dig_2` → только один элемент
- **Почему НЕ баг в реальном протоколе:**
  - В реальном коде: `sk = random::<u64>()` генерируется для КАЖДОГО депозита
  - `digest = Poseidon(sk_commitment, amount, token, sk)` — sk уникален!
  - Два депозита с одинаковыми (owner, amount, token) имеют **РАЗНЫЕ** digests
- **Решение:** Обновлена модель v3 — добавлено поле `nonce` в тип Digest
- **Статус:** ❌ NOT A BUG — артефакт упрощённой модели
- **Верификация после исправления модели:**
  - Quint random simulation: ✅ PASS
  - Apalache bounded model checking: ✅ PASS

### BC-009: Timing side-channel в verifier — ACCEPT (недостижимая атака)
- **Найден:** Timing analysis 21.01.2026
- **Описание:** Разница во времени верификации valid vs wrong_digest proof
- **Измерения:**
  ```
  Correct digest:   Median=5608 µs
  Wrong digests:    Median=5292 µs (среднее по 20 разным digests)
  Relative difference: 5.64%
  Signal-to-noise ratio: 0.59
  ```
- **Вопрос:** Можно ли найти правильный digest через timing oracle?
- **Анализ:**
  1. **Correct digest SLOWER** — атакующий ищет максимум, не минимум
  2. **Signal-to-noise = 0.59** — сигнал меньше шума между разными wrong digests
  3. **Measurements needed = 33** — на каждый digest-кандидат
  4. **Field size = 2^254** — brute force невозможен даже с оракулом
  5. **No algebraic structure** — нет способа уменьшить пространство поиска
  6. **Network jitter (1ms) >> timing difference (316µs)** — 3.2x маскирование
- **Расчёт времени brute force с oracle:** 1.70×10^68 лет
- **Статус:** ✅ **ACCEPT** — недостижимая атака
- **Обоснование:** Атака требует 2^254 кандидатов × 33 измерений × 5ms = 10^68 лет. Практически неэксплуатируемо.
- **Рекомендация:** Принято. Constant-time padding не требуется (defence in depth — низкий приоритет).
- **Тест:** `cargo test --release test_bc009_timing_oracle_attack -- --nocapture`

## Tracking System

All BC tests use the unified tracking system from `helpers.rs`:

```rust
use crate::helpers::{known_bugs, report_bug_candidate_status, check_bug_candidate_status};

let status = check_bug_candidate_status(|| {
    // code that may panic
    potentially_panicking_code()
});

report_bug_candidate_status(&known_bugs::BC_XXX, status);
```

### Statuses:
- `REPRODUCED` - BC reproduces in current version
- `FIXED` / `NOT CONFIRMED` - BC no longer reproduces
- `SKIPPED` - test skipped (files not found)

## How to Add a New Bug Candidate

1. Add `BugCandidateInfo` to `helpers.rs`:
```rust
pub const BC_008: BugCandidateInfo = BugCandidateInfo {
    id: "BC-008",
    title: "Description of the bug candidate",
    location: "where it is located",
    severity: "High/Medium/Low",
};
```

2. Create a test in `tests.rs`:
```rust
/// BC-008: Brief description
/// Run: cargo test test_bc008 --release -- --nocapture
#[test]
fn test_bc008_description() {
    use crate::helpers::{known_bugs, report_bug_candidate_status, check_bug_candidate_status};

    let status = check_bug_candidate_status(|| {
        // code reproducing the bug candidate
    });

    report_bug_candidate_status(&known_bugs::BC_008, status);
}
```

3. Update this documentation

## CI Integration

For CI, run BC tests separately:

```bash
# Tests that don't require files (always work)
cargo test test_generator_identity --release

# Tests that require files (ignored by default)
cargo test --release -- --ignored 2>&1 | grep -E "STATUS:|passed|failed"
```

---

## Связанные документы

- [TIMING_ANALYSIS.md](./TIMING_ANALYSIS.md) — анализ timing side-channels
- [FUZZING_REPORT.md](./FUZZING_REPORT.md) — результаты фаззинга
- [AUDIT_FINDINGS.md](./AUDIT_FINDINGS.md) — общие находки аудита
