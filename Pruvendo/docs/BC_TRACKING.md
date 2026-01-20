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
# Проверить статус ВСЕХ известных BC:
cd Pruvendo/tests/property_tests
cargo test --release -- --nocapture 2>&1 | grep -E "BC-00[0-9]|STATUS:"

# Запустить конкретный тест:
cargo test test_generator_identity --release -- --nocapture  # BC-002
cargo test test_corrupted_vk --release -- --ignored --nocapture  # BC-001
cargo test bc003 --release -- --ignored --nocapture  # BC-003
cargo test test_corrupted_kzg_params_bytes --release -- --ignored --nocapture  # BC-004/005
cargo test bc006 --release -- --ignored --nocapture  # BC-006
```

## Список Bug Candidates (актуальный статус на 2026-01-21)

| ID | Название | Severity | Текущий статус |
|----|----------|----------|----------------|
| BC-001 | Panic при corrupted VK bytes (header) | Medium | ⚠️ REPRODUCED |
| BC-001 | Panic при corrupted VK bytes (middle) | Medium | ✅ NOT CONFIRMED |
| BC-002 | Panic при g = identity point | Medium | ⚠️ REPRODUCED |
| BC-003 | shl_overflow при corrupted KZG header | Medium | ⚠️ REPRODUCED |
| BC-004 | shl_overflow в commitment.rs | Medium | ✅ NOT CONFIRMED |
| BC-005 | shl_overflow в domain.rs | Medium | Дубликат BC-004 |
| BC-006 | Non-canonical field elements | Low | ✅ Not a soundness issue |
| BC-007 | deposit_sum коллизии | Low | ✅ Not exploitable |
| ~~BC-008~~ | ~~Split с одинаковыми amounts~~ | ~~Low~~ | ❌ NOT A BUG (model artifact) |

## Детали каждого Bug Candidate

### BC-001: Panic при corrupted VK bytes
- **Тесты:** `test_corrupted_vk_bytes_header`, `test_corrupted_vk_bytes_middle`
- **Воспроизведение:** `cargo test test_corrupted_vk --release -- --ignored --nocapture`
- **Причина:** halo2curves не обрабатывает gracefully corrupted данные
- **Рекомендация:** Валидировать VK перед использованием

### BC-002: Panic при g = identity point
- **Тест:** `test_generator_identity`
- **Воспроизведение:** `cargo test test_generator_identity --release -- --nocapture`
- **Причина:** subtle crate не поддерживает identity point в операциях
- **Рекомендация:** Проверять g != identity на входе

### BC-003: OOM/panic при corrupted KZG header
- **Тест:** `test_corrupted_kzg_header_bc003`
- **Воспроизведение:** `cargo test bc003 --release -- --ignored --nocapture`
- **Причина:** Corrupted size в header приводит к попытке выделить петабайты памяти
- **Рекомендация:** Валидировать размеры перед аллокацией

### BC-004/BC-005: shl_overflow в halo2_proofs
- **Тест:** `test_corrupted_kzg_params_bytes`
- **Воспроизведение:** `cargo test test_corrupted_kzg_params_bytes --release -- --ignored --nocapture`
- **Причина:** Corrupted данные вызывают overflow при shift операциях
- **Рекомендация:** Upstream fix или валидация данных

### BC-006: Non-canonical field elements
- **Тесты:** `test_bc006_vk_bit7_manipulation_*`, `test_bc006_verification_with_modified_vk`
- **Воспроизведение:** `cargo test bc006 --release -- --ignored --nocapture`
- **Статус:** NOT a soundness issue - elements are reduced during arithmetic
- **Рекомендация:** Low priority, informational

### BC-007: deposit_sum collision (LOW - NOT EXPLOITABLE)
- **Найден:** Overnight fuzzing 15.01.2026
- **Fuzz targets:** `fuzz_digest_collision`, `fuzz_multikey_digest`
- **Воспроизведение:**
  ```bash
  cargo +nightly fuzz run fuzz_digest_collision --fuzz-dir Pruvendo/fuzz \
    Pruvendo/fuzz/artifacts/fuzz_digest_collision/crash-bf9dd64e8719cdd48add91072c80230cbe2ad6cb
  ```
- **Суть проблемы:**
  - `deposit_sum = token + sum + vault` (additive formula)
  - Different `(token, vault)` pairs with the same sum produce identical `deposit_sum`
  - Example: `(token=91577, vault=691321)` and `(token=93113, vault=689785)` produce same digest
- **Почему НЕ эксплуатируется:**
  - `token_type` и `private_note_sum` являются **PUBLIC INPUTS** (проверяются verifier'ом)
  - Схема проверяет: `public_inputs = [private_note_sum, token_type, digest]`
  - Если атакующий изменит token или sum, verifier это увидит
  - Единственный приватный компонент (`vault_rand_val`) не даёт атакующему преимущества
- **Статус:** ✅ Informational - не является soundness уязвимостью
- **Рекомендация (defense in depth):** Для большей прозрачности можно изменить формулу:
  ```
  digest = poseidon_hash([key_sum, token, sum, vault])  // hash separately
  ```

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

