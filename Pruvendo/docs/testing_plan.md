# План тестирования Dark DEX Halo2 Circuit

**Версия:** 6.0
**Обновлено:** 2026-01-20
**Архитектура:** poseidon_instead_of_ecc
**Best Practices:** см. [ZK_AUDIT_BEST_PRACTICES.md](./ZK_AUDIT_BEST_PRACTICES.md)

---

## Текущий статус

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 33 (26 stable + 4 P1 + 3 P0) |
| Property Tests | 116 |
| Integration Tests | 13 |
| Bug Candidates | 4 open, 3 closed |
| Overnight Coverage | Pending (новая архитектура) |

**Подробный статус**: см. [COVERAGE_STATUS.md](./COVERAGE_STATUS.md)

---

## Архитектура (poseidon_instead_of_ecc)

```
Старая (ECC):
- pk = sk * G (EC multiplication)
- key_data_sum = sk + Σ(pk.x limbs) + Σ(pk.y limbs)
- deposit_sum = private_note_sum + token_type + vault_rand_val
- digest = poseidon([key_data_sum, deposit_sum])
- k = 18, params ~33MB

Новая (Poseidon only):
- sk_commitment = poseidon([sk, 0])
- digest = poseidon([sk_commitment, private_note_sum, token_type, sk])
- Public inputs: [private_note_sum, token_type, digest]
- k = 8, params ~33KB
```

---

## Выполненные задачи

### ✅ Фаза 1-5: Базовое покрытие (ECC версия)

Все задачи выполнены на ECC версии, затем адаптированы.

### ✅ Фаза 6: Миграция на poseidon_instead_of_ecc

| Задача | Статус |
|--------|--------|
| Merge poseidon_instead_of_ecc | ✅ Выполнено |
| Адаптация property tests | ✅ 116 тестов |
| Адаптация fuzz targets | ✅ 26 targets |
| Удаление ECC targets | ✅ 16 удалено |
| Обновление BC статусов | ✅ 3 закрыты |

---

## Bug Candidates

| ID | Описание | Severity | Статус |
|----|----------|----------|--------|
| BC-001 | halo2curves panic on short input | Medium | Upstream |
| BC-002 | g = identity point | — | **CLOSED** (no g) |
| BC-003 | shl_overflow in KZG header | Medium | Upstream |
| BC-004 | Limb overflow > Fr modulus | — | **CLOSED** (no limbs) |
| BC-005 | shl_overflow in domain.rs | Medium | Upstream |
| BC-006 | Non-canonical field elements | Low | Upstream |
| BC-007 | deposit_sum collision | — | **CLOSED** (formula changed) |

---

## Fuzz Targets (26)

### Core (10)
- fuzz_completeness
- fuzz_determinism
- fuzz_soundness
- fuzz_soundness_extended
- fuzz_edge_cases
- fuzz_field_wrap
- fuzz_sum_binding
- fuzz_token_binding
- fuzz_proof_replay
- fuzz_public_input_mismatch

### Poseidon (6)
- fuzz_poseidon_consistency
- fuzz_poseidon_algebraic
- fuzz_poseidon_gadget_consistency
- fuzz_poseidon_preimage
- fuzz_digest_collision
- fuzz_digest_preimage

### Attack Simulation (4)
- fuzz_double_spend_attack
- fuzz_multikey_digest
- fuzz_witness_manipulation
- fuzz_proof_malleability

### Serialization (6)
- fuzz_proof_mutations
- fuzz_structured_proof
- fuzz_verifier_bytes
- fuzz_verifier_negative
- fuzz_proving_key_bytes
- fuzz_prover_error_paths

---

## Приоритетные задачи (на основе Best Practices)

### P0: Критично (96% багов!)

> **Under-constrained circuits вызывают 96% багов в ZK системах**

| Задача | Приоритет | Статус | Описание |
|--------|-----------|--------|----------|
| fuzz_unused_public_inputs | P0 | ✅ | Проверка что все public inputs используются |
| fuzz_witness_unconstrained | P0 | ✅ | Assigned but not constrained |
| fuzz_copy_constraint_violation | P0 | ✅ | Missing equality constraints |

### P1: Высокий

| Задача | Приоритет | Статус | Описание |
|--------|-----------|--------|----------|
| fuzz_commitment_binding | P1 | ✅ | sk_commitment binding |
| fuzz_digest_binding | P1 | ✅ | 4-input digest binding |
| fuzz_sk_hiding | P1 | ✅ | sk cannot be recovered |
| fuzz_zero_padding_security | P1 | ✅ | Zero padding security |

### P2: Средний

| Задача | Приоритет | Статус | Описание |
|--------|-----------|--------|----------|
| Overnight fuzzing (30 targets) | P2 | ⏳ | Ночной прогон всех новых таргетов |
| Документирование закрытых BC | P2 | ⏳ | BC-002, BC-004, BC-007 |

---

## Покрытие по Best Practices

| Уязвимость | Покрытие | Тесты |
|------------|----------|-------|
| Under-constrained (96% багов) | ✅ | soundness, witness_manipulation + P0 |
| Over-constrained | ✅ | completeness |
| Arithmetic overflow | ✅ | field_wrap, edge_cases |
| Nondeterministic | ✅ | determinism |
| Unused public inputs | ✅ | fuzz_unused_public_inputs |
| Fiat-Shamir (Frozen Heart) | N/A | Halo2 handles internally |
| Assigned not constrained | ✅ | fuzz_witness_unconstrained |
| Copy constraints | ✅ | fuzz_copy_constraint_violation |
| Lookup tables | N/A | Не используются в схеме |
| Poseidon security | ✅ | poseidon_*, digest_*, commitment_* |

---

## New Fuzz Targets (7)

### P1: Poseidon Architecture (новые)
- fuzz_commitment_binding ✅
- fuzz_digest_binding ✅
- fuzz_sk_hiding ✅
- fuzz_zero_padding_security ✅

### P0: Critical Security (best practices)
- fuzz_unused_public_inputs ✅
- fuzz_copy_constraint_violation ✅
- fuzz_witness_unconstrained ✅

---

## Скрипты

| Скрипт | Назначение |
|--------|------------|
| `run_new_targets.sh` | Ночной прогон НОВЫХ targets (7 шт) |
| `check_known_bc.sh` | Проверка известных BC |
| `quick_smoke_test.sh` | Smoke test (5s каждый) |

---

## Аудит качества тестов (2026-01-19)

### Выявленные проблемы

| Приоритет | Проблема | Файлы | Статус |
|-----------|----------|-------|--------|
| 🔴 P0 | Узкий диапазон фаззинга (`% 1_000_000`) | 6 файлов | ✅ Исправлено |
| 🔴 P0 | `fuzz_proof_malleability` не тестирует реальный proof | 1 файл | ✅ Исправлено |
| 🔴 P0 | `fuzz_sum_binding`/`fuzz_token_binding` не тестируют soundness | 2 файла | ✅ Исправлено |
| 🟡 P1 | Тавтологии (тест использует ту же формулу что и circuit) | 4 файла | ⏳ |
| 🟡 P1 | Дублирование тестов | 4 группы | ⏳ |

### Выполненные исправления (2026-01-19)

#### ✅ Этап 1: Расширение диапазонов фаззинга (P0)

Исправленные файлы:
- `fuzz_soundness.rs` - убраны `% 1_000_000` ограничения, полный u64 диапазон
- `fuzz_completeness.rs` - аналогично
- `fuzz_determinism.rs` - аналогично
- `fuzz_sum_binding.rs` - аналогично
- `fuzz_token_binding.rs` - аналогично

#### ✅ Этап 2: Исправление fuzz_sum_binding / fuzz_token_binding (P0)

Теперь тесты проверяют:
- Completeness (valid accepted): правильные значения принимаются
- Soundness (wrong rejected): неправильные значения отклоняются

#### ✅ Этап 3: Переписан fuzz_proof_malleability (P0)

Новая реализация тестирует реальные атаки:
- WrongCommitment: commitment от другого sk
- SwapPublicInputs: перестановка public inputs
- MutateDigest: изменение digest
- WrongSk: неправильный sk
- WrongToken: неправильный token
- WrongSum: неправильная sum

Использует реальный MockProver вместо fake proof.

### Pending исправления

#### ⏳ Этап 4: Добавить reference implementation (P1)

Проблема: compute_digest/poseidon_hash используются и в тестах и в circuit
Решение: Добавить независимую Poseidon реализацию для cross-validation

---

