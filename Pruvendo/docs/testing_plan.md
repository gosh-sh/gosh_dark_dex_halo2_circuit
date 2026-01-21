# План тестирования Dark DEX Halo2 Circuit

**Версия:** 8.0
**Обновлено:** 2026-01-21
**Архитектура:** poseidon_instead_of_ecc
**Best Practices:** см. [ZK_AUDIT_BEST_PRACTICES.md](./ZK_AUDIT_BEST_PRACTICES.md)
**Test Profiles:** см. [TEST_PROFILES.md](./TEST_PROFILES.md)

---

## Текущий статус

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 32 (30 stable + 2 known BC) |
| Property Tests | 130+ |
| Real Prover Tests | 12 |
| Integration Tests | 13 |
| Bug Candidates | 4 open, 3 closed |
| Smoke Test | ✅ 30/32 passed (2 known BC) |

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

### ✅ Фаза 7: Мета-аудит улучшения (2026-01-21)

| Задача | Статус |
|--------|--------|
| Добавить fuzz_zero_sk_edge_case | ✅ Новый target |
| Унифицировать диапазоны в property tests | ✅ Full u64 range |
| Добавить Fr boundary property tests | ✅ 5 тестов |
| Добавить Real prover tests | ✅ 12 тестов |
| Создать систему профилей (day/night) | ✅ Скрипты + docs |
| Синхронизировать документацию | ✅ Числа выровнены |

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

## Fuzz Targets (32)

### Core (10)
- fuzz_completeness
- fuzz_determinism
- fuzz_soundness
- fuzz_edge_cases
- fuzz_field_wrap
- fuzz_sum_binding
- fuzz_token_binding
- fuzz_proof_replay
- fuzz_public_input_mismatch
- fuzz_zero_sk_edge_case *(NEW 2026-01-21)*

### Poseidon (5)
- fuzz_poseidon_consistency (cross-validation)
- fuzz_poseidon_algebraic
- fuzz_poseidon_gadget_consistency
- fuzz_poseidon_preimage
- fuzz_digest_collision (cross-validation)

### Digest/Commitment (5)
- fuzz_digest_preimage (cross-validation)
- fuzz_digest_binding
- fuzz_commitment_binding
- fuzz_sk_hiding
- fuzz_zero_padding_security

### Attack Simulation (3)
- fuzz_double_spend_attack
- fuzz_witness_manipulation
- fuzz_proof_malleability (MockProver-based)

### Constraint Security P0 (3)
- fuzz_unused_public_inputs
- fuzz_copy_constraint_violation
- fuzz_witness_unconstrained

### Serialization (6) - 2 known BC
- fuzz_proof_mutations
- fuzz_structured_proof
- fuzz_verifier_bytes (BC-001)
- fuzz_verifier_negative
- fuzz_proving_key_bytes (BC-005)
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
| Reference Poseidon implementation | P1 | ✅ | Cross-validation (e00fe87) |
| Удаление дубликатов тестов | P1 | ✅ | -2 targets (e00fe87) |

### P2: Средний

| Задача | Приоритет | Статус | Описание |
|--------|-----------|--------|----------|
| Overnight fuzzing (31 targets) | P2 | ⏳ | Ночной прогон всех таргетов |
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

## Smoke Test Results (2026-01-20)

| Результат | Количество |
|-----------|------------|
| ✅ Passed | 29/31 |
| ❌ Known BC | 2/31 |
| Total runs | ~4.7M |

Known BC crashes (upstream issues):
- `fuzz_proving_key_bytes` (BC-005)
- `fuzz_verifier_bytes` (BC-001)

---

## Скрипты

| Скрипт | Назначение |
|--------|------------|
| `quick_smoke_test.sh` | Smoke test (5s каждый, skips known BC) |
| `run_new_targets.sh` | Ночной прогон новых targets |
| `check_known_bc.sh` | Проверка известных BC |

---

## Аудит качества тестов (2026-01-19)

### Выявленные проблемы

| Приоритет | Проблема | Файлы | Статус |
|-----------|----------|-------|--------|
| 🔴 P0 | Узкий диапазон фаззинга (`% 1_000_000`) | 6 файлов | ✅ Исправлено |
| 🔴 P0 | `fuzz_proof_malleability` не тестирует реальный proof | 1 файл | ✅ Исправлено |
| 🔴 P0 | `fuzz_sum_binding`/`fuzz_token_binding` не тестируют soundness | 2 файла | ✅ Исправлено |
| 🟡 P1 | Тавтологии (тест использует ту же формулу что и circuit) | 4 файла | ✅ Исправлено |
| 🟡 P1 | Дублирование тестов | 2 файла | ✅ Удалены |

### Выполненные исправления

#### ✅ Этап 1: Расширение диапазонов фаззинга (P0)

**Коммит:** f34f93b

Исправленные файлы:
- `fuzz_soundness.rs` - убраны `% 1_000_000` ограничения, полный u64 диапазон
- `fuzz_completeness.rs` - аналогично
- `fuzz_determinism.rs` - аналогично
- `fuzz_sum_binding.rs` - аналогично
- `fuzz_token_binding.rs` - аналогично

#### ✅ Этап 2: Исправление fuzz_sum_binding / fuzz_token_binding (P0)

**Коммит:** f34f93b

Теперь тесты проверяют:
- Completeness (valid accepted): правильные значения принимаются
- Soundness (wrong rejected): неправильные значения отклоняются

#### ✅ Этап 3: Переписан fuzz_proof_malleability (P0)

**Коммит:** f34f93b

Новая реализация тестирует реальные атаки:
- WrongCommitment: commitment от другого sk
- SwapPublicInputs: перестановка public inputs
- MutateDigest: изменение digest
- WrongSk: неправильный sk
- WrongToken: неправильный token
- WrongSum: неправильная sum

Использует реальный MockProver вместо fake proof.

#### ✅ Этап 4: Reference Poseidon implementation (P1)

**Коммит:** e00fe87

Решение проблемы тавтологий - добавлена независимая реализация Poseidon:
- `reference_poseidon_hash_2()` - для 2-элементных хэшей
- `reference_poseidon_hash_4()` - для 4-элементных хэшей
- `compute_digest_verified()` - с cross-validation

Обновлённые тесты:
- `fuzz_poseidon_consistency` - сравнение library vs reference
- `fuzz_digest_collision` - использует cross-validation
- `fuzz_digest_preimage` - использует cross-validation

#### ✅ Этап 5: Удаление дубликатов (P1)

**Коммит:** e00fe87

Удалённые дубликаты:
- `fuzz_soundness_extended` → дубликат `fuzz_soundness`
- `fuzz_multikey_digest` → дубликат `fuzz_digest_collision`

---

