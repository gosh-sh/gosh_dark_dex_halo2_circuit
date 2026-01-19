# План тестирования Dark DEX Halo2 Circuit

**Версия:** 5.0
**Обновлено:** 2026-01-19
**Архитектура:** poseidon_instead_of_ecc

---

## Текущий статус

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 26 (все адаптированы) |
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

## Следующие шаги

- [ ] Overnight fuzzing на новой архитектуре (26 targets)
- [ ] Анализ новых потенциальных уязвимостей
- [ ] Документирование закрытых BC

