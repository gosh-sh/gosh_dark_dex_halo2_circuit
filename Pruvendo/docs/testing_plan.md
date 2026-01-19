# План тестирования Dark DEX Halo2 Circuit

**Версия:** 4.0
**Обновлено:** 2026-01-16

---

## Текущий статус

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 42 (38 stable, 4 known BC) |
| Property Tests | 198 |
| Integration Tests | 13 |
| Bug Candidates | 7 (BC-001 to BC-007) |
| Overnight Coverage | 38 targets × 5h = ✅ 0 crashes |

**Подробный статус**: см. [COVERAGE_STATUS.md](./COVERAGE_STATUS.md)

---

## Выполненные задачи

### ✅ Фаза 1: Базовое покрытие

| Задача | Deliverables | Тесты |
|--------|--------------|-------|
| Property-based тесты | `tests.rs` | 112 |
| Fuzz targets (core) | 26 fuzz targets | — |
| Integration tests | `integration_tests.rs` | 13 |

### ✅ Фаза 2: Аудит компонентов

| Задача | Deliverables | Тесты |
|--------|--------------|-------|
| Poseidon audit | `poseidon_audit.rs` | 15 |
| FpChip audit | `fpchip_audit.rs` | 14 |
| Bug candidates | BC-001 to BC-007 | — |

### ✅ Фаза 3: P1 (желтые зоны)

| Задача | Deliverables | Тесты |
|--------|--------------|-------|
| Prover error paths | `prover_tests.rs`, fuzz | 8 |
| Verifier negative | `verifier_tests.rs`, fuzz | 10 |
| Non-malleability | `fuzz_proof_malleability` | — |
| KZG integration | `kzg_tests.rs` | 7 |

### ✅ Фаза 4: P2 (красные зоны)

| Задача | Deliverables | Тесты |
|--------|--------------|-------|
| VK/PK generation | `keygen_tests.rs` | 4 |
| Serialization | `serialization_tests.rs` | 6 |
| KZG params setup | `params_tests.rs` | 7 |

### ✅ Фаза 5: Overnight fuzzing

| Дата | Targets | Время | Результат |
|------|---------|-------|-----------|
| 2026-01-15 | 26 | 6h | 10 crashes → 4 BC, 2 transient |
| 2026-01-16 | 18 | 5h | 0 crashes ✅ |

---

## P3: Низкий приоритет (не выполнено)

| Задача | Причина |
|--------|---------|
| bn256 Pairing tests | Внешняя библиотека (halo2-lib) |
| Performance benchmarks | Не критично для аудита |
| SMT/Z3 verification | halo2-analyzer несовместим |

---

## Bug Candidates

| ID | Описание | Severity | Статус |
|----|----------|----------|--------|
| BC-001 | halo2curves panic on short input | Medium | Upstream |
| BC-002 | deposit_sum collision (theoretical) | Info | Expected |
| BC-003 | key_sum collision (theoretical) | Info | Expected |
| BC-004 | Limb overflow > Fr modulus | Info | Covered |
| BC-005 | halo2_proofs panic on malformed VK | Medium | Upstream |
| BC-006 | Poseidon preimage (computational) | Info | Expected |
| BC-007 | deposit_sum collision (not exploitable) | Low | Documented |

---

## Fuzz Scripts

| Script | Targets | Назначение |
|--------|---------|------------|
| `run_overnight_stable_v2.sh` | 38 | Все стабильные targets |
| `run_overnight_known_crashes.sh` | 4 | Известные BC |

---

## Следующие шаги

- [ ] Merge `poseidon_instead_of_ecc` branch
- [ ] Адаптировать тесты под новую архитектуру
- [ ] Проверить какие BC закрылись
- [ ] Overnight run на новой версии

