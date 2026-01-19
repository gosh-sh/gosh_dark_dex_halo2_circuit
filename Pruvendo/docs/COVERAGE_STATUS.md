# DarkDex Protocol Test Coverage Status

**Дата**: 2026-01-19
**Версия**: 3.0
**Архитектура**: poseidon_instead_of_ecc

## Легенда

- 🟢 **Хорошо покрыто** - есть fuzz targets + property tests
- 🟡 **Частично покрыто** - есть базовые тесты, внешние зависимости
- 🔴 **Не покрыто** - нет специфических тестов
- ⚫ **Не применимо** - удалено в новой архитектуре

---

## 1. Circuit Layer (Схема)

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| DarkDexCircuit synthesize | 🟢 | 10+ | 30+ | Soundness, completeness |
| sk_commitment = poseidon(sk, 0) | 🟢 | 6 | 10+ | Новая архитектура |
| poseidon_hash_gadget | 🟢 | 6 | 15+ | Poseidon audit |
| Public Input Constraints | 🟢 | 3 | 10+ | Integration tests |
| ~~scalar_multiply (pk=sk*g)~~ | ⚫ | — | — | Удалено |
| ~~FpChip (limb decomposition)~~ | ⚫ | — | — | Удалено |

## 2. Cryptographic Primitives

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| Poseidon Hash | 🟢 | 6 | 15+ | Полный аудит |
| bn256 Pairing | 🟡 | 0 | 0 | halo2-lib dependency (P3) |
| KZG Commitment | 🟢 | 1 | 7 | kzg_tests.rs |
| ~~secp256k1 EC operations~~ | ⚫ | — | — | Удалено |

## 3. Proof System

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| generate_proof (prover.rs) | 🟢 | 1 | 8 | prover_tests.rs |
| verify_proof (verifier.rs) | 🟢 | 2 | 10 | verifier_tests.rs |
| VK/PK Generation | 🟢 | 1 | 4 | keygen_tests.rs |
| KZG Params Setup | 🟢 | 0 | 7 | params_tests.rs |
| Serialization (read/write) | 🟢 | 2 | 6 | serialization_tests.rs |

## 4. Security Properties

| Свойство | Статус | Fuzz | Props | Примечание |
|----------|--------|------|-------|------------|
| Soundness | 🟢 | 2 | 15+ | Полное покрытие |
| Completeness | 🟢 | 1 | 10+ | Полное покрытие |
| Replay Protection | 🟢 | 1 | 2 | Integration tests |
| Collision Resistance | 🟢 | 2 | 5+ | Poseidon-based |
| Non-malleability | 🟢 | 2 | 2 | fuzz_proof_malleability |
| Binding properties | 🟢 | 2 | 4+ | Token, sum |

## 5. Attack Vectors

| Атака | Статус | Fuzz | Props | Примечание |
|-------|--------|------|-------|------------|
| Digest preimage | 🟢 | 2 | 1 | Покрыто |
| Double spend | 🟢 | 1 | 1 | Покрыто |
| Field wrap | 🟢 | 1 | 2 | Покрыто |
| Witness manipulation | 🟢 | 1 | 2 | Покрыто |
| Multikey digest | 🟢 | 1 | 1 | Покрыто |
| ~~Keypair swap~~ | ⚫ | — | — | Удалено (нет pk) |
| ~~Limb overflow~~ | ⚫ | — | — | Удалено (нет limbs) |
| ~~Weak generator~~ | ⚫ | — | — | Удалено (нет g) |

---

## Статистика

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 26 |
| Property Tests | 116 |
| Integration Tests | 13 |
| Bug Candidates | 4 open, 3 closed |

---

## Bug Candidates

| ID | Статус | Описание |
|----|--------|----------|
| BC-001 | Open | halo2curves panic on short input (upstream) |
| BC-002 | **CLOSED** | g = identity (нет g в новой архитектуре) |
| BC-003 | Open | shl_overflow in KZG header (upstream) |
| BC-004 | **CLOSED** | Limb overflow (нет limbs в новой архитектуре) |
| BC-005 | Open | shl_overflow in domain.rs (upstream) |
| BC-006 | Open | Non-canonical field elements (upstream) |
| BC-007 | **CLOSED** | deposit_sum collision (формула изменена) |

---

## P3: Низкий приоритет (внешние зависимости)

| Компонент | Причина |
|-----------|---------|
| bn256 Pairing | halo2-lib внешняя библиотека |
| Performance benchmarks | Не критично для аудита |
| SMT/Z3 verification | halo2-analyzer несовместим |

---

## См. также

- [TESTING_PLAN.md](./TESTING_PLAN.md)
- [BUG_CANDIDATES.md](./BUG_CANDIDATES.md)

