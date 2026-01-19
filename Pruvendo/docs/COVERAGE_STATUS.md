# DarkDex Protocol Test Coverage Status

**Дата**: 2026-01-16
**Версия**: 2.0

## Легенда

- 🟢 **Хорошо покрыто** - есть fuzz targets + property tests
- 🟡 **Частично покрыто** - есть базовые тесты, внешние зависимости
- 🔴 **Не покрыто** - нет специфических тестов

---

## 1. Circuit Layer (Схема)

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| DarkDexCircuit synthesize | 🟢 | 15+ | 50+ | Soundness, completeness |
| scalar_multiply (pk=sk*g) | 🟢 | 3 | 14 | FpChip audit |
| poseidon_hash_gadget | 🟢 | 6 | 17 | Poseidon audit |
| FpChip (limb decomposition) | 🟢 | 4 | 14 | FpChip audit |
| Public Input Constraints | 🟢 | 3 | 10+ | Integration tests |

## 2. Cryptographic Primitives

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| Poseidon Hash | 🟢 | 6 | 17 | Полный аудит |
| secp256k1 EC operations | 🟢 | 5 | 10+ | Point validation |
| bn256 Pairing | 🟡 | 0 | 0 | halo2-lib dependency (P3) |
| KZG Commitment | 🟢 | 1 | 7 | kzg_tests.rs |

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
| Soundness | 🟢 | 3 | 20+ | Полное покрытие |
| Completeness | 🟢 | 1 | 15+ | Полное покрытие |
| Replay Protection | 🟢 | 2 | 2 | Integration tests |
| Collision Resistance | 🟢 | 3 | 5+ | BC-007 documented |
| Non-malleability | 🟢 | 2 | 2 | fuzz_proof_malleability |
| Binding properties | 🟢 | 4 | 4+ | Vault, token, sum |

## 5. Attack Vectors

| Атака | Статус | Fuzz | Props | Примечание |
|-------|--------|------|-------|------------|
| Keypair swap | 🟢 | 2 | 2 | cross_keypair_attack |
| Digest preimage | 🟢 | 2 | 1 | Покрыто |
| Limb overflow | 🟢 | 3 | 5+ | limb_overflow_attack |
| Range check bypass | 🟢 | 1 | 2 | Покрыто |
| Double spend | 🟢 | 1 | 1 | Покрыто |
| Weak generator | 🟢 | 1 | 1 | Покрыто |
| Field wrap | 🟢 | 1 | 2 | Покрыто |
| Constraint bypass | 🟢 | 1 | 2 | fuzz_constraint_bypass |

---

## Статистика

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 42 |
| Property Tests | 198 |
| Integration Tests | 13 |
| Stable Overnight Runs | 38 targets |
| Bug Candidates | 7 (BC-001 to BC-007) |

---

## Ночной фаззинг (2026-01-16)

- **Время**: ~5 часов
- **Targets**: 38 stable
- **Результат**: 0 crashes

Лучшие по пропускной способности:
- fuzz_proof_malleability: 132M runs
- fuzz_verifier_negative: 63M runs
- fuzz_structured_proof: 66M runs

---

## P3: Низкий приоритет (внешние зависимости)

| Компонент | Причина |
|-----------|---------|
| bn256 Pairing | halo2-lib внешняя библиотека |
| Performance benchmarks | Не критично для аудита |
| SMT/Z3 verification | halo2-analyzer несовместим |

---

## См. также

- [POSEIDON_AUDIT_REPORT.md](./POSEIDON_AUDIT_REPORT.md)
- [FPCHIP_AUDIT_REPORT.md](./FPCHIP_AUDIT_REPORT.md)
- [BUG_CANDIDATES.md](./BUG_CANDIDATES.md)

