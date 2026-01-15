# DarkDex Protocol Test Coverage Status

**Дата**: 2026-01-15
**Версия**: 1.0

## Легенда

- 🟢 **Хорошо покрыто** - есть fuzz targets + property tests
- 🟡 **Частично покрыто** - есть базовые тесты, но требует доработки
- 🔴 **Не покрыто** - нет специфических тестов

---

## 1. Circuit Layer (Схема)

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| DarkDexCircuit synthesize | 🟢 | 15+ | 50+ | Soundness, completeness |
| scalar_multiply (pk=sk*g) | 🟢 | 2 | 14 | FpChip audit |
| poseidon_hash_gadget | 🟢 | 5 | 17 | Poseidon audit |
| FpChip (limb decomposition) | 🟢 | 3 | 14 | FpChip audit |
| Public Input Constraints | 🟢 | 2 | 10+ | Integration tests |

## 2. Cryptographic Primitives

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| Poseidon Hash | 🟢 | 5 | 17 | Полный аудит |
| secp256k1 EC operations | 🟢 | 4 | 10+ | Point validation |
| bn256 Pairing | 🟡 | 0 | 0 | halo2-lib dependency |
| KZG Commitment | 🟡 | 1 | 0 | halo2-proofs dependency |

## 3. Proof System

| Компонент | Статус | Fuzz | Props | Примечание |
|-----------|--------|------|-------|------------|
| generate_proof (prover.rs) | 🟡 | 1 | 13 | Требует error path тесты |
| verify_proof (verifier.rs) | 🟡 | 2 | 3 | Требует negative тесты |
| VK/PK Generation | 🔴 | 1 | 0 | Только crash resistance |
| KZG Params Setup | 🔴 | 0 | 0 | Не тестируется |
| Serialization (read/write) | 🔴 | 0 | 0 | Критично для production |

## 4. Security Properties

| Свойство | Статус | Fuzz | Props | Примечание |
|----------|--------|------|-------|------------|
| Soundness | 🟢 | 3 | 20+ | Полное покрытие |
| Completeness | 🟢 | 1 | 15+ | Полное покрытие |
| Replay Protection | 🟢 | 2 | 2 | Integration tests |
| Collision Resistance | 🟢 | 3 | 5+ | BC-007 documented |
| Non-malleability | 🟡 | 1 | 2 | Требует расширения |
| Binding properties | 🟢 | 4 | 4+ | Vault, token, sum |

## 5. Attack Vectors

| Атака | Статус | Fuzz | Props | Примечание |
|-------|--------|------|-------|------------|
| Keypair swap | 🟢 | 1 | 2 | Покрыто |
| Digest preimage | 🟢 | 1 | 1 | Покрыто |
| Limb overflow | 🟢 | 2 | 5+ | Покрыто |
| Range check bypass | 🟢 | 1 | 2 | Покрыто |
| Double spend | 🟢 | 1 | 1 | Покрыто |
| Weak generator | 🟢 | 1 | 1 | Покрыто |
| Field wrap | 🟢 | 1 | 2 | Покрыто |

---

## Статистика

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 39 |
| Property Tests | 156+ |
| Integration Tests | 13 |
| Audit Reports | 3 |
| Bug Candidates | 7 (BC-001 to BC-007) |

---

## Зоны требующие доработки

### 🟡 Желтые зоны (частично покрыты)

1. **bn256 Pairing** - внешняя зависимость, но можно добавить smoke tests
2. **KZG Commitment** - внешняя зависимость, но можно тестировать интеграцию
3. **generate_proof** - нет тестов error paths
4. **verify_proof** - нет negative tests с malformed proofs
5. **Non-malleability** - требует расширения proof mutation тестов

### 🔴 Красные зоны (не покрыты)

1. **VK/PK Generation** - нет property tests
2. **KZG Params Setup** - нет тестов вообще
3. **Serialization** - критично для production, нет тестов

---

## См. также

- [POSEIDON_AUDIT_REPORT.md](./POSEIDON_AUDIT_REPORT.md)
- [FPCHIP_AUDIT_REPORT.md](./FPCHIP_AUDIT_REPORT.md)
- [BUG_CANDIDATES.md](./BUG_CANDIDATES.md)

