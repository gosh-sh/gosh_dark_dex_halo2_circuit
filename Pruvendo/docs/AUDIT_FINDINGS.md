# DarkDex ZK Circuit - Audit Findings Report

**Дата:** 2026-01-21
**Версия схемы:** poseidon_instead_of_ecc
**Аудитор:** Pruvendo

## Executive Summary

Проведён комплексный аудит безопасности ZK-схемы DarkDex, включающий:
- Фаззинг (32 targets, 5+ часов overnight)
- Property-based тестирование (130+ тестов)
- Real prover тестирование (12 тестов)
- Формальное моделирование (Quint + Apalache BMC)
- Ручной анализ constraints

**Общий вердикт: ✅ БЕЗОПАСНО** (с оговорками по upstream зависимостям)

---

## 1. Bug Candidates Summary

| BC ID | Название | Severity | Статус | Локация |
|-------|----------|----------|--------|---------|
| BC-001 | Panic при некорректном VK bytes | Medium | OPEN | halo2curves (upstream) |
| BC-002 | g = identity point | Critical | CLOSED | Убрано с ECC |
| BC-003 | shl_overflow в KZG header | Medium | OPEN | halo2_proofs (upstream) |
| BC-004 | Limb overflow | High | CLOSED | Убрано с ECC |
| BC-005 | shl_overflow в domain.rs | Medium | OPEN | halo2_proofs (upstream) |
| BC-006 | Non-canonical field elements | Low | OPEN | halo2curves (upstream) |
| BC-007 | deposit_sum collision | Critical | CLOSED | Формула изменена |
| BC-008 | Split с одинаковыми суммами | Info | NOT A BUG | Артефакт модели |
| BC-009 | Timing side-channel verifier | Medium | **ACCEPT** (недостижимая атака) | verifier::verify_proof_ |

### Статистика
- **Найдено:** 9 bug candidates
- **Подтверждено/исправлено:** 3 (BC-002, BC-004, BC-007)
- **Upstream issues:** 4 (BC-001, BC-003, BC-005, BC-006)
- **Не баг:** 1 (BC-008)
- **ACCEPT (недостижимая атака):** 1 (BC-009)

---

## 2. Проверенные Security Properties

### 2.1 Soundness ✅
**Невалидные доказательства отклоняются**

| Тест | Результат |
|------|-----------|
| Wrong sk_commitment | REJECTED |
| Wrong digest | REJECTED |
| Wrong token_type | REJECTED |
| Wrong private_note_sum | REJECTED |
| Mutated proof bytes | REJECTED |

### 2.2 Completeness ✅
**Валидные доказательства принимаются**

- Протестировано на полном диапазоне u64
- 146+ fuzz runs без false rejections
- Property tests: 50 cases × 6 categories

### 2.3 Binding Properties ✅
**Public inputs связаны с witness**

| Property | Статус |
|----------|--------|
| Token binding | ✅ Verified |
| Sum binding | ✅ Verified |
| Commitment binding | ✅ Verified |
| Digest binding | ✅ Verified |

### 2.4 Constraint Security ✅
**Нет under-constrained witnesses**

| Check | Статус |
|-------|--------|
| All public inputs used | ✅ Verified |
| sk constrained to commitment | ✅ Verified |
| No unused witnesses | ✅ Verified |
| Copy constraints valid | ✅ Verified |

### 2.5 Poseidon Hash ✅
**Криптографически корректен**

- MDS matrix invertible
- S-box = x^5
- Round constants non-trivial
- Gadget = Primitive consistency
- 2000+ random tests passed

---

## 3. Attack Vectors Tested

| Attack | Результат | Тест |
|--------|-----------|------|
| Double spend | BLOCKED | fuzz_double_spend_attack |
| Proof replay | BLOCKED | fuzz_proof_replay |
| Digest collision | BLOCKED | fuzz_digest_collision |
| Cross-user attack | BLOCKED | integration_tests |
| Witness manipulation | BLOCKED | fuzz_witness_manipulation |
| Proof malleability | BLOCKED | fuzz_proof_malleability |

---

## 4. Ограничения аудита

1. **Upstream dependencies не исправлены** - BC-001, BC-003, BC-005, BC-006 требуют исправления в halo2_proofs/halo2curves
2. **Formal verification ограничена** - Korrekt не интегрирован; Apalache выполняет **bounded** model checking (см. ниже)
3. **Side-channel attacks не тестировались** - Timing attacks вне scope
4. **Real prover tests добавлены** - ✅ Теперь есть 12 тестов с реальным KZG prover/verifier

### ⚠️ Важно: Bounded Model Checking

Apalache выполняет **bounded model checking**, а не exhaustive verification:
- "VERIFIED" означает: *"нет контрпримера в пределах N шагов"*
- Это **НЕ** означает: *"свойство доказано для всех возможных путей"*
- Текущая конфигурация: max-steps=5 (day), max-steps=25 (night)

Для увеличения уверенности используйте night profile с большим max-steps.

### Проверяемые инварианты Quint/Apalache

| Инвариант | Описание | Статус |
|-----------|----------|--------|
| `inv_dex_non_negative` | DEX balance ≥ 0 | ✅ VERIFIED |
| `inv_owner_only` | Только владелец может вывести | ✅ VERIFIED |
| `inv_no_double_withdraw` | Нет двойного вывода | ✅ VERIFIED |
| `inv_unique_digests` | Уникальность digest | ✅ VERIFIED |
| `inv_conservation` | Общая консервация токенов | ✅ VERIFIED |
| `inv_no_overflow` | Нет переполнения сумм | ✅ VERIFIED |
| `inv_token_isolation` | Изоляция типов токенов | ✅ VERIFIED |
| `inv_token_conservation` | Консервация по типам токенов | ✅ VERIFIED |

---

## 5. Рекомендации

### Критические (до production)
- [ ] Обновить upstream зависимости при появлении фиксов BC-001, BC-003, BC-005
- [ ] Валидировать входные данные перед десериализацией (BC-006)

### Рекомендуемые
- [ ] Добавить regression тест на gate count
- [x] Интегрировать Apalache для formal verification (8 инвариантов)

---

## 6. Timing Side-Channel Analysis

**Статус:** ✅ Безопасно (см. [TIMING_ANALYSIS.md](./TIMING_ANALYSIS.md), [BC_TRACKING.md](./BC_TRACKING.md) BC-009)

### Проверенные vectors:

| Vector | Результат | Risk |
|--------|-----------|------|
| Poseidon hash timing | Constant-time | NONE |
| Valid vs Invalid proof | 0.20% deviation | NONE |
| Prover sk correlation | r=0.68, 6.95% dev | VERY LOW |
| Field multiplication | 0.00% deviation | NONE |
| Field inversion | 30% variance | N/A (не используется) |
| **Timing oracle attack (BC-009)** | **ACCEPT: SNR=0.59, 2^254 field, 10^68 лет** | **NONE** |

### Архитектурные защиты:
- Prover изолирован на клиенте
- Verifier доступен только через сеть (latency >> µs)
- sk fresh для каждой транзакции
- BC-009: **ACCEPT** — timing oracle brute-force требует 1.70×10^68 лет (недостижимая атака)

---

## 7. Файлы аудита

| Файл | Описание |
|------|----------|
| `Pruvendo/docs/BC_TRACKING.md` | Детали bug candidates |
| `Pruvendo/docs/FUZZING_REPORT.md` | Описание fuzz targets |
| `Pruvendo/docs/POSEIDON_AUDIT_REPORT.md` | Аудит Poseidon hash |
| `Pruvendo/docs/TIMING_ANALYSIS.md` | Анализ timing side-channels |
| `Pruvendo/fuzz/fuzz_targets/` | 31 fuzz target |
| `Pruvendo/tests/property_tests/` | Property тесты (132 теста) |
| `Pruvendo/models/dark_dex_protocol.qnt` | Quint модель |

---

**Подпись:** Pruvendo Security Audit Team
**Дата последнего обновления:** 2026-01-21

