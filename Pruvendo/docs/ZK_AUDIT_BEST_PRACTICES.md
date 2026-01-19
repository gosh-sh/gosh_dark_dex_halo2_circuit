# ZK Circuit Audit Best Practices

**Версия:** 1.0  
**Обновлено:** 2026-01-20  
**Источники:** Nethermind, Trail of Bits, Veridise, 0xPARC, Kudelski Security

---

## Ключевая статистика

> **96% всех задокументированных багов в SNARK системах вызваны under-constrained circuits**  
> — Nethermind Security, 2025

---

## Классификация уязвимостей

### 1. Under-Constrained Circuits (КРИТИЧНО)

**Описание:** Недостаточно constraints для предотвращения невалидных proofs.

**Признаки:**
- Prover может подставить произвольные значения
- Невалидные входы проходят верификацию
- Нарушение soundness

**Примеры атак:**
- Zcash 2018: unlimited token counterfeiting
- zkSync Era 2023: $1.9B forged withdrawals (fixed)

**Тестирование:**
- Fuzzing с невалидными witness значениями
- Mutation testing на proof bytes
- Проверка всех граничных случаев

---

### 2. Over-Constrained Circuits

**Описание:** Избыточные constraints отклоняют валидные входы.

**Признаки:**
- Валидные proofs не проходят верификацию
- Нарушение completeness

**Тестирование:**
- Property tests на completeness
- Fuzzing с валидными входами

---

### 3. Arithmetic Overflow/Underflow

**Описание:** Операции в scalar field выполняются modulo p.

**Пример (Circom/Halo2):**
```
(0 - 1) === p - 1  // underflow!
(p - 1 + 2) === 1  // overflow!
```

**Тестирование:**
- Edge cases: 0, 1, p-1, p-2
- Fuzzing с большими значениями
- Range check verification

---

### 4. Nondeterministic Circuits

**Описание:** Множественные способы создать валидный proof для одного outcome.

**Риски:**
- Replay attacks
- Nullifier bypass (double spend)

**Тестирование:**
- Determinism tests: same input → same proof
- Nullifier uniqueness verification

---

### 5. Unused Public Inputs (Optimizer Bug)

**Описание:** Circom/Halo2 оптимизаторы удаляют public inputs без constraints.

**Пример:**
```rust
// public input без constraints - будет удалён!
signal input unconstrained_public;
```

**Атака:** Prover может подставить любое значение для удалённого input.

**Тестирование:**
- Verify all public inputs are constrained
- Check R1CS/constraint count

---

### 6. Fiat-Shamir Vulnerabilities (Frozen Heart)

**Описание:** Неправильные входы в hash при генерации challenges.

**Риски:**
- Forging of proofs
- Replay attacks

**Типы:**
- Missing public inputs in transcript
- Missing proof elements in final challenge

**Тестирование:**
- Transcript manipulation tests
- Challenge derivation verification

---

### 7. Assigned but Not Constrained

**Описание:** Значение присвоено, но не ограничено constraint.

**Circom:** `<--` (assign) vs `<==` (constrain)  
**Halo2:** `assign_advice()` без соответствующего gate constraint

**Тестирование:**
- Static analysis
- Witness manipulation fuzzing

---

## Halo2-Специфичные уязвимости

### 8. Missing Copy Constraints

**Описание:** Отсутствие equality constraints между cells.

```rust
// Должно быть: region.constrain_equal(cell_a, cell_b)?;
```

**Тестирование:**
- Проверка что связанные значения действительно равны
- Fuzzing с разными значениями в "связанных" cells

---

### 9. Lookup Table Vulnerabilities

**Описание:** Неправильное использование lookup tables.

**Риски:**
- Lookup bypass
- Invalid table entries

---

### 10. Selector Misuse

**Описание:** Неправильные selector polynomials.

**Риски:**
- Gate activation errors
- Constraint bypass

---

## Чек-лист аудита ZK Circuit

### Soundness (Prover не может обмануть)
- [ ] Все witness values properly constrained
- [ ] Нет arithmetic overflow/underflow
- [ ] Range checks на все inputs
- [ ] Nullifiers deterministic и unique

### Completeness (Честный prover всегда успешен)
- [ ] Валидные inputs всегда дают valid proof
- [ ] Нет over-constraining
- [ ] Edge cases работают

### Zero-Knowledge (Proof не раскрывает witness)
- [ ] Private inputs не утекают через public outputs
- [ ] Нет timing/side-channel leaks

### Implementation
- [ ] Все public inputs used in constraints
- [ ] Copy constraints present where needed
- [ ] Correct Fiat-Shamir transcript
- [ ] No trusted setup leaks (if applicable)

---

## Инструменты

| Инструмент | Тип | Язык |
|------------|-----|------|
| Circomspect | Static Analysis | Circom |
| Korrekt (halo2-analyzer) | Static Analysis | Halo2 |
| Ecne | Formal Verification | R1CS |
| Picus | Under-constraint Detection | Circom |
| SNARKProbe | Dynamic Analysis | General |

---

## Ссылки

- [0xPARC ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker)
- [Nethermind ZK Security Guide](https://www.nethermind.io/blog/zk-circuit-security)
- [Kudelski: Halo2 Security](https://kudelskisecurity.com/research/on-the-security-of-halo2-proof-system)
- [Trail of Bits: Frozen Heart](https://blog.trailofbits.com/2022/04/13/part-1-coordinated-disclosure-of-vulnerabilities-affecting-girault-bulletproofs-and-plonk/)

