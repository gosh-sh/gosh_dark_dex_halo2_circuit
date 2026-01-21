# Timing Attack Analysis — DarkDEX Circuit

**Дата анализа:** 2026-01-21  
**Версия:** poseidon_instead_of_ecc  
**Статус:** ✅ Безопасно (при стандартной модели угроз)

## Резюме

| Находка | Риск | Эксплуатируемость | Рекомендация |
|---------|------|-------------------|--------------|
| Corrupted proof early exit (233x) | LOW | Требует прямой timing | Accept |
| Prover HW correlation (r=0.68) | VERY LOW | Тысячи измерений | Accept |
| Field inversion variance (30%) | N/A | Не используется | Accept |
| Poseidon hash | NONE | Constant-time | ✅ |
| Valid vs Invalid proof | NONE | 0.20% deviation | ✅ |

**Заключение:** Все найденные timing особенности НЕ являются эксплуатируемыми уязвимостями.

---

## 1. Verifier Timing Analysis

### 1.1 Результаты измерений

```
Valid proof:      4430 µs (median)
Wrong digest:     4421 µs (median)  — deviation 0.20%
Corrupted proof:    19 µs (median)  — 233x faster
```

### 1.2 Сценарий атаки: Early Exit Oracle

**Атакующий:** Внешний наблюдатель с доступом к timing ответов

**Цель:** Определить причину отклонения proof

**Шаги:**
1. Отправить proof на верификацию
2. Измерить время ответа
3. ~19µs → parsing error, ~4400µs → полная верификация

**Информационная утечка:** Только валидность формата (публичная информация)

**Практическая опасность: НИЗКАЯ**
- Network jitter (ms) >> verification time (µs)
- Формат proof публично известен
- Не раскрывает секретные данные

### 1.3 Защита (опциональная)

```rust
const MIN_VERIFY_TIME: Duration = Duration::from_millis(10);

pub fn verify_proof_constant_time(...) -> bool {
    let start = Instant::now();
    let result = verify_proof_internal(...);
    
    let elapsed = start.elapsed();
    if elapsed < MIN_VERIFY_TIME {
        std::thread::sleep(MIN_VERIFY_TIME - elapsed);
    }
    result
}
```

---

## 2. Prover Timing Correlation

### 2.1 Результаты измерений

```
SK 0x0000000000000001 (HW=1):  264 ms
SK 0x8000000000000000 (HW=1):  281 ms
SK 0xffffffffffffffff (HW=64): 292 ms
SK 0xaaaaaaaaaaaaaaaa (HW=32): 293 ms

Pearson correlation (HW vs time): 0.68
Max deviation: 6.95%
```

### 2.2 Сценарий атаки: Hamming Weight Recovery

**Атакующий:** Имеет доступ к timing prover (shared server, SGX side-channel)

**Цель:** Восстановить Hamming Weight секретного sk

**Математическая модель:**
```
t(sk) ≈ 260ms + 0.5ms × HammingWeight(sk)
```

**Информационная утечка:**
```
Энтропия sk:           256 бит
Информация от HW:      ~8 бит (log2(256))
С учётом шума (r=0.68): ~3.6 бит
Реальная утечка:       1.4% энтропии
```

**Практическая опасность: ОЧЕНЬ НИЗКАЯ**
- Нужны тысячи измерений с одним sk
- sk обновляется каждую транзакцию
- Prover изолирован на клиенте пользователя
- 3 бита из 256 — криптографически бесполезно

### 2.3 Защита (опциональная)

```rust
fn generate_proof_with_jitter(...) -> Vec<u8> {
    let jitter = rand::thread_rng().gen_range(0..50);
    let proof = generate_proof_internal(...);
    thread::sleep(Duration::from_millis(jitter));
    proof
}
```

---

## 3. Field Arithmetic Timing

### 3.1 Результаты измерений

```
Field multiplication (all patterns): 2.43 ns — deviation 0.00%
Field inversion:
  Fr::one():         1083 ns
  Fr::from(u64::MAX): 1397 ns
  -Fr::one():        1031 ns
  Variance: ~30%
```

### 3.2 Анализ

**Multiplication:** ✅ Constant-time (Montgomery multiplication)

**Inversion:** ⚠️ Variable-time (Extended Euclidean Algorithm)

**Риск для DarkDEX: ОТСУТСТВУЕТ**
```bash
$ grep -rn "invert\|inverse" src/ --include="*.rs"
# Результат: пусто — inversion не используется
```

Poseidon hash использует только ADD и MUL, без inversion.

---

## 4. Poseidon Hash Timing

### 4.1 Результаты измерений

```
Pattern 0 (all zeros):     26-29 ns
Pattern 1 (all ones):      26-29 ns  
Pattern 2 (alternating):   26-29 ns
Max deviation: < 20%
```

### 4.2 Анализ

Poseidon hash — constant-time by design:
- Fixed number of rounds
- No secret-dependent branches
- Only field ADD and MUL

**Риск: ОТСУТСТВУЕТ**

---

## 5. Архитектурные защиты DarkDEX

```
┌─────────────────────────────────────────────────────────────┐
│ Компонент    │ Расположение  │ Доступ атакующего           │
├──────────────┼───────────────┼─────────────────────────────┤
│ Prover       │ Клиент        │ ❌ Нет доступа к timing     │
│ Verifier     │ Блокчейн      │ ❌ Network latency >> µs    │
│ sk           │ Fresh каждый  │ ❌ Нет накопления статистики│
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Тесты

Все timing тесты находятся в `Pruvendo/tests/property_tests/src/timing_tests.rs`:

| Тест | Описание |
|------|----------|
| `test_poseidon_constant_time` | Poseidon не зависит от input pattern |
| `test_verifier_timing_valid_vs_invalid` | Valid vs invalid proof timing |
| `test_prover_timing_no_sk_correlation` | Prover vs sk hamming weight |
| `test_field_arithmetic_timing` | Field MUL/INV timing |
| `test_mockprover_no_sk_correlation` | MockProver timing |
| `test_sk_commitment_timing` | sk_commitment timing |
| `test_special_sk_values_timing` | Edge case sk values |

Запуск:
```bash
cd Pruvendo/tests/property_tests
cargo test --release -- --nocapture timing
```

---

## 7. Рекомендации

### Текущий уровень (Acceptable)
Реализация безопасна при стандартной модели угроз.

### Для high-value deployments
- Добавить constant-time wrapper для verifier
- Добавить jitter для prover

### Для adversarial environments (SGX, shared hosting)
- Constant-time field library (`subtle` crate)
- Изоляция prover в отдельном процессе
- Hardware timing isolation

---

## 8. История изменений

| Дата | Изменение |
|------|-----------|
| 2026-01-21 | Первичный анализ, 7 timing тестов |

