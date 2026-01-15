# План тестирования Dark DEX Halo2 Circuit

**Версия:** 3.0
**Обновлено:** 2026-01-15

---

## Текущий статус

| Метрика | Значение |
|---------|----------|
| Fuzz Targets | 42 |
| Property Tests | 198+ |
| Integration Tests | 13 |
| Bug Candidates | 7 (BC-001 to BC-007) |

**Подробный статус покрытия**: см. [COVERAGE_STATUS.md](./COVERAGE_STATUS.md)

---

## ПРИОРИТЕТНЫЙ ПЛАН (v3.0) - ✅ ЗАВЕРШЁН

### Приоритеты
- **P1 (High)**: 🟢 Желтые зоны - ✅ ПОКРЫТЫ
- **P2 (Medium)**: 🟢 Красные зоны - ✅ ПОКРЫТЫ
- **P3 (Low)**: Дополнительные улучшения

---

## P1: Желтые зоны ✅ ЗАВЕРШЕНО

### 1.1 Prover Error Paths ✅
**Файл**: `src/prover.rs`

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| generate_proof с невалидными параметрами | ✅ | ✅ |
| keygen_vk/keygen_pk с некорректной схемой | ✅ | ✅ |
| Error handling при недостаточных ресурсах | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/tests/property_tests/src/prover_tests.rs` (8 тестов)
- ✅ `Pruvendo/fuzz/fuzz_targets/fuzz_prover_error_paths.rs`

---

### 1.2 Verifier Negative Tests ✅
**Файл**: `src/verifier.rs`

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| verify_proof_ с malformed proof bytes | ✅ | ✅ |
| verify_proof_ с неправильными public inputs | ✅ | ✅ |
| verification_key_from_bytes с corrupted VK | ✅ | ✅ |
| verification_key_from_path с несуществующим файлом | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/tests/property_tests/src/verifier_tests.rs` (10 тестов)
- ✅ `Pruvendo/fuzz/fuzz_targets/fuzz_verifier_negative.rs`

---

### 1.3 Non-malleability Extension ✅

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| Proof mutation (bit flips, truncation) | ✅ | ✅ |
| Transcript manipulation | ✅ | ✅ |
| Public input permutation | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/fuzz/fuzz_targets/fuzz_proof_malleability.rs`

---

### 1.4 KZG Integration Tests ✅

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| Params размер vs k | ✅ | ✅ |
| Commitment consistency | ✅ | ✅ |
| Pairing check smoke tests | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/tests/property_tests/src/kzg_tests.rs` (7 тестов)

**Важное наблюдение**: KZG params НЕ детерминистичны (используют RNG) - это ожидаемое поведение.

---

## P2: Красные зоны ✅ ЗАВЕРШЕНО

### 2.1 VK/PK Generation Tests ✅
**Файл**: `src/prover.rs`

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| VK детерминизм (same circuit → same VK) | ✅ | ✅ |
| PK детерминизм | ✅ | ✅ |
| VK/PK consistency | ✅ | ✅ |
| VK size bounds | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/tests/property_tests/src/keygen_tests.rs` (4 теста)

---

### 2.2 Serialization Tests ✅
**Файлы**: `src/prover.rs`, `src/verifier.rs`

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| VK write → read roundtrip | ✅ | ✅ |
| KZG Params write → read roundtrip | ✅ | ✅ |
| Corrupted bytes handling | ✅ | ✅ |
| Version compatibility | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/tests/property_tests/src/serialization_tests.rs` (6 тестов)

---

### 2.3 KZG Params Setup Tests ✅
**Файл**: `src/prover.rs`

| Что тестировать | Fuzz | Prop |
|-----------------|------|------|
| Params генерация детерминизм | ✅ | ✅ |
| Params size для разных k | ✅ | ✅ |
| read_kzg_params с corrupted данными | ✅ | ✅ |

**Deliverables**:
- ✅ `Pruvendo/tests/property_tests/src/params_tests.rs` (7 тестов)

---

## Ожидаемые результаты

После выполнения P1+P2:
- **Fuzz Targets**: 39 → ~47 (+8)
- **Property Tests**: 156 → ~200 (+44)
- **Все зоны**: 🟢 (полностью покрыты)

---

## Архив: ранее выполненные задачи

### ✅ Фаза 1: Базовое расширение (ЗАВЕРШЕНО)
- [x] Property-based тесты (156+ тестов)
- [x] Fuzz targets (39 targets)
- [x] Integration tests (13 тестов)

### ✅ Фаза 2: Аудит компонентов (ЗАВЕРШЕНО)
- [x] Poseidon audit (17 тестов)
- [x] FpChip audit (14 тестов)
- [x] Bug candidates tracking (BC-001 to BC-007)

---

# ===============================================
# АРХИВНЫЙ РАЗДЕЛ (старая версия плана)
# ===============================================

## Существующие тесты (из src/test.rs)

| Тест | Описание | Статус |
|------|----------|--------|
| `simple_test` | Базовый тест с MockProver | ✅ PASSED |
| `generate_and_backup_kzg_params_test` | Генерация KZG параметров | ✅ PASSED |
| `generate_and_backup_verification_key_test` | Генерация ключа верификации | ✅ PASSED |
| `verifier_sketch_test` | Верификация из файлов | ✅ PASSED |
| `full_test_with_backuped_params` | Полный тест с сохраненными параметрами | ✅ PASSED |
| `full_test` | End-to-end тест | ✅ PASSED |

## Архивный план тестирования

### 3.1 Unit-тесты (модульные)

#### 3.1.1 Модуль circuit.rs
- [ ] Тест создания DarkDexCircuit с валидными параметрами
- [ ] Тест создания DarkDexCircuit с None значениями (default)
- [ ] Тест загрузки конфигурации из файла
- [ ] Тест корректности constraint system

#### 3.1.2 Модуль prover.rs
- [ ] Тест `setup()` - создание KZG параметров
- [ ] Тест сериализации/десериализации KZG параметров
- [ ] Тест генерации proving key
- [ ] Тест генерации verification key
- [ ] Тест генерации proof

#### 3.1.3 Модуль verifier.rs
- [ ] Тест загрузки verification key из байтов
- [ ] Тест загрузки verification key из файла
- [ ] Тест верификации валидного proof
- [ ] Тест отклонения невалидного proof

### 3.2 Integration-тесты (интеграционные)

#### 3.2.1 Полный цикл prove-verify
- [ ] Генерация ключей → создание proof → верификация
- [ ] Тест с различными значениями token_type
- [ ] Тест с различными значениями private_note_sum
- [ ] Тест с различными секретными ключами

#### 3.2.2 Тесты персистентности
- [ ] Сохранение и загрузка KZG параметров
- [ ] Сохранение и загрузка verification key
- [ ] Сохранение и загрузка proof

### 3.3 Negative-тесты (негативные сценарии)

#### 3.3.1 Некорректные входные данные
- [ ] Неверная пара sk/pk (pk ≠ sk * G)
- [ ] Несоответствие public inputs и witness
- [ ] Неверный token_type в public inputs
- [ ] Неверный private_note_sum в public inputs

#### 3.3.2 Поврежденные данные
- [ ] Поврежденный proof
- [ ] Поврежденный verification key
- [ ] Поврежденные KZG параметры

### 3.4 Performance-тесты (производительность)

- [ ] Время генерации KZG параметров (k=18)
- [ ] Время генерации proving key
- [ ] Время генерации proof
- [ ] Время верификации proof
- [ ] Размер proof в байтах
- [ ] Размер verification key в байтах

### 3.5 Security-тесты (безопасность)

- [ ] Невозможность извлечения sk из proof
- [ ] Невозможность подделки proof без знания sk
- [ ] Soundness: невозможность создать валидный proof для неверных данных

## 4. Приоритеты тестирования

### Высокий приоритет
1. Запуск существующих тестов и проверка их работоспособности
2. Negative-тесты для проверки soundness схемы
3. Integration-тесты полного цикла

### Средний приоритет
4. Unit-тесты для каждого модуля
5. Performance-тесты

### Низкий приоритет
6. Security-тесты (требуют глубокого анализа)
7. Stress-тесты

## 5. Инструменты тестирования

### 5.1 Базовые инструменты (уже используются)

- **MockProver** - быстрая проверка constraint satisfaction
- **cargo test** - запуск unit и integration тестов

### 5.2 Рекомендуемые дополнительные инструменты

| Инструмент | Назначение | Сложность внедрения |
|------------|------------|---------------------|
| **criterion** | Бенчмарки производительности | Низкая |
| **proptest** | Property-based testing | Средняя |
| **cargo-fuzz** | Coverage-guided fuzzing | Средняя |
| **halo2-analyzer** | Статический анализ Halo2 схем | Средняя |
| **Z3 (rsmt2)** | SMT верификация constraints | Высокая |

## 6. Продвинутые методы тестирования

### 6.1 Property-Based Testing (proptest)

**Цель:** Автоматическая генерация тестовых случаев для проверки инвариантов схемы.

**Зависимость:**
```toml
[dev-dependencies]
proptest = "1.4"
```

**Примеры свойств для проверки:**

1. **Корректность ключевой пары:**
   ```rust
   proptest! {
       #[test]
       fn prop_valid_keypair_always_verifies(sk in 1u64..u64::MAX) {
           let sk = Fq::from(sk);
           let g = Secp256k1Affine::generator();
           let pk = Secp256k1Affine::from(g * sk);
           // Схема должна проходить для любой валидной пары
           assert!(circuit_verifies(sk, pk, g));
       }
   }
   ```

2. **Soundness (некорректные данные отклоняются):**
   ```rust
   proptest! {
       #[test]
       fn prop_invalid_keypair_fails(sk1 in 1u64..u64::MAX, sk2 in 1u64..u64::MAX) {
           prop_assume!(sk1 != sk2);
           let sk = Fq::from(sk1);
           let wrong_pk = Secp256k1Affine::from(Secp256k1Affine::generator() * Fq::from(sk2));
           // Схема должна отклонять неверную пару
           assert!(!circuit_verifies(sk, wrong_pk, g));
       }
   }
   ```

3. **Консистентность public inputs:**
   ```rust
   proptest! {
       #[test]
       fn prop_public_inputs_must_match(
           token_type in 0u64..1000,
           private_note_sum in 0u64..1_000_000,
           wrong_token in 0u64..1000
       ) {
           prop_assume!(token_type != wrong_token);
           // Proof с неправильным token_type не должен верифицироваться
       }
   }
   ```

### 6.2 Fuzzing (cargo-fuzz / libFuzzer)

**Цель:** Поиск крашей, паник и edge cases в коде схемы.

**Установка:**
```bash
cargo install cargo-fuzz
cargo fuzz init
```

**Targets для фаззинга:**

1. **Fuzz verifier с произвольным proof:**
   ```rust
   // fuzz/fuzz_targets/fuzz_verifier.rs
   #![no_main]
   use libfuzzer_sys::fuzz_target;

   fuzz_target!(|data: &[u8]| {
       if data.len() < 100 { return; }
       let _ = verify_proof_(&params, data, &vk, pub_inputs);
   });
   ```

2. **Fuzz witness generation:**
   ```rust
   fuzz_target!(|data: (u64, u64, u64)| {
       let (sk_val, token, note_sum) = data;
       let sk = Fq::from(sk_val);
       let circuit = DarkDexCircuit::new(...);
       let _ = MockProver::run(18, &circuit, public_inputs);
   });
   ```

3. **Fuzz serialization/deserialization:**
   ```rust
   fuzz_target!(|data: &[u8]| {
       let _ = verification_key_from_bytes(data);
       let _ = ParamsKZG::<Bn256>::read_custom(data, SerdeFormat::RawBytesUnchecked);
   });
   ```

### 6.3 SMT-based Formal Verification

**Цель:** Формальное доказательство корректности constraints схемы.

**Инструменты:**

| Инструмент | Описание | Применимость |
|------------|----------|--------------|
| **halo2-analyzer** | Quantstamp: анализ Halo2 схем | ★★★ Прямая |
| **Z3 (rsmt2 crate)** | SMT solver для Rust | ★★☆ Требует адаптации |
| **cvc5** | SMT solver с теорией конечных полей | ★★☆ Экспериментальный |

**Подход с halo2-analyzer:**

```bash
# Установка
cargo install halo2-analyzer

# Запуск анализа
halo2-analyzer analyze --circuit DarkDexCircuit
```

**Проверяемые свойства:**

1. **Under-constrained detection:**
   - Проверка что все witness значения уникально определены constraints
   - Поиск "свободных" переменных

2. **Soundness verification:**
   - Формальное доказательство: `∀ sk, pk, g: pk ≠ sk*g → circuit fails`

3. **Completeness verification:**
   - Формальное доказательство: `∀ sk, g: circuit(sk, sk*g, g) = OK`

**SMT формулировка (псевдокод для Z3):**

```smt2
; Определение конечного поля Fq (secp256k1 scalar field)
(declare-const sk (_ FiniteField 0x...))
(declare-const pk_x (_ FiniteField 0x...))
(declare-const pk_y (_ FiniteField 0x...))

; Constraint: pk = sk * G
(assert (= (scalar_mult sk G) (mk-point pk_x pk_y)))

; Проверка soundness: существует ли sk' ≠ sk такой что тот же pk?
(assert (exists ((sk_prime FiniteField))
    (and (not (= sk sk_prime))
         (= (scalar_mult sk_prime G) (mk-point pk_x pk_y)))))

(check-sat) ; Должен вернуть UNSAT (доказательство soundness)
```

### 6.4 Differential Testing

**Цель:** Сравнение результатов схемы с эталонной реализацией.

**Подход:**
```rust
#[test]
fn differential_test_scalar_mult() {
    // Эталонная реализация (например, из другой библиотеки)
    let expected = reference_impl::scalar_mult(sk, g);

    // Наша схема
    let circuit_result = run_circuit_and_extract_pk(...);

    assert_eq!(expected, circuit_result);
}
```

## 7. Команды для запуска тестов

```bash
# === Базовые тесты ===

# Запуск всех тестов (release для скорости)
cargo test --release

# Запуск конкретного теста
cargo test simple_test --release -- --nocapture

# Запуск только быстрых тестов
cargo test simple_test verifier_sketch_test --release

# === Property-based tests (после добавления proptest) ===
cargo test prop_ --release

# === Fuzzing (после настройки cargo-fuzz) ===
cargo +nightly fuzz run fuzz_verifier
cargo +nightly fuzz run fuzz_witness

# === Бенчмарки (после добавления criterion) ===
cargo bench

# === Статический анализ ===
cargo clippy -- -D warnings
halo2-analyzer analyze
```

## 8. Типичные уязвимости ZKP схем для проверки

На основе исследований (0xPARC zk-bug-tracker, zkSecurity):

| Категория | Описание | Метод проверки |
|-----------|----------|----------------|
| **Under-constrained** | Недостаточно constraints, witness не уникален | SMT, halo2-analyzer |
| **Over-constrained** | Избыточные constraints, валидный witness отклоняется | Property tests |
| **Missing range checks** | Переполнение полей | Fuzzing, property tests |
| **Nondeterministic** | Различные выходы для одинаковых входов | Differential testing |
| **Unsound** | Можно создать proof для ложного утверждения | SMT verification |
| **Fiat-Shamir attacks** | Слабый transcript | Ручной аудит |

## 9. План реализации

### Фаза 1: Базовое расширение (1-2 дня) ✅ ЗАВЕРШЕНО
- [x] Проверка существующих тестов
- [x] Добавление proptest зависимости
- [x] Написание 5-10 property tests (реализовано 73 теста!)
- [x] Обновление тестов для poseidon_integration

**Реализованные property-based тесты** (`Pruvendo/tests/property_tests/`):
```
cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release
# 59 обычных тестов + 23 ignored (требуют файлы) = 82 теста всего
```

### Фаза 2: Fuzzing (2-3 дня) ✅ ЗАВЕРШЕНО
- [x] Настройка cargo-fuzz (симлинк fuzz -> Pruvendo/fuzz)
- [x] Создание fuzz targets для verifier (fuzz_verifier_bytes)
- [x] Создание fuzz targets для soundness/completeness
- [x] Создание fuzz targets для binding (token, sum)
- [x] Создание fuzz targets для edge cases
- [x] Запуск fuzzing кампании и анализ результатов

**Найдено 6 багов**: BC-001 - BC-006 (см. component_testing_plan.md)

### Фаза 3: Расширенное тестирование схемы (НОВОЕ)

#### 3.1 Тесты на Limb Decomposition (proptest)
- [ ] **LIMB-01**: Корректность разбиения pk.x на 3 limbs (11+11+10 байт)
- [ ] **LIMB-02**: Корректность разбиения pk.y на 3 limbs
- [ ] **LIMB-03**: Корректность разбиения sk на 3 limbs
- [ ] **LIMB-04**: Обратимость: limbs → original value
- [ ] **LIMB-05**: Переполнение при суммировании 9 limbs в key_data_sum

#### 3.2 Тесты на Коллизии key_data_sum (proptest)
- [ ] **COLL-01**: Разные (sk, pk) дают разные key_data_sum
- [ ] **COLL-02**: Поиск коллизий методом дней рождения (birthday attack)
- [ ] **COLL-03**: Специально сконструированные sk для collision

#### 3.3 Тесты на Binding deposit_identifier (proptest)
- [ ] **BIND-01**: token + sum + vault_rand однозначно определяют deposit_id
- [ ] **BIND-02**: Нельзя найти (token', sum', vault') ≠ (token, sum, vault) с той же суммой и тем же digest
- [ ] **BIND-03**: Атака подмены значений при сохранении суммы

#### 3.4 Тесты на Generator Point (proptest)
- [ ] **GEN-01**: Нестандартный генератор (точка на кривой, но не G)
- [ ] **GEN-02**: Генератор с малым порядком (если существует)
- [ ] **GEN-03**: g = pk (самоссылка)
- [ ] **GEN-04**: g = identity (уже есть, BC-002)

#### 3.5 Тесты на Overflow (proptest)
- [ ] **OVF-01**: limb values близкие к Fr::MODULUS
- [ ] **OVF-02**: Суммы limbs вызывающие wrap-around
- [ ] **OVF-03**: deposit_identifier_sum overflow

#### 3.6 Тесты на Proof Malleability (proptest)
- [ ] **MAL-01**: Можно ли модифицировать proof сохранив валидность?
- [ ] **MAL-02**: Канонизация proof (нормализация представления)
- [ ] **MAL-03**: Эквивалентные proof с разными байтами

### Фаза 4: Статический анализ (1-2 дня)
- [ ] Установка и настройка halo2-analyzer
- [ ] Анализ схемы на under-constrained bugs
- [ ] Документирование результатов

### Фаза 5: Формальная верификация (3-5 дней)
- [ ] Изучение SMT подхода для ZK circuits
- [ ] Экспорт constraints в SMT формат
- [ ] Проверка soundness/completeness
- [ ] Документирование формальных доказательств

## 10. Ожидаемые результаты

После выполнения плана тестирования:
- ✅ Все существующие тесты проходят (82 теста)
- ✅ Property-based тесты покрывают инварианты (73 теста)
- ✅ Fuzzing выполнен, найдено 6 багов (BC-001 - BC-006)
- ⬜ Тесты на limb decomposition (LIMB-01 - LIMB-05)
- ⬜ Тесты на коллизии key_data_sum (COLL-01 - COLL-03)
- ⬜ Тесты на binding deposit_identifier (BIND-01 - BIND-03)
- ⬜ Тесты на generator point (GEN-01 - GEN-04)
- ⬜ Тесты на overflow (OVF-01 - OVF-03)
- ⬜ Тесты на proof malleability (MAL-01 - MAL-03)
- ⬜ Статический анализ не обнаруживает under-constrained bugs
- ⬜ Формальная верификация подтверждает soundness

## 11. Ресурсы и ссылки

### Инструменты
- [halo2-analyzer (Quantstamp)](https://github.com/quantstamp/halo2-analyzer)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [proptest](https://github.com/proptest-rs/proptest)
- [rsmt2 (Z3 bindings)](https://github.com/AdrienChampion/rsmt2)

### Исследования по безопасности ZKP
- [Awesome-ZKP-Security](https://github.com/StefanosChaliasos/Awesome-ZKP-Security)
- [0xPARC zk-bug-tracker](https://github.com/0xPARC/zk-bug-tracker)
- [Trail of Bits: Halo2 Deep Dive](https://blog.trailofbits.com/2025/05/30/a-deep-dive-into-axioms-halo2-circuits/)

### Научные статьи
- "Automated Analysis of Halo2 Circuits" (ePrint 2023/1051)
- "SoK: Understanding Security Vulnerabilities in SNARKs" (arXiv 2024)
- "Practical Security Analysis of Zero-Knowledge Proof Circuits" (ZKAP)

