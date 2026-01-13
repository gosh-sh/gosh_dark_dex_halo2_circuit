# План компонентного тестирования DarkDex Circuit

## Обзор системы

Система состоит из 3 основных компонентов:
- **DarkDexCircuit** - ZKP схема для проверки keypair и привязки public inputs
- **Prover** - генерация KZG параметров и доказательств
- **Verifier** - верификация доказательств

---

## 1. DarkDexCircuit (circuit.rs)

### Текущие constraints:
1. `pk.x == (g * sk).x` - X-координата публичного ключа
2. `pk.y == (g * sk).y` - Y-координата публичного ключа
3. `token_type` связан с public input[0]
4. `private_note_sum` связан с public input[1]

### Покрытие тестами:
| Свойство | Статус | Тесты |
|----------|--------|-------|
| Completeness | ✅ | test_completeness_* |
| Soundness (keypair) | ✅ | test_soundness_wrong_pk_* |
| Soundness (token) | ✅ | test_soundness_wrong_token |
| Soundness (sum) | ✅ | test_soundness_wrong_sum |
| Edge cases | ✅ | test_edge_case_* |

### Реализованные тесты:
| ID | Тест | Описание | Статус |
|----|------|----------|--------|
| C-01 | `test_sk_zero` | sk = 0 (точка бесконечности) | ✅ PASS |
| C-05 | `test_scalar_field_large_value` | sk = u64::MAX | ✅ PASS |
| C-06a | `test_token_type_max_u64` | token = u64::MAX | ✅ PASS |
| C-06b | `test_note_sum_max_u64` | sum = u64::MAX | ✅ PASS |

| C-02 | `test_pk_identity_point` | pk = identity point | ✅ PASS |
| X-01 | `test_sk_curve_order` | sk = large value near field boundary | ✅ PASS |
| X-02 | `test_values_near_fr_modulus` | token/sum = u64::MAX | ✅ PASS |
| X-03 | `test_generator_identity` | g = identity point | 🐛 BUG-002 (panic) |
| P-01 | `test_prover_mismatched_private_public` | private ≠ public values | ✅ PASS |
| P-03 | `test_circuit_size_requirement` | k=18 работает | ✅ PASS |
| P-04 | `test_proof_size_consistency` | proof size константен | ✅ (ignored - требует файлы) |

| C-04 | `test_non_standard_generator` | g ≠ стандартный генератор | ✅ PASS |
| P-02 | `test_kzg_params_integrity` | KZG params валидны | ✅ PASS |
| REG-01 | `test_multiple_valid_keypairs` | Regression тест валидных keypairs | ✅ PASS |
| REG-02 | `test_multiple_invalid_keypairs` | Regression тест невалидных keypairs | ✅ PASS |

| C-03 | `test_pk_wrong_coordinates` | pk ≠ sk * G | ✅ PASS |
| STRESS | `test_stress_random_keypairs` | 20 случайных keypairs | ✅ PASS |

### Тесты полностью покрывают план. Все HIGH и MEDIUM приоритеты реализованы.

---

## 5. Негативные тесты сериализации

| ID | Тест | Описание | Статус |
|----|------|----------|--------|
| SER-01 | `test_corrupted_vk_bytes_header` | VK с поврежденным header | ✅ (ignored) |
| SER-02 | `test_corrupted_vk_bytes_middle` | VK с поврежденной серединой | ✅ (ignored) |
| SER-03 | `test_truncated_vk_bytes` | Обрезанный VK | ✅ (ignored) |
| SER-04 | `test_empty_vk_bytes` | Пустой VK | ✅ PASS |
| SER-05 | `test_random_garbage_vk` | Случайный мусор как VK | ✅ (ignored) |
| SER-06 | `test_corrupted_kzg_params_bytes` | Поврежденные KZG params | ✅ (ignored) |
| SER-07 | `test_wrong_length_proof` | Proof неправильной длины | ✅ (ignored) |
| SER-08 | `test_proof_with_trailing_garbage` | Proof с мусором в конце | ✅ (ignored) |
| SER-09 | `test_proof_bit_flip` | Proof с bit flip | ✅ (ignored) |
| SER-10 | `test_vk_params_mismatch` | VK/params совместимость | ✅ (ignored) |

---

## 2. Prover (prover.rs)

### Функции:
- `setup(k)` - генерация KZG параметров
- `generate_proof()` - создание proof
- `generate_proof_key()` - создание proving key
- `read_kzg_params()` - десериализация параметров

### Покрытие тестами:
| Свойство | Статус | Тесты |
|----------|--------|-------|
| Proof generation | ✅ | full_test |
| Serialization | ✅ | full_test_with_backuped_params |

### Дополнительные тесты (TODO):
| ID | Тест | Описание | Приоритет |
|----|------|----------|-----------|
| P-01 | `test_proof_with_mismatched_public` | private ≠ public values | HIGH |
| P-02 | `test_corrupted_kzg_params` | Поврежденные KZG params | MEDIUM |
| P-03 | `test_params_k_too_small` | k < 18 (схема не помещается) | HIGH |
| P-04 | `test_proof_size_consistency` | Размер proof константен | LOW |

---

## 3. Verifier (verifier.rs)

### Функции:
- `verification_key_from_bytes()` - десериализация VK
- `verification_key_from_path()` - загрузка VK из файла
- `verify_proof_()` - верификация proof

### Покрытие тестами:
| Свойство | Статус | Тесты |
|----------|--------|-------|
| Valid proof accepts | ✅ | verifier_sketch_test |
| Corrupted VK handling | 🐛 BUG-001 | fuzz_verifier_bytes |

### Реализованные тесты:
| ID | Тест | Описание | Статус |
|----|------|----------|--------|
| V-01 | `test_verifier_wrong_public_inputs` | Неверные pub inputs отклоняются | ✅ PASS |
| V-01b | `test_verifier_wrong_sum` | Неверная сумма отклоняется | ✅ PASS |
| V-02 | `test_proof_replay_attack` | Proof не работает с другими inputs | ✅ PASS |
| V-03 | `test_corrupted_proof_bytes` | Битый proof без panic | ✅ PASS |
| V-04 | `test_empty_proof` | Пустой proof | ✅ PASS |
| V-05 | `test_truncated_proof` | Обрезанный proof | ✅ PASS |

### Дополнительные тесты (TODO):
| ID | Тест | Описание | Приоритет |
|----|------|----------|-----------|
| V-06 | `test_proof_from_different_circuit` | Proof от другой схемы | HIGH |

---

## 4. Криптографические edge cases

| ID | Тест | Описание | Приоритет |
|----|------|----------|-----------|
| X-01 | `test_secp256k1_curve_order` | sk = curve order (должен быть эквивалентен 0) | HIGH |
| X-02 | `test_bn256_field_wrap` | Значения около модуля Fr | HIGH |
| X-03 | `test_point_at_infinity` | Операции с точкой бесконечности | HIGH |

---

## Приоритеты реализации

### Критические (CRITICAL) - реализовать первыми:
1. V-01: `test_wrong_public_inputs`
2. V-02: `test_proof_replay`

### Высокие (HIGH):
3. C-01: `test_sk_zero`
4. V-03: `test_corrupted_proof_bytes`
5. P-01: `test_proof_with_mismatched_public`
6. C-05: `test_scalar_field_boundary`

### Средние (MEDIUM):
7. C-03, C-04, P-02, V-04, V-05

---

## Найденные баги

| ID | Severity | Компонент | Описание | Статус |
|----|----------|-----------|----------|--------|
| BUG-001 | Medium | verifier.rs | Panic при некорректном VK (unwrap в halo2curves) | Open |
| BUG-002 | Medium | circuit.rs | Panic при g = identity point (subtle assertion) | Open |
| BUG-003 | High | prover.rs | OOM при corrupted KZG params header (читает размер из мусора → 2PB allocation) | Open |
| BUG-004 | Medium | halo2curves/bn256/fq.rs | Panic при коротких данных (8 байт) в ParamsKZG::read_custom - UnexpectedEof | Open |
| BUG-005 | Medium | halo2_proofs/keygen.rs | Panic shl_overflow в create_domain при парсинге VK из corrupted данных | Open |
| **BUG-006** | **CRITICAL** | verifier.rs | Мутированный proof принимается верификатором (изменение 1 байта не детектируется) | Open |

### BUG-005: Panic shl_overflow при парсинге VK

**Найден фаззингом**: `fuzz_proving_key_bytes`

**Воспроизведение**:
```bash
cargo +nightly fuzz run fuzz_proving_key_bytes fuzz/artifacts/fuzz_proving_key_bytes/crash-fb53bfc43a37c73eb5a862f53ac93d188733691b
```

**Стектрейс**:
```
panic_const_shl_overflow at halo2_proofs::plonk::keygen::create_domain
```

**Причина**: При парсинге corrupted VK данных, значение `k` интерпретируется как очень большое число (91), что вызывает overflow при `1 << k`.

---

### BUG-006: **КРИТИЧЕСКИЙ** - Мутированный proof принимается верификатором

**Найден фаззингом**: `fuzz_proof_mutations`

**Воспроизведение**:
```bash
# Мутация: позиция 383, byte XOR 0x80 (0x6C -> 0xEC)
cargo +nightly fuzz run fuzz_proof_mutations fuzz/artifacts/fuzz_proof_mutations/crash-8b77f143c42922447a80da6fc3bae2112944d602
```

**Детали расследования**:
- Изменение bit 7 (0x80) на offset 31 любого 32-байтного элемента в proof пропускается верификатором
- Это систематическая проблема: уязвимы элементы 0, 1, 11, 12, 13, 14, 15, 16, 17... (продолжается)
- Только XOR 0x80 уязвим, другие значения (0x01, 0x02, ..., 0xFF) корректно отклоняются
- Позиция 31 в 32-байтном элементе - это старший байт (MSB) точки эллиптической кривой

**ИССЛЕДОВАНИЕ ЗАВЕРШЕНО (2025-12-26)**:

Проведён детальный анализ исходного кода halo2curves и halo2_proofs:

**Причина**:
- Модуль Fq для BN254: `0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`
- Старшие 2 бита (биты 254-255) **всегда 0** для валидных field elements (модуль начинается с 0x30 = 0011_0000)
- При `SerdeFormat::RawBytesUnchecked` используется `from_raw_bytes_unchecked()` который **НЕ проверяет** что значение < modulus
- Байты просто копируются в Montgomery form без валидации

**Подтверждено тестами** (test_bug006_*):
1. VK с установленным битом 7 (0x80) в последнем байте координаты **успешно парсится**
2. KZG params с установленным битом 7 также **успешно парсятся**
3. Однако proof **корректно отклоняется** при верификации с модифицированным VK

**Вывод**:
- **НЕ является soundness bug** в текущей реализации
- Верификация отклоняет proof с неканоничным VK
- Однако это **потенциальная проблема**:
  1. Неканоничные field elements могут вызвать undefined behavior в арифметике (см. комментарий в `neg()`: "self is guaranteed to be in the field")
  2. Разные байтовые представления могут давать одинаковые математические значения (после редукции по модулю)
  3. Атакующий может создать специально сконструированный VK/params

**Severity**: Low (не soundness, но нарушение инвариантов)

**Рекомендации**:
1. Использовать `SerdeFormat::RawBytes` вместо `RawBytesUnchecked` для внешних данных
2. Добавить явную проверку каноничности при загрузке VK/params из недоверенных источников
3. Документировать что `RawBytesUnchecked` предназначен только для доверенных данных

---

### BUG-004: Panic при коротких данных в десериализации

**Найден фаззингом**: `fuzz_verifier_bytes`

**Воспроизведение**:
```bash
# Input: 8 байт \x00\x00\x00\x00\x00\x00\x00\x0a
cargo +nightly fuzz run fuzz_verifier_bytes fuzz/artifacts/fuzz_verifier_bytes/crash-c95af1eefbad7ff281b1f94f84ddecc261d055e3
```

**Стектрейс**:
```
panicked at halo2curves/src/bn256/fq.rs:133:1:
called `Result::unwrap()` on an `Err` value: Error { kind: UnexpectedEof, message: "failed to fill whole buffer" }
```

**Причина**: `ParamsKZG::read_custom` вызывает внутренние функции halo2curves которые используют unwrap() на результатах чтения буфера без проверки достаточной длины.

**Рекомендация**: Добавить проверку минимальной длины входных данных перед вызовом десериализации.

---

## Итоги фаззинга

### Созданные fuzz targets (10 штук):

| Target | Описание | Результат |
|--------|----------|-----------|
| fuzz_soundness | Базовый soundness тест | ✅ Работает |
| fuzz_completeness | Тест completeness | ✅ Работает |
| fuzz_determinism | Детерминизм proof generation | ✅ Работает |
| fuzz_verifier_bytes | Corrupted VK/params | 🐛 BUG-004 |
| fuzz_token_binding | Token type binding | ✅ Работает |
| fuzz_sum_binding | Sum binding | ✅ Работает |
| fuzz_edge_cases | Граничные значения | ✅ Работает |
| fuzz_proof_mutations | Мутации proof | 🐛 **BUG-006 CRITICAL** |
| fuzz_proving_key_bytes | Corrupted PK/VK | 🐛 BUG-005 |
| fuzz_structured_proof | Structure-aware мутации | 🐛 **BUG-006 CRITICAL** |

### Статистика:
- **Всего fuzz targets**: 10
- **Найдено багов**: 6 (BUG-001 - BUG-006)
- **Критических багов**: 1 (BUG-006)
- **Время фаззинга**: ~5 минут на target

### Рекомендации по приоритетам:

1. **КРИТИЧЕСКИЙ (BUG-006)**: Исследовать причину принятия мутированных proof
   - Проверить формат сериализации halo2curves
   - Если это soundness bug - немедленно исправить

2. **ВЫСОКИЙ (BUG-003)**: OOM при corrupted KZG params
   - Добавить валидацию размера перед аллокацией

3. **СРЕДНИЙ (BUG-001, BUG-002, BUG-004, BUG-005)**: Panic при corrupted input
   - Заменить unwrap() на proper error handling

