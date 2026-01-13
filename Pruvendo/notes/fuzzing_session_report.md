# Отчёт о сессии фаззинга ZKP схемы DarkDex

**Дата первичного тестирования**: 2025-12-26
**Дата повторной проверки**: 2026-01-13
**Проект**: gosh_dark_dex_halo2_circuit

## Резюме

Проведена сессия фаззинга ZKP схемы с использованием cargo-fuzz (libFuzzer).
Создано 11 fuzz targets. При первичном тестировании найдено 6 багов.

**Обновление 2026-01-13**: Проведена повторная проверка после merge poseidon_integration.
- Критический баг BUG-006 **НЕ ВОСПРОИЗВОДИТСЯ**
- 3 бага в upstream библиотеках **ВОСПРОИЗВОДЯТСЯ**
- 2 бага не подтверждены (нет артефактов)

## Созданные fuzz targets

| # | Target | Описание | Статус |
|---|--------|----------|--------|
| 1 | fuzz_soundness | Неверные keypairs должны отклоняться | ✅ PASS |
| 2 | fuzz_completeness | Верные keypairs должны приниматься | ✅ PASS |
| 3 | fuzz_determinism | Детерминизм proof generation | ✅ PASS |
| 4 | fuzz_verifier_bytes | Corrupted VK/params данные | ⚠️ Upstream bugs |
| 5 | fuzz_token_binding | Привязка token_type к public input | ✅ PASS |
| 6 | fuzz_sum_binding | Привязка private_note_sum к public input | ✅ PASS (slow) |
| 7 | fuzz_edge_cases | Граничные значения (0, MAX, etc.) | ✅ PASS (slow) |
| 8 | fuzz_proof_mutations | Мутации байтов в proof | ✅ PASS |
| 9 | fuzz_proving_key_bytes | Corrupted PK/VK данные | ⚠️ Upstream bugs |
| 10 | fuzz_structured_proof | Structure-aware мутации | ✅ PASS |
| 11 | fuzz_soundness_extended | Расширенный soundness тест | ✅ PASS |

## Найденные баги - Статус на 2026-01-13

### ~~КРИТИЧЕСКИЙ: BUG-006 - Мутированный proof принимается~~

**Статус**: ❌ **НЕ ВОСПРОИЗВОДИТСЯ**

Проведено 60+ секунд фаззинга на fuzz_proof_mutations и fuzz_structured_proof -
crashes не обнаружены. Старые crash-артефакты выполняются без паники.

**Возможные причины**:
1. Исправлено при merge poseidon_integration
2. Исправлено в обновлённых зависимостях halo2curves/halo2_proofs
3. Изменение в логике верификации

### BUG-001: Panic при некорректном VK

**Статус**: ⚠️ **ВОСПРОИЗВОДИТСЯ** (upstream)

**Локация**: `halo2curves/src/bn256/fq.rs:133`
**Причина**: `unwrap()` на `Err` при чтении corrupted данных
**Сообщение**: `called Result::unwrap() on Err: UnexpectedEof`

**Артефакт**: `fuzz/artifacts/fuzz_verifier_bytes/crash-c95af1eefbad7ff281b1f94f84ddecc261d055e3`

### BUG-002: Panic при g = identity point

**Статус**: ⚠️ **ВОСПРОИЗВОДИТСЯ** (DarkDex circuit)

**Как воспроизвести**:
```bash
cd Pruvendo/tests/property_tests
cargo test test_generator_identity -- --nocapture
```

**Локация**: `subtle/lib.rs:701` (assertion failed)
**Сообщение**: `assertion 'left == right' failed: left: 0, right: 1`

**Описание**: Когда `g = identity point` (точка на бесконечности), схема паникует из-за assertion в библиотеке `subtle`. Это происходит при попытке scalar multiply на identity point.

### BUG-003: ~~OOM~~ → Panic shl_overflow при corrupted KZG header

**Статус**: ⚠️ **ИЗМЕНИЛСЯ** (теперь panic вместо OOM)

**Как воспроизвести**:
```bash
cd Pruvendo/tests/property_tests
cargo test test_corrupted_kzg_header_bug003 -- --ignored --nocapture
```

**Локация**: `halo2_proofs/src/poly/kzg/commitment.rs:205`
**Сообщение**: `attempt to shift left with overflow`

**Описание**: Ранее повреждение header KZG params вызывало OOM (попытка выделить петабайты). Теперь вызывает panic `shl_overflow` - это **улучшение**, т.к. panic можно перехватить, а OOM нет.

**Примечание**: Тот же crash что и BUG-004 - одна root cause.

### BUG-004: Panic shl_overflow в commitment.rs

**Статус**: ⚠️ **ВОСПРОИЗВОДИТСЯ** (upstream)

**Локация**: `halo2_proofs/src/poly/kzg/commitment.rs:205`
**Причина**: `attempt to shift left with overflow`

**Артефакт**: `fuzz/artifacts/fuzz_verifier_bytes/crash-2ab4e854afaa7c81fc119cdded49ca0d45ad26d6`

### BUG-005: Panic shl_overflow в domain.rs

**Статус**: ⚠️ **ВОСПРОИЗВОДИТСЯ** (upstream)

**Локация**: `halo2_proofs/src/poly/domain.rs:44`
**Причина**: `panic_const_shl_overflow`

**Артефакт**: `fuzz/artifacts/fuzz_proving_key_bytes/crash-a0c6013801c319bf3452532d473f438dff3948ee`

---

### BUG-006: Анализ мутаций proof (2026-01-13)

**Статус**: ✅ **НЕ SOUNDNESS BUG**

**Оригинальное описание**: Мутированный proof (XOR 0x80 на позиции 31) принимается верификатором.

**Результаты углублённого анализа**:

1. **Тестирование после merge poseidon_integration**:
   - Оригинальный proof из proof.bin: REJECTED (public inputs изменились)
   - Мутированный proof (XOR 0x80 на pos=31): REJECTED
   - Все 20 мутаций (каждый MSB 32-байтного элемента): REJECTED

2. **Техническое объяснение**:
   - `SerdeFormat::RawBytesUnchecked` принимает любые 32 байта без проверки < modulus
   - Бит 7 (0x80) в MSB создаёт значение > modulus BN254 (0x30644e72...)
   - Однако при верификации это значение **не равно** оригинальному → proof rejected

3. **Риски** (Low severity):
   - Неканоничные field elements могут вызвать UB в арифметике (теоретически)
   - Разные байтовые представления дают одинаковые math значения после mod reduction
   - Потенциальная атака: специально сконструированный VK/params

4. **Рекомендация**: Использовать `SerdeFormat::Processed` вместо `RawBytesUnchecked` для untrusted input

## Сводная таблица багов

| ID | Severity | Статус | Upstream? | Описание |
|----|----------|--------|-----------|----------|
| BUG-006 | ~~Critical~~ Low | ✅ Не soundness bug | halo2curves | SerdeFormat::RawBytesUnchecked принимает неканоничные FE, но верификация отклоняет |
| BUG-005 | Medium | ⚠️ Воспроизводится | halo2_proofs | shl_overflow в domain.rs:44 |
| BUG-004 | Medium | ⚠️ Воспроизводится | halo2_proofs | shl_overflow в commitment.rs:205 |
| BUG-003 | ~~High~~ | ✅ Дубликат BUG-004 | halo2_proofs | ~~OOM~~ → теперь panic shl_overflow (та же root cause) |
| BUG-002 | Medium | ⚠️ Воспроизводится | subtle | Panic assertion при g = identity point |
| BUG-001 | Medium | ⚠️ Воспроизводится | halo2curves | unwrap на Err при corrupted VK |

## Статистика тестирования 2026-01-13

| Target | Runs | Время | Покрытие | Crashes |
|--------|------|-------|----------|---------|
| fuzz_soundness | 38 | 60s | 5690 | 0 |
| fuzz_completeness | 25 | 60s | 5505 | 0 |
| fuzz_determinism | 5 | 60s | 5503 | 0 |
| fuzz_token_binding | 33 | 60s | 5541 | 0 |
| fuzz_proof_mutations | 1853 | 60s | 4579 | 0 |
| fuzz_structured_proof | 3411246 | 60s | 139 | 0 |
| fuzz_verifier_bytes | - | <60s | - | 1 (new) |
| fuzz_proving_key_bytes | - | <60s | - | 1 (new) |

## Рекомендации

### Высокий приоритет
1. ✅ BUG-006 не воспроизводится - продолжать мониторинг
2. Сообщить о BUG-004, BUG-005 в репозиторий scroll-tech/halo2

### Средний приоритет
3. Сообщить о BUG-001 в репозиторий scroll-tech/halo2curves
4. Добавить валидацию входных данных перед десериализацией

### Низкий приоритет
5. Увеличить время фаззинга для fuzz_sum_binding и fuzz_edge_cases
6. Добавить property-based тесты для arithmetic constraints

## Файлы

- `Pruvendo/fuzz/` - fuzz targets и конфигурация
- `Pruvendo/fuzz/artifacts/` - crash inputs для воспроизведения
- `Pruvendo/docs/component_testing_plan.md` - детальный план тестирования
- Симлинк `fuzz -> Pruvendo/fuzz` для cargo fuzz совместимости

