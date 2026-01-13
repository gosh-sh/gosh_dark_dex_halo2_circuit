# Отчёт о сессии фаззинга ZKP схемы DarkDex

**Дата**: 2025-12-26
**Проект**: gosh_dark_dex_halo2_circuit

## Резюме

Проведена сессия фаззинга ZKP схемы с использованием cargo-fuzz (libFuzzer).
Создано 10 fuzz targets, найдено 6 багов, включая 1 критический.

## Созданные fuzz targets

1. **fuzz_soundness** - базовый тест soundness (неверные keypairs должны отклоняться)
2. **fuzz_completeness** - тест completeness (верные keypairs должны приниматься)
3. **fuzz_determinism** - детерминизм proof generation
4. **fuzz_verifier_bytes** - corrupted VK/params данные
5. **fuzz_token_binding** - привязка token_type к public input
6. **fuzz_sum_binding** - привязка private_note_sum к public input
7. **fuzz_edge_cases** - граничные значения (0, MAX, etc.)
8. **fuzz_proof_mutations** - мутации байтов в proof
9. **fuzz_proving_key_bytes** - corrupted PK/VK данные
10. **fuzz_structured_proof** - structure-aware мутации с Arbitrary trait

## Найденные баги

### КРИТИЧЕСКИЙ: BUG-006 - Мутированный proof принимается

**Описание**: Изменение бита 7 (0x80) на позиции 31 любого 32-байтного элемента
в proof не детектируется верификатором.

**Воспроизведение**:
```bash
cargo +nightly fuzz run fuzz_structured_proof
# или
cargo +nightly fuzz run fuzz_proof_mutations
```

**Детали**:
- Proof состоит из 63 G1 points (32 bytes each)
- Позиция 31 - последний байт каждой точки (MSB)
- XOR 0x80 на этой позиции не влияет на результат верификации
- Другие мутации (0x01, 0x02, ..., 0x7F, 0x81, ..., 0xFF) корректно отклоняются

**Гипотеза**: Бит 7 последнего байта может быть unused в формате BN256 Fq
(поле ~254 бит, старшие биты не используются).

**Требуется**: Подтверждение от разработчиков halo2curves.

### Другие баги

| ID | Severity | Описание |
|----|----------|----------|
| BUG-001 | Medium | Panic при некорректном VK (unwrap в halo2curves) |
| BUG-002 | Medium | Panic при g = identity point |
| BUG-003 | High | OOM при corrupted KZG params (2PB allocation) |
| BUG-004 | Medium | Panic при коротких данных в ParamsKZG::read_custom |
| BUG-005 | Medium | Panic shl_overflow при парсинге corrupted VK |

## Статистика

- **Время фаззинга**: ~5 минут на target
- **Покрытие**: ~131K inline counters
- **Crashes найдено**: 6 уникальных

## Рекомендации

1. **Немедленно**: Исследовать BUG-006 - это потенциальный soundness bug
2. **Высокий приоритет**: Исправить OOM в BUG-003
3. **Средний приоритет**: Заменить unwrap() на proper error handling

## Файлы

- `Pruvendo/fuzz/` - fuzz targets и конфигурация
- `Pruvendo/docs/component_testing_plan.md` - детальный план тестирования
- `fuzz/artifacts/` - crash inputs для воспроизведения

