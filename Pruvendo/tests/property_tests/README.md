# Property-Based Tests для DarkDEX Halo2 Circuit

## Обзор

Данный crate содержит property-based тесты для проверки свойств ZK-схемы DarkDEX.
Используется библиотека [proptest](https://github.com/proptest-rs/proptest) для 
автоматической генерации тестовых случаев.

## Тестируемые свойства

| Свойство | Тест | Описание |
|----------|------|----------|
| **P1: Completeness** | `prop_valid_keypair_always_verifies` | Для любой валидной пары (sk, pk=sk*G) схема проходит |
| **P2: Soundness (keypair)** | `prop_invalid_keypair_fails` | Если pk≠sk*G, схема отклоняет |
| **P3: Public input soundness** | `prop_wrong_token_type_fails` | Несовпадение token_type отклоняется |
| **P3: Public input soundness** | `prop_wrong_note_sum_fails` | Несовпадение private_note_sum отклоняется |
| **P4: Determinism** | `test_determinism` | Одинаковые входы → одинаковый результат |

## Запуск тестов

**ВАЖНО:** Тесты необходимо запускать из корня проекта (где находится `config/circuit.config`)!

```bash
# Из корня проекта gosh_dark_dex_halo2_circuit:

# Запуск всех тестов (release для скорости!)
cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release

# Запуск с выводом
cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release -- --nocapture

# Запуск конкретного теста
cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release -- prop_valid_keypair

# Запуск только property-тестов
cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release -- prop_

# Запуск только детерминированных тестов
cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release -- test_
```

## Результаты тестов

Все 8 тестов проходят успешно (время ~26 секунд в release режиме):
```
test helpers::helper_tests::test_invalid_keypair_generation ... ok
test helpers::helper_tests::test_valid_keypair_generation ... ok
test tests::prop_invalid_keypair_fails ... ok
test tests::prop_valid_keypair_always_verifies ... ok
test tests::prop_wrong_note_sum_fails ... ok
test tests::prop_wrong_token_type_fails ... ok
test tests::test_determinism ... ok
test tests::test_edge_case_min_sk ... ok
```

## Важно

- Тесты используют **MockProver** который медленный (~секунды на тест)
- Количество случаев proptest ограничено (10) для приемлемого времени
- Рекомендуется запускать с `--release` для ускорения

## Структура

```
property_tests/
├── Cargo.toml      # Зависимости (proptest, основной проект)
├── README.md       # Этот файл
└── src/
    ├── lib.rs      # Точка входа
    ├── helpers.rs  # Вспомогательные функции
    └── tests.rs    # Property-based тесты
```

## Расширение тестов

Для добавления новых property-тестов:

1. Добавьте тест в `src/tests.rs` внутри блока `proptest! { ... }`
2. Используйте helpers из `helpers.rs` для работы со схемой
3. Ограничивайте диапазоны генерации для скорости

Пример нового теста:
```rust
proptest! {
    #[test]
    fn prop_my_new_property(value in 1u64..1000u64) {
        // ... проверка свойства
    }
}
```

