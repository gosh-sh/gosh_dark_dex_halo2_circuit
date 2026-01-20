# Property-Based Tests для DarkDEX Halo2 Circuit

**Обновлено:** 2026-01-21
**Архитектура:** poseidon_instead_of_ecc
**Тестов:** 116

## Обзор

Property-based тесты для ZK-схемы DarkDEX (Poseidon-only архитектура).

## Тестируемые свойства

| Категория | Тестов | Описание |
|-----------|--------|----------|
| Poseidon Hash | 15+ | Детерминизм, consistency, collision resistance |
| Digest Binding | 10+ | sk → digest, token → digest, sum → digest |
| Soundness | 10+ | Wrong sk fails, wrong commitment fails |
| Completeness | 5+ | Valid inputs always pass |
| Serialization | 10+ | VK roundtrip, corrupted bytes handling |
| Integration | 13 | Multi-user proofs, same user scenarios |

## Запуск

```bash
# Из корня проекта:
cd Pruvendo/tests/property_tests && cargo test --release

# С выводом:
cargo test --release -- --nocapture

# Конкретный тест:
cargo test test_digest_determinism --release
```

## Результаты (2026-01-21)

```
test result: ok. 116 passed; 0 failed; 0 ignored
```

## Структура

```
property_tests/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs       # Entry point
    ├── helpers.rs   # BC tracking, test utilities
    └── tests.rs     # Property tests
```
