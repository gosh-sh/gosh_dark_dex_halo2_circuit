# Отчет о структуре проекта Dark DEX Halo2 Circuit

## Общая информация

**Название проекта:** gosh_dark_dex_halo2_circuit
**Версия:** 0.1.0
**Rust Edition:** 2024
**Статус тестов:** ✅ Все 6 тестов проходят (обновлено 2025-12-25)

## Назначение проекта

Проект реализует zero-knowledge proof (ZKP) схему на базе Halo2 для приватной децентрализованной биржи (Dark DEX). Схема позволяет доказать:
- Владение токенами определенного типа
- Корректность суммы приватных нот (балансов)
- Связь между секретным и публичным ключами на эллиптической кривой secp256k1

## Структура файлов

```
gosh_dark_dex_halo2_circuit/
├── Cargo.toml              # Конфигурация проекта и зависимости
├── Cargo.lock              # Зафиксированные версии зависимостей
├── config/
│   └── circuit.config      # Параметры конфигурации схемы
├── src/
│   ├── lib.rs              # Точка входа библиотеки
│   ├── circuit.rs          # Основная ZK-схема DarkDexCircuit
│   ├── prover.rs           # Функции генерации доказательств
│   ├── verifier.rs         # Функции верификации доказательств
│   └── test.rs             # Тесты
├── kzg_params.bin          # Сгенерированные KZG параметры
├── verification_key.bin    # Ключ верификации
└── proof.bin               # Пример доказательства
```

## Основные модули

### 1. circuit.rs - Основная ZK-схема

**Структуры:**
- `CircuitParams` - параметры конфигурации схемы (strategy, degree, num_advice и др.)
- `DarkDexCircuit<F>` - основная схема с полями:
  - `token_type: Option<F>` - тип токена
  - `private_note_sum: Option<F>` - сумма приватных нот
  - `sk: Option<Fq>` - секретный ключ (secp256k1 scalar)
  - `pk: Option<Secp256k1Affine>` - публичный ключ
  - `g: Option<Secp256k1Affine>` - генератор кривой
- `DarkDexConfig<F>` - конфигурация колонок схемы

**Реализация Circuit trait:**
- `configure()` - настройка constraint system
- `synthesize()` - синтез схемы с тремя регионами:
  1. Проверка пары ключей (sk * G == pk)
  2. Проверка равенства результатов
  3. Проверка token_type и private_note_sum

### 2. prover.rs - Генерация доказательств

**Функции:**
- `setup(k: u32)` - создание KZG параметров
- `setup_and_backup_kzg_params()` - создание и сохранение параметров
- `read_kzg_params()` - чтение параметров из файла
- `generate_proof_key()` - генерация ключа доказательства
- `generate_proof()` - генерация ZK-доказательства
- `generate_verififcation_key_without_witness()` - генерация ключа верификации
- `generate_verififcation_key_without_witness_and_backup()` - с сохранением в файл

### 3. verifier.rs - Верификация доказательств

**Функции:**
- `verification_key_from_bytes()` - загрузка ключа из байтов
- `verification_key_from_path()` - загрузка ключа из файла
- `verify_proof_()` - верификация доказательства

### 4. test.rs - Тесты

**Тесты:**
- `simple_test` - базовый тест с MockProver
- `generate_and_backup_kzg_params_test` - генерация KZG параметров
- `generate_and_backup_verification_key_test` - генерация ключа верификации
- `verifier_sketch_test` - тест верификации из файлов
- `full_test_with_backuped_params` - полный тест с сохраненными параметрами
- `full_test` - полный end-to-end тест

## Зависимости

| Зависимость | Источник | Назначение |
|-------------|----------|------------|
| halo2_proofs | scroll-tech/halo2 v1.1 | Основная библиотека ZK-proofs |
| halo2-base | scroll-tech/halo2-lib develop | Базовые примитивы |
| halo2-ecc | scroll-tech/halo2-lib develop | ECC операции |
| halo2curves | scroll-tech/halo2curves v0.1.0 | Эллиптические кривые |
| rand | crates.io 0.8 | Генерация случайных чисел |
| serde/serde_json | crates.io | Сериализация |

## Конфигурация схемы (circuit.config)

```json
{
  "strategy": "Simple",
  "degree": 18,
  "num_advice": 2,
  "num_lookup_advice": 1,
  "num_fixed": 1,
  "lookup_bits": 17,
  "limb_bits": 88,
  "num_limbs": 3
}
```

- **degree (k=18)**: размер схемы 2^18 = 262144 строк
- **num_advice**: 2 advice колонки
- **num_lookup_advice**: 1 lookup advice колонка
- **limb_bits/num_limbs**: параметры для представления больших чисел (88*3=264 бит)

## Криптографические примитивы

- **Commitment Scheme:** KZG (Kate-Zaverucha-Goldberg)
- **Polynomial Opening:** SHPLONK
- **Transcript:** Blake2b
- **Curves:**
  - bn256 (BN254) - для proof system
  - secp256k1 - для ключей пользователей

## Размеры артефактов

| Файл | Размер | Описание |
|------|--------|----------|
| `kzg_params.bin` | ~32 MB (33,554,692 bytes) | KZG trusted setup для k=18 |
| `verification_key.bin` | 968 bytes | Ключ верификации схемы |
| `proof.bin` | 2,016 bytes | SNARK доказательство |

## Производительность тестов (release build)

| Тест | Время |
|------|-------|
| `simple_test` | ~4 сек |
| `generate_and_backup_kzg_params_test` | ~30 сек |
| `generate_and_backup_verification_key_test` | ~7 сек |
| `verifier_sketch_test` | <1 сек |
| `full_test_with_backuped_params` | ~26 сек |
| `full_test` | ~60 сек |

**Общее время всех тестов:** ~130 сек

