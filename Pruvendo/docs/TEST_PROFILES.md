# Test Profiles: Day vs Night Mode

**Дата:** 2026-01-21  
**Версия:** 1.0

## Обзор

Тестирование DarkDex разделено на два режима:

| Режим | Время | Цель | Когда использовать |
|-------|-------|------|-------------------|
| **Day (Quick)** | ~5-15 мин | Быстрая проверка | CI/CD, разработка |
| **Night (Full)** | 4-8 часов | Глубокое тестирование | Ночной запуск, перед релизом |

## Конфигурация профилей

### Фаззинг (cargo fuzz)

| Параметр | Day | Night |
|----------|-----|-------|
| Время на target | 30 сек | 30 мин |
| -runs | 1000 | 0 (бесконечно) |
| -max_total_time | 30 | 1800 |

### Property Tests (proptest)

| Параметр | Day | Night |
|----------|-----|-------|
| cases | 50 | 500 |
| timeout | 5 мин | 30 мин |

**Примечание:** Конфигурация в `tests.rs:proptest_config()`

### Apalache (Bounded Model Checking)

| Параметр | Day | Night |
|----------|-----|-------|
| --max-steps | 5 | 15 |
| --max-error | 1 | 10 |

### Quint Random Simulation

| Параметр | Day | Night |
|----------|-----|-------|
| --max-samples | 100 | 5000 |
| --max-steps | 10 | 30 |

### Real Prover Tests

| Параметр | Day | Night |
|----------|-----|-------|
| Test count | 10 | Все |
| cargo test filter | `test_real_prover_basic` | `real_prover` |

## Использование

### Скрипты запуска

```bash
# Day mode (быстрый)
./Pruvendo/scripts/run_tests.sh day

# Night mode (полный)
./Pruvendo/scripts/run_tests.sh night

# Только фаззинг
./Pruvendo/scripts/run_tests.sh day fuzz
./Pruvendo/scripts/run_tests.sh night fuzz

# Только property tests
./Pruvendo/scripts/run_tests.sh day property
./Pruvendo/scripts/run_tests.sh night property

# Только Apalache
./Pruvendo/scripts/run_tests.sh day apalache
./Pruvendo/scripts/run_tests.sh night apalache
```

### Переменные окружения

```bash
# Для property tests
export PROPTEST_CASES=500       # Override cases count
export PROPTEST_TIMEOUT=1800000 # Override timeout (ms)

# Для Apalache
export APALACHE_MAX_STEPS=15
export JAVA_HOME="/usr/local/opt/openjdk@17"
export APALACHE_DIST="$(pwd)/Pruvendo/external_packages/apalache/apalache"
```

## Важные замечания

### Bounded Model Checking ≠ Full Verification

⚠️ **ВАЖНО:** Apalache выполняет **bounded** model checking:
- "VERIFIED" означает: "нет контрпримера в пределах N шагов"
- Это **НЕ** означает: "свойство доказано для всех возможных путей"

Для увеличения уверенности:
1. Увеличивайте `--max-steps` (требует больше времени)
2. Используйте night mode для глубокой проверки
3. Комбинируйте с random simulation

### MockProver vs Real Prover

MockProver работает быстро, но:
- Не создаёт криптографический proof
- Не тестирует KZG commitment
- Может пропустить ошибки сериализации

Real Prover тесты (`real_prover_tests.rs`) обязательны перед релизом.

## Рекомендуемый workflow

1. **Во время разработки:** `./run_tests.sh day`
2. **Перед commit:** `./run_tests.sh day` + manual review
3. **Перед merge:** `./run_tests.sh night` (запустить на ночь)
4. **Перед релизом:** Full night run + Apalache с max-steps=20

## Файлы

- `Pruvendo/scripts/run_tests.sh` - Основной скрипт запуска
- `Pruvendo/scripts/profiles/day.conf` - Day profile конфигурация
- `Pruvendo/scripts/profiles/night.conf` - Night profile конфигурация

