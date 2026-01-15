# Bug Tracking - Отслеживание известных багов

## Быстрый старт

```bash
# Проверить статус ВСЕХ известных багов:
cd Pruvendo/tests/property_tests
cargo test --release -- --nocapture 2>&1 | grep -E "BUG-00[0-9]|STATUS:"

# Запустить конкретный тест бага:
cargo test test_generator_identity --release -- --nocapture  # BUG-002
cargo test test_corrupted_vk --release -- --ignored --nocapture  # BUG-001
cargo test bug003 --release -- --ignored --nocapture  # BUG-003
cargo test test_corrupted_kzg_params_bytes --release -- --ignored --nocapture  # BUG-004/005
cargo test bug006 --release -- --ignored --nocapture  # BUG-006
```

## Список багов (актуальный статус на 2026-01-15)

| ID | Название | Severity | Текущий статус |
|----|----------|----------|----------------|
| BUG-001 | Panic при corrupted VK bytes (header) | Medium | ⚠️ REPRODUCED |
| BUG-001 | Panic при corrupted VK bytes (middle) | Medium | ✅ FIXED |
| BUG-002 | Panic при g = identity point | Medium | ⚠️ REPRODUCED |
| BUG-003 | shl_overflow при corrupted KZG header | Medium | ⚠️ REPRODUCED |
| BUG-004 | shl_overflow в commitment.rs | Medium | ✅ FIXED |
| BUG-005 | shl_overflow в domain.rs | Medium | Дубликат BUG-004 |
| BUG-006 | Non-canonical field elements | Low | ✅ Не soundness bug |
| **BUG-007** | **deposit_sum коллизии** | **High** | **🔴 НАЙДЕН ФАЗЗИНГОМ** |

## Детали каждого бага

### BUG-001: Panic при corrupted VK bytes
- **Тесты:** `test_corrupted_vk_bytes_header`, `test_corrupted_vk_bytes_middle`
- **Воспроизведение:** `cargo test test_corrupted_vk --release -- --ignored --nocapture`
- **Причина:** halo2curves не обрабатывает gracefully corrupted данные
- **Рекомендация:** Валидировать VK перед использованием

### BUG-002: Panic при g = identity point
- **Тест:** `test_generator_identity`
- **Воспроизведение:** `cargo test test_generator_identity --release -- --nocapture`
- **Причина:** subtle crate не поддерживает identity point в операциях
- **Рекомендация:** Проверять g != identity на входе

### BUG-003: OOM/panic при corrupted KZG header
- **Тест:** `test_corrupted_kzg_header_bug003`
- **Воспроизведение:** `cargo test bug003 --release -- --ignored --nocapture`
- **Причина:** Corrupted size в header приводит к попытке выделить петабайты памяти
- **Рекомендация:** Валидировать размеры перед аллокацией

### BUG-004/BUG-005: shl_overflow в halo2_proofs
- **Тест:** `test_corrupted_kzg_params_bytes`
- **Воспроизведение:** `cargo test test_corrupted_kzg_params_bytes --release -- --ignored --nocapture`
- **Причина:** Corrupted данные вызывают overflow при shift операциях
- **Рекомендация:** Upstream fix или валидация данных

### BUG-006: Non-canonical field elements
- **Тесты:** `test_bug006_vk_bit7_manipulation_*`, `test_bug006_verification_with_modified_vk`
- **Воспроизведение:** `cargo test bug006 --release -- --ignored --nocapture`
- **Статус:** НЕ soundness bug - elements редуцируются при арифметике
- **Рекомендация:** Low priority, informational

### BUG-007: deposit_sum коллизии (КРИТИЧЕСКИЙ)
- **Найден:** Ночным фаззингом 15.01.2026
- **Fuzz targets:** `fuzz_digest_collision`, `fuzz_multikey_digest`
- **Воспроизведение:**
  ```bash
  cargo +nightly fuzz run fuzz_digest_collision --fuzz-dir Pruvendo/fuzz \
    Pruvendo/fuzz/artifacts/fuzz_digest_collision/crash-bf9dd64e8719cdd48add91072c80230cbe2ad6cb
  ```
- **Суть проблемы:**
  - `deposit_sum = token + sum + vault` (аддитивная формула)
  - Разные комбинации `(token, vault)` с одинаковой суммой дают одинаковый `deposit_sum`
  - Пример: `(token=91577, vault=691321)` и `(token=93113, vault=689785)` дают одинаковый digest
- **Влияние на безопасность:**
  - Злоумышленник может создать разные notes с одинаковым digest
  - Публичные данные (token, sum) не разделены от приватных (vault)
- **Рекомендация:** Изменить формулу:
  ```
  digest = poseidon_hash([key_sum, token, sum, vault])  // раздельно
  ```
  вместо:
  ```
  deposit_sum = token + sum + vault
  digest = poseidon_hash([key_sum, deposit_sum])
  ```

## Система отслеживания

Все тесты багов используют единую систему отслеживания из `helpers.rs`:

```rust
use crate::helpers::{known_bugs, report_bug_status, check_bug_status};

let status = check_bug_status(|| {
    // код который может panic
    potentially_panicking_code()
});

report_bug_status(&known_bugs::BUG_XXX, status);
```

### Статусы:
- `REPRODUCED` - баг воспроизводится в текущей версии
- `FIXED` - баг больше не воспроизводится
- `SKIPPED` - тест пропущен (отсутствуют файлы)

## Как добавить новый баг

1. Добавить `BugInfo` в `helpers.rs`:
```rust
pub const BUG_007: BugInfo = BugInfo {
    id: "BUG-007",
    title: "Описание бага",
    location: "где находится",
    severity: "High/Medium/Low",
};
```

2. Создать тест в `tests.rs`:
```rust
/// BUG-007: Краткое описание
/// Запуск: cargo test test_bug007 --release -- --nocapture
#[test]
fn test_bug007_description() {
    use crate::helpers::{known_bugs, report_bug_status, check_bug_status};
    
    let status = check_bug_status(|| {
        // код воспроизводящий баг
    });
    
    report_bug_status(&known_bugs::BUG_007, status);
}
```

3. Обновить эту документацию

## Интеграция в CI

Для CI рекомендуется запускать тесты багов отдельно:

```bash
# Тесты которые не требуют файлов (всегда работают)
cargo test test_generator_identity --release

# Тесты которые требуют файлы (ignored)
cargo test --release -- --ignored 2>&1 | grep -E "STATUS:|passed|failed"
```

