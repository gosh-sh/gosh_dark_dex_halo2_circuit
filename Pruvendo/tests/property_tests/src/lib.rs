//! Property-based tests for DarkDEX Halo2 Circuit
//!
//! Тесты проверяют свойства ZK-схемы DarkDEX:
//! - Completeness: валидные данные всегда проходят
//! - Soundness: невалидные данные отклоняются
//!
//! Запуск: cargo test --release (из директории property_tests)

pub mod helpers;

#[cfg(test)]
mod tests;

