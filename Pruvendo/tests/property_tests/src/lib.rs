//! Property-based tests for DarkDEX Halo2 Circuit
//!
//! Тесты проверяют свойства ZK-схемы DarkDEX:
//! - Completeness: валидные данные всегда проходят
//! - Soundness: невалидные данные отклоняются
//! - Poseidon audit: корректность hash функции
//!
//! Запуск: cargo test --release (из директории property_tests)

pub mod helpers;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod poseidon_audit;

#[cfg(test)]
mod fpchip_audit;

#[cfg(test)]
mod integration_tests;

