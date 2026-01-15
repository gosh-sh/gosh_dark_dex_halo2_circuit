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

#[cfg(test)]
mod prover_tests;

#[cfg(test)]
mod verifier_tests;

#[cfg(test)]
mod kzg_tests;

#[cfg(test)]
mod keygen_tests;

#[cfg(test)]
mod serialization_tests;

#[cfg(test)]
mod params_tests;
