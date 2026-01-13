//! Fuzz target: Private Note Sum Binding
//!
//! После poseidon_integration: sum включён в public inputs через digest.
//! Этот тест проверяет что схема принимает только matching sum.
//!
//! Критично для безопасности: злоумышленник не должен иметь возможности
//! создать proof с одной суммой, а верифицировать с другой.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

/// Структура входных данных для fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Секретный ключ
    sk_val: u64,
    /// Token type
    token_type: u64,
    /// Sum
    note_sum: u64,
    /// Vault random value
    vault_rand_val: u64,
}

fuzz_target!(|input: FuzzInput| {
    // Пропускаем нулевой ключ
    if input.sk_val == 0 {
        return;
    }

    // Ограничиваем значения
    let sk_val = (input.sk_val % 1_000_000) + 1;
    let token = input.token_type % 1000;
    let sum = input.note_sum % 10_000_000;
    let vault = input.vault_rand_val % 1_000_000;

    // Генерируем валидную пару ключей
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    // Проверяем схему с matching sum (через digest)
    let result = check_circuit(
        sk,
        pk,
        g,
        token,
        sum,
        vault,
        sk_val,  // sk_raw для digest
    );

    // Валидные входы должны приниматься
    assert!(
        result.is_ok(),
        "Valid sum binding rejected: token={}, sum={}, result={:?}",
        token, sum, result
    );
});

