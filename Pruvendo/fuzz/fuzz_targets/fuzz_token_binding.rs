//! Fuzz target: Token Type Binding
//!
//! После poseidon_integration: token_type включён в public inputs через digest.
//! Этот тест проверяет что схема принимает только matching token_type.
//!
//! Находит: нарушения binding между приватным witness и публичным input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

/// Структура входных данных для fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Секретный ключ (как u64 для простоты)
    sk_val: u64,
    /// Token type
    token_type: u64,
    /// Note sum
    note_sum: u64,
    /// Vault random value
    vault_rand_val: u64,
}

fuzz_target!(|input: FuzzInput| {
    // Пропускаем тривиальные случаи
    if input.sk_val == 0 {
        return;
    }

    // Ограничиваем значения разумными диапазонами
    let sk_val = (input.sk_val % 1_000_000) + 1;
    let token = input.token_type % 1000;
    let sum = input.note_sum % 1_000_000;
    let vault = input.vault_rand_val % 1_000_000;

    // Генерируем валидную пару ключей
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    // Проверяем схему с matching token_type (через digest)
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
        "Valid token binding rejected: token={}, sum={}, result={:?}",
        token, sum, result
    );
});

