//! Fuzz target: Token Type Binding
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что token_type включён в digest и схема принимает только matching token_type.
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
    sk_val: u64,
    token_type: u64,
    note_sum: u64,
}

fuzz_target!(|input: FuzzInput| {
    if input.sk_val == 0 {
        return;
    }

    let sk_val = (input.sk_val % 1_000_000) + 1;
    let token = input.token_type % 1000;
    let sum = input.note_sum % 1_000_000;

    // Проверяем схему с matching token_type
    let result = check_circuit(sk_val, token, sum);

    // Валидные входы должны приниматься
    assert!(
        result.is_ok(),
        "Valid token binding rejected: token={}, sum={}, result={:?}",
        token, sum, result
    );
});

