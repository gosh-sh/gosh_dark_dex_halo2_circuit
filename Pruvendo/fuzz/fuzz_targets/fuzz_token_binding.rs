//! Fuzz target: Token Type Binding
//!
//! Проверяет что token_type в circuit должен совпадать с public input.
//! Если witness.token_type ≠ public_input.token_type → scheme ДОЛЖНА отклонить.
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
    /// Token type в witness (приватный)
    witness_token_type: u64,
    /// Token type в public input
    public_token_type: u64,
    /// Note sum (одинаковый для упрощения)
    note_sum: u64,
}

fuzz_target!(|input: FuzzInput| {
    // Пропускаем тривиальные случаи
    if input.sk_val == 0 {
        return;
    }

    // Ограничиваем значения разумными диапазонами
    let sk_val = (input.sk_val % 1_000_000) + 1;
    let witness_token = input.witness_token_type % 1000;
    let public_token = input.public_token_type % 1000;
    let note_sum = input.note_sum % 1_000_000;

    // Генерируем валидную пару ключей
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    // Проверяем схему с возможно несовпадающими token_type
    let result = check_circuit(
        sk,
        pk,
        g,
        witness_token,  // witness token_type
        note_sum,
        public_token,   // public input token_type (может отличаться!)
        note_sum,
    );

    // PROPERTY: если token_type отличается, схема ДОЛЖНА отклонить
    if witness_token != public_token {
        assert!(
            result.is_err(),
            "SOUNDNESS VIOLATION: Different token types accepted! \
             witness={}, public={}, result={:?}",
            witness_token, public_token, result
        );
    }
});

