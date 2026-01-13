//! Fuzz target: Private Note Sum Binding
//!
//! Проверяет что private_note_sum в circuit должен совпадать с public input.
//! Если witness.sum ≠ public_input.sum → схема ДОЛЖНА отклонить.
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
    /// Token type (одинаковый)
    token_type: u64,
    /// Sum в witness (приватный)
    witness_sum: u64,
    /// Sum в public input
    public_sum: u64,
}

fuzz_target!(|input: FuzzInput| {
    // Пропускаем нулевой ключ
    if input.sk_val == 0 {
        return;
    }

    // Ограничиваем значения
    let sk_val = (input.sk_val % 1_000_000) + 1;
    let token_type = input.token_type % 1000;
    let witness_sum = input.witness_sum % 10_000_000;
    let public_sum = input.public_sum % 10_000_000;

    // Генерируем валидную пару ключей
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    // Проверяем схему с возможно несовпадающими суммами
    let result = check_circuit(
        sk,
        pk,
        g,
        token_type,
        witness_sum,    // witness sum
        token_type,
        public_sum,     // public input sum (может отличаться!)
    );

    // PROPERTY: если сумма отличается, схема ДОЛЖНА отклонить
    if witness_sum != public_sum {
        assert!(
            result.is_err(),
            "SOUNDNESS VIOLATION: Different sums accepted! \
             witness={}, public={}, result={:?}",
            witness_sum, public_sum, result
        );
    }
});

