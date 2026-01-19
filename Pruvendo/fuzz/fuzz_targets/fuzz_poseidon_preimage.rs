//! Fuzz target: POS-01 - Poseidon Preimage Soundness
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что нельзя подобрать другие inputs дающие тот же digest.
//! Если inputs изменились, то верификация должна провалиться даже с тем же digest.
//!
//! КРИТИЧЕСКИЙ БАГ если этот fuzz target находит нарушение!

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::{check_circuit_with_custom_digest, compute_digest};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct PoseidonPreimageInput {
    /// Seed для sk
    sk_seed: u64,
    /// Оригинальные значения
    original_token: u64,
    original_sum: u64,
    /// Модифицированные значения (пытаемся подделать)
    modified_token: u64,
    modified_sum: u64,
}

fuzz_target!(|input: PoseidonPreimageInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 {
        return;
    }

    // Ограничиваем значения
    let orig_token = input.original_token % 1_000_000;
    let orig_sum = input.original_sum % 1_000_000_000;

    let mod_token = input.modified_token % 1_000_000;
    let mod_sum = input.modified_sum % 1_000_000_000;

    // Если значения не изменились - пропускаем (это валидный случай)
    if orig_token == mod_token && orig_sum == mod_sum {
        return;
    }

    let sk = Fr::from(input.sk_seed);

    // Вычисляем digest с ОРИГИНАЛЬНЫМИ значениями
    let original_digest = compute_digest(sk, Fr::from(orig_token), Fr::from(orig_sum));

    // Пытаемся пройти верификацию с МОДИФИЦИРОВАННЫМИ значениями
    // но с digest от оригинальных
    let result = check_circuit_with_custom_digest(
        sk,
        mod_token,      // Модифицированный token в circuit
        mod_sum,        // Модифицированная sum в circuit
        original_digest, // Но digest вычислен для оригинальных значений!
    );

    // ASSERTION: модифицированные inputs с чужим digest ДОЛЖНЫ быть отклонены
    assert!(
        result.is_err(),
        "POSEIDON PREIMAGE ATTACK! Modified inputs accepted with original digest!\n\
         Original: token={}, sum={}\n\
         Modified: token={}, sum={}",
        orig_token, orig_sum,
        mod_token, mod_sum
    );
});

