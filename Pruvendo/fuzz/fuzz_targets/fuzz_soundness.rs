//! Fuzz target: Soundness property
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что схема ОТКЛОНЯЕТ неверные sk_commitment.
//! Если sk_commitment ≠ poseidon(sk, 0), то verify() должен вернуть ошибку.
//!
//! КРИТИЧЕСКИЙ БАГ если этот fuzz target находит нарушение!

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use common::{compute_sk_commitment, check_circuit_with_wrong_commitment};

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct SoundnessInput {
    /// Seed для секретного ключа
    sk_seed: u64,
    /// Seed для НЕВЕРНОГО commitment (от другого sk)
    wrong_sk_seed: u64,
    /// Тип токена
    token_type: u64,
    /// Сумма
    note_sum: u64,
}

fuzz_target!(|input: SoundnessInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 || input.wrong_sk_seed == 0 {
        return;
    }

    // Если sk == wrong_sk, то commitment будет верным — пропускаем
    if input.sk_seed == input.wrong_sk_seed {
        return;
    }

    // Ограничиваем значения
    let token = input.token_type % 1_000_000;
    let sum = input.note_sum % 1_000_000_000;

    let sk = Fr::from(input.sk_seed);
    let wrong_sk = Fr::from(input.wrong_sk_seed);
    let wrong_commitment = compute_sk_commitment(wrong_sk);

    // Проверяем схему с неверным commitment
    let result = check_circuit_with_wrong_commitment(
        sk,
        wrong_commitment,  // НЕВЕРНЫЙ commitment!
        token,
        sum,
    );

    // ASSERTION: неверный commitment ДОЛЖЕН быть отклонён
    assert!(
        result.is_err(),
        "SOUNDNESS VIOLATION! Wrong commitment was accepted!\n\
         sk_seed = {}, wrong_sk_seed = {}\n\
         token = {}, sum = {}",
        input.sk_seed, input.wrong_sk_seed, token, sum
    );
});

