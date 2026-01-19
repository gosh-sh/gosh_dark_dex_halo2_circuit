//! Fuzz target: Extended Soundness Testing
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Расширенная проверка soundness: проверяет что неверный sk_commitment отклоняется.
//! Soundness проверяется через digest.
//!
//! Находит: нарушения soundness при неверных ключах.
//!
//! Запуск: cargo +nightly fuzz run fuzz_soundness_extended

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

mod common;
use common::*;

/// Входные данные для расширенного soundness теста
#[derive(Debug, Arbitrary)]
struct ExtendedSoundnessInput {
    /// Seed для sk
    sk_seed: u64,
    /// Seed для wrong_sk (для wrong_commitment)
    wrong_sk_seed: u64,
    /// Token type
    token: u64,
    /// Sum
    sum: u64,
}

fuzz_target!(|input: ExtendedSoundnessInput| {
    // Фильтры
    if input.sk_seed == 0 || input.wrong_sk_seed == 0 {
        return;
    }
    if input.sk_seed == input.wrong_sk_seed {
        return; // commitment будет верным
    }

    ensure_working_directory();

    let token = input.token % 1_000_000;
    let sum = input.sum % 1_000_000_000;

    // Вычисляем wrong_commitment от другого sk
    let wrong_sk = Fr::from(input.wrong_sk_seed);
    let wrong_commitment = compute_sk_commitment(wrong_sk);

    // Проверяем схему с неверным sk_commitment
    let result = check_circuit_with_wrong_commitment(
        Fr::from(input.sk_seed),
        wrong_commitment,  // НЕВЕРНЫЙ sk_commitment!
        token,
        sum,
    );

    // ASSERTION: неверный sk_commitment ДОЛЖЕН быть отклонён
    assert!(
        result.is_err(),
        "SOUNDNESS VIOLATION! Wrong sk_commitment was accepted!\n\
         sk={}, wrong_sk={}\n\
         token={}, sum={}",
        input.sk_seed, input.wrong_sk_seed,
        token, sum
    );
});
