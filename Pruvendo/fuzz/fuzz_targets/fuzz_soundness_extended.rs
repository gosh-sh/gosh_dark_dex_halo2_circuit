//! Fuzz target: Extended soundness testing
//!
//! Расширенная проверка soundness: проверяет что неверный pk отклоняется.
//! После poseidon_integration: soundness проверяется через digest.
//!
//! Находит: нарушения soundness при неверных ключах.
//!
//! Запуск: cargo +nightly fuzz run fuzz_soundness_extended

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

/// Входные данные для расширенного soundness теста
#[derive(Debug, Arbitrary)]
struct ExtendedSoundnessInput {
    /// Seed для sk
    sk_seed: u64,
    /// Seed для wrong_sk
    wrong_sk_seed: u64,
    /// Token type
    token: u64,
    /// Sum
    sum: u64,
    /// Vault random value
    vault: u64,
}

fuzz_target!(|input: ExtendedSoundnessInput| {
    // Фильтры
    if input.sk_seed == 0 || input.wrong_sk_seed == 0 {
        return;
    }
    if input.sk_seed == input.wrong_sk_seed {
        return; // pk будет верным
    }

    let token = input.token % 1_000_000;
    let sum = input.sum % 1_000_000_000;
    let vault = input.vault % 1_000_000;

    // Генерируем неверную пару: pk ≠ sk * G
    let (sk, wrong_pk, g) = generate_invalid_keypair(input.sk_seed, input.wrong_sk_seed);

    // Проверяем схему с неверным pk
    // Используем wrong_sk_seed для digest чтобы digest соответствовал wrong_pk
    let result = check_circuit(
        sk,
        wrong_pk,  // НЕВЕРНЫЙ публичный ключ!
        g,
        token,
        sum,
        vault,
        input.wrong_sk_seed,  // sk_raw для digest - консистентен с wrong_pk
    );

    // ASSERTION: неверный pk ДОЛЖЕН быть отклонён
    assert!(
        result.is_err(),
        "SOUNDNESS VIOLATION! Wrong pk was accepted!\n\
         sk={}, wrong_sk={}\n\
         token={}, sum={}",
        input.sk_seed, input.wrong_sk_seed,
        token, sum
    );
});
