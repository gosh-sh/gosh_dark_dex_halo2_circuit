//! Fuzz target: Soundness property
//!
//! Проверяет что схема ОТКЛОНЯЕТ неверные пары ключей.
//! Если pk ≠ sk * G, то verify() должен вернуть ошибку.
//!
//! КРИТИЧЕСКИЙ БАГ если этот fuzz target находит нарушение!

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::{generate_invalid_keypair, check_circuit};

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct SoundnessInput {
    /// Seed для секретного ключа
    sk_seed: u64,
    /// Seed для НЕВЕРНОГО публичного ключа (pk = wrong_sk * G)
    wrong_sk_seed: u64,
    /// Тип токена
    token_type: u64,
    /// Сумма
    note_sum: u64,
    /// Vault random value
    vault_rand_val: u64,
}

fuzz_target!(|input: SoundnessInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 || input.wrong_sk_seed == 0 {
        return;
    }

    // Если sk == wrong_sk, то pk будет верным — пропускаем
    if input.sk_seed == input.wrong_sk_seed {
        return;
    }

    // Ограничиваем значения чтобы избежать overflow
    let token = input.token_type % 1_000_000;
    let sum = input.note_sum % 1_000_000_000;
    let vault = input.vault_rand_val % 1_000_000;

    // Генерируем неверную пару: pk ≠ sk * G
    let (sk, wrong_pk, g) = generate_invalid_keypair(input.sk_seed, input.wrong_sk_seed);

    // Проверяем схему - используем wrong_sk_seed для digest (неверный pk)
    let result = check_circuit(
        sk,
        wrong_pk,  // НЕВЕРНЫЙ публичный ключ!
        g,
        token,
        sum,
        vault,
        input.wrong_sk_seed,  // sk_raw для digest - используем wrong чтобы digest был консистентен с wrong_pk
    );

    // ASSERTION: неверная пара ключей ДОЛЖНА быть отклонена
    assert!(
        result.is_err(),
        "SOUNDNESS VIOLATION! Invalid keypair was accepted!\n\
         sk_seed = {}, wrong_sk_seed = {}\n\
         token = {}, sum = {}",
        input.sk_seed, input.wrong_sk_seed, token, sum
    );
});

