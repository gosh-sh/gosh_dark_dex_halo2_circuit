//! Fuzz target: POS-01 - Poseidon preimage soundness
//!
//! Проверяет что нельзя подобрать другие inputs дающие тот же digest.
//! Если inputs изменились, то верификация должна провалиться даже с тем же digest.
//!
//! КРИТИЧЕСКИЙ БАГ если этот fuzz target находит нарушение!

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::{generate_valid_keypair, check_circuit_with_custom_digest};

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct PoseidonPreimageInput {
    /// Seed для keypair
    sk_seed: u64,
    /// Оригинальные значения
    original_token: u64,
    original_sum: u64,
    original_vault: u64,
    /// Модифицированные значения (пытаемся подделать)
    modified_token: u64,
    modified_sum: u64,
    modified_vault: u64,
}

fuzz_target!(|input: PoseidonPreimageInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 {
        return;
    }

    // Ограничиваем значения
    let orig_token = input.original_token % 1_000_000;
    let orig_sum = input.original_sum % 1_000_000_000;
    let orig_vault = input.original_vault % 1_000_000;

    let mod_token = input.modified_token % 1_000_000;
    let mod_sum = input.modified_sum % 1_000_000_000;
    let mod_vault = input.modified_vault % 1_000_000;

    // Если значения не изменились - пропускаем (это валидный случай)
    if orig_token == mod_token && orig_sum == mod_sum && orig_vault == mod_vault {
        return;
    }

    // Генерируем валидную пару ключей
    let (sk, pk, g) = generate_valid_keypair(input.sk_seed);

    // Вычисляем digest с ОРИГИНАЛЬНЫМИ значениями
    // Но пытаемся пройти верификацию с МОДИФИЦИРОВАННЫМИ значениями
    let result = check_circuit_with_custom_digest(
        sk,
        pk,
        g,
        mod_token,      // Модифицированный token в circuit
        mod_sum,        // Модифицированная sum в circuit  
        mod_vault,      // Модифицированный vault в circuit
        input.sk_seed,
        orig_token,     // Но digest вычислен для оригинальных значений!
        orig_sum,
        orig_vault,
    );

    // ASSERTION: модифицированные inputs с чужим digest ДОЛЖНЫ быть отклонены
    assert!(
        result.is_err(),
        "POSEIDON PREIMAGE ATTACK! Modified inputs accepted with original digest!\n\
         Original: token={}, sum={}, vault={}\n\
         Modified: token={}, sum={}, vault={}",
        orig_token, orig_sum, orig_vault,
        mod_token, mod_sum, mod_vault
    );
});

