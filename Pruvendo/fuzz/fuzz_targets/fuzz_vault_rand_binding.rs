//! Fuzz target: POS-02 - vault_rand_val binding
//!
//! Проверяет что vault_rand_val влияет на digest и proof.
//! Если vault_rand_val изменился, proof должен быть отклонён.
//!
//! КРИТИЧЕСКИЙ БАГ если vault_rand_val не влияет на верификацию!

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::{generate_valid_keypair, check_circuit_with_custom_digest};

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct VaultRandBindingInput {
    /// Seed для keypair
    sk_seed: u64,
    /// Фиксированные значения token и sum
    token_type: u64,
    note_sum: u64,
    /// Оригинальное значение vault_rand_val
    original_vault: u64,
    /// Модифицированное значение vault_rand_val
    modified_vault: u64,
}

fuzz_target!(|input: VaultRandBindingInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 {
        return;
    }

    // Ограничиваем значения
    let token = input.token_type % 1_000_000;
    let sum = input.note_sum % 1_000_000_000;
    let orig_vault = input.original_vault % 1_000_000;
    let mod_vault = input.modified_vault % 1_000_000;

    // Если vault не изменился - пропускаем
    if orig_vault == mod_vault {
        return;
    }

    // Генерируем валидную пару ключей
    let (sk, pk, g) = generate_valid_keypair(input.sk_seed);

    // Создаём circuit с МОДИФИЦИРОВАННЫМ vault_rand_val
    // Но digest вычислен для ОРИГИНАЛЬНОГО vault_rand_val
    let result = check_circuit_with_custom_digest(
        sk,
        pk,
        g,
        token,
        sum,
        mod_vault,      // Модифицированный vault в circuit
        input.sk_seed,
        token,          // Те же token/sum
        sum,
        orig_vault,     // Но digest для оригинального vault!
    );

    // ASSERTION: изменённый vault_rand_val ДОЛЖЕН быть отклонён
    assert!(
        result.is_err(),
        "VAULT_RAND_VAL BINDING VIOLATION! Modified vault accepted!\n\
         Original vault = {}, Modified vault = {}\n\
         Token = {}, Sum = {}",
        orig_vault, mod_vault, token, sum
    );
});

