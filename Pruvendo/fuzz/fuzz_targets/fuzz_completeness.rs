//! Fuzz target: Completeness property
//!
//! Проверяет что схема ПРИНИМАЕТ валидные пары ключей.
//! Если pk = sk * G и public inputs = witness, то verify() должен успешно пройти.
//!
//! БАГ если этот fuzz target находит нарушение — схема over-constrained.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::{generate_valid_keypair, check_circuit};

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct CompletenessInput {
    /// Seed для секретного ключа (pk = sk * G)
    sk_seed: u64,
    /// Тип токена
    token_type: u64,
    /// Сумма
    note_sum: u64,
    /// Vault random value
    vault_rand_val: u64,
}

fuzz_target!(|input: CompletenessInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 {
        return;
    }

    // Ограничиваем значения
    let token = input.token_type % 1_000_000;
    let sum = input.note_sum % 1_000_000_000;
    let vault = input.vault_rand_val % 1_000_000;

    // Генерируем ВАЛИДНУЮ пару: pk = sk * G
    let (sk, pk, g) = generate_valid_keypair(input.sk_seed);

    // Проверяем схему с совпадающими witness и public inputs
    let result = check_circuit(
        sk,
        pk,     // ВЕРНЫЙ публичный ключ
        g,
        token,
        sum,
        vault,
        input.sk_seed,  // sk_raw для digest
    );

    // ASSERTION: валидная пара ДОЛЖНА быть принята
    assert!(
        result.is_ok(),
        "COMPLETENESS VIOLATION! Valid keypair was rejected!\n\
         sk_seed = {}, token = {}, sum = {}\n\
         Error: {:?}",
        input.sk_seed, token, sum, result
    );
});

