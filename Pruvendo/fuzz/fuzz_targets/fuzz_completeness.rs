//! Fuzz target: Completeness property
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что схема ПРИНИМАЕТ валидные входы.
//! Если sk_commitment = poseidon(sk, 0) и public inputs корректны,
//! то verify() должен успешно пройти.
//!
//! БАГ если этот fuzz target находит нарушение — схема over-constrained.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::check_circuit;

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct CompletenessInput {
    /// Seed для секретного ключа
    sk_seed: u64,
    /// Тип токена
    token_type: u64,
    /// Сумма
    note_sum: u64,
}

fuzz_target!(|input: CompletenessInput| {
    // Фильтруем невалидные входы
    if input.sk_seed == 0 {
        return;
    }

    // Используем полный диапазон u64 для лучшего покрытия
    let token = input.token_type;
    let sum = input.note_sum;

    // Проверяем схему с валидными входами
    let result = check_circuit(input.sk_seed, token, sum);

    // ASSERTION: валидные входы ДОЛЖНЫ быть приняты
    assert!(
        result.is_ok(),
        "COMPLETENESS VIOLATION! Valid inputs were rejected!\n\
         sk_seed = {}, token = {}, sum = {}\n\
         Error: {:?}",
        input.sk_seed, token, sum, result
    );
});

