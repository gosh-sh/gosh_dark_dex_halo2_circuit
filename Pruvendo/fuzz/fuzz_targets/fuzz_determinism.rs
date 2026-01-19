//! Fuzz target: Determinism property
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что схема детерминирована: одинаковые входы → одинаковый результат.
//! Запускает схему дважды с теми же параметрами и сравнивает результаты.
//!
//! БАГ если результаты различаются — схема недетерминирована.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::check_circuit;

/// Входные данные для fuzzing
#[derive(Arbitrary, Debug)]
struct DeterminismInput {
    sk_seed: u64,
    token_type: u64,
    note_sum: u64,
}

fuzz_target!(|input: DeterminismInput| {
    if input.sk_seed == 0 {
        return;
    }

    // Используем полный диапазон u64 для лучшего покрытия
    let token = input.token_type;
    let sum = input.note_sum;

    // Первый запуск
    let result1 = check_circuit(input.sk_seed, token, sum);

    // Второй запуск с теми же параметрами
    let result2 = check_circuit(input.sk_seed, token, sum);

    // ASSERTION: результаты должны совпадать
    assert_eq!(
        result1, result2,
        "DETERMINISM VIOLATION! Same inputs produced different results!\n\
         sk_seed = {}, token = {}, sum = {}\n\
         Result 1: {:?}\n\
         Result 2: {:?}",
        input.sk_seed, token, sum, result1, result2
    );
});

