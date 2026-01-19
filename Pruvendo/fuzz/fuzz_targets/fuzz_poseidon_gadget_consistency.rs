//! Fuzz target: Poseidon Gadget vs Primitive Consistency
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что poseidon_hash_gadget (в схеме) даёт тот же результат,
//! что и poseidon_hash (вне схемы).
//!
//! Это критично для безопасности - если gadget вычисляет неправильный hash,
//! то digest в схеме будет отличаться от ожидаемого.

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    ensure_working_directory();

    // Генерируем sk
    let sk_val = u64::from_le_bytes(data[0..8].try_into().unwrap()).max(1);
    let sk = Fr::from(sk_val);

    // Генерируем параметры транзакции
    let token = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 1000 + 1;
    let sum = u64::from_le_bytes(data[16..24].try_into().unwrap()) % 1000000 + 1;

    // Вычисляем digest вне схемы (primitive)
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);

    let expected_digest = compute_digest(sk, token_fr, sum_fr);

    // Проверяем схему - она должна пройти только если gadget вычислил
    // тот же digest что и primitive
    let result = check_circuit(sk_val, token, sum);

    // Схема ДОЛЖНА пройти для валидных входов
    assert!(result.is_ok(),
        "Circuit should pass when gadget and primitive compute same digest. \
         sk={}, token={}, sum={}, expected_digest={:?}",
        sk_val, token, sum, expected_digest);
});

