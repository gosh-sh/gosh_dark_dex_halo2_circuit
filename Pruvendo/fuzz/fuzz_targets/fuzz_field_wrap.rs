//! Fuzz target: Field Modulus Wraparound
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Тестирует значения около модуля Fr для поиска wraparound уязвимостей.
//! Фокус на арифметике, которая может дать неожиданные результаты.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    ff::Field,
};

mod common;
use common::{poseidon_hash, compute_sk_commitment, compute_digest};

#[derive(Arbitrary, Debug)]
struct FieldWrapInput {
    sk_seed: u64,
    /// Offset from -1 (max Fr value)
    offset_from_max: u8,
    /// Which value to set near max: 0=token, 1=sum
    which_max: u8,
    other: u64,
}

fuzz_target!(|input: FieldWrapInput| {
    if input.sk_seed == 0 {
        return;
    }

    let sk = Fr::from(input.sk_seed);

    // Создаём значение близкое к Fr max (modulus - 1 - offset)
    let near_max = -Fr::one() - Fr::from(input.offset_from_max as u64);

    // Назначаем значения
    let (token_fr, sum_fr) = match input.which_max % 2 {
        0 => (near_max, Fr::from(input.other)),
        _ => (Fr::from(input.other), near_max),
    };

    // Вычисляем sk_commitment и digest
    let sk_commitment = compute_sk_commitment(sk);
    let digest = compute_digest(sk, token_fr, sum_fr);

    // Проверка: digest должен быть детерминированным
    let digest2 = compute_digest(sk, token_fr, sum_fr);
    assert_eq!(digest, digest2, "Digest not deterministic with near-max values!");

    // Проверка: sk_commitment должен быть детерминированным
    let sk_commitment2 = compute_sk_commitment(sk);
    assert_eq!(sk_commitment, sk_commitment2, "sk_commitment not deterministic!");

    // Проверка: wraparound арифметика
    let small_val = Fr::from(100u64);
    let wrapped = near_max + small_val;

    // Если offset_from_max < 100, произойдёт wraparound
    if input.offset_from_max < 100 {
        let expected_small = Fr::from((99 - input.offset_from_max) as u64);

        if wrapped != expected_small {
            panic!(
                "FIELD WRAPAROUND UNEXPECTED RESULT!\n\
                 near_max (modulus-1-{}): {:?}\n\
                 near_max + 100 = {:?}\n\
                 Expected: {:?}",
                input.offset_from_max, near_max, wrapped, expected_small
            );
        }
    }

    // Дополнительная проверка: Fr::zero() - Fr::one() = Fr(-1) = near max
    let zero_minus_one = Fr::zero() - Fr::one();
    assert_eq!(zero_minus_one + Fr::one(), Fr::zero(), "Fr arithmetic broken!");
});

