//! Fuzz target: Limb reconstruction attacks
//!
//! Проверяет: можно ли найти разные (sk, pk) пары которые дают
//! одинаковый key_data_sum?
//!
//! key_data_sum = sk + Σ(pk.x limbs) + Σ(pk.y limbs)
//!
//! Если найти (sk1, pk1) и (sk2, pk2) где sums равны,
//! это может позволить подмену keypair.
//!
//! Ожидание: Для случайных keypairs collision маловероятна
#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    ff::PrimeField,
};

/// Input for limb reconstruction attack fuzzing
#[derive(Debug)]
struct LimbReconstructionInput {
    // Два sk для сравнения
    sk1: u64,
    sk2: u64,
    // Дополнительные параметры для манипуляции
    offset: u64,
}

impl<'a> Arbitrary<'a> for LimbReconstructionInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        Ok(LimbReconstructionInput {
            sk1: u.int_in_range(1..=u64::MAX)?,
            sk2: u.int_in_range(1..=u64::MAX)?,
            offset: u.arbitrary()?,
        })
    }
}

/// Вычисляет key_data_sum для данного keypair
fn compute_key_sum(sk_raw: u64, pk: &Secp256k1Affine) -> u128 {
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes().to_vec()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes().to_vec()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes().to_vec()[22..]);

    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes().to_vec()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes().to_vec()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes().to_vec()[22..]);

    (sk_raw as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
        + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2
}

/// Возвращает отдельные limbs для анализа
fn get_limbs(sk_raw: u64, pk: &Secp256k1Affine) -> [u128; 7] {
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes().to_vec()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes().to_vec()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes().to_vec()[22..]);

    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes().to_vec()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes().to_vec()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes().to_vec()[22..]);

    [sk_raw as u128, pk_x_limb_0, pk_x_limb_1, pk_x_limb_2, pk_y_limb_0, pk_y_limb_1, pk_y_limb_2]
}

fuzz_target!(|input: LimbReconstructionInput| {
    ensure_working_directory();
    
    // Skip если одинаковые sk
    if input.sk1 == input.sk2 {
        return;
    }
    
    // Генерируем два keypair
    let g = Secp256k1Affine::generator();
    
    let sk1 = Fq::from(input.sk1);
    let pk1 = Secp256k1Affine::from(g * sk1);
    
    let sk2 = Fq::from(input.sk2);
    let pk2 = Secp256k1Affine::from(g * sk2);
    
    // Вычисляем key_data_sum
    let sum1 = compute_key_sum(input.sk1, &pk1);
    let sum2 = compute_key_sum(input.sk2, &pk2);
    
    // COLLISION CHECK
    if sum1 == sum2 {
        // Это ОЧЕНЬ КРИТИЧНО - разные keypairs с одинаковым key_data_sum!
        let limbs1 = get_limbs(input.sk1, &pk1);
        let limbs2 = get_limbs(input.sk2, &pk2);
        
        panic!(
            "KEY_DATA_SUM COLLISION FOUND!\n\
            sk1={}, sk2={}\n\
            limbs1={:?}\n\
            limbs2={:?}\n\
            sum={}",
            input.sk1, input.sk2,
            limbs1, limbs2,
            sum1
        );
    }
    
    // Дополнительная проверка: sk близкие по значению
    // sk2 = sk1 + offset должны давать разные sums
    if let Some(sk_offset) = input.sk1.checked_add(input.offset % 1000) {
        if sk_offset != input.sk1 && sk_offset > 0 {
            let sk_o = Fq::from(sk_offset);
            let pk_o = Secp256k1Affine::from(g * sk_o);
            let sum_o = compute_key_sum(sk_offset, &pk_o);
            
            if sum1 == sum_o {
                panic!(
                    "KEY_DATA_SUM COLLISION (adjacent sk)!\n\
                    sk1={}, sk_offset={}, offset={}\n\
                    sum={}",
                    input.sk1, sk_offset, input.offset % 1000,
                    sum1
                );
            }
        }
    }
});

