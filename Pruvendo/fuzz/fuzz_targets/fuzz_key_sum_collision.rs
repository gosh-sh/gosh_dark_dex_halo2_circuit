//! FUZZ-KEY-SUM: Key data sum collision search
//!
//! Ищет две разные пары (sk1, pk1) и (sk2, pk2) с одинаковым key_data_sum.
//! Коллизия = криптографическая уязвимость, позволяющая подмену ключей.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    group::Curve,
    ff::PrimeField,
};

mod common;
use common::{consume_uint128_11, consume_uint128_10};

#[derive(Arbitrary, Debug)]
struct KeySumInput {
    sk1_seed: u64,
    sk2_seed: u64,
}

/// Вычисляет key_data_sum для пары (sk_seed, pk)
fn compute_key_data_sum(sk_seed: u64, pk: &Secp256k1Affine) -> u128 {
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes()[22..]);
    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes()[22..]);
    
    (sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                      + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2
}

fuzz_target!(|input: KeySumInput| {
    // Пропускаем если ключи одинаковые
    if input.sk1_seed == input.sk2_seed {
        return;
    }
    
    // Пропускаем sk = 0 (identity point)
    if input.sk1_seed == 0 || input.sk2_seed == 0 {
        return;
    }
    
    let g = Secp256k1Affine::generator();
    
    // Keypair 1
    let sk1 = Fq::from(input.sk1_seed);
    let pk1 = Secp256k1Affine::from(g * sk1);
    let sum1 = compute_key_data_sum(input.sk1_seed, &pk1);
    
    // Keypair 2
    let sk2 = Fq::from(input.sk2_seed);
    let pk2 = Secp256k1Affine::from(g * sk2);
    let sum2 = compute_key_data_sum(input.sk2_seed, &pk2);
    
    // Проверяем на коллизию
    if sum1 == sum2 {
        // КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: найдена коллизия в key_data_sum!
        panic!(
            "KEY_DATA_SUM COLLISION FOUND!\n\
             sk1_seed: {}, pk1: {:?}\n\
             sk2_seed: {}, pk2: {:?}\n\
             key_data_sum: {}",
            input.sk1_seed, pk1,
            input.sk2_seed, pk2,
            sum1
        );
    }
    
    // Также проверяем модульную коллизию (разные суммы, одинаковый Fr)
    let fr1 = Fr::from_u128(sum1);
    let fr2 = Fr::from_u128(sum2);
    
    if fr1 == fr2 && sum1 != sum2 {
        panic!(
            "KEY_DATA_SUM Fr MODULAR COLLISION!\n\
             sum1: {} -> {:?}\n\
             sum2: {} -> {:?}\n\
             Fr values equal despite different sums!",
            sum1, fr1,
            sum2, fr2
        );
    }
});

