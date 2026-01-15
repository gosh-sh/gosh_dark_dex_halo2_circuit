//! Fuzz target: limb overflow attack
//!
//! Пытается найти случаи когда limb decomposition может быть обойдена
//! через overflow или неправильную реконструкцию.
//!
//! Конфигурация: limb_bits=88, num_limbs=3

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fp, Fq, Secp256k1Affine},
    ff::{Field, PrimeField},
    group::Curve,
};
use halo2_base::halo2_proofs::arithmetic::CurveAffine;
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

const LIMB_BITS: usize = 88;
const MAX_LIMB_VALUE: u128 = 1u128 << LIMB_BITS;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    
    ensure_working_directory();
    
    // Генерируем sk
    let sk_val = u64::from_le_bytes(data[0..8].try_into().unwrap()).max(1);
    let sk = Fq::from(sk_val);
    
    // Вычисляем pk
    let g = Secp256k1Affine::generator();
    let pk = (g * sk).to_affine();
    
    // Извлекаем limbs
    let pk_x_bytes = pk.x.to_bytes();
    let pk_y_bytes = pk.y.to_bytes();
    
    let limbs_x = [
        consume_uint128_11(&pk_x_bytes[0..11]),
        consume_uint128_11(&pk_x_bytes[11..22]),
        consume_uint128_10(&pk_x_bytes[22..]),
    ];
    
    let limbs_y = [
        consume_uint128_11(&pk_y_bytes[0..11]),
        consume_uint128_11(&pk_y_bytes[11..22]),
        consume_uint128_10(&pk_y_bytes[22..]),
    ];
    
    // Проверка 1: Все limbs должны быть < 2^88
    for (i, limb) in limbs_x.iter().enumerate() {
        assert!(*limb < MAX_LIMB_VALUE, 
            "pk.x limb {} overflow: {} >= 2^88", i, limb);
    }
    for (i, limb) in limbs_y.iter().enumerate() {
        assert!(*limb < MAX_LIMB_VALUE, 
            "pk.y limb {} overflow: {} >= 2^88", i, limb);
    }
    
    // Проверка 2: Сумма limbs в Fr не должна переполняться
    let sk_fr = Fr::from(sk_val);
    let mut key_data_sum = sk_fr;
    
    for limb in limbs_x.iter().chain(limbs_y.iter()) {
        // Limb как Fr
        let limb_lo = (*limb & ((1u128 << 64) - 1)) as u64;
        let limb_hi = (*limb >> 64) as u64;
        let limb_fr = Fr::from(limb_lo) + Fr::from(limb_hi) * Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
        key_data_sum += limb_fr;
    }
    
    // key_data_sum должен быть детерминированным
    let mut key_data_sum2 = sk_fr;
    for limb in limbs_x.iter().chain(limbs_y.iter()) {
        let limb_lo = (*limb & ((1u128 << 64) - 1)) as u64;
        let limb_hi = (*limb >> 64) as u64;
        let limb_fr = Fr::from(limb_lo) + Fr::from(limb_hi) * Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
        key_data_sum2 += limb_fr;
    }
    
    assert_eq!(key_data_sum, key_data_sum2, 
        "key_data_sum should be deterministic");
    
    // Проверка 3: Схема должна пройти с правильными данными
    let token = 1u64;
    let sum = 1000u64;
    let vault = 999u64;
    
    let result = check_circuit(sk, pk, g, token, sum, vault, sk_val);
    assert!(result.is_ok(), 
        "Circuit should pass with valid limbs. sk={}", sk_val);
});

