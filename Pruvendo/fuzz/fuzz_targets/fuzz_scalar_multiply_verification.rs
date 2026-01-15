//! Fuzz target: scalar_multiply verification
//!
//! Проверяет что scalar_multiply(g, sk) == pk когда pk = sk * g
//! и что схема отклоняет неправильные pk.
//!
//! Это критично для безопасности - если scalar_multiply вычисляет
//! неправильное значение, то is_equal constraint может быть обойден.

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

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    
    ensure_working_directory();
    
    // Генерируем sk
    let sk_val = u64::from_le_bytes(data[0..8].try_into().unwrap()).max(1);
    let sk = Fq::from(sk_val);
    
    // Вычисляем правильный pk
    let g = Secp256k1Affine::generator();
    let correct_pk = (g * sk).to_affine();
    
    // Тип теста
    let test_type = data[8] % 4;
    
    match test_type {
        0 => {
            // Тест 1: Правильный pk должен пройти
            let token = 1u64;
            let sum = 1000u64;
            let vault = 999u64;
            
            let result = check_circuit(sk, correct_pk, g, token, sum, vault, sk_val);
            assert!(result.is_ok(), 
                "Correct pk should pass verification. sk={}", sk_val);
        }
        1 => {
            // Тест 2: Неправильный sk (pk не соответствует sk)
            if data.len() < 16 {
                return;
            }
            let wrong_sk_val = u64::from_le_bytes(data[8..16].try_into().unwrap()).max(1);
            if wrong_sk_val == sk_val {
                return; // Skip if same sk
            }
            
            let wrong_sk = Fq::from(wrong_sk_val);
            
            let result = check_circuit(wrong_sk, correct_pk, g, 1, 1000, 999, wrong_sk_val);
            assert!(result.is_err(), 
                "Wrong sk should fail verification. correct_sk={}, wrong_sk={}", 
                sk_val, wrong_sk_val);
        }
        2 => {
            // Тест 3: Неправильный generator
            if data.len() < 24 {
                return;
            }
            let fake_g_sk = u64::from_le_bytes(data[16..24].try_into().unwrap()).max(2);
            let fake_g = (g * Fq::from(fake_g_sk)).to_affine();
            
            if fake_g == g {
                return; // Skip if same generator
            }
            
            // pk был вычислен с оригинальным g, но мы даём fake_g
            let result = check_circuit(sk, correct_pk, fake_g, 1, 1000, 999, sk_val);
            // Это должно fail потому что fake_g * sk != correct_pk
            assert!(result.is_err(), 
                "Wrong generator should fail. sk={}, fake_g_sk={}", 
                sk_val, fake_g_sk);
        }
        _ => {
            // Тест 4: Проверка point on curve
            let y2 = correct_pk.y * correct_pk.y;
            let x3 = correct_pk.x * correct_pk.x * correct_pk.x;
            let b = Fp::from(7u64);
            
            assert_eq!(y2, x3 + b, 
                "pk should be on secp256k1 curve (y^2 = x^3 + 7)");
        }
    }
});

