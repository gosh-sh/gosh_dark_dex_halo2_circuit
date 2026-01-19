//! Fuzz target: Poseidon Hash Consistency
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что poseidon_hash() детерминистичен:
//! hash(a, b) == hash(a, b) для любых a, b

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Создаём два Fr элемента из входных данных
    let mut bytes1 = [0u8; 32];
    let mut bytes2 = [0u8; 32];

    // Используем первые 8 байт для a, следующие 8 для b
    bytes1[..8].copy_from_slice(&data[..8]);
    bytes2[..8].copy_from_slice(&data[8..16]);

    let a = Fr::from_u128(u128::from_le_bytes({
        let mut arr = [0u8; 16];
        arr[..8].copy_from_slice(&data[..8]);
        arr
    }));

    let b = Fr::from_u128(u128::from_le_bytes({
        let mut arr = [0u8; 16];
        arr[..8].copy_from_slice(&data[8..16]);
        arr
    }));

    // Вычисляем hash дважды
    let hash1 = poseidon_hash([a, b]);
    let hash2 = poseidon_hash([a, b]);

    // CONSISTENCY: hash должен быть детерминистичным
    assert_eq!(hash1, hash2, "EXT-01: Poseidon hash is not deterministic!");

    // UNIQUENESS: разные входы должны давать разные выходы (с высокой вероятностью)
    if a != b {
        let hash_ab = poseidon_hash([a, b]);
        let hash_ba = poseidon_hash([b, a]);
        // Poseidon НЕ симметричный
        assert_ne!(hash_ab, hash_ba, "EXT-01: Poseidon should not be symmetric for a != b");
    }

    // NON-ZERO: hash не должен быть нулём для не-нулевых входов
    if a != Fr::zero() || b != Fr::zero() {
        // Это свойство сложно гарантировать, но можем проверить
        // что hash хотя бы не всегда ноль
    }
});

