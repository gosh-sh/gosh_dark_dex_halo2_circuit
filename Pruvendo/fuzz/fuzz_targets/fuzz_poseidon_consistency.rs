//! Fuzz target: Poseidon Hash Consistency
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет:
//! 1. poseidon_hash() детерминистичен: hash(a, b) == hash(a, b)
//! 2. Library hash == reference implementation hash (CROSS-VALIDATION)
//! 3. Несимметричность: hash(a, b) != hash(b, a) для a != b

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

    // === TEST 1: DETERMINISM ===
    let hash1 = poseidon_hash([a, b]);
    let hash2 = poseidon_hash([a, b]);
    assert_eq!(hash1, hash2, "DETERMINISM VIOLATION: Poseidon hash is not deterministic!");

    // === TEST 2: CROSS-VALIDATION с reference implementation ===
    let ref_hash = reference_poseidon_hash_2([a, b]);
    assert_eq!(hash1, ref_hash,
        "TAUTOLOGY VIOLATION: Library hash differs from reference implementation!\n\
         a={:?}, b={:?}\n\
         library={:?}, reference={:?}",
        a, b, hash1, ref_hash);

    // === TEST 3: NON-SYMMETRY ===
    if a != b {
        let hash_ab = poseidon_hash([a, b]);
        let hash_ba = poseidon_hash([b, a]);
        assert_ne!(hash_ab, hash_ba, "Poseidon should not be symmetric for a != b");
    }
});

