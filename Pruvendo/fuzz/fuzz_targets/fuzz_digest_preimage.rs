//! Fuzz target: Digest preimage attacks
//!
//! Проверяет: можно ли найти разные (key_data_sum', deposit_sum')
//! которые дают тот же Poseidon digest?
//!
//! Это атака на collision resistance Poseidon hash.
//!
//! Если digest = H([key_sum, deposit_sum]), найти:
//! (key_sum', deposit_sum') ≠ (key_sum, deposit_sum) где H() одинаков
//!
//! Ожидание: Poseidon collision resistant, не должно быть найдено
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

/// Input for digest preimage attack fuzzing
#[derive(Debug)]
struct DigestPreimageInput {
    // Original values
    sk1: u64,
    token1: u64,
    sum1: u64,
    vault1: u64,
    // Attack values
    sk2: u64,
    token2: u64,
    sum2: u64,
    vault2: u64,
}

impl<'a> Arbitrary<'a> for DigestPreimageInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        Ok(DigestPreimageInput {
            sk1: u.int_in_range(1..=u64::MAX)?,
            token1: u.arbitrary()?,
            sum1: u.arbitrary()?,
            vault1: u.arbitrary()?,
            sk2: u.int_in_range(1..=u64::MAX)?,
            token2: u.arbitrary()?,
            sum2: u.arbitrary()?,
            vault2: u.arbitrary()?,
        })
    }
}

/// Вычисляет key_data_sum для данного keypair
fn compute_key_data_sum(sk_raw: u64, pk: &Secp256k1Affine) -> Fr {
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes().to_vec()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes().to_vec()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes().to_vec()[22..]);

    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes().to_vec()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes().to_vec()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes().to_vec()[22..]);

    let key_data_sum = (sk_raw as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
        + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    Fr::from_u128(key_data_sum)
}

fuzz_target!(|input: DigestPreimageInput| {
    ensure_working_directory();
    
    // Генерируем два разных keypair
    let (sk1, pk1, g) = generate_valid_keypair(input.sk1);
    let (sk2, pk2, _) = generate_valid_keypair(input.sk2);
    
    // Вычисляем key_data_sum для обоих
    let key_sum1 = compute_key_data_sum(input.sk1, &pk1);
    let key_sum2 = compute_key_data_sum(input.sk2, &pk2);
    
    // Вычисляем deposit_sum для обоих
    let deposit_sum1 = Fr::from(input.token1) + Fr::from(input.sum1) + Fr::from(input.vault1);
    let deposit_sum2 = Fr::from(input.token2) + Fr::from(input.sum2) + Fr::from(input.vault2);
    
    // Вычисляем digests
    let digest1 = poseidon_hash([key_sum1, deposit_sum1]);
    let digest2 = poseidon_hash([key_sum2, deposit_sum2]);
    
    // Проверяем collision
    if digest1 == digest2 {
        // Collision найдена! Проверяем что это не тривиальная (одинаковые входы)
        let same_inputs = (key_sum1 == key_sum2) && (deposit_sum1 == deposit_sum2);
        
        if !same_inputs {
            // НАСТОЯЩАЯ COLLISION В POSEIDON!
            panic!(
                "POSEIDON COLLISION FOUND!\n\
                key_sum1={:?}, deposit_sum1={:?}\n\
                key_sum2={:?}, deposit_sum2={:?}\n\
                digest={:?}",
                key_sum1, deposit_sum1,
                key_sum2, deposit_sum2,
                digest1
            );
        }
    }
    
    // Также проверяем частичные collision (только key_sum или только deposit_sum)
    // Если key_sum одинаковый но deposit_sum разный - разные digest (должно быть)
    // Если deposit_sum одинаковый но key_sum разный - разные digest (должно быть)
    
    // Проверка: разные key_sum но одинаковый deposit_sum
    if key_sum1 != key_sum2 && deposit_sum1 == deposit_sum2 {
        assert!(
            digest1 != digest2,
            "PARTIAL COLLISION: Same deposit_sum, different key_sum, same digest!"
        );
    }
    
    // Проверка: одинаковый key_sum но разный deposit_sum
    if key_sum1 == key_sum2 && deposit_sum1 != deposit_sum2 {
        assert!(
            digest1 != digest2,
            "PARTIAL COLLISION: Same key_sum, different deposit_sum, same digest!"
        );
    }
});

