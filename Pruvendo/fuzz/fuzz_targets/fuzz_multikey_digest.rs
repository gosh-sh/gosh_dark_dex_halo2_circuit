//! FUZZ-MULTIKEY: Multiple keys same digest
//!
//! Ищет разные keypairs с одинаковым финальным Poseidon digest.
//! Коллизия в digest = критическая уязвимость (можно подменить ключ).

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
use common::poseidon_hash;

use common::{consume_uint128_11, consume_uint128_10};

#[derive(Arbitrary, Debug)]
struct MultiKeyInput {
    sk1_seed: u64,
    sk2_seed: u64,
    token1: u64,
    sum1: u64,
    vault1: u64,
    token2: u64,
    sum2: u64,
    vault2: u64,
}

/// Вычисляет полный digest
fn compute_full_digest(sk_seed: u64, pk: &Secp256k1Affine, token: u64, sum: u64, vault: u64) -> Fr {
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);
    let vault_fr = Fr::from(vault);
    let deposit_sum = token_fr + sum_fr + vault_fr;
    
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes()[22..]);
    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes()[22..]);
    
    let key_sum = (sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                  + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_sum_fr = Fr::from_u128(key_sum);
    
    poseidon_hash([key_sum_fr, deposit_sum])
}

fuzz_target!(|input: MultiKeyInput| {
    // Пропускаем если ключи одинаковые и все inputs одинаковые
    let same_key = input.sk1_seed == input.sk2_seed;
    let same_deposit = (input.token1, input.sum1, input.vault1) == 
                       (input.token2, input.sum2, input.vault2);
    
    if same_key && same_deposit {
        return;
    }
    
    // Пропускаем sk = 0
    if input.sk1_seed == 0 || input.sk2_seed == 0 {
        return;
    }
    
    let g = Secp256k1Affine::generator();
    
    // Keypair 1
    let sk1 = Fq::from(input.sk1_seed);
    let pk1 = Secp256k1Affine::from(g * sk1);
    let digest1 = compute_full_digest(input.sk1_seed, &pk1, input.token1, input.sum1, input.vault1);
    
    // Keypair 2
    let sk2 = Fq::from(input.sk2_seed);
    let pk2 = Secp256k1Affine::from(g * sk2);
    let digest2 = compute_full_digest(input.sk2_seed, &pk2, input.token2, input.sum2, input.vault2);
    
    // Проверяем на коллизию digest
    if digest1 == digest2 {
        // КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: разные inputs дают одинаковый digest!
        panic!(
            "POSEIDON DIGEST COLLISION FOUND!\n\
             Key1: sk_seed={}, pk={:?}\n\
             Deposit1: token={}, sum={}, vault={}\n\
             Key2: sk_seed={}, pk={:?}\n\
             Deposit2: token={}, sum={}, vault={}\n\
             SAME DIGEST: {:?}",
            input.sk1_seed, pk1,
            input.token1, input.sum1, input.vault1,
            input.sk2_seed, pk2,
            input.token2, input.sum2, input.vault2,
            digest1
        );
    }
});

