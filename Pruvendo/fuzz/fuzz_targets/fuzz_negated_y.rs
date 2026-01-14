//! FUZZ-NEGY: Negated Y coordinate attack
//!
//! Для каждой точки P=(x,y) на secp256k1, существует -P=(x,-y).
//! Проверяем что circuit корректно отклоняет -P когда ожидается P.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::panic::{catch_unwind, AssertUnwindSafe};

use halo2_base::halo2_proofs::{
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
        group::{Curve, prime::PrimeCurveAffine},
        ff::PrimeField,
    },
    dev::MockProver,
};

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

mod common;
use common::poseidon_hash;

use common::{consume_uint128_11, consume_uint128_10};

#[derive(Arbitrary, Debug)]
struct NegYInput {
    sk_seed: u64,
    token: u64,
    sum: u64,
    vault: u64,
}

fuzz_target!(|input: NegYInput| {
    // Пропускаем sk = 0 (identity point)
    if input.sk_seed == 0 {
        return;
    }
    
    let g = Secp256k1Affine::generator();
    let sk = Fq::from(input.sk_seed);
    let pk = Secp256k1Affine::from(g * sk);
    
    // Пропускаем если pk is identity
    if pk.is_identity().into() {
        return;
    }
    
    // Создаём -P (та же x, отрицательная y)
    let neg_pk = -pk;
    
    // Убеждаемся что neg_pk != pk
    if pk == neg_pk {
        return; // Редкий случай точки порядка 2
    }
    
    let token_fr = Fr::from(input.token);
    let sum_fr = Fr::from(input.sum);
    let vault_fr = Fr::from(input.vault);
    
    // Вычисляем deposit_sum
    let deposit_sum = token_fr + sum_fr + vault_fr;
    
    // Вычисляем digest с КОРРЕКТНЫМ pk
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes()[22..]);
    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes()[22..]);
    
    let key_sum = (input.sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                  + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_sum_fr = Fr::from_u128(key_sum);
    let correct_digest = poseidon_hash([key_sum_fr, deposit_sum]);
    
    // Теперь создаём circuit с neg_pk но digest от корректного pk
    // Это атака: злоумышленник пытается использовать -P вместо P
    let attack_circuit = DarkDexCircuit::new(
        Some(token_fr),
        Some(sum_fr),
        Some(vault_fr),
        Some(sk),
        Some(neg_pk),  // АТАКА: используем -P
        Some(g),
    );
    
    // Public inputs с digest от корректного pk
    let public_inputs = vec![sum_fr, token_fr, correct_digest];
    
    let result = catch_unwind(AssertUnwindSafe(|| {
        let prover = MockProver::run(18, &attack_circuit, vec![public_inputs]).unwrap();
        prover.verify()
    }));
    
    match result {
        Ok(Ok(())) => {
            // КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: -P принят вместо P!
            panic!(
                "NEGATED Y ATTACK SUCCEEDED!\n\
                 sk_seed: {}\n\
                 pk: {:?}\n\
                 neg_pk (-P): {:?}\n\
                 Circuit accepted -P with digest computed for P!",
                input.sk_seed, pk, neg_pk
            );
        }
        Ok(Err(_)) => {
            // Ожидаемо: circuit отклонил атаку
        }
        Err(_) => {
            // Panic - возможно BUG
        }
    }
});

