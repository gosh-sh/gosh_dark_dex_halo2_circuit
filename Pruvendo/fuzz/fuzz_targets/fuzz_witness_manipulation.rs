//! FUZZ-WITNESS: Witness manipulation attacks
//!
//! Пытается создать witness который удовлетворяет constraints,
//! но содержит некорректные данные.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::panic::{catch_unwind, AssertUnwindSafe};

use halo2_base::halo2_proofs::{
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
        group::Curve,
        ff::PrimeField,
    },
    dev::MockProver,
};

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

mod common;
use common::poseidon_hash;

use common::{consume_uint128_11, consume_uint128_10};

#[derive(Arbitrary, Debug)]
struct WitnessInput {
    sk_seed: u64,
    token: u64,
    sum: u64,
    vault: u64,
    /// Манипуляция: 0=нет, 1=подмена sk limbs, 2=фальшивый deposit_sum
    manipulation_type: u8,
    /// Значение для манипуляции
    fake_value: u64,
}

fuzz_target!(|input: WitnessInput| {
    if input.sk_seed == 0 {
        return;
    }
    
    let g = Secp256k1Affine::generator();
    let sk = Fq::from(input.sk_seed);
    let pk = Secp256k1Affine::from(g * sk);
    
    let token_fr = Fr::from(input.token);
    let sum_fr = Fr::from(input.sum);
    let vault_fr = Fr::from(input.vault);
    
    // Вычисляем корректный deposit_sum
    let deposit_sum = token_fr + sum_fr + vault_fr;
    
    // Вычисляем корректный key_sum
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes()[22..]);
    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes()[22..]);
    
    let key_sum = (input.sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                  + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_sum_fr = Fr::from_u128(key_sum);
    
    let digest = poseidon_hash([key_sum_fr, deposit_sum]);
    
    // Применяем манипуляцию
    match input.manipulation_type % 3 {
        0 => {
            // Без манипуляции - должен пройти
            return;
        }
        1 => {
            // Атака: пытаемся подставить другой sk с тем же pk
            // Это невозможно математически, но проверяем что circuit это ловит
            let fake_sk = Fq::from(input.fake_value);
            
            if input.fake_value == input.sk_seed || input.fake_value == 0 {
                return;
            }
            
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(vault_fr),
                Some(fake_sk),  // АТАКА: неверный sk
                Some(pk),       // Но правильный pk
                Some(g),
            );
            
            let public_inputs = vec![sum_fr, token_fr, digest];
            
            let result = catch_unwind(AssertUnwindSafe(|| {
                let prover = MockProver::run(18, &circuit, vec![public_inputs]).unwrap();
                prover.verify()
            }));
            
            if let Ok(Ok(())) = result {
                panic!(
                    "WITNESS MANIPULATION: FAKE SK ACCEPTED!\n\
                     Real sk_seed: {}\n\
                     Fake sk_seed: {}\n\
                     pk: {:?}",
                    input.sk_seed, input.fake_value, pk
                );
            }
        }
        2 => {
            // Атака: другой vault_rand_val с подстроенным digest
            let fake_vault = Fr::from(input.fake_value);
            
            if input.fake_value == input.vault {
                return;
            }
            
            // Создаём circuit с фальшивым vault
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(fake_vault),  // АТАКА: неверный vault
                Some(sk),
                Some(pk),
                Some(g),
            );
            
            // Но используем корректный digest (от оригинального vault)
            let public_inputs = vec![sum_fr, token_fr, digest];
            
            let result = catch_unwind(AssertUnwindSafe(|| {
                let prover = MockProver::run(18, &circuit, vec![public_inputs]).unwrap();
                prover.verify()
            }));
            
            if let Ok(Ok(())) = result {
                panic!(
                    "WITNESS MANIPULATION: FAKE VAULT ACCEPTED!\n\
                     Real vault: {}\n\
                     Fake vault: {}\n\
                     Using original digest: {:?}",
                    input.vault, input.fake_value, digest
                );
            }
        }
        _ => unreachable!(),
    }
});

