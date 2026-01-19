//! FUZZ-WITNESS: Witness Manipulation Attacks
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Пытается создать witness который удовлетворяет constraints,
//! но содержит некорректные данные.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::panic::{catch_unwind, AssertUnwindSafe};

use halo2_base::halo2_proofs::{
    halo2curves::bn256::Fr,
    dev::MockProver,
};

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

mod common;
use common::{poseidon_hash, compute_sk_commitment, CIRCUIT_K};

#[derive(Arbitrary, Debug)]
struct WitnessInput {
    sk_seed: u64,
    token: u64,
    sum: u64,
    /// Манипуляция: 0=нет, 1=подмена sk, 2=фальшивый sk_commitment
    manipulation_type: u8,
    /// Значение для манипуляции
    fake_value: u64,
}

fuzz_target!(|input: WitnessInput| {
    if input.sk_seed == 0 {
        return;
    }

    let sk = Fr::from(input.sk_seed);
    let sk_commitment = compute_sk_commitment(sk);

    let token_fr = Fr::from(input.token);
    let sum_fr = Fr::from(input.sum);

    // Вычисляем корректный digest
    let digest = poseidon_hash([sk_commitment, sum_fr, token_fr, sk]);

    // Применяем манипуляцию
    match input.manipulation_type % 3 {
        0 => {
            // Без манипуляции - должен пройти
            return;
        }
        1 => {
            // Атака: пытаемся подставить другой sk
            let fake_sk = Fr::from(input.fake_value);

            if input.fake_value == input.sk_seed || input.fake_value == 0 {
                return;
            }

            // Используем правильный sk_commitment но неверный sk
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(fake_sk),        // АТАКА: неверный sk
                Some(sk_commitment),  // Но правильный sk_commitment
            );

            let public_inputs = vec![sum_fr, token_fr, digest];

            let result = catch_unwind(AssertUnwindSafe(|| {
                let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]).unwrap();
                prover.verify()
            }));

            if let Ok(Ok(())) = result {
                panic!(
                    "WITNESS MANIPULATION: FAKE SK ACCEPTED!\n\
                     Real sk_seed: {}\n\
                     Fake sk_seed: {}",
                    input.sk_seed, input.fake_value
                );
            }
        }
        2 => {
            // Атака: другой sk_commitment
            let fake_commitment = Fr::from(input.fake_value);

            if fake_commitment == sk_commitment {
                return;
            }

            // Создаём circuit с фальшивым sk_commitment
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(sk),
                Some(fake_commitment),  // АТАКА: неверный sk_commitment
            );

            // Но используем корректный digest
            let public_inputs = vec![sum_fr, token_fr, digest];

            let result = catch_unwind(AssertUnwindSafe(|| {
                let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]).unwrap();
                prover.verify()
            }));

            if let Ok(Ok(())) = result {
                panic!(
                    "WITNESS MANIPULATION: FAKE SK_COMMITMENT ACCEPTED!\n\
                     Real sk_commitment: {:?}\n\
                     Fake sk_commitment: {:?}",
                    sk_commitment, fake_commitment
                );
            }
        }
        _ => unreachable!(),
    }
});

