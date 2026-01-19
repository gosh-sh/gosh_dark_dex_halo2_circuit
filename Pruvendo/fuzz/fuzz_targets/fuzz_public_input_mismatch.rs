//! Fuzz target: Public Input Mismatch Attacks
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет: можно ли создать proof с одними public inputs,
//! а верифицировать с другими?
//!
//! Атаки:
//! - Изменить token_type в public inputs после proof generation
//! - Изменить private_note_sum в public inputs
//! - Изменить digest (подставить чужой)
//!
//! Ожидание: scheme должна ОТКЛОНИТЬ все несоответствия

#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Input for public input mismatch fuzzing
#[derive(Debug)]
struct PublicInputMismatchInput {
    sk: u64,
    token: u64,
    sum: u64,
    alt_token: u64,
    alt_sum: u64,
    attack_type: u8,
}

impl<'a> Arbitrary<'a> for PublicInputMismatchInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        let token = u.int_in_range(0..=1000000u64)?;
        let sum = u.int_in_range(0..=1000000000u64)?;
        let alt_token = u.int_in_range(0..=1000000u64)?;
        let alt_sum = u.int_in_range(0..=1000000000u64)?;
        Ok(PublicInputMismatchInput {
            sk: u.int_in_range(1..=u64::MAX)?,
            token,
            sum,
            alt_token,
            alt_sum,
            attack_type: u.int_in_range(0..=3)?,
        })
    }
}

fuzz_target!(|input: PublicInputMismatchInput| {
    ensure_working_directory();

    let sk = Fr::from(input.sk);

    match input.attack_type {
        0 => {
            // Attack 0: Использовать circuit с token=T1 но digest вычислен для token=T2
            if input.token == input.alt_token {
                return;
            }

            // Вычисляем digest для alt_token, но circuit использует token
            let wrong_digest = compute_digest(sk, Fr::from(input.alt_token), Fr::from(input.sum));
            let result = check_circuit_with_custom_digest(
                sk,
                input.token,  // circuit использует token
                input.sum,
                wrong_digest, // но digest вычислен для alt_token
            );

            assert!(
                result.is_err(),
                "ATTACK SUCCEEDED: Different token in circuit vs digest! token={} vs {}",
                input.token,
                input.alt_token
            );
        },
        1 => {
            // Attack 1: Использовать circuit с sum=S1 но digest вычислен для sum=S2
            if input.sum == input.alt_sum {
                return;
            }

            let wrong_digest = compute_digest(sk, Fr::from(input.token), Fr::from(input.alt_sum));
            let result = check_circuit_with_custom_digest(
                sk,
                input.token,
                input.sum,    // circuit использует sum
                wrong_digest, // но digest вычислен для alt_sum
            );

            assert!(
                result.is_err(),
                "ATTACK SUCCEEDED: Different sum in circuit vs digest! sum={} vs {}",
                input.sum,
                input.alt_sum
            );
        },
        2 => {
            // Attack 2: Использовать чужой sk для digest
            let other_sk = Fr::from(input.sk.wrapping_add(1));
            let wrong_digest = compute_digest(other_sk, Fr::from(input.token), Fr::from(input.sum));
            let result = check_circuit_with_custom_digest(
                sk,           // circuit использует sk
                input.token,
                input.sum,
                wrong_digest, // но digest вычислен для other_sk
            );

            assert!(
                result.is_err(),
                "ATTACK SUCCEEDED: Different sk in circuit vs digest!"
            );
        },
        _ => {
            // Default: просто проверяем что валидные данные работают
            let _result = check_circuit(input.sk, input.token, input.sum);
        },
    }
});

