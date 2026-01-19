//! P1.3: Fuzz Proof Malleability
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Тестирует атаки на модификацию proof:
//! - Bit flips в байтах witness data
//! - Изменение порядка public inputs
//! - Мутация значений в circuit
//!
//! Использует РЕАЛЬНУЮ верификацию через MockProver.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::dev::MockProver;
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

mod common;
use common::{ensure_working_directory, compute_sk_commitment, compute_digest, CIRCUIT_K};

#[derive(Arbitrary, Debug)]
enum MutationType {
    /// Используем commitment от другого sk
    WrongCommitment { wrong_sk: u64 },
    /// Перестановка public inputs
    SwapPublicInputs { swap_idx: u8 },
    /// Добавляем delta к digest
    MutateDigest { delta: u64 },
    /// Изменяем sk в circuit, но оставляем commitment от оригинального
    WrongSk { wrong_sk: u64 },
    /// Изменяем token в circuit, но используем digest от оригинального
    WrongToken { wrong_token: u64 },
    /// Изменяем sum в circuit, но используем digest от оригинального
    WrongSum { wrong_sum: u64 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    sk_val: u64,
    token: u64,
    sum: u64,
    mutation: MutationType,
}

fuzz_target!(|input: FuzzInput| {
    if input.sk_val == 0 {
        return;
    }

    ensure_working_directory();

    let sk = Fr::from(input.sk_val);
    let token_fr = Fr::from(input.token);
    let sum_fr = Fr::from(input.sum);
    let correct_commitment = compute_sk_commitment(sk);
    let correct_digest = compute_digest(sk, token_fr, sum_fr);

    let (circuit, public_inputs, should_fail) = match &input.mutation {
        MutationType::WrongCommitment { wrong_sk } => {
            if *wrong_sk == input.sk_val || *wrong_sk == 0 {
                return;
            }
            let wrong_commitment = compute_sk_commitment(Fr::from(*wrong_sk));
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(sk),
                Some(wrong_commitment),  // WRONG commitment
            );
            // Digest всё равно вычисляется правильно в circuit, но constraint fails
            (circuit, vec![sum_fr, token_fr, correct_digest], true)
        }

        MutationType::SwapPublicInputs { swap_idx } => {
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(sk),
                Some(correct_commitment),
            );
            // Перестановка public inputs
            let mut pub_inputs = vec![sum_fr, token_fr, correct_digest];
            let idx = (*swap_idx % 3) as usize;
            let other = (idx + 1) % 3;
            if pub_inputs[idx] != pub_inputs[other] {
                pub_inputs.swap(idx, other);
                (circuit, pub_inputs, true)
            } else {
                return; // Skip if swap is no-op
            }
        }

        MutationType::MutateDigest { delta } => {
            if *delta == 0 {
                return;
            }
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(sk),
                Some(correct_commitment),
            );
            let mutated_digest = correct_digest + Fr::from(*delta);
            (circuit, vec![sum_fr, token_fr, mutated_digest], true)
        }

        MutationType::WrongSk { wrong_sk } => {
            if *wrong_sk == input.sk_val || *wrong_sk == 0 {
                return;
            }
            // Wrong sk but commitment from original sk
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(sum_fr),
                Some(Fr::from(*wrong_sk)),  // WRONG sk
                Some(correct_commitment),   // Commitment from original sk
            );
            (circuit, vec![sum_fr, token_fr, correct_digest], true)
        }

        MutationType::WrongToken { wrong_token } => {
            if *wrong_token == input.token {
                return;
            }
            let circuit = DarkDexCircuit::new(
                Some(Fr::from(*wrong_token)),  // WRONG token
                Some(sum_fr),
                Some(sk),
                Some(correct_commitment),
            );
            // Digest was computed with original token
            (circuit, vec![sum_fr, token_fr, correct_digest], true)
        }

        MutationType::WrongSum { wrong_sum } => {
            if *wrong_sum == input.sum {
                return;
            }
            let circuit = DarkDexCircuit::new(
                Some(token_fr),
                Some(Fr::from(*wrong_sum)),  // WRONG sum
                Some(sk),
                Some(correct_commitment),
            );
            // Digest was computed with original sum
            (circuit, vec![sum_fr, token_fr, correct_digest], true)
        }
    };

    // Run MockProver
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);

    match prover {
        Ok(prover) => {
            let verify_result = prover.verify();
            if should_fail {
                assert!(
                    verify_result.is_err(),
                    "MALLEABILITY ATTACK SUCCEEDED!\nMutation: {:?}\nsk={}, token={}, sum={}",
                    input.mutation, input.sk_val, input.token, input.sum
                );
            }
        }
        Err(_) => {
            // Prover failed to run - acceptable for malformed inputs
        }
    }
});

