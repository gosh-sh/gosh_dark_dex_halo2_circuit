//! Fuzz target: Witness Unconstrained (P0)
//!
//! Проверяет, что все witness values правильно ограничены.
//!
//! Best Practice: "Assigned but not constrained" vulnerability -
//! witness value is assigned but not used in any constraint,
//! allowing prover to use arbitrary values.
//!
//! В DarkDexCircuit witness values:
//! - sk: used in sk_commitment = poseidon([sk, 0]) and final digest
//! - sk_commitment: constrained to equal poseidon([sk, 0])
//! - token_type: constrained to public input
//! - private_note_sum: constrained to public input
//!
//! Тесты:
//! 1. Wrong sk with correct commitment - should fail (sk used in digest)
//! 2. Mismatched sk/commitment - should fail (copy constraint)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::ff::Field,
};
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

mod common;
use common::{ensure_working_directory, compute_sk_commitment, CIRCUIT_K, poseidon_hash};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    real_sk_val: u64,
    fake_sk_val: u64,
    token_type: u64,
    private_note_sum: u64,
    test_variant: u8,
}

fuzz_target!(|input: FuzzInput| {
    ensure_working_directory();
    
    // Skip if sk values are same
    if input.real_sk_val == input.fake_sk_val {
        return;
    }
    
    let real_sk = Fr::from(input.real_sk_val);
    let fake_sk = Fr::from(input.fake_sk_val);
    let token_type_fr = Fr::from(input.token_type);
    let private_note_sum_fr = Fr::from(input.private_note_sum);
    
    let real_commitment = compute_sk_commitment(real_sk);
    let fake_commitment = compute_sk_commitment(fake_sk);
    
    match input.test_variant % 3 {
        0 => {
            // Test 1: Use real sk but fake sk's commitment
            // If sk is not constrained, circuit would accept fake commitment
            let digest_with_fake = poseidon_hash([fake_commitment, private_note_sum_fr, token_type_fr, real_sk]);
            
            let circuit = DarkDexCircuit::new(
                Some(token_type_fr),
                Some(private_note_sum_fr),
                Some(real_sk),           // Real sk
                Some(fake_commitment),   // But fake commitment
            );
            
            let public_inputs = vec![private_note_sum_fr, token_type_fr, digest_with_fake];
            
            let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);
            
            if let Ok(prover) = prover {
                let result = prover.verify();
                assert!(
                    result.is_err(),
                    "WITNESS UNCONSTRAINED: sk_commitment is not bound to sk! \
                     Circuit accepted mismatched sk/commitment. \
                     real_sk={:?}, fake_commitment={:?}",
                    real_sk, fake_commitment
                );
            }
        }
        1 => {
            // Test 2: Use fake sk but real commitment
            // If sk used in digest is constrained, this should fail
            let digest_with_real = poseidon_hash([real_commitment, private_note_sum_fr, token_type_fr, fake_sk]);
            
            let circuit = DarkDexCircuit::new(
                Some(token_type_fr),
                Some(private_note_sum_fr),
                Some(fake_sk),           // Fake sk
                Some(real_commitment),   // But real commitment (computed from real_sk)
            );
            
            let public_inputs = vec![private_note_sum_fr, token_type_fr, digest_with_real];
            
            let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);
            
            if let Ok(prover) = prover {
                let result = prover.verify();
                assert!(
                    result.is_err(),
                    "WITNESS UNCONSTRAINED: sk is not properly constrained! \
                     Circuit accepted commitment from different sk. \
                     fake_sk={:?}, real_commitment={:?}",
                    fake_sk, real_commitment
                );
            }
        }
        2 => {
            // Test 3: Try to create valid proof with wrong sk value
            // Use all values from fake_sk, but put real_sk in circuit
            let correct_digest = poseidon_hash([real_commitment, private_note_sum_fr, token_type_fr, real_sk]);
            
            // Create circuit with all correct values (should work)
            let circuit = DarkDexCircuit::new(
                Some(token_type_fr),
                Some(private_note_sum_fr),
                Some(real_sk),
                Some(real_commitment),
            );
            
            let public_inputs = vec![private_note_sum_fr, token_type_fr, correct_digest];
            
            let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);
            
            if let Ok(prover) = prover {
                let result = prover.verify();
                // This one SHOULD pass (completeness check)
                assert!(
                    result.is_ok(),
                    "COMPLETENESS FAILURE: Valid circuit should pass! \
                     real_sk={:?}, commitment={:?}",
                    real_sk, real_commitment
                );
            }
        }
        _ => unreachable!(),
    }
});

