//! Fuzz target: Copy Constraint Violation (P0)
//!
//! Проверяет, что copy constraints между cells работают.
//!
//! Best Practice: "Missing copy constraints" - Halo2-specific vulnerability
//! where values should be equal but equality is not enforced.
//!
//! В DarkDexCircuit критичный copy constraint:
//! - sk_commitment (circuit input) === poseidon([sk, 0]) (computed)
//! 
//! Если constraint отсутствует, prover может использовать
//! любой sk_commitment, не связанный с sk.
//!
//! Тест: подставляем sk_commitment != poseidon([sk, 0]),
//! верификация ДОЛЖНА провалиться.

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
    sk_val: u64,
    token_type: u64,
    private_note_sum: u64,
    // Wrong commitment variants
    commitment_variant: u8,
    random_commitment: u64,
}

fuzz_target!(|input: FuzzInput| {
    ensure_working_directory();
    
    let sk = Fr::from(input.sk_val);
    let correct_commitment = compute_sk_commitment(sk);
    let token_type_fr = Fr::from(input.token_type);
    let private_note_sum_fr = Fr::from(input.private_note_sum);
    
    // Generate wrong commitment based on variant
    let wrong_commitment = match input.commitment_variant % 5 {
        0 => Fr::from(input.random_commitment),               // Random value
        1 => correct_commitment + Fr::one(),                  // Off by one
        2 => poseidon_hash([sk, Fr::one()]),                  // Wrong padding (1 instead of 0)
        3 => poseidon_hash([Fr::from(input.random_commitment), Fr::zero()]),  // Wrong sk
        4 => sk,                                              // sk itself (not hash)
        _ => unreachable!(),
    };
    
    // Skip if accidentally got correct commitment
    if wrong_commitment == correct_commitment {
        return;
    }
    
    // Compute digest with WRONG commitment (as if constraint was missing)
    // Note: the circuit computes digest internally with its assigned values
    // so we use the digest that WOULD be correct if commitment was correct
    let correct_digest = poseidon_hash([correct_commitment, private_note_sum_fr, token_type_fr, sk]);
    
    // Circuit with wrong commitment
    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(sk),
        Some(wrong_commitment),  // Wrong commitment!
    );
    
    // Public inputs with correct digest (based on correct commitment)
    let public_inputs = vec![private_note_sum_fr, token_type_fr, correct_digest];
    
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);
    
    match prover {
        Ok(prover) => {
            let result = prover.verify();
            // MUST fail - if it passes, copy constraint is missing!
            assert!(
                result.is_err(),
                "COPY CONSTRAINT MISSING! Circuit passed with wrong sk_commitment. \
                 sk_commitment should be constrained to equal poseidon([sk, 0]). \
                 wrong_commitment variant={}, sk={:?}, correct_commitment={:?}, wrong_commitment={:?}",
                input.commitment_variant % 5, sk, correct_commitment, wrong_commitment
            );
        }
        Err(_) => {
            // MockProver error is OK
        }
    }
});

