//! Fuzz target: Unused Public Inputs (P0)
//!
//! Проверяет, что ВСЕ public inputs используются в constraints.
//! 
//! Best Practice: "Unused public inputs" vulnerability - 
//! compiler optimizers can remove unconstrained public inputs,
//! allowing prover to substitute arbitrary values.
//!
//! В DarkDexCircuit public inputs:
//! - [0] private_note_sum - constrained to deposit_identifier_data[1] 
//! - [1] token_type - constrained to deposit_identifier_data[2]
//! - [2] digest - constrained to final_hash output
//!
//! Тест: если заменить public input на неправильное значение,
//! верификация ДОЛЖНА провалиться (значит input используется).

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
use common::{ensure_working_directory, compute_sk_commitment, compute_digest, CIRCUIT_K};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    sk_val: u64,
    token_type: u64,
    private_note_sum: u64,
    // Which public input to corrupt (0-2)
    corrupt_index: u8,
    // Value to use for corruption
    corrupt_delta: u64,
}

fuzz_target!(|input: FuzzInput| {
    ensure_working_directory();
    
    // Skip trivial cases
    if input.corrupt_delta == 0 {
        return;
    }
    
    let sk = Fr::from(input.sk_val);
    let sk_commitment = compute_sk_commitment(sk);
    let token_type_fr = Fr::from(input.token_type);
    let private_note_sum_fr = Fr::from(input.private_note_sum);
    let digest = compute_digest(sk, token_type_fr, private_note_sum_fr);
    
    // Correct circuit
    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(sk),
        Some(sk_commitment),
    );
    
    // Corrupt one public input
    let corrupt_index = (input.corrupt_index % 3) as usize;
    let delta = Fr::from(input.corrupt_delta);
    
    let mut public_inputs = vec![private_note_sum_fr, token_type_fr, digest];
    public_inputs[corrupt_index] = public_inputs[corrupt_index] + delta;
    
    // Run MockProver with corrupted public input
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);
    
    match prover {
        Ok(prover) => {
            let result = prover.verify();
            // MUST fail - if it passes, public input is not constrained!
            assert!(
                result.is_err(),
                "PUBLIC INPUT {} IS NOT CONSTRAINED! Circuit passed with corrupted input. \
                 This is a critical vulnerability (unused public inputs). \
                 corrupt_index={}, delta={:?}",
                corrupt_index, corrupt_index, delta
            );
        }
        Err(_) => {
            // MockProver error is OK (e.g., invalid values)
        }
    }
});

