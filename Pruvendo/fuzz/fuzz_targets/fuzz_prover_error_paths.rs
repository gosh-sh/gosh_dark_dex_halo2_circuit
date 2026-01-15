//! P1.1: Fuzz Prover Error Paths
//!
//! Fuzzes error handling in prover.rs functions:
//! - read_kzg_params with corrupted data
//! - generate_proof_key with edge case inputs

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Corrupted KZG params data
    params_data: Vec<u8>,
    // K value for setup (limited to avoid OOM)
    k_value: u8,
}

fuzz_target!(|input: FuzzInput| {
    // Test 1: Try to read corrupted KZG params
    if input.params_data.len() >= 32 {
        let mut slice: &[u8] = &input.params_data;
        let _ = ParamsKZG::<Bn256>::read_custom(
            &mut slice, 
            SerdeFormat::RawBytesUnchecked
        );
        // Should not panic - just return error or garbage
    }
    
    // Test 2: Try setup with various k values
    // Limit k to avoid OOM (k > 10 uses too much memory for fuzzing)
    let k = (input.k_value % 8) + 1; // k in range [1, 8]
    
    let result = std::panic::catch_unwind(|| {
        gosh_dark_dex_halo2_circuit::prover::setup(k as u32)
    });
    
    // Setup should never panic for valid k values
    if result.is_err() {
        // This would be a bug - setup should not panic
        panic!("setup({}) panicked unexpectedly!", k);
    }
});

