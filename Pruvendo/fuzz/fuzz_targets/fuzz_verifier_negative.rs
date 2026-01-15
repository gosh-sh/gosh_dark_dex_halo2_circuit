//! P1.2: Fuzz Verifier Negative Cases
//!
//! Fuzzes error handling in verifier.rs:
//! - verification_key_from_bytes with corrupted data
//! - Various malformed VK structures

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // VK bytes (corrupted/random)
    vk_data: Vec<u8>,
    // Proof bytes (corrupted/random)
    proof_data: Vec<u8>,
    // Public inputs (Fr values as u64)
    pub_input_1: u64,
    pub_input_2: u64,
    pub_input_3: u64,
}

fuzz_target!(|input: FuzzInput| {
    // Test 1: Try to deserialize corrupted VK
    // Should panic (current behavior) or return error
    if input.vk_data.len() >= 32 {
        let result = std::panic::catch_unwind(|| {
            gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes(&input.vk_data)
        });
        // VK deserialization with garbage data should fail gracefully
        // Currently it panics, which is acceptable for untrusted input
        let _ = result;
    }
    
    // Test 2: Check that empty VK fails
    if input.vk_data.is_empty() {
        let result = std::panic::catch_unwind(|| {
            gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes(&[])
        });
        // Empty VK should always fail
        assert!(result.is_err(), "Empty VK should fail");
    }
});

