//! Fuzz target: Double Spend Attack Simulation
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Tests if the same sk can be used to create proofs for different
//! transactions (different token/sum values) that might allow double spending.
//!
//! Invariant: Each proof should be uniquely bound to its public inputs.
//! Reusing a proof with different public inputs should fail verification.

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    ensure_working_directory();

    // Generate sk
    let sk_val = u64::from_le_bytes(data[0..8].try_into().unwrap()).max(1);
    let sk = Fr::from(sk_val);

    // Transaction 1 parameters
    let token1 = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 1000 + 1;
    let sum1 = u64::from_le_bytes(data[16..24].try_into().unwrap()) % 1000000 + 1;

    // Transaction 2 parameters (different amounts)
    let token2 = token1 + 1;
    let sum2 = sum1 + 1000;

    // Compute digests for both transactions
    let digest1 = compute_digest(sk, Fr::from(token1), Fr::from(sum1));
    let digest2 = compute_digest(sk, Fr::from(token2), Fr::from(sum2));

    // Test 1: Verify that transaction 1 works
    let result1 = check_circuit(sk_val, token1, sum1);
    assert!(result1.is_ok(), "Valid transaction 1 should pass");

    // Test 2: Verify that transaction 2 also works (with different digest)
    let result2 = check_circuit(sk_val, token2, sum2);
    assert!(result2.is_ok(), "Valid transaction 2 should pass");

    // Key security property: digests must be different!
    assert_ne!(digest1, digest2,
        "Different transactions must have different digests! \
         token1={}, sum1={}, token2={}, sum2={}",
        token1, sum1, token2, sum2);

    // Test 3: Try to use tx1's digest with tx2's values (cross-transaction attack)
    let attack_result = check_circuit_with_custom_digest(
        sk,
        token2, sum2,  // tx2 values
        digest1,       // tx1 digest
    );

    // This MUST fail - otherwise double spend is possible
    assert!(attack_result.is_err(),
        "Cross-transaction attack must fail! Using tx1 digest with tx2 values should be rejected");
});

