//! Fuzz target: Double spend attack simulation
//!
//! Tests if the same keypair can be used to create proofs for different
//! transactions (different token/sum values) that might allow double spending.
//!
//! Invariant: Each proof should be uniquely bound to its public inputs.
//! Reusing a proof with different public inputs should fail verification.

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    ff::PrimeField,
    CurveAffine,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    ensure_working_directory();

    // Generate a valid keypair
    let sk_val = u64::from_le_bytes(data[0..8].try_into().unwrap()).max(1);
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    // Transaction 1 parameters
    let token1 = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 1000 + 1;
    let sum1 = u64::from_le_bytes(data[16..24].try_into().unwrap()) % 1000000 + 1;
    let vault1 = u64::from_le_bytes(data[24..32].try_into().unwrap());

    // Transaction 2 parameters (different amounts)
    let token2 = token1 + 1; // Different token
    let sum2 = sum1 + 1000; // Different sum (trying to spend more)

    // Compute digests for both transactions
    let digest1 = compute_digest(sk_val, &pk, Fr::from(token1), Fr::from(sum1), Fr::from(vault1));
    let digest2 = compute_digest(sk_val, &pk, Fr::from(token2), Fr::from(sum2), Fr::from(vault1));

    // Test 1: Verify that transaction 1 works
    let result1 = check_circuit(sk, pk, g, token1, sum1, vault1, sk_val);
    assert!(result1.is_ok(), "Valid transaction 1 should pass");

    // Test 2: Verify that transaction 2 also works (with different digest)
    let result2 = check_circuit(sk, pk, g, token2, sum2, vault1, sk_val);
    assert!(result2.is_ok(), "Valid transaction 2 should pass");

    // Key security property: digests must be different!
    // If they're the same, it might indicate a collision vulnerability
    assert_ne!(digest1, digest2,
        "Different transactions must have different digests! \
         token1={}, sum1={}, token2={}, sum2={}",
        token1, sum1, token2, sum2);

    // Test 3: Try to use tx1's digest with tx2's values (cross-transaction attack)
    // This simulates: prover claims tx2 values but uses tx1's digest
    let attack_result = check_circuit_with_custom_digest(
        sk, pk, g,
        token2, sum2, vault1, sk_val,  // tx2 values
        token1, sum1, vault1,           // tx1 values for digest
    );

    // This MUST fail - otherwise double spend is possible
    assert!(attack_result.is_err(),
        "Cross-transaction attack must fail! Using tx1 digest with tx2 values should be rejected");
});

