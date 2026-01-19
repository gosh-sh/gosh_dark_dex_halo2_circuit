//! Fuzz target: SK Hiding Property
//!
//! Tests that sk cannot be recovered from sk_commitment or digest.
//! This is a computational test - we verify that:
//! 1. No simple algebraic relation exists
//! 2. Commitment doesn't leak bits of sk
//!
//! New architecture: sk_commitment = poseidon(sk, 0)

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::{compute_sk_commitment, compute_digest};

use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, ff::Field};

#[derive(Arbitrary, Debug)]
struct SkHidingInput {
    sk: u64,
    token_type: u64,
    private_note_sum: u64,
    // Candidate sk values to test
    candidate_sk: u64,
}

fuzz_target!(|input: SkHidingInput| {
    let sk = Fr::from(input.sk);
    let token = Fr::from(input.token_type);
    let sum = Fr::from(input.private_note_sum);

    let sk_commitment = compute_sk_commitment(sk);
    let digest = compute_digest(sk, token, sum);

    // Test: candidate_sk should only match if it equals sk
    let candidate = Fr::from(input.candidate_sk);
    let candidate_commitment = compute_sk_commitment(candidate);

    if candidate != sk {
        // Different sk must give different commitment (hiding property)
        assert_ne!(
            sk_commitment, candidate_commitment,
            "Commitment collision found! sk={:?}, candidate={:?}",
            input.sk, input.candidate_sk
        );

        // Even with correct token/sum, wrong sk must give wrong digest
        let candidate_digest = compute_digest(candidate, token, sum);
        assert_ne!(
            digest, candidate_digest,
            "Digest collision found with wrong sk!"
        );
    }

    // Test: commitment should not be related to sk by simple operations
    // (This catches implementation errors like commitment = sk + constant)
    assert_ne!(sk_commitment, sk, "Commitment equals sk - trivial!");
    assert_ne!(sk_commitment, -sk, "Commitment equals -sk - trivial relation!");

    // sk_commitment should not be a small multiple of sk (unless sk=0)
    if sk != Fr::zero() {
        let double_sk = sk + sk;
        assert_ne!(sk_commitment, double_sk, "Commitment equals 2*sk!");
    }
});

