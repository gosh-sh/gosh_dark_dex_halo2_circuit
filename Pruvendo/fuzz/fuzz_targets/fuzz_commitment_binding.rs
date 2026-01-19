//! Fuzz target: Commitment Binding Property
//!
//! Tests that sk_commitment = poseidon(sk, 0) is binding:
//! - Different sk values must produce different commitments
//! - Same sk must always produce same commitment
//!
//! New architecture: poseidon_instead_of_ecc

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::{compute_sk_commitment, poseidon_hash};

use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, ff::Field};

#[derive(Arbitrary, Debug)]
struct CommitmentBindingInput {
    sk1_bytes: [u8; 8],
    sk2_bytes: [u8; 8],
}

fuzz_target!(|input: CommitmentBindingInput| {
    let sk1 = Fr::from(u64::from_le_bytes(input.sk1_bytes));
    let sk2 = Fr::from(u64::from_le_bytes(input.sk2_bytes));

    let commitment1 = compute_sk_commitment(sk1);
    let commitment2 = compute_sk_commitment(sk2);

    // Property 1: Determinism - same sk gives same commitment
    let commitment1_again = compute_sk_commitment(sk1);
    assert_eq!(commitment1, commitment1_again, "Commitment must be deterministic");

    // Property 2: Binding - different sk gives different commitment
    if sk1 != sk2 {
        assert_ne!(
            commitment1, commitment2,
            "Different sk must produce different commitments: sk1={:?}, sk2={:?}",
            sk1, sk2
        );
    }

    // Property 3: sk_commitment = poseidon([sk, 0])
    let expected = poseidon_hash([sk1, Fr::zero()]);
    assert_eq!(commitment1, expected, "Commitment formula mismatch");
});

