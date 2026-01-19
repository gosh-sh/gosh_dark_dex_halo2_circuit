//! Fuzz target: Zero Padding Security
//!
//! Tests that poseidon(sk, 0) is secure against:
//! - Length extension attacks
//! - Related-key attacks with zero padding
//!
//! New architecture uses fixed padding: sk_commitment = poseidon([sk, 0])

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::{compute_sk_commitment, poseidon_hash};

use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, ff::Field};

#[derive(Arbitrary, Debug)]
struct ZeroPaddingInput {
    sk: u64,
    // Try different "padding" values instead of 0
    alt_padding: u64,
}

fuzz_target!(|input: ZeroPaddingInput| {
    let sk = Fr::from(input.sk);

    // Standard commitment with zero padding
    let commitment_zero = compute_sk_commitment(sk);

    // Alternative with non-zero padding (should be different)
    if input.alt_padding != 0 {
        let alt_pad = Fr::from(input.alt_padding);
        let commitment_alt = poseidon_hash([sk, alt_pad]);

        // Different padding must produce different hash
        assert_ne!(
            commitment_zero, commitment_alt,
            "Zero padding collision with alt_padding={}",
            input.alt_padding
        );
    }

    // Test: poseidon(sk, 0) != poseidon(0, sk) (non-commutativity)
    if sk != Fr::zero() {
        let swapped = poseidon_hash([Fr::zero(), sk]);
        assert_ne!(
            commitment_zero, swapped,
            "Poseidon must not be commutative!"
        );
    }

    // Test: poseidon(sk, 0) != poseidon(sk + 0, 0) = poseidon(sk, 0)
    // This is trivially true, but test identity preservation
    let commitment_again = poseidon_hash([sk + Fr::zero(), Fr::zero()]);
    assert_eq!(commitment_zero, commitment_again, "Identity must be preserved");

    // Test: poseidon([sk, 0]) vs poseidon([sk]) behavior
    // The 2-input and 4-input hashes should be domain separated
    let sk_commitment = compute_sk_commitment(sk);
    let four_input = poseidon_hash([sk, Fr::zero(), Fr::zero(), Fr::zero()]);
    
    // These should be different due to different input lengths
    // (Poseidon with ConstantLength should handle this)
    assert_ne!(
        sk_commitment, four_input,
        "2-input and 4-input Poseidon should be different"
    );
});

