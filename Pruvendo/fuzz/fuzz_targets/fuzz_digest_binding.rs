//! Fuzz target: Digest Binding Property (4-input Poseidon)
//!
//! Tests that digest = poseidon(sk_commitment, sum, token, sk) is binding.
//! New architecture uses 4 inputs instead of 2 (key_sum, deposit_sum).
//!
//! Any change to any input must change the digest.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::compute_digest;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

#[derive(Arbitrary, Debug)]
struct DigestBindingInput {
    sk: u64,
    token_type: u64,
    private_note_sum: u64,
    // Which input to modify (0=sk, 1=token, 2=sum)
    modify_which: u8,
    modification: u64,
}

fuzz_target!(|input: DigestBindingInput| {
    // Skip trivial case where modification is 0
    if input.modification == 0 {
        return;
    }

    let sk = Fr::from(input.sk);
    let token = Fr::from(input.token_type);
    let sum = Fr::from(input.private_note_sum);

    let digest_original = compute_digest(sk, token, sum);

    // Modify one input based on modify_which
    let digest_modified = match input.modify_which % 3 {
        0 => {
            // Modify sk
            let modified_sk = Fr::from(input.sk.wrapping_add(input.modification));
            if modified_sk == sk {
                return; // Skip if no actual change
            }
            compute_digest(modified_sk, token, sum)
        }
        1 => {
            // Modify token
            let modified_token = Fr::from(input.token_type.wrapping_add(input.modification));
            if modified_token == token {
                return;
            }
            compute_digest(sk, modified_token, sum)
        }
        _ => {
            // Modify sum
            let modified_sum = Fr::from(input.private_note_sum.wrapping_add(input.modification));
            if modified_sum == sum {
                return;
            }
            compute_digest(sk, token, modified_sum)
        }
    };

    // Binding property: any change must change the digest
    assert_ne!(
        digest_original, digest_modified,
        "Digest must change when input changes"
    );
});

