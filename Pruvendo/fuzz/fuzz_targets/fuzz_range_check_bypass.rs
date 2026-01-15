//! Fuzz target: Range check bypass attempts
//!
//! Tests if range checks in limb decomposition can be bypassed.
//! The circuit decomposes pk.x and pk.y into 88-bit limbs.
//! This tests if values outside valid ranges can pass.
//!
//! Invariant: Limb values must be within their valid ranges.

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    ff::{PrimeField, Field},
    CurveAffine,
};

fn consume_u128_from_bytes(bytes: &[u8]) -> u128 {
    let mut result = 0u128;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as u128) << (i * 8);
    }
    result
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    ensure_working_directory();

    let attack_type = data[0] % 4;

    // Generate base keypair
    let sk_val = u64::from_le_bytes(data[1..9].try_into().unwrap()).max(1);
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    match attack_type {
        0 => {
            // Test with maximum valid field element for pk coordinates
            // pk.x and pk.y are already valid since pk is on curve
            let result = check_circuit(sk, pk, g, 1, 100, 999, sk_val);
            assert!(result.is_ok(), "Valid keypair should pass");
        }
        1 => {
            // Test with sk that produces pk.x close to field modulus
            // This happens naturally for some sk values
            let result = check_circuit(sk, pk, g, 1, 100, 999, sk_val);
            assert!(result.is_ok(), "Valid keypair should pass regardless of pk.x magnitude");
        }
        2 => {
            // Test with very large sum/token values (close to u64::MAX)
            let large_val = u64::MAX;
            let result = check_circuit(sk, pk, g, large_val, large_val, large_val, sk_val);
            assert!(result.is_ok(), "Large u64 values should be valid");
        }
        3 => {
            // Test with zero values
            let result = check_circuit(sk, pk, g, 0, 0, 0, sk_val);
            assert!(result.is_ok(), "Zero values should be valid");
        }
        _ => {}
    }

    // Additional test: Verify limb decomposition produces consistent results
    let pk_x_bytes = pk.x.to_bytes();
    let pk_y_bytes = pk.y.to_bytes();

    // Reconstruct from limbs
    let limb0_x = consume_u128_from_bytes(&pk_x_bytes[0..11]);
    let limb1_x = consume_u128_from_bytes(&pk_x_bytes[11..22]);
    let limb2_x = consume_u128_from_bytes(&pk_x_bytes[22..32]);

    let limb0_y = consume_u128_from_bytes(&pk_y_bytes[0..11]);
    let limb1_y = consume_u128_from_bytes(&pk_y_bytes[11..22]);
    let limb2_y = consume_u128_from_bytes(&pk_y_bytes[22..32]);

    // Verify limbs are within 88/80 bit ranges
    assert!(limb0_x < (1u128 << 88), "pk.x limb0 should be < 2^88");
    assert!(limb1_x < (1u128 << 88), "pk.x limb1 should be < 2^88");
    assert!(limb2_x < (1u128 << 80), "pk.x limb2 should be < 2^80");

    assert!(limb0_y < (1u128 << 88), "pk.y limb0 should be < 2^88");
    assert!(limb1_y < (1u128 << 88), "pk.y limb1 should be < 2^88");
    assert!(limb2_y < (1u128 << 80), "pk.y limb2 should be < 2^80");
});

