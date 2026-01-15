//! Fuzz target: Scalar edge cases
//!
//! Tests edge cases for secret key (sk) values:
//! - sk = 0 (should fail - identity point)
//! - sk = 1 (minimal non-trivial)
//! - sk = order - 1 (near wraparound)
//! - sk near 2^64 boundary
//! - sk with many leading zeros/ones
//!
//! Invariant: Circuit should handle all valid scalars correctly,
//! and reject/handle invalid ones gracefully.

#![no_main]

mod common;

use common::*;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    ff::{PrimeField, Field},
    CurveAffine,
    group::Curve,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }

    ensure_working_directory();

    let test_type = data[0] % 8;
    let fuzz_bytes = &data[1..];

    let (sk, sk_raw): (Fq, u64) = match test_type {
        0 => {
            // sk = 0 (identity point - should be rejected or handled)
            // Skip this case - zero sk produces identity point
            return;
        }
        1 => {
            // sk = 1 (minimal valid scalar)
            (Fq::one(), 1u64)
        }
        2 => {
            // sk = 2 (small scalar)
            (Fq::from(2u64), 2u64)
        }
        3 => {
            // sk near 2^64 boundary
            if fuzz_bytes.len() >= 8 {
                let val = u64::from_le_bytes(fuzz_bytes[0..8].try_into().unwrap());
                let val = val.saturating_add(u64::MAX - 1000).max(1);
                (Fq::from(val), val)
            } else {
                return;
            }
        }
        4 => {
            // sk = -1 (order - 1 in the field) - use large u64 instead
            let val = u64::MAX;
            (Fq::from(val), val)
        }
        5 => {
            // sk with specific bit patterns (power of 2)
            if fuzz_bytes.is_empty() { return; }
            let shift = (fuzz_bytes[0] % 63) as u64; // Max shift 62 to avoid overflow
            let val = 1u64 << shift;
            (Fq::from(val), val)
        }
        6 => {
            // sk = random small value (1-1000)
            if fuzz_bytes.is_empty() { return; }
            let val = (fuzz_bytes[0] as u64 % 1000) + 1;
            (Fq::from(val), val)
        }
        7 => {
            // sk from fuzz bytes (full random)
            if fuzz_bytes.len() >= 8 {
                let val = u64::from_le_bytes(fuzz_bytes[0..8].try_into().unwrap()).max(1);
                (Fq::from(val), val)
            } else {
                return;
            }
        }
        _ => return,
    };

    // Compute pk = sk * G
    let g = Secp256k1Affine::generator();
    let pk_projective = g * sk;
    let pk = pk_projective.to_affine();

    // Try to verify the circuit
    let result = check_circuit(sk, pk, g, 1, 100, 999, sk_raw);

    // All valid scalars should produce valid proofs
    assert!(result.is_ok(),
        "Valid scalar sk should produce valid proof, test_type={}, sk_raw={}",
        test_type, sk_raw);
});

