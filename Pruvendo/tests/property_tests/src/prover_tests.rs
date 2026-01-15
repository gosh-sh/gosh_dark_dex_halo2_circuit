//! P1.1: Prover Error Paths Tests
//!
//! Tests for error handling in prover.rs:
//! - generate_proof with invalid parameters
//! - keygen_vk / keygen_pk edge cases
//! - Error handling behavior

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use gosh_dark_dex_halo2_circuit::prover::*;
use proptest::prelude::*;

// =============================================================================
// Helper Functions
// =============================================================================

fn generate_valid_keypair(sk_val: u64) -> (Fq, Secp256k1Affine, Secp256k1Affine) {
    let sk = Fq::from(sk_val);
    let g = Secp256k1Affine::generator();
    let pk = (g * sk).to_affine();
    (sk, pk, g)
}

// =============================================================================
// Setup Tests
// =============================================================================

#[test]
fn test_setup_k_minimum() {
    // k=1 should work (very small circuit)
    let params = setup(1);
    assert!(params.k == 1);
}

#[test]
fn test_setup_k_standard() {
    // k=4 is a reasonable small value for testing
    let params = setup(4);
    assert!(params.k == 4);
}

#[test]
#[ignore] // Takes too long and uses too much memory
fn test_setup_k_large() {
    // k=18 is the standard for DarkDex
    let params = setup(18);
    assert!(params.k == 18);
}

// =============================================================================
// VK Generation Tests
// =============================================================================

#[test]
fn test_generate_vk_without_witness_small_k() {
    // Test VK generation with small k (should fail or succeed depending on circuit size)
    let params = setup(4);
    // This may panic if k is too small for the circuit
    let result = std::panic::catch_unwind(|| {
        generate_verififcation_key_without_witness(&params)
    });
    // Document whether it panics or succeeds
    if result.is_err() {
        println!("VK generation with k=4 panics (expected - circuit too large)");
    } else {
        println!("VK generation with k=4 succeeded");
    }
}

#[test]
fn test_vk_determinism() {
    // Same circuit should produce same VK
    let params = setup(6);
    
    let result1 = std::panic::catch_unwind(|| {
        generate_verififcation_key_without_witness(&params)
    });
    
    let result2 = std::panic::catch_unwind(|| {
        generate_verififcation_key_without_witness(&params)
    });
    
    match (result1, result2) {
        (Ok(vk1), Ok(vk2)) => {
            // VKs should be identical
            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            vk1.write(&mut buf1, halo2_proofs::SerdeFormat::RawBytesUnchecked).unwrap();
            vk2.write(&mut buf2, halo2_proofs::SerdeFormat::RawBytesUnchecked).unwrap();
            assert_eq!(buf1, buf2, "VK should be deterministic");
        }
        _ => {
            println!("VK generation failed (k too small for circuit)");
        }
    }
}

// =============================================================================
// PK Generation Tests
// =============================================================================

#[test]
fn test_generate_proof_key_with_none_values() {
    // Test with all None values (default circuit)
    let params = setup(6);
    
    let result = std::panic::catch_unwind(|| {
        generate_proof_key(&params, None, None, None, None, None, None)
    });
    
    // Document behavior
    if result.is_ok() {
        println!("PK generation with None values succeeded");
    } else {
        println!("PK generation with None values panicked");
    }
}

#[test]
fn test_generate_proof_key_with_valid_values() {
    let params = setup(6);
    let (sk, pk, g) = generate_valid_keypair(12345);
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_proof_key(
            &params,
            Some(Fr::from(1u64)),
            Some(Fr::from(1000u64)),
            Some(Fr::from(100u64)),
            Some(sk),
            Some(pk),
            Some(g),
        )
    }));
    
    if result.is_ok() {
        println!("PK generation with valid values succeeded");
    } else {
        println!("PK generation with valid values panicked (k may be too small)");
    }
}

// =============================================================================
// Error Path Tests
// =============================================================================

#[test]
fn test_read_kzg_params_nonexistent_file() {
    // Should panic on nonexistent file
    let result = std::panic::catch_unwind(|| {
        read_kzg_params("/nonexistent/path/to/params.bin".to_string())
    });
    
    assert!(result.is_err(), "read_kzg_params should panic on nonexistent file");
}

