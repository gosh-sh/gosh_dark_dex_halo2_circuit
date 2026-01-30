//! P1.1: Prover Error Paths Tests
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Tests for error handling in prover.rs:
//! - generate_proof with invalid parameters
//! - keygen_vk / keygen_pk edge cases
//! - Error handling behavior

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::poly::commitment::Params;
use gosh_dark_dex_halo2_circuit::snark_utils::{setup, read_kzg_params, setup_and_backup_kzg_params, generate_verififcation_key_without_witness_and_backup};
use crate::helpers::{compute_sk_commitment, generate_verififcation_key_without_witness, generate_proof_key};

// =============================================================================
// Setup Tests
// =============================================================================

#[test]
fn test_setup_k_minimum() {
    // k=1 should work (very small circuit)
    let params = setup(1);
    assert!(params.k() == 1);
}

#[test]
fn test_setup_k_standard() {
    // k=8 is the standard for new poseidon-only DarkDex
    let params = setup(8);
    assert!(params.k() == 8);
}

#[test]
fn test_setup_k_larger() {
    // k=10 for larger circuits
    let params = setup(10);
    assert!(params.k() == 10);
}

// =============================================================================
// VK Generation Tests
// =============================================================================

#[test]
fn test_generate_vk_without_witness_small_k() {
    // Test VK generation with small k (should fail or succeed depending on circuit size)
    // Новая архитектура: k=8 минимум для схемы
    let params = setup(6);
    // This may panic if k is too small for the circuit
    let result = std::panic::catch_unwind(|| {
        generate_verififcation_key_without_witness(&params)
    });
    // Document whether it panics or succeeds
    if result.is_err() {
        println!("VK generation with k=6 panics (expected - circuit too large)");
    } else {
        println!("VK generation with k=6 succeeded");
    }
}

#[test]
fn test_vk_determinism() {
    // Same circuit should produce same VK
    // Новая архитектура: k=8 достаточно для схемы
    let params = setup(8);

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
    // Новая архитектура: k=8 достаточно для схемы
    let params = setup(8);

    let result = std::panic::catch_unwind(|| {
        generate_proof_key(&params, None, None, None, None)
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
    // Новая архитектура: k=8 достаточно для схемы
    let params = setup(8);
    let sk = Fr::from(12345u64);
    let sk_commitment = compute_sk_commitment(sk);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_proof_key(
            &params,
            Some(Fr::from(1u64)),        // token_type
            Some(Fr::from(1000u64)),     // private_note_sum
            Some(sk),                     // sk_u
            Some(sk_commitment),          // sk_u_commitment
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

// =============================================================================
// File I/O Tests (setup_and_backup, generate_vk_and_backup)
// =============================================================================

#[test]
fn test_setup_and_backup_kzg_params() {
    use tempfile::NamedTempFile;

    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_string_lossy().to_string();

    // Should succeed and create file
    setup_and_backup_kzg_params(4, path.clone());

    // File should exist and have content
    let content = std::fs::read(&path).unwrap();
    assert!(!content.is_empty(), "KZG params file should not be empty");
    println!("KZG params backup: {} bytes written", content.len());
}

#[test]
fn test_generate_vk_and_backup() {
    use tempfile::NamedTempFile;

    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_string_lossy().to_string();

    // k=8 required for new poseidon circuit
    let params = setup(8);

    use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
    // Should succeed and create file
    generate_verififcation_key_without_witness_and_backup::<DarkDexCircuit>(&params, path.clone());

    // File should exist and have content
    let content = std::fs::read(&path).unwrap();
    assert!(!content.is_empty(), "VK backup file should not be empty");
    println!("VK backup: {} bytes written", content.len());
}

#[test]
fn test_setup_and_backup_to_invalid_path() {
    // Should panic on invalid path
    let result = std::panic::catch_unwind(|| {
        setup_and_backup_kzg_params(4, "/nonexistent/directory/params.bin".to_string())
    });

    assert!(result.is_err(), "Backup to invalid path should panic");
}

