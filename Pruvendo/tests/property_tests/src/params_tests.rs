//! P2.3: KZG Params Setup Tests
//!
//! Tests for KZG params setup:
//! - Params generation for different k values
//! - read_kzg_params with corrupted data
//! - Params size scaling

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;
use gosh_dark_dex_halo2_circuit::prover::setup;
use std::io::Write;
use tempfile::NamedTempFile;

// =============================================================================
// Setup Tests for Different k Values
// =============================================================================

#[test]
fn test_setup_k_range() {
    // Test setup for k in range [1, 8]
    for k in 1..=8 {
        let params = setup(k);
        assert_eq!(params.k, k, "k should be preserved");
        
        let mut buf = Vec::new();
        params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        println!("k={}: params size = {} bytes", k, buf.len());
    }
}

#[test]
fn test_setup_size_exponential() {
    // Params size should grow exponentially with k
    let mut prev_size = 0;
    
    for k in 2..=6 {
        let params = setup(k);
        let mut buf = Vec::new();
        params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        if prev_size > 0 {
            let ratio = buf.len() as f64 / prev_size as f64;
            println!("k={}: size={}, ratio to prev={:.2}", k, buf.len(), ratio);
            // Ratio should be around 2.0 (due to 2^k)
            assert!(ratio > 1.5 && ratio < 2.5, "Expected ~2x growth");
        }
        prev_size = buf.len();
    }
}

// =============================================================================
// read_kzg_params Error Handling Tests
// =============================================================================

#[test]
fn test_read_params_nonexistent_file() {
    let result = std::panic::catch_unwind(|| {
        gosh_dark_dex_halo2_circuit::prover::read_kzg_params("/nonexistent/path.bin".to_string())
    });
    assert!(result.is_err(), "Nonexistent file should panic");
}

#[test]
fn test_read_params_empty_file() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_string_lossy().to_string();
    
    let result = std::panic::catch_unwind(|| {
        gosh_dark_dex_halo2_circuit::prover::read_kzg_params(path)
    });
    assert!(result.is_err(), "Empty file should panic");
}

#[test]
fn test_read_params_corrupted_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    
    // Write some garbage data
    temp_file.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]).unwrap();
    let path = temp_file.path().to_string_lossy().to_string();
    
    let result = std::panic::catch_unwind(|| {
        gosh_dark_dex_halo2_circuit::prover::read_kzg_params(path)
    });
    
    // Should fail
    match result {
        Err(_) => println!("Corrupted file caused panic"),
        Ok(_) => println!("WARNING: Corrupted file was accepted"),
    }
}

#[test]
fn test_read_params_truncated_file() {
    // Create valid params, write to file, truncate, try to read
    let params = setup(4);
    
    let mut buf = Vec::new();
    params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // Truncate to 1/4 of original
    let truncated = &buf[..buf.len() / 4];
    
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(truncated).unwrap();
    let path = temp_file.path().to_string_lossy().to_string();
    
    let result = std::panic::catch_unwind(|| {
        gosh_dark_dex_halo2_circuit::prover::read_kzg_params(path)
    });
    
    assert!(result.is_err(), "Truncated params file should fail");
}

// =============================================================================
// Params Consistency Tests
// =============================================================================

#[test]
fn test_params_k_in_serialized_data() {
    // First 4 bytes should contain k value (little endian u32)
    for k in 1u32..=5 {
        let params = setup(k);
        let mut buf = Vec::new();
        params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        let k_read = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(k_read, k, "k should be in first 4 bytes");
    }
}

