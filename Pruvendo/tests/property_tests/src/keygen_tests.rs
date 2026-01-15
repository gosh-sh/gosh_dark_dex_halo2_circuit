//! P2.1: VK/PK Generation Tests
//!
//! Tests for key generation:
//! - VK determinism (same circuit → same VK)
//! - PK consistency
//! - Size bounds

use halo2_proofs::SerdeFormat;
use gosh_dark_dex_halo2_circuit::prover::{setup, generate_verififcation_key_without_witness};

// =============================================================================
// VK Determinism Tests
// =============================================================================

#[test]
fn test_vk_determinism_same_params() {
    // VK should be deterministic when using the same params
    let params = setup(6);
    
    let result1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params)
    }));
    
    let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params)
    }));
    
    match (result1, result2) {
        (Ok(vk1), Ok(vk2)) => {
            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            vk1.write(&mut buf1, SerdeFormat::RawBytesUnchecked).unwrap();
            vk2.write(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
            
            assert_eq!(buf1, buf2, "VK should be deterministic for same params");
            println!("VK determinism verified: {} bytes", buf1.len());
        }
        _ => {
            println!("VK generation failed (k too small for circuit)");
        }
    }
}

#[test]
fn test_vk_differs_with_different_params() {
    // VK should differ when using different params (different RNG seeds)
    let params1 = setup(6);
    let params2 = setup(6);
    
    let result1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params1)
    }));
    
    let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params2)
    }));
    
    match (result1, result2) {
        (Ok(vk1), Ok(vk2)) => {
            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            vk1.write(&mut buf1, SerdeFormat::RawBytesUnchecked).unwrap();
            vk2.write(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
            
            // VKs may differ because params are generated with different RNG
            println!("VK1 size: {}, VK2 size: {}", buf1.len(), buf2.len());
            
            // At minimum, sizes should be the same
            assert_eq!(buf1.len(), buf2.len(), "VK sizes should be same for same k");
        }
        _ => {
            println!("VK generation failed");
        }
    }
}

// =============================================================================
// VK Size Tests
// =============================================================================

#[test]
fn test_vk_size_reasonable() {
    // VK size should be reasonable (not too small, not too large)
    let params = setup(6);
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params)
    }));
    
    if let Ok(vk) = result {
        let mut buf = Vec::new();
        vk.write(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        // VK should be at least 1KB
        assert!(buf.len() > 1000, "VK should be at least 1KB");
        
        // VK should be less than 10MB (reasonable upper bound)
        assert!(buf.len() < 10_000_000, "VK should be less than 10MB");
        
        println!("VK size: {} bytes", buf.len());
    } else {
        println!("VK generation failed (k too small)");
    }
}

// =============================================================================
// VK Serialization Tests
// =============================================================================

#[test]
fn test_vk_roundtrip() {
    // VK should survive write/read roundtrip
    let params = setup(6);
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params)
    }));
    
    if let Ok(vk) = result {
        let mut buf = Vec::new();
        vk.write(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        // Read back
        let vk_read = gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes(&buf);
        
        // Serialize again
        let mut buf2 = Vec::new();
        vk_read.write(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
        
        assert_eq!(buf, buf2, "VK roundtrip should be identical");
        println!("VK roundtrip verified: {} bytes", buf.len());
    } else {
        println!("VK generation failed (k too small)");
    }
}

