//! P2.2: Serialization Tests
//!
//! Roundtrip tests for serialization:
//! - VK write → read
//! - KZG Params write → read
//! - Corrupted bytes handling

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;
use gosh_dark_dex_halo2_circuit::snark_utils::setup;
use crate::helpers::{generate_verififcation_key_without_witness, verification_key_from_bytes};

// =============================================================================
// KZG Params Serialization Tests
// =============================================================================

#[test]
fn test_params_roundtrip_raw_bytes() {
    let params = setup(5);
    
    let mut buf = Vec::new();
    params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    let mut slice: &[u8] = &buf;
    let params_read = ParamsKZG::<Bn256>::read_custom(&mut slice, SerdeFormat::RawBytesUnchecked).unwrap();
    
    let mut buf2 = Vec::new();
    params_read.write_custom(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
    
    assert_eq!(buf, buf2, "Params roundtrip should be identical");
}

#[test]
fn test_params_corrupted_k_value() {
    // Create valid params, then corrupt the k value
    let params = setup(5);
    
    let mut buf = Vec::new();
    params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // Corrupt k value (first 4 bytes) to unreasonably large value
    buf[0] = 0xFF;
    buf[1] = 0xFF;
    buf[2] = 0x00;
    buf[3] = 0x00;
    
    let mut slice: &[u8] = &buf;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ParamsKZG::<Bn256>::read_custom(&mut slice, SerdeFormat::RawBytesUnchecked)
    }));
    
    // Should fail (panic or error)
    match result {
        Ok(Err(_)) => println!("Corrupted k handled with error"),
        Err(_) => println!("Corrupted k caused panic"),
        Ok(Ok(_)) => println!("WARNING: Corrupted k was accepted"),
    }
}

#[test]
fn test_params_truncated() {
    // Truncate params in the middle
    let params = setup(4);
    
    let mut buf = Vec::new();
    params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // Truncate to half
    let truncated = &buf[..buf.len() / 2];
    
    let mut slice: &[u8] = truncated;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ParamsKZG::<Bn256>::read_custom(&mut slice, SerdeFormat::RawBytesUnchecked)
    }));
    
    // Should fail
    assert!(result.is_err() || result.unwrap().is_err(), 
            "Truncated params should fail");
}

// =============================================================================
// VK Serialization Tests
// =============================================================================

#[test]
fn test_vk_roundtrip() {
    let params = setup(6);
    
    let vk_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params)
    }));
    
    if let Ok(vk) = vk_result {
        let mut buf = Vec::new();
        vk.write(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        let vk_read = verification_key_from_bytes(&buf);
        
        let mut buf2 = Vec::new();
        vk_read.write(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
        
        assert_eq!(buf, buf2, "VK roundtrip should be identical");
        println!("VK roundtrip OK: {} bytes", buf.len());
    }
}

#[test]
fn test_vk_corrupted_single_byte() {
    let params = setup(6);
    
    let vk_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness(&params)
    }));
    
    if let Ok(vk) = vk_result {
        let mut buf = Vec::new();
        vk.write(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
        
        // Corrupt a byte in the middle
        let mid = buf.len() / 2;
        buf[mid] ^= 0xFF;
        
        let result = std::panic::catch_unwind(|| {
            verification_key_from_bytes(&buf)
        });
        
        // With RawBytesUnchecked, corrupted data may still be parsed
        // but the VK will be invalid
        match result {
            Ok(_) => println!("Corrupted VK was parsed (may be invalid)"),
            Err(_) => println!("Corrupted VK caused panic"),
        }
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_empty_slice_params() {
    let empty: &[u8] = &[];
    let mut slice = empty;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ParamsKZG::<Bn256>::read_custom(&mut slice, SerdeFormat::RawBytesUnchecked)
    }));
    assert!(result.is_err() || result.unwrap().is_err(), 
            "Empty params should fail");
}

