//! P1.4: KZG Integration Tests
//!
//! Smoke tests for KZG polynomial commitment scheme:
//! - Params size vs k relationship
//! - Params determinism
//! - Read/write consistency

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;
use gosh_dark_dex_halo2_circuit::snark_utils::setup;

// =============================================================================
// Params Size Tests
// =============================================================================

#[test]
fn test_params_size_increases_with_k() {
    // Params size should increase exponentially with k
    // Size ≈ 2^k * constant
    
    let params_k2 = setup(2);
    let params_k3 = setup(3);
    let params_k4 = setup(4);
    
    let mut buf2 = Vec::new();
    let mut buf3 = Vec::new();
    let mut buf4 = Vec::new();
    
    params_k2.write_custom(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
    params_k3.write_custom(&mut buf3, SerdeFormat::RawBytesUnchecked).unwrap();
    params_k4.write_custom(&mut buf4, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // Each increment of k should roughly double the size
    assert!(buf3.len() > buf2.len(), "k=3 should be larger than k=2");
    assert!(buf4.len() > buf3.len(), "k=4 should be larger than k=3");
    
    // Approximate 2x relationship (with some tolerance)
    let ratio_3_2 = buf3.len() as f64 / buf2.len() as f64;
    let ratio_4_3 = buf4.len() as f64 / buf3.len() as f64;
    
    println!("Params sizes: k=2: {}, k=3: {}, k=4: {}", buf2.len(), buf3.len(), buf4.len());
    println!("Ratios: 3/2 = {:.2}, 4/3 = {:.2}", ratio_3_2, ratio_4_3);
    
    assert!(ratio_3_2 > 1.5 && ratio_3_2 < 2.5, "Expected ~2x growth");
    assert!(ratio_4_3 > 1.5 && ratio_4_3 < 2.5, "Expected ~2x growth");
}

#[test]
fn test_params_non_determinism() {
    // KZG params use RNG for trusted setup, so they are NOT deterministic!
    // This is expected behavior - each call generates new random params
    // This test documents this behavior
    let params1 = setup(3);
    let params2 = setup(3);

    let mut buf1 = Vec::new();
    let mut buf2 = Vec::new();

    params1.write_custom(&mut buf1, SerdeFormat::RawBytesUnchecked).unwrap();
    params2.write_custom(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();

    // Params are NOT deterministic (uses RNG) - this is expected
    // The k value (first 4 bytes) should be the same
    assert_eq!(&buf1[0..4], &buf2[0..4], "k value should be same");

    // But the rest (random points) will differ
    // This documents the non-deterministic behavior
    println!("KZG params are non-deterministic (uses RNG) - this is expected");
}

// =============================================================================
// Params Read/Write Tests
// =============================================================================

#[test]
fn test_params_roundtrip() {
    // Write params to buffer, read back, compare
    let params_orig = setup(4);
    
    let mut buf = Vec::new();
    params_orig.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    let mut slice: &[u8] = &buf;
    let params_read = ParamsKZG::<Bn256>::read_custom(&mut slice, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // Serialize again and compare
    let mut buf2 = Vec::new();
    params_read.write_custom(&mut buf2, SerdeFormat::RawBytesUnchecked).unwrap();
    
    assert_eq!(buf, buf2, "Params roundtrip should be identical");
}

#[test]
fn test_params_k_preserved() {
    // After roundtrip, k should be preserved
    let k = 5;
    let params_orig = setup(k);
    
    let mut buf = Vec::new();
    params_orig.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    let mut slice: &[u8] = &buf;
    let params_read = ParamsKZG::<Bn256>::read_custom(&mut slice, SerdeFormat::RawBytesUnchecked).unwrap();
    
    assert_eq!(params_orig.k, params_read.k, "k should be preserved after roundtrip");
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_params_k_1() {
    // Minimum k=1 should work
    let params = setup(1);
    assert_eq!(params.k, 1);
    
    let mut buf = Vec::new();
    params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    assert!(!buf.is_empty(), "k=1 params should have non-zero size");
}

#[test]
fn test_params_k_10() {
    // k=10 is a reasonable upper bound for unit tests
    let params = setup(10);
    assert_eq!(params.k, 10);
    
    let mut buf = Vec::new();
    params.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // k=10 means 2^10 = 1024 points, each point is ~64 bytes
    // So minimum size is around 64KB
    println!("k=10 params size: {} bytes", buf.len());
    assert!(buf.len() > 50000, "k=10 should have at least 50KB of params");
}

#[test]
fn test_params_write_read_format_consistency() {
    // RawBytesUnchecked format should be consistent
    let params = setup(4);
    
    let mut buf_raw = Vec::new();
    params.write_custom(&mut buf_raw, SerdeFormat::RawBytesUnchecked).unwrap();
    
    // First 4 bytes should be k (u32)
    let k_bytes = &buf_raw[0..4];
    let k_read = u32::from_le_bytes([k_bytes[0], k_bytes[1], k_bytes[2], k_bytes[3]]);
    assert_eq!(k_read, 4, "First 4 bytes should be k value");
}

