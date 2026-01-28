// =============================================================================
// BC-TVM-004: Panic tests for tvm-sdk wrapper
// These tests confirm that Fr::from_bytes().unwrap() panics on invalid input
// =============================================================================

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Test that Fr::from_bytes returns None for value >= modulus
#[test]
fn test_fr_from_bytes_returns_none_for_invalid_input() {
    // All 0xFF bytes - definitely >= BN254 Fr modulus
    let invalid_bytes: [u8; 32] = [0xFF; 32];
    
    let result = Fr::from_bytes(&invalid_bytes);
    let is_valid = result.is_some().unwrap_u8();
    
    println!("Fr::from_bytes with all 0xFF: is_some = {}", is_valid);
    assert_eq!(is_valid, 0, "All 0xFF should NOT be a valid Fr element");
}

/// Test that Fr::from_bytes().unwrap() panics on invalid input
#[test]
fn test_fr_from_bytes_unwrap_panics_on_invalid_input() {
    let invalid_bytes: [u8; 32] = [0xFF; 32];
    
    let panic_result = std::panic::catch_unwind(|| {
        let _ = Fr::from_bytes(&invalid_bytes).unwrap();
    });
    
    assert!(panic_result.is_err(), "Fr::from_bytes().unwrap() should panic on invalid input!");
    println!("✅ Confirmed: Fr::from_bytes().unwrap() panics on value >= modulus");
}

/// Test valid Fr values work correctly
#[test]
fn test_fr_from_bytes_valid_values() {
    // Zero - valid
    let zero_bytes: [u8; 32] = [0; 32];
    let result = Fr::from_bytes(&zero_bytes);
    assert_eq!(result.is_some().unwrap_u8(), 1, "Zero should be valid Fr");
    
    // One (little-endian) - valid
    let mut one_bytes: [u8; 32] = [0; 32];
    one_bytes[0] = 1;
    let result = Fr::from_bytes(&one_bytes);
    assert_eq!(result.is_some().unwrap_u8(), 1, "One should be valid Fr");
    
    println!("✅ Valid Fr values work correctly");
}

/// Test boundary: value just at modulus (should be invalid)
#[test]
fn test_fr_from_bytes_at_modulus_boundary() {
    // BN254 Fr modulus in little-endian:
    // r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    let modulus_bytes: [u8; 32] = [
        0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43,
        0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
        0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
        0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
    ];
    
    let result = Fr::from_bytes(&modulus_bytes);
    let is_valid = result.is_some().unwrap_u8();
    println!("Fr::from_bytes at modulus: is_some = {}", is_valid);
    
    // Modulus itself should be invalid (it's equivalent to 0 in the field, but >= r)
    assert_eq!(is_valid, 0, "Modulus value should NOT be valid Fr (it's >= r)");
}

/// Simulate the exact code path from tvm-sdk zk_halo2.rs line 86
#[test]
fn test_tvm_sdk_panic_scenario() {
    println!("\n=== Simulating tvm-sdk zk_halo2.rs line 86 ===");
    println!("Code: let private_note_digest = Fr::from_bytes(&private_note_digest_bytes).unwrap();");
    println!("");
    
    // Attacker sends private_note_digest with all 0xFF bytes
    let attacker_digest: [u8; 32] = [0xFF; 32];
    
    println!("Attacker input: {:?}", &attacker_digest[..8]);
    println!("This value is >= BN254 Fr modulus");
    println!("");
    
    let panic_result = std::panic::catch_unwind(|| {
        // This is exactly what tvm-sdk does:
        let _private_note_digest = Fr::from_bytes(&attacker_digest).unwrap();
    });
    
    if panic_result.is_err() {
        println!("✅ PANIC CONFIRMED!");
        println!("BC-TVM-004: TVM will crash if user sends digest >= Fr modulus");
    } else {
        println!("❌ No panic - unexpected!");
    }
    
    assert!(panic_result.is_err(), "This MUST panic - it's the BC-TVM-004 vulnerability");
}

