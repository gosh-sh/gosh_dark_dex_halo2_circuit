//! Fuzz target: Poseidon algebraic properties
//!
//! Tests algebraic properties of Poseidon hash that could be exploited:
//! - Related key attacks (H(k) vs H(k+1))
//! - Differential properties
//! - Linearity attacks (H(a+b) vs H(a) + H(b))
//! - Zero input behavior
//!
//! Invariant: Poseidon should behave as a random oracle.

#![no_main]

mod common;

use common::poseidon_hash;
use libfuzzer_sys::fuzz_target;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    
    let test_type = data[0] % 6;
    
    // Parse two Fr values from input
    let a = Fr::from(u64::from_le_bytes(data[1..9].try_into().unwrap()));
    let b = Fr::from(u64::from_le_bytes(data[9..17].try_into().unwrap()));
    let delta = Fr::from(u64::from_le_bytes(data[17..25].try_into().unwrap()) % 1000 + 1);
    
    match test_type {
        0 => {
            // Test: H(0, 0) should be defined and deterministic
            let h1 = poseidon_hash([Fr::zero(), Fr::zero()]);
            let h2 = poseidon_hash([Fr::zero(), Fr::zero()]);
            assert_eq!(h1, h2, "Poseidon(0,0) should be deterministic");
        }
        1 => {
            // Test: Related inputs should have unrelated outputs
            // H(a, b) should be "far" from H(a+1, b)
            let h1 = poseidon_hash([a, b]);
            let h2 = poseidon_hash([a + Fr::one(), b]);
            // They should be different
            assert_ne!(h1, h2, "H(a,b) should differ from H(a+1,b)");
            // Check they're not trivially related (h2 != h1 + 1)
            assert_ne!(h2, h1 + Fr::one(), "Output should not be trivially related to input change");
        }
        2 => {
            // Test: Non-linearity - H(a+b, c) != H(a, c) + H(b, c)
            let c = Fr::from(42u64);
            let h_sum = poseidon_hash([a + b, c]);
            let h_a = poseidon_hash([a, c]);
            let h_b = poseidon_hash([b, c]);
            assert_ne!(h_sum, h_a + h_b, "Poseidon should be non-linear");
        }
        3 => {
            // Test: Symmetry - H(a, b) should differ from H(b, a)
            if a != b {
                let h1 = poseidon_hash([a, b]);
                let h2 = poseidon_hash([b, a]);
                assert_ne!(h1, h2, "H(a,b) should differ from H(b,a) for a != b");
            }
        }
        4 => {
            // Test: Small differences in input should cause large differences in output
            let h1 = poseidon_hash([a, b]);
            let h2 = poseidon_hash([a + delta, b]);
            
            // Outputs should differ
            assert_ne!(h1, h2, "Small input difference should cause output difference");
            
            // Check that difference is not proportional to delta
            let output_diff = h2 - h1;
            assert_ne!(output_diff, delta, "Output difference should not equal input difference");
        }
        5 => {
            // Test: Negation - H(-a, -b) should differ from -H(a, b)
            let h1 = poseidon_hash([a, b]);
            let h2 = poseidon_hash([-a, -b]);
            
            assert_ne!(h2, -h1, "H(-a,-b) should not equal -H(a,b)");
        }
        _ => {}
    }
    
    // Additional collision resistance test
    // Generate multiple hashes and check for collisions
    if data.len() >= 64 {
        let inputs: Vec<(Fr, Fr)> = (0..4).map(|i| {
            let offset = 1 + i * 16;
            if offset + 16 <= data.len() {
                let x = Fr::from(u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()));
                let y = Fr::from(u64::from_le_bytes(data[offset+8..offset+16].try_into().unwrap()));
                (x, y)
            } else {
                (Fr::from(i as u64), Fr::from(i as u64 + 1))
            }
        }).collect();
        
        // Check no collisions among different inputs
        for i in 0..inputs.len() {
            for j in (i+1)..inputs.len() {
                if inputs[i] != inputs[j] {
                    let h_i = poseidon_hash([inputs[i].0, inputs[i].1]);
                    let h_j = poseidon_hash([inputs[j].0, inputs[j].1]);
                    assert_ne!(h_i, h_j, 
                        "Collision found! H({:?}) == H({:?})", inputs[i], inputs[j]);
                }
            }
        }
    }
});

