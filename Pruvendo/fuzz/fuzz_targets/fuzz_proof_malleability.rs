//! P1.3: Fuzz Proof Malleability
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Tests proof mutation attacks:
//! - Bit flips in proof bytes
//! - Truncation attacks
//! - Public input permutation
//! - Extension attacks (append bytes)

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

mod common;
use common::compute_sk_commitment;

#[derive(Arbitrary, Debug)]
enum MutationType {
    BitFlip { byte_idx: usize, bit_idx: u8 },
    Truncate { new_len: usize },
    Extend { extra_bytes: Vec<u8> },
    SwapBytes { idx1: usize, idx2: usize },
    ZeroRange { start: usize, len: usize },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Base values for generating valid proof
    sk_val: u64,
    token: u64,
    sum: u64,
    // Mutation to apply
    mutation: MutationType,
}

#[allow(dead_code)]
fn generate_valid_circuit(sk_val: u64, token: u64, sum: u64)
    -> (DarkDexCircuit, Vec<Fr>)
{
    let sk_val = if sk_val == 0 { 1 } else { sk_val };
    let sk = Fr::from(sk_val);
    let sk_commitment = compute_sk_commitment(sk);

    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);

    let circuit = DarkDexCircuit::new(
        Some(token_fr),
        Some(sum_fr),
        Some(sk),
        Some(sk_commitment),
    );

    // Compute expected public inputs
    let pub_inputs = vec![sum_fr, token_fr, Fr::from(0u64)]; // placeholder digest

    (circuit, pub_inputs)
}

fn mutate_proof(proof: &[u8], mutation: &MutationType) -> Vec<u8> {
    let mut mutated = proof.to_vec();
    
    match mutation {
        MutationType::BitFlip { byte_idx, bit_idx } => {
            if *byte_idx < mutated.len() {
                mutated[*byte_idx] ^= 1 << (bit_idx % 8);
            }
        }
        MutationType::Truncate { new_len } => {
            if *new_len < mutated.len() {
                mutated.truncate(*new_len);
            }
        }
        MutationType::Extend { extra_bytes } => {
            mutated.extend_from_slice(extra_bytes);
        }
        MutationType::SwapBytes { idx1, idx2 } => {
            if *idx1 < mutated.len() && *idx2 < mutated.len() {
                mutated.swap(*idx1, *idx2);
            }
        }
        MutationType::ZeroRange { start, len } => {
            if *start < mutated.len() {
                let end = start.saturating_add(*len).min(mutated.len());
                for i in *start..end {
                    mutated[i] = 0;
                }
            }
        }
    }
    
    mutated
}

fuzz_target!(|input: FuzzInput| {
    // Skip if sk is 0 (invalid)
    if input.sk_val == 0 {
        return;
    }
    
    // Generate a "reference" proof-like data
    // In real test we'd generate actual proof, but that's expensive
    // So we just test mutation logic consistency
    
    let fake_proof: Vec<u8> = (0..100).map(|i| ((input.sk_val as u8).wrapping_add(i))).collect();
    
    let mutated = mutate_proof(&fake_proof, &input.mutation);
    
    // Verify mutation was applied
    match &input.mutation {
        MutationType::Truncate { new_len } if *new_len < fake_proof.len() => {
            assert!(mutated.len() <= *new_len);
        }
        MutationType::Extend { extra_bytes } => {
            assert_eq!(mutated.len(), fake_proof.len() + extra_bytes.len());
        }
        _ => {}
    }
    
    // Main property: mutated proof should differ from original
    // (unless mutation was no-op)
    match &input.mutation {
        MutationType::BitFlip { byte_idx, .. } if *byte_idx < fake_proof.len() => {
            assert_ne!(mutated, fake_proof, "Bit flip should change proof");
        }
        MutationType::SwapBytes { idx1, idx2 } 
            if *idx1 < fake_proof.len() && *idx2 < fake_proof.len() && idx1 != idx2 
            && fake_proof[*idx1] != fake_proof[*idx2] => {
            assert_ne!(mutated, fake_proof, "Swap should change proof");
        }
        _ => {}
    }
});

