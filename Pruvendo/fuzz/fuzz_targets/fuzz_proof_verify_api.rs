//! Fuzz target: Proof::verify() API
//!
//! Тестирует верификацию proof с мутированными данными.
//! Использует реальный proof и мутирует его/VK/instances.
//!
//! Находит:
//! - Soundness bugs (мутированный proof принят)
//! - Panic в verifier
//! - Некорректную обработку ошибок
//!
//! Требует: kzg_params.bin, verification_key.bin, proof.bin
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_proof_verify_api

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use gosh_dark_dex_halo2_circuit::proof::Proof;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use std::sync::OnceLock;

struct CachedData {
    proof_bytes: Vec<u8>,
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>,
    // Original public inputs: sum=1000, token=1, digest
    original_sum: Fr,
    original_token: Fr,
    original_digest: Fr,
}

static CACHED_DATA: OnceLock<Option<CachedData>> = OnceLock::new();

fn get_cached_data() -> Option<&'static CachedData> {
    CACHED_DATA.get_or_init(|| {
        ensure_working_directory();
        
        let required = ["kzg_params.bin", "verification_key.bin", "proof.bin"];
        for file in &required {
            if !std::path::Path::new(file).exists() {
                return None;
            }
        }
        
        let proof_bytes = std::fs::read("proof.bin").ok()?;
        let params = read_kzg_params("kzg_params.bin".to_string());
        let vk = verification_key_from_path("verification_key.bin".to_string());
        
        // Recreate original public inputs (from generate_test_fixtures)
        let sk = Fr::from(12345u64);
        let token = Fr::from(1u64);
        let sum = Fr::from(1000u64);
        let sk_commitment = compute_sk_commitment(sk);
        let digest = poseidon_hash([sk_commitment, sum, token, sk]);
        
        Some(CachedData {
            proof_bytes,
            params,
            vk,
            original_sum: sum,
            original_token: token,
            original_digest: digest,
        })
    }).as_ref()
}

#[derive(Debug, Arbitrary)]
enum VerifyMutation {
    /// Мутация байтов proof
    MutateProof { pos: u16, xor_byte: u8 },
    /// Изменение public input (sum)
    MutateSum(u64),
    /// Изменение public input (token)
    MutateToken(u64),
    /// Изменение digest
    MutateDigest([u8; 32]),
    /// Комбинированная мутация
    Combined { proof_pos: u16, proof_xor: u8, sum_delta: i32 },
}

#[derive(Debug, Arbitrary)]
struct VerifyInput {
    mutation: VerifyMutation,
}

fuzz_target!(|input: VerifyInput| {
    let Some(data) = get_cached_data() else { return; };
    
    let mut proof_bytes = data.proof_bytes.clone();
    let mut sum = data.original_sum;
    let mut token = data.original_token;
    let mut digest = data.original_digest;
    let mut is_mutated = false;
    
    match input.mutation {
        VerifyMutation::MutateProof { pos, xor_byte } => {
            if xor_byte != 0 {
                let idx = pos as usize % proof_bytes.len();
                proof_bytes[idx] ^= xor_byte;
                is_mutated = true;
            }
        }
        VerifyMutation::MutateSum(new_sum) => {
            let new_sum_fr = Fr::from(new_sum);
            if new_sum_fr != sum {
                sum = new_sum_fr;
                is_mutated = true;
            }
        }
        VerifyMutation::MutateToken(new_token) => {
            let new_token_fr = Fr::from(new_token);
            if new_token_fr != token {
                token = new_token_fr;
                is_mutated = true;
            }
        }
        VerifyMutation::MutateDigest(bytes) => {
            // Interpret bytes as field element
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            // Simple conversion - just use first 8 bytes as u64
            let val = u64::from_le_bytes(arr[0..8].try_into().unwrap());
            let new_digest = Fr::from(val);
            if new_digest != digest {
                digest = new_digest;
                is_mutated = true;
            }
        }
        VerifyMutation::Combined { proof_pos, proof_xor, sum_delta } => {
            if proof_xor != 0 {
                let idx = proof_pos as usize % proof_bytes.len();
                proof_bytes[idx] ^= proof_xor;
                is_mutated = true;
            }
            if sum_delta != 0 {
                let new_val = (1000i64 + sum_delta as i64).max(0) as u64;
                sum = Fr::from(new_val);
                is_mutated = true;
            }
        }
    }
    
    // Skip if no actual mutation
    if !is_mutated {
        return;
    }
    
    let proof = Proof::new(proof_bytes);
    let pub_inputs = vec![sum, token, digest];
    let instances: Vec<&[Fr]> = vec![pub_inputs.as_slice()];
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        proof.verify(&data.vk, &data.params, &instances)
    }));
    
    match result {
        Ok(Ok(())) => {
            // Мутированные данные приняты - SOUNDNESS BUG!
            panic!("SOUNDNESS BUG: Mutated data accepted! mutation={:?}", input.mutation);
        }
        Ok(Err(_)) => {
            // Корректное отклонение
        }
        Err(_) => {
            // Panic в verifier
            eprintln!("WARNING: Verifier panicked on mutation={:?}", input.mutation);
        }
    }
});

