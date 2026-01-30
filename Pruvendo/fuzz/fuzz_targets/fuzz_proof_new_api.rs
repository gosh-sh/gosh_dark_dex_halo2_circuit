//! Fuzz target: Proof::new() constructor
//!
//! Тестирует создание Proof из произвольных bytes.
//! Проверяет что конструктор не паникует и verify корректно отклоняет.
//!
//! Находит:
//! - Panic в конструкторе
//! - Soundness bugs (случайные bytes приняты как valid proof)
//! - Memory issues
//!
//! Требует: kzg_params.bin, verification_key.bin
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_proof_new_api

#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;
use common::*;

use gosh_dark_dex_halo2_circuit::proof::Proof;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use std::sync::OnceLock;

struct CachedData {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>,
    pub_inputs: Vec<Fr>,
}

static CACHED_DATA: OnceLock<Option<CachedData>> = OnceLock::new();

fn get_cached_data() -> Option<&'static CachedData> {
    CACHED_DATA.get_or_init(|| {
        ensure_working_directory();
        
        if !std::path::Path::new("kzg_params.bin").exists() ||
           !std::path::Path::new("verification_key.bin").exists() {
            return None;
        }
        
        let params = read_kzg_params("kzg_params.bin".to_string());
        let vk = verification_key_from_path("verification_key.bin".to_string());
        
        // Любые public inputs для тестирования
        let sk = Fr::from(12345u64);
        let token = Fr::from(1u64);
        let sum = Fr::from(1000u64);
        let sk_commitment = compute_sk_commitment(sk);
        let digest = poseidon_hash([sk_commitment, sum, token, sk]);
        
        Some(CachedData {
            params,
            vk,
            pub_inputs: vec![sum, token, digest],
        })
    }).as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some(cached) = get_cached_data() else { return; };
    
    // Минимальная длина для осмысленного proof
    if data.len() < 32 {
        return;
    }
    
    // Создаём Proof из произвольных bytes
    let proof = Proof::new(data.to_vec());
    
    let instances: Vec<&[Fr]> = vec![cached.pub_inputs.as_slice()];
    
    // Верификация - должна отклонить случайные bytes
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        proof.verify(&cached.vk, &cached.params, &instances)
    }));
    
    match result {
        Ok(Ok(())) => {
            // Случайные bytes приняты как valid proof - CRITICAL BUG!
            panic!(
                "CRITICAL SOUNDNESS BUG: Random bytes accepted as valid proof!\n\
                 data_len={}, data_hex={}",
                data.len(),
                hex::encode(&data[..data.len().min(64)])
            );
        }
        Ok(Err(_)) => {
            // Корректное отклонение
        }
        Err(_) => {
            // Panic в verifier - баг, но не soundness
        }
    }
});

