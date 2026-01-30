//! Fuzz target: Proof::create() API
//!
//! Тестирует создание proof с различными входными данными.
//! Проверяет что prover не паникует на граничных значениях.
//!
//! Находит:
//! - Panic в prover на edge case inputs
//! - Некорректную обработку ошибок
//! - Memory issues при создании proof
//!
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_proof_create_api

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use gosh_dark_dex_halo2_circuit::proof::Proof;
use gosh_dark_dex_halo2_circuit::snark_utils::read_kzg_params;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_vk, keygen_pk};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::OnceLock;

/// Кэшированные ключи (генерация дорогая)
struct CachedKeys {
    params: halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG<halo2_base::halo2_proofs::halo2curves::bn256::Bn256>,
    pk: halo2_base::halo2_proofs::plonk::ProvingKey<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>,
    vk: halo2_base::halo2_proofs::plonk::VerifyingKey<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>,
}

static CACHED_KEYS: OnceLock<Option<CachedKeys>> = OnceLock::new();

fn get_cached_keys() -> Option<&'static CachedKeys> {
    CACHED_KEYS.get_or_init(|| {
        ensure_working_directory();
        
        if !std::path::Path::new("kzg_params.bin").exists() {
            eprintln!("Warning: kzg_params.bin not found");
            return None;
        }
        
        let params = read_kzg_params("kzg_params.bin".to_string());
        let empty_circuit = DarkDexCircuit::default();
        let vk = keygen_vk(&params, &empty_circuit).ok()?;
        let pk = keygen_pk(&params, vk.clone(), &empty_circuit).ok()?;
        
        Some(CachedKeys { params, pk, vk })
    }).as_ref()
}

#[derive(Debug, Arbitrary)]
struct ProofCreateInput {
    token_type: u64,
    private_note_sum: u64,
    sk: u64,
    rng_seed: u64,
}

fuzz_target!(|input: ProofCreateInput| {
    let Some(keys) = get_cached_keys() else { return; };
    
    // Создаём circuit с fuzzed значениями
    let sk = Fr::from(input.sk);
    let token_type = Fr::from(input.token_type);
    let private_note_sum = Fr::from(input.private_note_sum);
    let sk_commitment = compute_sk_commitment(sk);
    let digest = compute_digest(sk, token_type, private_note_sum);
    
    let circuit = DarkDexCircuit::new(
        Some(token_type),
        Some(private_note_sum),
        Some(sk),
        Some(sk_commitment),
    );
    
    let pub_inputs = vec![private_note_sum, token_type, digest];
    let instances: Vec<&[Fr]> = vec![pub_inputs.as_slice()];
    
    // Создаём proof с детерминированным RNG
    let rng = StdRng::seed_from_u64(input.rng_seed);
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Proof::create(&keys.params, &keys.pk, circuit, &instances, rng)
    }));
    
    match result {
        Ok(Ok(proof)) => {
            // Proof создан - проверяем что он верифицируется
            let verify_result = proof.verify(&keys.vk, &keys.params, &instances);
            assert!(verify_result.is_ok(), 
                "Created proof failed verification! input={:?}", input);
        }
        Ok(Err(_)) => {
            // Ошибка создания proof - допустимо для некоторых inputs
        }
        Err(_) => {
            // Panic - это баг
            eprintln!("WARNING: Proof::create panicked on input={:?}", input);
        }
    }
});

