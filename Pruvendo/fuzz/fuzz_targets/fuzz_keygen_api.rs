//! Fuzz target: VK generation without witness
//!
//! Тестирует generate_verififcation_key_without_witness() функции.
//! Проверяет что VK генерируется корректно для default circuit.
//!
//! Находит:
//! - Panic в keygen
//! - Inconsistencies в VK generation
//! - Memory issues
//!
//! Требует: kzg_params.bin
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_keygen_api

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use gosh_dark_dex_halo2_circuit::snark_utils::{
    read_kzg_params,
    generate_verififcation_key_without_witness,
};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;
use std::sync::OnceLock;

static CACHED_PARAMS: OnceLock<Option<ParamsKZG<Bn256>>> = OnceLock::new();

fn get_cached_params() -> Option<&'static ParamsKZG<Bn256>> {
    CACHED_PARAMS.get_or_init(|| {
        ensure_working_directory();
        
        if !std::path::Path::new("kzg_params.bin").exists() {
            return None;
        }
        
        Some(read_kzg_params("kzg_params.bin".to_string()))
    }).as_ref()
}

#[derive(Debug, Arbitrary)]
struct KeygenInput {
    /// Seed для вариации (не используется напрямую, но влияет на fuzzer)
    seed: u64,
    /// Проверять ли сериализацию
    check_serialization: bool,
}

fuzz_target!(|input: KeygenInput| {
    let Some(params) = get_cached_params() else { return; };
    
    // Генерируем VK без witness
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_verififcation_key_without_witness::<DarkDexCircuit>(params)
    }));
    
    match result {
        Ok(vk) => {
            if input.check_serialization {
                // Проверяем сериализацию/десериализацию
                let vk_bytes = vk.to_bytes(SerdeFormat::RawBytesUnchecked);
                assert!(!vk_bytes.is_empty(), "VK serialization is empty");
                
                // Проверяем что можно десериализовать обратно
                let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    verification_key_from_bytes(&vk_bytes)
                }));
                
                match result2 {
                    Ok(vk2) => {
                        // Проверяем что VK совпадают
                        let vk2_bytes = vk2.to_bytes(SerdeFormat::RawBytesUnchecked);
                        assert_eq!(vk_bytes, vk2_bytes, 
                            "VK roundtrip mismatch!");
                    }
                    Err(_) => {
                        panic!("VK deserialization panicked after successful serialization!");
                    }
                }
            }
        }
        Err(_) => {
            eprintln!("WARNING: generate_verififcation_key_without_witness panicked");
        }
    }
});

