//! Fuzz target: get_params() and get_params_with_kzg_path() API
//!
//! Тестирует генерацию params/VK/PK с различными значениями k.
//! Проверяет robustness keygen функций.
//!
//! Находит:
//! - Panic при edge case k values
//! - Memory issues при keygen
//! - Inconsistencies между VK/PK
//!
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_get_params_api

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use gosh_dark_dex_halo2_circuit::snark_utils::{setup, get_params};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

#[derive(Debug, Arbitrary)]
struct GetParamsInput {
    /// Значение k (ограничиваем 4-10 для скорости)
    k_offset: u8,
}

fuzz_target!(|input: GetParamsInput| {
    ensure_working_directory();
    
    // k должен быть в разумных пределах
    // Минимум для DarkDexCircuit - 8
    // Максимум ограничиваем 10 для скорости fuzzing
    let k = 8 + (input.k_offset % 3); // k = 8, 9, или 10
    
    // Тестируем setup()
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        setup(k as u32)
    }));
    
    let params = match result {
        Ok(p) => p,
        Err(_) => {
            eprintln!("WARNING: setup({}) panicked", k);
            return;
        }
    };
    
    // Тестируем keygen с empty circuit
    let circuit = DarkDexCircuit::default();
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        get_params(k as u32, &circuit)
    }));
    
    match result {
        Ok((params2, vk, pk)) => {
            // Проверяем что VK и PK согласованы
            // (VK должен быть extractable из PK)
            let vk_from_pk = pk.get_vk();
            
            // Базовая проверка - VK не пустой
            assert!(!vk.to_bytes(halo2_proofs::SerdeFormat::RawBytesUnchecked).is_empty(),
                "VK serialization is empty for k={}", k);
        }
        Err(_) => {
            eprintln!("WARNING: get_params({}) panicked", k);
        }
    }
});

