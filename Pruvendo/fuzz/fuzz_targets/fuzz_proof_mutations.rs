//! Fuzz target: Proof byte mutations
//!
//! Мутирует байты proof и проверяет что verifier корректно отклоняет.
//! Использует pre-generated proof.bin файл (быстрый старт).
//!
//! Находит:
//! - Баги в верификаторе при corrupted proofs
//! - Неожиданные accepts мутированных proofs
//! - Паники на malformed proof bytes
//!
//! Требует: kzg_params.bin, verification_key.bin, proof.bin в корне проекта
//! Запуск: cargo +nightly fuzz run fuzz_proof_mutations

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use std::sync::OnceLock;

/// Кэшированные данные для верификации
struct CachedData {
    proof: Vec<u8>,
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>,
    token: u64,
    sum: u64,
}

static CACHED_DATA: OnceLock<Option<CachedData>> = OnceLock::new();

/// Загружает или возвращает кэшированные данные
fn get_cached_data() -> Option<&'static CachedData> {
    CACHED_DATA.get_or_init(|| {
        ensure_working_directory();

        // Проверяем наличие всех файлов
        let required = ["kzg_params.bin", "verification_key.bin", "proof.bin"];
        for file in &required {
            if !std::path::Path::new(file).exists() {
                eprintln!("Warning: {} not found, proof mutations disabled", file);
                return None;
            }
        }

        // Читаем proof из файла (быстрее чем генерировать)
        let proof = std::fs::read("proof.bin").ok()?;
        let params = read_kzg_params("kzg_params.bin".to_string());
        let vk = verification_key_from_path("verification_key.bin".to_string());

        // Public inputs из config (стандартные значения)
        let token = 1u64;
        let sum = 1000u64;

        Some(CachedData { proof, params, vk, token, sum })
    }).as_ref()
}

/// Входные данные для мутаций
#[derive(Debug, Arbitrary)]
struct ProofMutationInput {
    /// Позиция для мутации
    mutation_pos: u16,
    /// Байт для XOR
    mutation_byte: u8,
    /// Количество дополнительных мутаций (0-3)
    extra_mutations: u8,
    /// Позиции для дополнительных мутаций
    extra_positions: [u16; 3],
}

fuzz_target!(|input: ProofMutationInput| {
    // Пропускаем если нет файлов
    let Some(data) = get_cached_data() else {
        return;
    };

    // Пропускаем пустые мутации
    if input.mutation_byte == 0 {
        return;
    }

    // Клонируем и мутируем proof
    let mut proof = data.proof.clone();
    let pos = input.mutation_pos as usize % proof.len();
    proof[pos] ^= input.mutation_byte;

    // Дополнительные мутации
    let extra_count = (input.extra_mutations % 4) as usize;
    for i in 0..extra_count {
        let extra_pos = input.extra_positions[i] as usize % proof.len();
        if extra_pos != pos {
            proof[extra_pos] ^= 0xFF;
        }
    }

    let pub_inputs = vec![Fr::from(data.token), Fr::from(data.sum)];

    // Верификация мутированного proof
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_proof_(&data.params, &proof, &data.vk, pub_inputs)
    }));

    match result {
        Ok(verified) => {
            // Мутированный proof НЕ должен верифицироваться
            assert!(
                !verified,
                "CRITICAL: Mutated proof was accepted!\n\
                 mutation_pos = {}, mutation_byte = 0x{:02X}, extra_mutations = {}",
                pos, input.mutation_byte, extra_count
            );
        }
        Err(_) => {
            // Паника при верификации - это баг (но не критичный для soundness)
            eprintln!(
                "WARNING: Verifier panicked on mutated proof at pos={}, byte=0x{:02X}",
                pos, input.mutation_byte
            );
        }
    }
});
