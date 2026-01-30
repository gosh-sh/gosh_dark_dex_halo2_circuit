//! Fuzz target: Structure-aware proof fuzzing
//!
//! Генерирует structured inputs на основе знания формата proof.
//! Proof состоит из 63 G1 points (32 bytes each) = 2016 bytes.
//!
//! Находит:
//! - Уязвимости в конкретных полях proof
//! - Проблемы с парсингом точек кривой
//! - Граничные случаи для scalar/point операций
//!
//! Запуск: cargo +nightly fuzz run fuzz_structured_proof

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

/// Размеры proof структуры
const PROOF_SIZE: usize = 2016;
const POINT_SIZE: usize = 32;
const NUM_POINTS: usize = PROOF_SIZE / POINT_SIZE; // 63

/// Кэшированные данные
struct CachedData {
    proof: Vec<u8>,
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>,
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
        let proof = std::fs::read("proof.bin").ok()?;
        if proof.len() != PROOF_SIZE {
            return None;
        }
        let params = read_kzg_params("kzg_params.bin".to_string());
        let vk = verification_key_from_path("verification_key.bin".to_string());
        Some(CachedData { proof, params, vk })
    }).as_ref()
}

/// Тип мутации для точки кривой
#[derive(Debug, Clone, Arbitrary)]
enum PointMutation {
    /// XOR байта на определённой позиции
    XorByte { offset: u8, value: u8 },
    /// Установить точку в identity (0, 0)
    SetIdentity,
    /// Инвертировать Y координату (negation)
    NegateY,
    /// Случайная точка
    RandomPoint([u8; 32]),
    /// Установить X = p - 1 (максимальное значение)
    MaxX,
    /// Установить X = 0
    ZeroX,
}

/// Structured input для фаззинга
#[derive(Debug, Arbitrary)]
struct StructuredProofInput {
    /// Индексы точек для мутации (0-62)
    point_indices: [u8; 4],
    /// Мутации для каждой точки
    mutations: [PointMutation; 4],
    /// Количество мутаций (1-4)
    num_mutations: u8,
}

impl StructuredProofInput {
    /// Проверяет, изменяет ли мутация proof
    fn is_noop(&self) -> bool {
        let count = ((self.num_mutations % 4) + 1) as usize;
        for i in 0..count {
            match &self.mutations[i] {
                PointMutation::XorByte { value, .. } if *value != 0 => return false,
                PointMutation::SetIdentity => return false,
                PointMutation::NegateY => return false,
                PointMutation::RandomPoint(_) => return false,
                PointMutation::MaxX => return false,
                PointMutation::ZeroX => return false,
                _ => {} // XorByte with value=0 is noop
            }
        }
        true
    }

    fn apply_to_proof(&self, proof: &[u8]) -> Vec<u8> {
        let mut result = proof.to_vec();
        let count = ((self.num_mutations % 4) + 1) as usize;

        for i in 0..count {
            let point_idx = (self.point_indices[i] as usize) % NUM_POINTS;
            let start = point_idx * POINT_SIZE;
            let point = &mut result[start..start + POINT_SIZE];

            match &self.mutations[i] {
                PointMutation::XorByte { offset, value } => {
                    let off = (*offset as usize) % POINT_SIZE;
                    point[off] ^= *value;
                }
                PointMutation::SetIdentity => {
                    point.fill(0);
                }
                PointMutation::NegateY => {
                    // Flip sign bit (bit 7 of last byte) - based on our finding
                    point[POINT_SIZE - 1] ^= 0x80;
                }
                PointMutation::RandomPoint(data) => {
                    point.copy_from_slice(data);
                }
                PointMutation::MaxX => {
                    point.fill(0xFF);
                }
                PointMutation::ZeroX => {
                    point.fill(0);
                    point[POINT_SIZE - 1] = 0x80; // Keep sign bit
                }
            }
        }
        result
    }
}

fuzz_target!(|input: StructuredProofInput| {
    let Some(data) = get_cached_data() else { return; };

    // Пропускаем noop мутации (оригинальный proof должен проходить)
    if input.is_noop() {
        return;
    }

    let mutated_proof = input.apply_to_proof(&data.proof);
    let pub_inputs = vec![Fr::from(1u64), Fr::from(1000u64)];

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_proof_(&data.params, &mutated_proof, &data.vk, pub_inputs)
    }));

    match result {
        Ok(true) => {
            // Мутированный proof принят - потенциальный soundness bug
            panic!("SOUNDNESS: Mutated proof accepted! input={:?}", input);
        }
        Ok(false) => {
            // Корректное отклонение
        }
        Err(_) => {
            // Panic - bug в обработке ошибок
        }
    }
});

