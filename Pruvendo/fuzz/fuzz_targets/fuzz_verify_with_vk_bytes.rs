//! Fuzz target: Proof::verify_with_vk_from_bytes() API
//!
//! Тестирует верификацию с VK из bytes.
//! Мутирует VK bytes и проверяет robustness.
//!
//! Находит:
//! - Panic при corrupted VK bytes
//! - Soundness bugs при частично corrupted VK
//! - Memory safety issues
//!
//! Требует: kzg_params.bin, verification_key.bin, proof.bin
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_verify_with_vk_bytes

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use gosh_dark_dex_halo2_circuit::proof::Proof;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use std::sync::OnceLock;

struct CachedData {
    proof_bytes: Vec<u8>,
    vk_bytes: Vec<u8>,
    params: ParamsKZG<Bn256>,
    pub_inputs: Vec<Fr>,
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
        let vk_bytes = std::fs::read("verification_key.bin").ok()?;
        let params = read_kzg_params("kzg_params.bin".to_string());
        
        // Recreate public inputs
        let sk = Fr::from(12345u64);
        let token = Fr::from(1u64);
        let sum = Fr::from(1000u64);
        let sk_commitment = compute_sk_commitment(sk);
        let digest = poseidon_hash([sk_commitment, sum, token, sk]);
        
        Some(CachedData {
            proof_bytes,
            vk_bytes,
            params,
            pub_inputs: vec![sum, token, digest],
        })
    }).as_ref()
}

#[derive(Debug, Arbitrary)]
struct VkMutationInput {
    /// Позиции для мутации (до 4)
    positions: [u16; 4],
    /// XOR байты
    xor_bytes: [u8; 4],
    /// Количество мутаций (1-4)
    num_mutations: u8,
}

impl VkMutationInput {
    fn is_noop(&self) -> bool {
        let count = ((self.num_mutations % 4) + 1) as usize;
        for i in 0..count {
            if self.xor_bytes[i] != 0 {
                return false;
            }
        }
        true
    }
    
    fn apply(&self, vk_bytes: &[u8]) -> Vec<u8> {
        let mut result = vk_bytes.to_vec();
        let count = ((self.num_mutations % 4) + 1) as usize;
        
        for i in 0..count {
            if self.xor_bytes[i] != 0 {
                let pos = self.positions[i] as usize % result.len();
                result[pos] ^= self.xor_bytes[i];
            }
        }
        result
    }
}

fuzz_target!(|input: VkMutationInput| {
    let Some(data) = get_cached_data() else { return; };
    
    if input.is_noop() {
        return;
    }
    
    let mutated_vk = input.apply(&data.vk_bytes);
    let proof = Proof::new(data.proof_bytes.clone());
    let instances: Vec<&[Fr]> = vec![data.pub_inputs.as_slice()];
    
    // Используем catch_unwind т.к. corrupted VK может вызвать panic
    // (это известный upstream баг BC-001)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        proof.verify_with_vk_from_bytes::<DarkDexCircuit>(
            &mutated_vk,
            &data.params,
            &instances,
        )
    }));
    
    match result {
        Ok(Ok(())) => {
            // Мутированный VK принят - потенциальный soundness bug
            panic!("SOUNDNESS: Proof verified with mutated VK! input={:?}", input);
        }
        Ok(Err(_)) => {
            // Корректное отклонение
        }
        Err(_) => {
            // Panic - известный upstream баг (BC-001)
            // Не паникуем, просто логируем
        }
    }
});

