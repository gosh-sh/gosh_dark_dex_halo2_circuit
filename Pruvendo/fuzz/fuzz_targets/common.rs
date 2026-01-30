//! Общие функции для fuzz targets
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Содержит helpers для работы с ZKP схемой в контексте fuzzing.
//! Новая архитектура использует только Poseidon hash, без ECC.
//!
//! Включает REFERENCE IMPLEMENTATION Poseidon для cross-validation.

#![allow(dead_code)]

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
pub use gosh_dark_dex_halo2_circuit::circuit::poseidon_hash;
use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Fr,
};
use std::sync::Once;

/// Константа k для схемы (новая архитектура: k=8)
pub const CIRCUIT_K: u32 = 8;

// =============================================================================
// REFERENCE POSEIDON IMPLEMENTATION
// =============================================================================
//
// Независимая реализация Poseidon для cross-validation.
// Использует poseidon_base primitives напрямую, step-by-step.
//
// Это устраняет тавтологию: если poseidon_hash сломан, reference_poseidon_hash
// покажет расхождение.
//
// Sponge construction для ConstantLength<L>:
// - Initial state: [input[0], input[1], capacity] где capacity = 2^65 * L
// - Для L > RATE: absorb по RATE элементов, permute между absorb
// - Output = state[0] после финальной permutation

use poseidon_base::primitives::{permute, P128Pow5T3};
use poseidon_base::primitives::bn256::fp::{ROUND_CONSTANTS, MDS};

/// Вычисляет capacity element для ConstantLength<L>
/// capacity = L * 2^64 (согласно ePrint 2019/458 section 4.2)
fn compute_capacity(len: usize) -> Fr {
    // F::from_u128((L as u128) << 64)
    // 2^64 = 2^63 * 2
    let two_to_63 = Fr::from(1u64 << 63);
    let two_to_64 = two_to_63.double();
    two_to_64 * Fr::from(len as u64)
}

/// Reference Poseidon hash - использует низкоуровневые primitives
/// для независимой верификации
pub fn reference_poseidon_hash_2(inputs: [Fr; 2]) -> Fr {
    // Sponge construction для rate=2, capacity=1, L=2
    // Initial state: [input[0], input[1], capacity]
    // capacity = 2 * 2^65
    let capacity = compute_capacity(2);
    let mut state = [inputs[0], inputs[1], capacity];

    // Apply permutation
    #[allow(clippy::explicit_auto_deref)]
    let rc: &[[Fr; 3]] = &*ROUND_CONSTANTS;
    #[allow(clippy::explicit_auto_deref)]
    let mds: &[[Fr; 3]; 3] = &*MDS;

    permute::<Fr, P128Pow5T3<Fr>, 3, 2>(&mut state, mds, rc);

    // Output is first element after permutation
    state[0]
}

/// Reference Poseidon hash для 4 элементов
pub fn reference_poseidon_hash_4(inputs: [Fr; 4]) -> Fr {
    // Для L=4: нужно 2 absorb фазы (rate=2)
    // Initial state: [input[0], input[1], capacity] где capacity = 4 * 2^65
    let capacity = compute_capacity(4);
    let mut state = [inputs[0], inputs[1], capacity];

    #[allow(clippy::explicit_auto_deref)]
    let rc: &[[Fr; 3]] = &*ROUND_CONSTANTS;
    #[allow(clippy::explicit_auto_deref)]
    let mds: &[[Fr; 3]; 3] = &*MDS;

    // Phase 1: permute с первыми 2 элементами
    permute::<Fr, P128Pow5T3<Fr>, 3, 2>(&mut state, mds, rc);

    // Phase 2: absorb следующие 2 элемента (XOR with state)
    state[0] += inputs[2];
    state[1] += inputs[3];

    // Phase 2: permute
    permute::<Fr, P128Pow5T3<Fr>, 3, 2>(&mut state, mds, rc);

    state[0]
}

/// Hardcoded test vectors для верификации Poseidon реализации
/// Эти значения вычислены и зафиксированы как baseline
pub const POSEIDON_TEST_VECTORS: &[([u64; 2], &str)] = &[
    // (inputs, expected_hash_hex)
    ([2, 3], "0x19014d18a3179c5731155fcb7b6da422f456bccbd6da9dbc7df0f8dc6d4938ed"),
    ([0, 0], "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"),
    ([1, 1], "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"),
];

/// Проверяет что poseidon_hash соответствует reference implementation
pub fn verify_poseidon_consistency(a: Fr, b: Fr) -> bool {
    let lib_hash = poseidon_hash([a, b]);
    let ref_hash = reference_poseidon_hash_2([a, b]);
    lib_hash == ref_hash
}

/// Вычисляет digest с cross-validation
/// Панкует если library и reference дают разные результаты
pub fn compute_digest_verified(sk: Fr, token_type: Fr, private_note_sum: Fr) -> Fr {
    // Library implementation
    let sk_commitment = compute_sk_commitment(sk);
    let digest = poseidon_hash([sk_commitment, private_note_sum, token_type, sk]);

    // Reference implementation для sk_commitment
    let ref_sk_commitment = reference_poseidon_hash_2([sk, Fr::zero()]);

    // Cross-validate sk_commitment
    assert_eq!(sk_commitment, ref_sk_commitment,
        "TAUTOLOGY VIOLATION: sk_commitment mismatch between library and reference!");

    // Reference implementation для digest
    let ref_digest = reference_poseidon_hash_4([sk_commitment, private_note_sum, token_type, sk]);

    // Cross-validate digest
    assert_eq!(digest, ref_digest,
        "TAUTOLOGY VIOLATION: digest mismatch between library and reference!");

    digest
}

static INIT: Once = Once::new();

/// Устанавливает рабочую директорию на корень проекта
pub fn ensure_working_directory() {
    INIT.call_once(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let manifest_path = std::path::Path::new(manifest_dir);

        let project_root = manifest_path
            .parent() // Pruvendo
            .and_then(|p| p.parent()) // корень проекта
            .expect("Failed to find project root");

        let config_path = project_root.join("config/circuit.config");
        if !config_path.exists() {
            let cwd = std::env::current_dir().ok();
            if let Some(ref cwd) = cwd {
                if cwd.join("config/circuit.config").exists() {
                    return;
                }
            }
            panic!(
                "Cannot find config/circuit.config. manifest_dir={}, project_root={:?}, cwd={:?}",
                manifest_dir, project_root, cwd
            );
        }

        std::env::set_current_dir(project_root)
            .expect("Failed to set working directory");
    });
}

/// Вычисляет sk_commitment = poseidon(sk, 0)
pub fn compute_sk_commitment(sk: Fr) -> Fr {
    poseidon_hash([sk, Fr::zero()])
}

/// Вычисляет digest = poseidon(sk_commitment, sum, token, sk)
pub fn compute_digest(sk: Fr, token_type: Fr, private_note_sum: Fr) -> Fr {
    let sk_commitment = compute_sk_commitment(sk);
    poseidon_hash([sk_commitment, private_note_sum, token_type, sk])
}

/// Результат проверки схемы
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitResult {
    Ok,
    Failed(String),
}

impl CircuitResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, CircuitResult::Ok)
    }

    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }
}

/// Проверяет схему через MockProver
///
/// Новая архитектура (poseidon_instead_of_ecc):
/// DarkDexCircuit::new(token_type, private_note_sum, sk, sk_commitment)
/// Public inputs: [private_note_sum, token_type, digest]
pub fn check_circuit(
    sk_val: u64,
    token_type: u64,
    private_note_sum: u64,
) -> CircuitResult {
    ensure_working_directory();

    let sk = Fr::from(sk_val);
    let sk_commitment = compute_sk_commitment(sk);
    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);

    let digest = compute_digest(sk, token_type_fr, private_note_sum_fr);

    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(sk),
        Some(sk_commitment),
    );

    let public_inputs = vec![
        private_note_sum_fr,
        token_type_fr,
        digest,
    ];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);

    match prover {
        Ok(prover) => {
            match prover.verify() {
                Ok(_) => CircuitResult::Ok,
                Err(errors) => CircuitResult::Failed(format!("{:?}", errors)),
            }
        }
        Err(e) => CircuitResult::Failed(format!("MockProver::run failed: {:?}", e)),
    }
}

/// Проверяет схему с Fr значениями
pub fn check_circuit_fr(
    sk: Fr,
    token_type: Fr,
    private_note_sum: Fr,
) -> CircuitResult {
    ensure_working_directory();

    let sk_commitment = compute_sk_commitment(sk);
    let digest = compute_digest(sk, token_type, private_note_sum);

    let circuit = DarkDexCircuit::new(
        Some(token_type),
        Some(private_note_sum),
        Some(sk),
        Some(sk_commitment),
    );

    let public_inputs = vec![
        private_note_sum,
        token_type,
        digest,
    ];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);

    match prover {
        Ok(prover) => {
            match prover.verify() {
                Ok(_) => CircuitResult::Ok,
                Err(errors) => CircuitResult::Failed(format!("{:?}", errors)),
            }
        }
        Err(e) => CircuitResult::Failed(format!("MockProver::run failed: {:?}", e)),
    }
}

/// Проверяет схему с неправильным commitment (для тестирования soundness)
pub fn check_circuit_with_wrong_commitment(
    sk: Fr,
    wrong_commitment: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> CircuitResult {
    ensure_working_directory();

    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);
    let digest = compute_digest(sk, token_type_fr, private_note_sum_fr);

    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(sk),
        Some(wrong_commitment), // Wrong commitment!
    );

    let public_inputs = vec![
        private_note_sum_fr,
        token_type_fr,
        digest,
    ];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);

    match prover {
        Ok(prover) => {
            match prover.verify() {
                Ok(_) => CircuitResult::Ok,
                Err(errors) => CircuitResult::Failed(format!("{:?}", errors)),
            }
        }
        Err(e) => CircuitResult::Failed(format!("MockProver::run failed: {:?}", e)),
    }
}

/// Проверяет схему с кастомным digest (для тестирования preimage attacks)
pub fn check_circuit_with_custom_digest(
    sk: Fr,
    circuit_token: u64,
    circuit_sum: u64,
    custom_digest: Fr,
) -> CircuitResult {
    ensure_working_directory();

    let sk_commitment = compute_sk_commitment(sk);
    let circuit_token_fr = Fr::from(circuit_token);
    let circuit_sum_fr = Fr::from(circuit_sum);

    let circuit = DarkDexCircuit::new(
        Some(circuit_token_fr),
        Some(circuit_sum_fr),
        Some(sk),
        Some(sk_commitment),
    );

    // Public inputs используют circuit значения, но чужой digest
    let public_inputs = vec![
        circuit_sum_fr,
        circuit_token_fr,
        custom_digest,  // Custom digest!
    ];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![public_inputs]);

    match prover {
        Ok(prover) => {
            match prover.verify() {
                Ok(_) => CircuitResult::Ok,
                Err(errors) => CircuitResult::Failed(format!("{:?}", errors)),
            }
        }
        Err(e) => CircuitResult::Failed(format!("MockProver::run failed: {:?}", e)),
    }
}

// =============================================================================
// REAL PROVER/VERIFIER HELPERS (for fuzz targets that use real proofs)
// =============================================================================

pub use gosh_dark_dex_halo2_circuit::snark_utils::read_kzg_params;
pub use gosh_dark_dex_halo2_circuit::proof::Proof;

use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use halo2_proofs::SerdeFormat;

/// Читает VerifyingKey из файла
/// Замена для старой verifier::verification_key_from_path
pub fn verification_key_from_path(path: String) -> VerifyingKey<G1Affine> {
    let vk_bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("Failed to read VK from {}: {}", path, e));
    verification_key_from_bytes(&vk_bytes)
}

/// Читает VerifyingKey из bytes
/// Замена для старой verifier::verification_key_from_bytes
pub fn verification_key_from_bytes(bytes: &[u8]) -> VerifyingKey<G1Affine> {
    let mut slice: &[u8] = bytes;
    VerifyingKey::read::<_, DarkDexCircuit>(&mut slice, SerdeFormat::RawBytesUnchecked)
        .expect("Failed to read VerifyingKey")
}

/// Верифицирует proof с заданными public inputs
/// Замена для старой verifier::verify_proof_
/// Возвращает true если proof верифицирован, false если отклонён
pub fn verify_proof_(
    params: &ParamsKZG<Bn256>,
    proof_bytes: &[u8],
    vk: &VerifyingKey<G1Affine>,
    pub_inputs: Vec<Fr>,
) -> bool {
    let proof = Proof::new(proof_bytes.to_vec());
    let instances: Vec<&[Fr]> = vec![pub_inputs.as_slice()];
    proof.verify(vk, params, &instances).is_ok()
}

