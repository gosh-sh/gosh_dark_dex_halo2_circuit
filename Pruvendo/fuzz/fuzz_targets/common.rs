//! Общие функции для fuzz targets
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Содержит helpers для работы с ZKP схемой в контексте fuzzing.
//! Новая архитектура использует только Poseidon hash, без ECC.

#![allow(dead_code)]

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
pub use gosh_dark_dex_halo2_circuit::circuit::poseidon_hash;
use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        ff::Field,
    },
};
use std::sync::Once;

/// Константа k для схемы (новая архитектура: k=8)
pub const CIRCUIT_K: u32 = 8;

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

