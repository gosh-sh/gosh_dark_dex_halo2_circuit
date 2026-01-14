//! Общие функции для fuzz targets
//!
//! Содержит helpers для работы с ZKP схемой в контексте fuzzing.

#![allow(dead_code)]

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
pub use gosh_dark_dex_halo2_circuit::circuit::poseidon_hash;
pub use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};
use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
        ff::PrimeField,
    },
};
use std::sync::Once;

/// Константа k для схемы (из config/circuit.config)
pub const CIRCUIT_K: u32 = 18;

static INIT: Once = Once::new();

/// Устанавливает рабочую директорию на корень проекта
pub fn ensure_working_directory() {
    INIT.call_once(|| {
        // CARGO_MANIFEST_DIR указывает на реальный путь Pruvendo/fuzz
        // Нужно подняться на 2 уровня вверх до корня проекта
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let manifest_path = std::path::Path::new(manifest_dir);

        // Пробуем найти корень проекта (где есть config/circuit.config)
        let project_root = manifest_path
            .parent() // Pruvendo
            .and_then(|p| p.parent()) // корень проекта
            .expect("Failed to find project root");

        // Проверяем что config существует
        let config_path = project_root.join("config/circuit.config");
        if !config_path.exists() {
            // Fallback: может быть мы уже в корне
            let cwd = std::env::current_dir().ok();
            if let Some(ref cwd) = cwd {
                if cwd.join("config/circuit.config").exists() {
                    return; // Уже в правильной директории
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

/// Генерирует валидную пару ключей (sk, pk = sk * G)
pub fn generate_valid_keypair(sk_val: u64) -> (Fq, Secp256k1Affine, Secp256k1Affine) {
    let sk = Fq::from(sk_val);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(g * sk);
    (sk, pk, g)
}

/// Генерирует невалидную пару ключей (sk, wrong_pk где wrong_pk ≠ sk * G)
pub fn generate_invalid_keypair(sk_val: u64, wrong_sk_val: u64) -> (Fq, Secp256k1Affine, Secp256k1Affine) {
    let sk = Fq::from(sk_val);
    let wrong_sk = Fq::from(wrong_sk_val);
    let g = Secp256k1Affine::generator();
    let wrong_pk = Secp256k1Affine::from(g * wrong_sk);
    (sk, wrong_pk, g)
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

/// Вычисляет digest для public inputs (Poseidon hash)
fn compute_digest(sk_raw: u64, pk: &Secp256k1Affine, token_type: Fr, private_note_sum: Fr, vault_rand_val: Fr) -> Fr {
    let deposit_identifier_data_sum = token_type + private_note_sum + vault_rand_val;

    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes().to_vec()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes().to_vec()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes().to_vec()[22..]);

    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes().to_vec()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes().to_vec()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes().to_vec()[22..]);

    let key_data_sum = (sk_raw as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_data_sum = Fr::from_u128(key_data_sum);

    poseidon_hash([key_data_sum, deposit_identifier_data_sum])
}

/// Проверяет схему через MockProver
///
/// Сигнатура DarkDexCircuit::new после poseidon_integration:
/// (token_type, private_note_sum, vault_rand_val, sk, pk, g)
/// Public inputs: [private_note_sum, token_type, digest]
pub fn check_circuit(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    vault_rand_val: u64,
    sk_raw: u64,  // raw sk value for digest computation
) -> CircuitResult {
    ensure_working_directory();

    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);
    let vault_rand_val_fr = Fr::from(vault_rand_val);

    let digest = compute_digest(sk_raw, &pk, token_type_fr, private_note_sum_fr, vault_rand_val_fr);

    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(vault_rand_val_fr),
        Some(sk),
        Some(pk),
        Some(g),
    );

    // Public inputs: [private_note_sum, token_type, digest]
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
///
/// circuit_* - значения которые идут в circuit
/// digest_* - значения для вычисления digest (могут отличаться для теста атаки)
pub fn check_circuit_with_custom_digest(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    circuit_token: u64,
    circuit_sum: u64,
    circuit_vault: u64,
    sk_raw: u64,
    digest_token: u64,
    digest_sum: u64,
    digest_vault: u64,
) -> CircuitResult {
    ensure_working_directory();

    let circuit_token_fr = Fr::from(circuit_token);
    let circuit_sum_fr = Fr::from(circuit_sum);
    let circuit_vault_fr = Fr::from(circuit_vault);

    // Вычисляем digest с ДРУГИМИ значениями (для теста атаки)
    let digest_token_fr = Fr::from(digest_token);
    let digest_sum_fr = Fr::from(digest_sum);
    let digest_vault_fr = Fr::from(digest_vault);
    let digest = compute_digest(sk_raw, &pk, digest_token_fr, digest_sum_fr, digest_vault_fr);

    let circuit = DarkDexCircuit::new(
        Some(circuit_token_fr),
        Some(circuit_sum_fr),
        Some(circuit_vault_fr),
        Some(sk),
        Some(pk),
        Some(g),
    );

    // Public inputs используют circuit значения для token/sum, но чужой digest
    let public_inputs = vec![
        circuit_sum_fr,
        circuit_token_fr,
        digest,  // Digest от других значений!
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

