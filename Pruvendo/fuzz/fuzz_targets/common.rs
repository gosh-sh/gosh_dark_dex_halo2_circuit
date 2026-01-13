//! Общие функции для fuzz targets
//!
//! Содержит helpers для работы с ZKP схемой в контексте fuzzing.

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
    },
    arithmetic::CurveAffine,
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

/// Проверяет схему через MockProver
///
/// Сигнатура DarkDexCircuit::new:
/// (token_type: Option<F>, private_note_sum: Option<F>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>)
pub fn check_circuit(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    public_token: u64,
    public_sum: u64,
) -> CircuitResult {
    ensure_working_directory();

    let circuit = DarkDexCircuit::<Fr>::new(
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(pk),
        Some(g),
    );

    let public_inputs = vec![
        Fr::from(public_token),
        Fr::from(public_sum),
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

