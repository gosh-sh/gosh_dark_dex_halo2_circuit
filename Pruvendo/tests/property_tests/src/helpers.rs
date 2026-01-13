//! Вспомогательные функции для property-тестов
//!
//! Переиспользует логику из оригинальных тестов (src/test.rs),
//! адаптируя её для property-based testing.
//!
//! ВАЖНО: Тесты необходимо запускать из корня проекта!
//! cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
    },
};

use std::sync::Once;

static INIT: Once = Once::new();

/// Устанавливает рабочую директорию на корень проекта
/// (где находится config/circuit.config)
pub fn ensure_working_directory() {
    INIT.call_once(|| {
        // Находим корень проекта по Cargo.toml основного пакета
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        // Pruvendo/tests/property_tests -> корень проекта (3 уровня вверх)
        let project_root = std::path::Path::new(manifest_dir)
            .parent() // Pruvendo/tests
            .and_then(|p| p.parent()) // Pruvendo
            .and_then(|p| p.parent()) // корень
            .expect("Failed to find project root");

        std::env::set_current_dir(project_root)
            .expect("Failed to set working directory to project root");
    });
}

/// Результат проверки схемы
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitResult {
    /// Схема прошла верификацию
    Ok,
    /// Схема не прошла верификацию (constraint violation)
    ConstraintViolation(String),
    /// Ошибка при создании/запуске схемы
    Error(String),
}

impl CircuitResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, CircuitResult::Ok)
    }

    pub fn is_constraint_violation(&self) -> bool {
        matches!(self, CircuitResult::ConstraintViolation(_))
    }
}

/// Проверяет схему DarkDEX через MockProver
///
/// # Arguments
/// * `sk` - секретный ключ (secp256k1 scalar)
/// * `pk` - публичный ключ (точка на кривой)
/// * `g` - генератор кривой
/// * `token_type` - тип токена (witness)
/// * `private_note_sum` - сумма приватных нот (witness)
/// * `public_token` - тип токена (public input)
/// * `public_sum` - сумма (public input)
///
/// # Returns
/// CircuitResult с результатом проверки
pub fn check_circuit_with_mock(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    public_token: u64,
    public_sum: u64,
) -> CircuitResult {
    // Убедимся что рабочая директория установлена на корень проекта
    ensure_working_directory();

    let circuit = DarkDexCircuit::<Fr>::new(
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(pk),
        Some(g),
    );

    let pub_inputs = vec![vec![Fr::from(public_token), Fr::from(public_sum)]];

    // k=18 как в оригинальных тестах
    match MockProver::run(18, &circuit, pub_inputs) {
        Ok(prover) => match prover.verify() {
            Ok(()) => CircuitResult::Ok,
            Err(errors) => CircuitResult::ConstraintViolation(format!("{:?}", errors)),
        },
        Err(e) => CircuitResult::Error(format!("{:?}", e)),
    }
}

/// Генерирует валидную пару ключей из секретного ключа
///
/// pk = sk * G (скалярное умножение на генератор)
pub fn generate_valid_keypair(sk_value: u64) -> (Fq, Secp256k1Affine, Secp256k1Affine) {
    let sk = Fq::from(sk_value);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(g * sk);
    (sk, pk, g)
}

/// Генерирует НЕвалидную пару ключей (pk от другого sk)
pub fn generate_invalid_keypair(
    sk_value: u64,
    wrong_sk_value: u64,
) -> (Fq, Secp256k1Affine, Secp256k1Affine) {
    let sk = Fq::from(sk_value);
    let g = Secp256k1Affine::generator();
    // pk вычислен от ДРУГОГО секретного ключа
    let wrong_pk = Secp256k1Affine::from(g * Fq::from(wrong_sk_value));
    (sk, wrong_pk, g)
}

// ============================================================
// Функции для полного proof/verify flow
// ============================================================

use gosh_dark_dex_halo2_circuit::prover::{generate_proof, read_kzg_params};
use gosh_dark_dex_halo2_circuit::verifier::{verification_key_from_path, verify_proof_};

/// Результат верификации proof
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyResult {
    /// Proof верифицирован успешно
    Valid,
    /// Proof не прошёл верификацию
    Invalid,
    /// Ошибка при верификации (panic, corrupted data)
    Error(String),
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, VerifyResult::Invalid)
    }
}

/// Генерирует proof и верифицирует его с заданными public inputs
///
/// Это полный flow: prover -> verifier
pub fn generate_and_verify_proof(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    verify_token: u64,
    verify_sum: u64,
) -> VerifyResult {
    ensure_working_directory();

    // Загружаем параметры
    let params = read_kzg_params("kzg_params.bin".to_string());
    let vk = verification_key_from_path("verification_key.bin".to_string());

    // Генерируем proof с оригинальными public values
    let proof = generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(pk),
        Some(g),
        token_type,
        private_note_sum,
    );

    // Верифицируем с (возможно другими) public inputs
    let pub_inputs = vec![Fr::from(verify_token), Fr::from(verify_sum)];

    if verify_proof_(&params, &proof, &vk, pub_inputs) {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

/// Верифицирует заданный proof с заданными public inputs
pub fn verify_existing_proof(
    proof: &[u8],
    verify_token: u64,
    verify_sum: u64,
) -> VerifyResult {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    let vk = verification_key_from_path("verification_key.bin".to_string());
    let pub_inputs = vec![Fr::from(verify_token), Fr::from(verify_sum)];

    if verify_proof_(&params, proof, &vk, pub_inputs) {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

/// Генерирует proof и возвращает его вместе с public inputs
pub fn generate_proof_for_test(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
) -> Vec<u8> {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());

    generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(pk),
        Some(g),
        token_type,
        private_note_sum,
    )
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use halo2_base::halo2_proofs::arithmetic::CurveAffine;

    #[test]
    fn test_valid_keypair_generation() {
        let (_sk, pk, g) = generate_valid_keypair(12345);
        // pk должен быть точкой на кривой
        assert!(bool::from(pk.is_on_curve()));
        // g - стандартный генератор
        assert_eq!(g, Secp256k1Affine::generator());
    }

    #[test]
    fn test_invalid_keypair_generation() {
        let (_sk, wrong_pk, _g) = generate_invalid_keypair(12345, 67890);
        let (_, correct_pk, _) = generate_valid_keypair(12345);
        // wrong_pk должен отличаться от correct_pk
        assert_ne!(wrong_pk, correct_pk);
    }
}

