//! Вспомогательные функции для property-тестов
//!
//! Переиспользует логику из оригинальных тестов (src/test.rs),
//! адаптируя её для property-based testing.
//!
//! ВАЖНО: Тесты необходимо запускать из корня проекта!
//! cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release

use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
        ff::PrimeField,
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
/// * `sk_raw` - raw значение sk (u64) для вычисления digest
/// * `_unused` - не используется (для обратной совместимости)
///
/// # Returns
/// CircuitResult с результатом проверки
pub fn check_circuit_with_mock(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    sk_raw: u64,
    _unused: u64,
) -> CircuitResult {
    // Делегируем в check_circuit_with_mock_and_vault с default vault_rand_val
    check_circuit_with_mock_and_vault(sk, pk, g, token_type, private_note_sum, 111, sk_raw)
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

/// Проверяет схему с явным vault_rand_val
///
/// Версия check_circuit_with_mock с поддержкой vault_rand_val для тестирования
/// edge cases связанных с vault.
///
/// # Arguments
/// * `sk_raw` - raw значение sk (u64) для вычисления digest
pub fn check_circuit_with_mock_and_vault(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    vault_rand_val: u64,
    sk_raw: u64,
) -> CircuitResult {
    ensure_working_directory();

    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);
    let vault_rand_val_fr = Fr::from(vault_rand_val);

    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(vault_rand_val_fr),
        Some(sk),
        Some(pk),
        Some(g),
    );

    // После poseidon_integration: public inputs = [private_note_sum, token_type, digest]
    let digest = compute_digest(sk_raw, &pk, token_type_fr, private_note_sum_fr, vault_rand_val_fr);
    let pub_inputs = vec![vec![
        private_note_sum_fr,
        token_type_fr,
        digest,
    ]];

    match MockProver::run(18, &circuit, pub_inputs) {
        Ok(prover) => match prover.verify() {
            Ok(()) => CircuitResult::Ok,
            Err(errors) => CircuitResult::ConstraintViolation(format!("{:?}", errors)),
        },
        Err(e) => CircuitResult::Error(format!("{:?}", e)),
    }
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

/// Генерирует proof и верифицирует его с теми же public inputs
///
/// Это полный flow: prover -> verifier
/// После poseidon_integration public inputs вычисляются внутри схемы
pub fn generate_and_verify_proof(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    _verify_token: u64,  // Deprecated: не используется после poseidon_integration
    _verify_sum: u64,    // Deprecated: не используется после poseidon_integration
) -> VerifyResult {
    ensure_working_directory();

    // Загружаем параметры
    let params = read_kzg_params("kzg_params.bin".to_string());
    let vk = verification_key_from_path("verification_key.bin".to_string());

    // После poseidon_integration добавлен vault_rand_val
    let vault_rand_val = 111u64;

    // Вычисляем public inputs
    let mut pub_inputs = compute_public_inputs(sk, pk, token_type, private_note_sum, vault_rand_val);

    // Генерируем proof
    let proof = generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(Fr::from(vault_rand_val)),
        Some(sk),
        Some(pk),
        Some(g),
        &mut pub_inputs,
    );

    // Верифицируем с теми же public inputs
    if verify_proof_(&params, &proof, &vk, pub_inputs) {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

/// Вычисляет public inputs для схемы
/// Public inputs: [private_note_sum, token_type, poseidon_digest]
pub fn compute_public_inputs(
    sk: Fq,
    pk: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
    vault_rand_val: u64,
) -> Vec<Fr> {
    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);
    let vault_rand_val_fr = Fr::from(vault_rand_val);

    // deposit_identifier_data_sum = token_type + private_note_sum + vault_rand_val
    let deposit_identifier_data_sum = token_type_fr + private_note_sum_fr + vault_rand_val_fr;

    // Вычисляем key_data_sum из sk и pk
    let sk_raw = {
        let bytes = sk.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };

    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes().to_vec()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes().to_vec()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes().to_vec()[22..]);

    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes().to_vec()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes().to_vec()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes().to_vec()[22..]);

    let key_data_sum = (sk_raw as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2
        + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_data_sum_fr = Fr::from_u128(key_data_sum);

    // Вычисляем poseidon digest
    let digest = poseidon_hash([key_data_sum_fr, deposit_identifier_data_sum]);

    vec![private_note_sum_fr, token_type_fr, digest]
}

/// Генерирует proof и возвращает его вместе с public inputs
pub fn generate_proof_with_pub_inputs(
    sk: Fq,
    pk: Secp256k1Affine,
    g: Secp256k1Affine,
    token_type: u64,
    private_note_sum: u64,
) -> (Vec<u8>, Vec<Fr>) {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    let vault_rand_val = 111u64;

    // Вычисляем public inputs
    let mut pub_inputs = compute_public_inputs(sk, pk, token_type, private_note_sum, vault_rand_val);

    let proof = generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(Fr::from(vault_rand_val)),
        Some(sk),
        Some(pk),
        Some(g),
        &mut pub_inputs,
    );

    (proof, pub_inputs)
}

/// Верифицирует заданный proof с заданными public inputs (poseidon digest)
pub fn verify_existing_proof_with_pub_inputs(
    proof: &[u8],
    pub_inputs: Vec<Fr>,
) -> VerifyResult {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    let vk = verification_key_from_path("verification_key.bin".to_string());

    if verify_proof_(&params, proof, &vk, pub_inputs) {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

/// Deprecated: Верифицирует proof - для совместимости со старыми тестами
/// После poseidon_integration эта функция НЕ работает корректно,
/// т.к. public inputs теперь включают poseidon digest
#[deprecated(note = "Use verify_existing_proof_with_pub_inputs instead")]
pub fn verify_existing_proof(
    _proof: &[u8],
    _verify_token: u64,
    _verify_sum: u64,
) -> VerifyResult {
    // Не можем верифицировать без знания sk для вычисления poseidon digest
    VerifyResult::Invalid
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

    // После poseidon_integration добавлен vault_rand_val
    let vault_rand_val = 111u64;
    let mut pub_inputs_out = Vec::new();

    generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(Fr::from(vault_rand_val)),
        Some(sk),
        Some(pk),
        Some(g),
        &mut pub_inputs_out,
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

// ============================================================================
// BUG CANDIDATE TRACKING - Система отслеживания потенциальных багов
// ============================================================================
// NOTE: We use "Bug Candidate" (BC) instead of "Bug" because we cannot be
// 100% certain something is a bug until fully verified. See AGENTS.md.

/// Статус bug candidate
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BugCandidateStatus {
    /// Bug candidate воспроизводится в текущей версии
    Reproduced,
    /// Bug candidate исправлен / не подтвердился
    Fixed,
    /// Статус неизвестен (тест пропущен)
    Skipped,
}

// Backwards compatibility alias
pub type BugStatus = BugCandidateStatus;

/// Информация о bug candidate
pub struct BugCandidateInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub location: &'static str,
    pub severity: &'static str,
}

// Backwards compatibility alias
pub type BugInfo = BugCandidateInfo;

/// Известные bug candidates
pub mod known_bugs {
    use super::BugCandidateInfo;

    pub const BC_001: BugCandidateInfo = BugCandidateInfo {
        id: "BC-001",
        title: "Panic при некорректном VK bytes",
        location: "halo2curves (upstream)",
        severity: "Medium",
    };

    pub const BC_002: BugCandidateInfo = BugCandidateInfo {
        id: "BC-002",
        title: "Panic при g = identity point",
        location: "subtle crate (upstream)",
        severity: "Medium",
    };

    pub const BC_003: BugCandidateInfo = BugCandidateInfo {
        id: "BC-003",
        title: "shl_overflow при corrupted KZG header",
        location: "halo2_proofs (upstream) - дубликат BC-005",
        severity: "Medium",
    };

    pub const BC_004: BugCandidateInfo = BugCandidateInfo {
        id: "BC-004",
        title: "shl_overflow в commitment.rs",
        location: "halo2_proofs (upstream)",
        severity: "Medium",
    };

    pub const BC_005: BugCandidateInfo = BugCandidateInfo {
        id: "BC-005",
        title: "shl_overflow в domain.rs",
        location: "halo2_proofs (upstream)",
        severity: "Medium",
    };

    pub const BC_006: BugCandidateInfo = BugCandidateInfo {
        id: "BC-006",
        title: "Non-canonical field elements принимаются при десериализации",
        location: "halo2curves SerdeFormat::RawBytesUnchecked",
        severity: "Low (не soundness bug candidate)",
    };

    pub const BC_007: BugCandidateInfo = BugCandidateInfo {
        id: "BC-007",
        title: "deposit_sum коллизии из-за аддитивной формулы",
        location: "circuit.rs deposit_sum = token + sum + vault",
        severity: "Low (not exploitable - token and sum are public inputs)",
    };

    // Backwards compatibility aliases
    pub const BUG_001: &BugCandidateInfo = &BC_001;
    pub const BUG_002: &BugCandidateInfo = &BC_002;
    pub const BUG_003: &BugCandidateInfo = &BC_003;
    pub const BUG_004: &BugCandidateInfo = &BC_004;
    pub const BUG_005: &BugCandidateInfo = &BC_005;
    pub const BUG_006: &BugCandidateInfo = &BC_006;
}

/// Логирует результат теста bug candidate
pub fn report_bug_candidate_status(bc: &BugCandidateInfo, status: BugCandidateStatus) {
    match status {
        BugCandidateStatus::Reproduced => {
            eprintln!("┌─────────────────────────────────────────────────────────────┐");
            eprintln!("│ {} STATUS: ⚠️  REPRODUCED", bc.id);
            eprintln!("│ Title: {}", bc.title);
            eprintln!("│ Location: {}", bc.location);
            eprintln!("│ Severity: {}", bc.severity);
            eprintln!("└─────────────────────────────────────────────────────────────┘");
        }
        BugCandidateStatus::Fixed => {
            eprintln!("┌─────────────────────────────────────────────────────────────┐");
            eprintln!("│ {} STATUS: ✅ NOT CONFIRMED / FIXED", bc.id);
            eprintln!("│ Title: {}", bc.title);
            eprintln!("│ The bug candidate no longer reproduces in current version");
            eprintln!("└─────────────────────────────────────────────────────────────┘");
        }
        BugCandidateStatus::Skipped => {
            eprintln!("┌─────────────────────────────────────────────────────────────┐");
            eprintln!("│ {} STATUS: ⏭️  SKIPPED", bc.id);
            eprintln!("│ Title: {}", bc.title);
            eprintln!("│ Reason: Required files not found");
            eprintln!("└─────────────────────────────────────────────────────────────┘");
        }
    }
}

// Backwards compatibility alias
pub fn report_bug_status(bug: &BugInfo, status: BugStatus) {
    report_bug_candidate_status(bug, status);
}

/// Выполняет код и возвращает статус bug candidate
/// Если код паникует - bug candidate воспроизводится
/// Если код выполняется успешно - bug candidate не подтвердился
pub fn check_bug_candidate_status<F, R>(f: F) -> BugCandidateStatus
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(_) => BugCandidateStatus::Fixed,
        Err(_) => BugCandidateStatus::Reproduced,
    }
}

// Backwards compatibility alias
pub fn check_bug_status<F, R>(f: F) -> BugStatus
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    check_bug_candidate_status(f)
}

