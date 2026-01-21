//! Вспомогательные функции для property-тестов
//!
//! Версия: poseidon_instead_of_ecc (без ECC, только Poseidon)
//!
//! Новая архитектура схемы:
//! - sk: секретный ключ (Fr)
//! - sk_commitment = poseidon_hash([sk, 0])
//! - digest = poseidon_hash([sk_commitment, private_note_sum, token_type, sk])
//! - Public inputs: [private_note_sum, token_type, digest]
//!
//! ВАЖНО: Тесты необходимо запускать из корня проекта!
//! cargo test --manifest-path Pruvendo/tests/property_tests/Cargo.toml --release

use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};

use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Fr,
};

use std::sync::Once;

static INIT: Once = Once::new();

/// Устанавливает рабочую директорию на корень проекта
/// (где находится config/circuit.config)
pub fn ensure_working_directory() {
    INIT.call_once(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
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

/// Вычисляет sk_commitment = poseidon_hash([sk, 0])
pub fn compute_sk_commitment(sk: Fr) -> Fr {
    poseidon_hash([sk, Fr::zero()])
}

/// Вычисляет digest = poseidon_hash([sk_commitment, private_note_sum, token_type, sk])
pub fn compute_digest(sk: Fr, token_type: Fr, private_note_sum: Fr) -> Fr {
    let sk_commitment = compute_sk_commitment(sk);
    poseidon_hash([sk_commitment, private_note_sum, token_type, sk])
}

/// Проверяет схему DarkDEX через MockProver (новая архитектура)
///
/// # Arguments
/// * `sk` - секретный ключ (Fr)
/// * `token_type` - тип токена
/// * `private_note_sum` - сумма приватных нот
///
/// # Returns
/// CircuitResult с результатом проверки
pub fn check_circuit_with_mock(
    sk: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> CircuitResult {
    ensure_working_directory();

    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);
    let sk_commitment = compute_sk_commitment(sk);

    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(sk),
        Some(sk_commitment),
    );

    // Public inputs: [private_note_sum, token_type, digest]
    let digest = compute_digest(sk, token_type_fr, private_note_sum_fr);
    let pub_inputs = vec![vec![
        private_note_sum_fr,
        token_type_fr,
        digest,
    ]];

    // k=8 для новой схемы (была k=18)
    match MockProver::run(8, &circuit, pub_inputs) {
        Ok(prover) => match prover.verify() {
            Ok(()) => CircuitResult::Ok,
            Err(errors) => CircuitResult::ConstraintViolation(format!("{:?}", errors)),
        },
        Err(e) => CircuitResult::Error(format!("{:?}", e)),
    }
}

/// Проверяет схему с неправильным sk_commitment (для negative tests)
pub fn check_circuit_with_wrong_commitment(
    sk: Fr,
    wrong_commitment: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> CircuitResult {
    ensure_working_directory();

    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);

    let circuit = DarkDexCircuit::new(
        Some(token_type_fr),
        Some(private_note_sum_fr),
        Some(sk),
        Some(wrong_commitment), // Неправильный commitment!
    );

    // Digest вычисляем с wrong_commitment
    let digest = poseidon_hash([wrong_commitment, private_note_sum_fr, token_type_fr, sk]);
    let pub_inputs = vec![vec![
        private_note_sum_fr,
        token_type_fr,
        digest,
    ]];

    match MockProver::run(8, &circuit, pub_inputs) {
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

use gosh_dark_dex_halo2_circuit::prover::{generate_proof, read_kzg_params, generate_verififcation_key_without_witness};
use gosh_dark_dex_halo2_circuit::verifier::verify_proof_;

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

/// Вычисляет public inputs для схемы
/// Public inputs: [private_note_sum, token_type, digest]
pub fn compute_public_inputs(
    sk: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> Vec<Fr> {
    let token_type_fr = Fr::from(token_type);
    let private_note_sum_fr = Fr::from(private_note_sum);
    let digest = compute_digest(sk, token_type_fr, private_note_sum_fr);
    vec![private_note_sum_fr, token_type_fr, digest]
}

/// Генерирует proof и верифицирует его с теми же public inputs
///
/// ВАЖНО: Используем generate_verififcation_key_without_witness вместо
/// verification_key_from_path, т.к. сериализованный VK несовместим
/// с VK созданным при генерации proof.
pub fn generate_and_verify_proof(
    sk: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> VerifyResult {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    // Создаём VK "on the fly" - это гарантирует совместимость с proof
    let vk = generate_verififcation_key_without_witness(&params);

    let sk_commitment = compute_sk_commitment(sk);
    let mut pub_inputs = compute_public_inputs(sk, token_type, private_note_sum);

    let proof = generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(sk_commitment),
        &mut pub_inputs,
    );

    if verify_proof_(&params, &proof, &vk, pub_inputs) {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

/// Генерирует proof и возвращает его вместе с public inputs
pub fn generate_proof_with_pub_inputs(
    sk: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> (Vec<u8>, Vec<Fr>) {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    let sk_commitment = compute_sk_commitment(sk);
    let mut pub_inputs = compute_public_inputs(sk, token_type, private_note_sum);

    let proof = generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(sk_commitment),
        &mut pub_inputs,
    );

    (proof, pub_inputs)
}

/// Верифицирует заданный proof с заданными public inputs
///
/// ВАЖНО: Используем generate_verififcation_key_without_witness вместо
/// verification_key_from_path для совместимости с proof.
pub fn verify_existing_proof_with_pub_inputs(
    proof: &[u8],
    pub_inputs: Vec<Fr>,
) -> VerifyResult {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    // Создаём VK "on the fly" - это гарантирует совместимость с proof
    let vk = generate_verififcation_key_without_witness(&params);

    if verify_proof_(&params, proof, &vk, pub_inputs) {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

/// Генерирует proof для тестов
pub fn generate_proof_for_test(
    sk: Fr,
    token_type: u64,
    private_note_sum: u64,
) -> Vec<u8> {
    ensure_working_directory();

    let params = read_kzg_params("kzg_params.bin".to_string());
    let sk_commitment = compute_sk_commitment(sk);
    let mut pub_inputs_out = Vec::new();

    generate_proof(
        &params,
        Some(Fr::from(token_type)),
        Some(Fr::from(private_note_sum)),
        Some(sk),
        Some(sk_commitment),
        &mut pub_inputs_out,
    )
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn test_sk_commitment_consistency() {
        let sk = Fr::from(12345u64);
        let commitment1 = compute_sk_commitment(sk);
        let commitment2 = compute_sk_commitment(sk);
        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_digest_consistency() {
        let sk = Fr::from(12345u64);
        let token = Fr::from(1u64);
        let sum = Fr::from(1000u64);
        let digest1 = compute_digest(sk, token, sum);
        let digest2 = compute_digest(sk, token, sum);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_different_sk_different_commitment() {
        let sk1 = Fr::from(12345u64);
        let sk2 = Fr::from(67890u64);
        let c1 = compute_sk_commitment(sk1);
        let c2 = compute_sk_commitment(sk2);
        assert_ne!(c1, c2);
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
/// NOTE: После poseidon_instead_of_ecc многие BC закрылись (BC-002, BC-004, BC-007)
pub mod known_bugs {
    use super::BugCandidateInfo;

    pub const BC_001: BugCandidateInfo = BugCandidateInfo {
        id: "BC-001",
        title: "Panic при некорректном VK bytes",
        location: "halo2curves (upstream)",
        severity: "Medium",
    };

    // BC-002: CLOSED - g = identity point больше не используется (нет ECC)

    pub const BC_003: BugCandidateInfo = BugCandidateInfo {
        id: "BC-003",
        title: "shl_overflow при corrupted KZG header",
        location: "halo2_proofs (upstream)",
        severity: "Medium",
    };

    // BC-004: CLOSED - limb overflow больше не актуален (нет limbs decomposition)

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
        severity: "Low (не soundness bug)",
    };

    // BC-007: CLOSED - deposit_sum/vault_rand_val коллизии, vault_rand_val убран
    // BC-008: NOT A BUG - model artifact в Quint модели (split с одинаковыми amounts)

    pub const BC_009: BugCandidateInfo = BugCandidateInfo {
        id: "BC-009",
        title: "Timing side-channel в verifier: valid vs wrong_digest timing deviation",
        location: "verifier::verify_proof_",
        severity: "Medium (требует анализа эксплуатируемости)",
    };

    // BC-007: CLOSED - deposit_sum formula изменилась, vault_rand_val убран
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

