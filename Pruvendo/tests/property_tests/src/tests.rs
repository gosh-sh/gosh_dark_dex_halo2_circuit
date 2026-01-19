//! Property-based тесты для DarkDEX схемы
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Новая архитектура схемы:
//! - sk: секретный ключ (Fr)
//! - sk_commitment = poseidon_hash([sk, 0])
//! - digest = poseidon_hash([sk_commitment, private_note_sum, token_type, sk])
//! - Public inputs: [private_note_sum, token_type, digest]

use proptest::prelude::*;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::helpers::{
    check_circuit_with_mock, check_circuit_with_wrong_commitment,
    compute_sk_commitment, compute_digest,
};

// Конфигурация proptest: MockProver теперь быстрый (k=8 вместо k=18)
fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 50, // Увеличено т.к. k=8 намного быстрее
        timeout: 300_000, // 5 минут на весь тест
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    // ============================================================
    // P1: COMPLETENESS - валидные данные всегда проходят
    // ============================================================

    /// Для любого секретного ключа sk схема должна успешно верифицироваться
    /// при правильно вычисленном sk_commitment = poseidon(sk, 0)
    #[test]
    fn prop_valid_sk_always_verifies(
        sk_val in 1u64..1_000_000u64,
        token_type in 1u64..1000u64,
        note_sum in 1u64..1_000_000u64,
    ) {
        let sk = Fr::from(sk_val);
        let result = check_circuit_with_mock(sk, token_type, note_sum);

        prop_assert!(
            result.is_ok(),
            "Valid sk should always verify, got: {:?}", result
        );
    }

    // ============================================================
    // P2: SOUNDNESS - неверный sk_commitment отклоняется
    // ============================================================

    /// Если sk_commitment вычислен неправильно (от другого sk),
    /// схема должна отклонить такой witness.
    #[test]
    fn prop_wrong_commitment_fails(
        sk_val in 1u64..100_000u64,
        wrong_sk_val in 100_001u64..200_000u64,
        token_type in 1u64..1000u64,
        note_sum in 1u64..1_000_000u64,
    ) {
        let sk = Fr::from(sk_val);
        let wrong_sk = Fr::from(wrong_sk_val);
        let wrong_commitment = compute_sk_commitment(wrong_sk);

        let result = check_circuit_with_wrong_commitment(
            sk, wrong_commitment, token_type, note_sum
        );

        prop_assert!(
            result.is_constraint_violation(),
            "Wrong commitment should fail, got: {:?}", result
        );
    }

    // ============================================================
    // P3: DETERMINISM - одинаковые входы → одинаковый результат
    // ============================================================

    /// Схема детерминистична
    #[test]
    fn prop_determinism(
        sk_val in 1u64..100_000u64,
        token_type in 1u64..1000u64,
        note_sum in 1u64..100_000u64,
    ) {
        let sk = Fr::from(sk_val);

        let result1 = check_circuit_with_mock(sk, token_type, note_sum);
        let result2 = check_circuit_with_mock(sk, token_type, note_sum);

        prop_assert_eq!(
            result1.is_ok(), result2.is_ok(),
            "Same inputs should give same result"
        );
    }

    // ============================================================
    // P4: EDGE CASES - граничные значения
    // ============================================================

    /// Граничные значения sk не должны ломать схему
    #[test]
    fn prop_boundary_sk_values(
        sk_val in prop::strategy::Union::new([
            Just(1u64),           // минимальный
            Just(u64::MAX),       // максимальный
            Just(u64::MAX / 2),   // середина
        ].into_iter()),
        token_type in 1u64..100u64,
        note_sum in 1u64..1000u64,
    ) {
        let sk = Fr::from(sk_val);
        let result = check_circuit_with_mock(sk, token_type, note_sum);

        // Результат должен быть либо Ok либо ConstraintViolation, но НЕ panic
        prop_assert!(
            result.is_ok() || result.is_constraint_violation(),
            "Boundary sk should not cause unexpected errors: {:?}", result
        );
    }

    // ============================================================
    // P5: POSEIDON CONSISTENCY - хеш детерминистичен
    // ============================================================

    #[test]
    fn prop_poseidon_commitment_consistency(
        sk_val in 1u64..1_000_000u64,
    ) {
        let sk = Fr::from(sk_val);
        let c1 = compute_sk_commitment(sk);
        let c2 = compute_sk_commitment(sk);
        prop_assert_eq!(c1, c2, "Same sk should produce same commitment");
    }

    #[test]
    fn prop_different_sk_different_commitment(
        sk1_val in 1u64..500_000u64,
        sk2_val in 500_001u64..1_000_000u64,
    ) {
        let sk1 = Fr::from(sk1_val);
        let sk2 = Fr::from(sk2_val);
        let c1 = compute_sk_commitment(sk1);
        let c2 = compute_sk_commitment(sk2);
        prop_assert_ne!(c1, c2, "Different sk should produce different commitment");
    }

    // ============================================================
    // P6: DIGEST BINDING - digest связывает все inputs
    // ============================================================

    #[test]
    fn prop_different_token_different_digest(
        sk_val in 1u64..100_000u64,
        token1 in 1u64..500u64,
        token2 in 501u64..1000u64,
        note_sum in 1u64..1000u64,
    ) {
        let sk = Fr::from(sk_val);
        let d1 = compute_digest(sk, Fr::from(token1), Fr::from(note_sum));
        let d2 = compute_digest(sk, Fr::from(token2), Fr::from(note_sum));
        prop_assert_ne!(d1, d2, "Different token should produce different digest");
    }

    #[test]
    fn prop_different_sum_different_digest(
        sk_val in 1u64..100_000u64,
        token in 1u64..100u64,
        sum1 in 1u64..500_000u64,
        sum2 in 500_001u64..1_000_000u64,
    ) {
        let sk = Fr::from(sk_val);
        let d1 = compute_digest(sk, Fr::from(token), Fr::from(sum1));
        let d2 = compute_digest(sk, Fr::from(token), Fr::from(sum2));
        prop_assert_ne!(d1, d2, "Different sum should produce different digest");
    }
}


// ============================================================
// Детерминированные тесты (не property-based)
// ============================================================

/// Детерминизм - один и тот же вход даёт одинаковый результат
#[test]
fn test_determinism() {
    let sk = Fr::from(42u64);
    let result1 = check_circuit_with_mock(sk, 1, 1000);
    let result2 = check_circuit_with_mock(sk, 1, 1000);
    assert_eq!(result1, result2, "Same inputs should produce same results");
    assert!(result1.is_ok());
}

/// Граничный случай: минимальный секретный ключ
#[test]
fn test_edge_case_min_sk() {
    let sk = Fr::from(1u64);
    let result = check_circuit_with_mock(sk, 1, 1);
    assert!(result.is_ok(), "Minimum sk should work: {:?}", result);
}

/// Граничный случай: большой секретный ключ
#[test]
fn test_edge_case_large_sk() {
    let sk = Fr::from(u64::MAX / 2);
    let result = check_circuit_with_mock(sk, 1, 1000);
    assert!(result.is_ok(), "Large sk should work: {:?}", result);
}

/// Граничный случай: нулевой token_type
#[test]
fn test_edge_case_zero_token() {
    let sk = Fr::from(12345u64);
    let result = check_circuit_with_mock(sk, 0, 1000);
    assert!(result.is_ok(), "Zero token_type should work: {:?}", result);
}

/// Граничный случай: нулевая сумма
#[test]
fn test_edge_case_zero_sum() {
    let sk = Fr::from(12345u64);
    let result = check_circuit_with_mock(sk, 1, 0);
    assert!(result.is_ok(), "Zero sum should work: {:?}", result);
}

/// Граничный случай: большие значения token_type и sum
#[test]
fn test_edge_case_large_values() {
    let sk = Fr::from(12345u64);
    let large_token = u64::MAX / 4;
    let large_sum = u64::MAX / 4;
    let result = check_circuit_with_mock(sk, large_token, large_sum);
    assert!(result.is_ok(), "Large values should work: {:?}", result);
}

/// Тест: одинаковые sk дают одинаковые commitment
#[test]
fn test_commitment_determinism() {
    let sk = Fr::from(42u64);
    let c1 = compute_sk_commitment(sk);
    let c2 = compute_sk_commitment(sk);
    assert_eq!(c1, c2, "Same sk should produce same commitment");
}

/// Тест: разные sk дают разные commitment
#[test]
fn test_different_sk_different_commitment() {
    let sk1 = Fr::from(42u64);
    let sk2 = Fr::from(43u64);
    let c1 = compute_sk_commitment(sk1);
    let c2 = compute_sk_commitment(sk2);
    assert_ne!(c1, c2, "Different sk should produce different commitment");
}

// ============================================================
// SOUNDNESS тесты
// ============================================================

/// Soundness: неправильный commitment должен отклоняться
#[test]
fn test_soundness_wrong_commitment() {
    let sk = Fr::from(12345u64);
    let wrong_sk = Fr::from(54321u64);
    let wrong_commitment = compute_sk_commitment(wrong_sk);

    let result = check_circuit_with_wrong_commitment(sk, wrong_commitment, 1, 1000);
    assert!(
        result.is_constraint_violation(),
        "Wrong commitment should fail: {:?}", result
    );
}

/// Soundness: commitment от нуля отличается от commitment от 1
#[test]
fn test_commitment_zero_vs_one() {
    let c0 = compute_sk_commitment(Fr::from(0u64));
    let c1 = compute_sk_commitment(Fr::from(1u64));
    assert_ne!(c0, c1, "Commitment(0) should differ from Commitment(1)");
}

// ============================================================
// DIGEST тесты
// ============================================================

/// Digest детерминистичен
#[test]
fn test_digest_determinism() {
    let sk = Fr::from(42u64);
    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);
    let d1 = compute_digest(sk, token, sum);
    let d2 = compute_digest(sk, token, sum);
    assert_eq!(d1, d2, "Same inputs should produce same digest");
}

/// Разные token_type дают разные digest
#[test]
fn test_different_token_different_digest() {
    let sk = Fr::from(42u64);
    let sum = Fr::from(1000u64);
    let d1 = compute_digest(sk, Fr::from(1u64), sum);
    let d2 = compute_digest(sk, Fr::from(2u64), sum);
    assert_ne!(d1, d2, "Different token should produce different digest");
}

/// Разные sum дают разные digest
#[test]
fn test_different_sum_different_digest() {
    let sk = Fr::from(42u64);
    let token = Fr::from(1u64);
    let d1 = compute_digest(sk, token, Fr::from(1000u64));
    let d2 = compute_digest(sk, token, Fr::from(2000u64));
    assert_ne!(d1, d2, "Different sum should produce different digest");
}

/// Разные sk дают разные digest
#[test]
fn test_different_sk_different_digest() {
    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);
    let d1 = compute_digest(Fr::from(42u64), token, sum);
    let d2 = compute_digest(Fr::from(43u64), token, sum);
    assert_ne!(d1, d2, "Different sk should produce different digest");
}

