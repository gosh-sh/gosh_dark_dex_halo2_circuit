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
        sk_val in 1u64..u64::MAX,  // Full u64 range
        token_type in 0u64..u64::MAX,  // Full u64 range
        note_sum in 0u64..u64::MAX,  // Full u64 range
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
        sk_val in 1u64..u64::MAX/2,  // First half of u64 range
        wrong_sk_val in (u64::MAX/2)..u64::MAX,  // Second half - guaranteed different
        token_type in 0u64..u64::MAX,
        note_sum in 0u64..u64::MAX,
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
        sk_val in 1u64..u64::MAX,
        token_type in 0u64..u64::MAX,
        note_sum in 0u64..u64::MAX,
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
        sk_val in 1u64..u64::MAX,  // Full u64 range
    ) {
        let sk = Fr::from(sk_val);
        let c1 = compute_sk_commitment(sk);
        let c2 = compute_sk_commitment(sk);
        prop_assert_eq!(c1, c2, "Same sk should produce same commitment");
    }

    #[test]
    fn prop_different_sk_different_commitment(
        sk1_val in 1u64..u64::MAX/2,        // Full range, first half
        sk2_val in (u64::MAX/2)..u64::MAX,  // Full range, second half - guaranteed different
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
        sk_val in 1u64..u64::MAX,
        token1 in 0u64..u64::MAX/2,
        token2 in (u64::MAX/2)..u64::MAX,
        note_sum in 1u64..1000u64,
    ) {
        let sk = Fr::from(sk_val);
        let d1 = compute_digest(sk, Fr::from(token1), Fr::from(note_sum));
        let d2 = compute_digest(sk, Fr::from(token2), Fr::from(note_sum));
        prop_assert_ne!(d1, d2, "Different token should produce different digest");
    }

    #[test]
    fn prop_different_sum_different_digest(
        sk_val in 1u64..u64::MAX,
        token in 0u64..u64::MAX,
        sum1 in 0u64..u64::MAX/2,              // Full range, first half
        sum2 in (u64::MAX/2)..u64::MAX,        // Full range, second half - guaranteed different
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

// ============================================================
// FIELD WRAPAROUND TESTS
// ============================================================
// Tests for values close to field modulus to check for wraparound issues

/// Test with values close to field modulus
#[test]
fn test_large_values_near_modulus() {
    // bn256::Fr modulus is approximately 2^254
    // Use u64::MAX as large value (still within Fr)
    let large_sk = Fr::from(u64::MAX);
    let large_token = Fr::from(u64::MAX - 1);
    let large_sum = Fr::from(u64::MAX - 2);

    // Should compute without panics
    let commitment = compute_sk_commitment(large_sk);
    let digest = compute_digest(large_sk, large_token, large_sum);

    // Verify non-trivial results
    assert_ne!(commitment, Fr::zero(), "Commitment should not be zero");
    assert_ne!(digest, Fr::zero(), "Digest should not be zero");
}

/// Test field addition wraparound
#[test]
fn test_field_addition_wraparound() {
    // Fr::zero() - 1 should wrap to p-1 (largest field element)
    let max_minus_one = Fr::zero() - Fr::one();
    let back_to_zero = max_minus_one + Fr::one();

    assert_eq!(back_to_zero, Fr::zero(), "Field arithmetic should wrap correctly");

    // Hash should still work with wrapped values
    let digest = compute_digest(max_minus_one, Fr::from(1u64), Fr::from(1000u64));
    assert_ne!(digest, Fr::zero(), "Hash with wrapped value should work");
}

/// Verify that Fr::from(u64) doesn't wrap unexpectedly
#[test]
fn test_u64_to_fr_no_wrap() {
    // u64::MAX is much smaller than Fr modulus, so no wrapping should occur
    let a = Fr::from(u64::MAX);
    let b = Fr::from(u64::MAX - 1);

    // a - b should equal 1, not wrap
    let diff = a - b;
    assert_eq!(diff, Fr::one(), "u64::MAX - (u64::MAX-1) should be 1");
}

/// Test that circuit handles full u64 range without issues
#[test]
fn test_circuit_full_u64_range() {
    // Test with u64::MAX values
    let sk = Fr::from(u64::MAX);
    let result = check_circuit_with_mock(sk, u64::MAX, u64::MAX);

    assert!(result.is_ok(), "Circuit should handle u64::MAX values: {:?}", result);
}

// ============================================================
// FR BOUNDARY PROPERTY TESTS
// ============================================================
// Property tests for values close to Fr modulus (bn256 ~2^254)
// These catch edge cases that u64 range cannot trigger

/// Test with field elements near modulus (p-1, p-2, etc.)
#[test]
fn test_fr_boundary_elements() {
    // p-1 is the largest field element
    let p_minus_1 = Fr::zero() - Fr::one();
    let p_minus_2 = Fr::zero() - Fr::from(2u64);
    let p_minus_1000 = Fr::zero() - Fr::from(1000u64);

    // Commitments should be different for different inputs
    let c1 = compute_sk_commitment(p_minus_1);
    let c2 = compute_sk_commitment(p_minus_2);
    let c3 = compute_sk_commitment(p_minus_1000);

    assert_ne!(c1, c2, "p-1 and p-2 should give different commitments");
    assert_ne!(c1, c3, "p-1 and p-1000 should give different commitments");
    assert_ne!(c2, c3, "p-2 and p-1000 should give different commitments");

    // None should be zero (highly improbable for good hash)
    assert_ne!(c1, Fr::zero());
    assert_ne!(c2, Fr::zero());
    assert_ne!(c3, Fr::zero());
}

/// Test circuit with Fr boundary values
#[test]
fn test_circuit_fr_boundary() {
    use crate::helpers::ensure_working_directory;
    use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
    use halo2_base::halo2_proofs::dev::MockProver;

    ensure_working_directory();

    // p-1 is the maximum field element
    let sk = Fr::zero() - Fr::one();
    let token_type = Fr::zero() - Fr::from(2u64);
    let sum = Fr::zero() - Fr::from(3u64);

    let sk_commitment = compute_sk_commitment(sk);
    let digest = poseidon_hash([sk_commitment, sum, token_type, sk]);

    let circuit = DarkDexCircuit::new(
        Some(token_type),
        Some(sum),
        Some(sk),
        Some(sk_commitment),
    );

    let pub_inputs = vec![sum, token_type, digest];
    let prover = MockProver::run(8, &circuit, vec![pub_inputs]).unwrap();

    assert!(
        prover.verify().is_ok(),
        "Circuit should handle Fr boundary values (p-1, p-2, p-3)"
    );
}

/// Test that sk near modulus vs sk=1 give different results
#[test]
fn test_fr_boundary_vs_small() {
    let small_sk = Fr::one();
    let large_sk = Fr::zero() - Fr::one();  // p-1

    let c_small = compute_sk_commitment(small_sk);
    let c_large = compute_sk_commitment(large_sk);

    assert_ne!(c_small, c_large, "sk=1 and sk=p-1 should have different commitments");

    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);

    let d_small = compute_digest(small_sk, token, sum);
    let d_large = compute_digest(large_sk, token, sum);

    assert_ne!(d_small, d_large, "sk=1 and sk=p-1 should have different digests");
}

// Property test: random Fr field elements (not just u64 range)
// Uses Fr arithmetic to create values beyond u64 range
proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn prop_fr_boundary_offset(
        base_offset in 1u64..1000u64,  // Small offset from p-1
    ) {
        // Create sk = p - base_offset (near modulus)
        let sk = Fr::zero() - Fr::from(base_offset);
        let result = check_circuit_with_mock(sk, 1, 1000);

        prop_assert!(
            result.is_ok(),
            "Circuit should handle sk near modulus: {:?}", result
        );
    }

    #[test]
    fn prop_fr_boundary_commitment_unique(
        offset1 in 1u64..500u64,
        offset2 in 501u64..1000u64,  // Guaranteed different
    ) {
        let sk1 = Fr::zero() - Fr::from(offset1);  // p - offset1
        let sk2 = Fr::zero() - Fr::from(offset2);  // p - offset2

        let c1 = compute_sk_commitment(sk1);
        let c2 = compute_sk_commitment(sk2);

        prop_assert_ne!(
            c1, c2,
            "Different boundary sks should give different commitments"
        );
    }
}
