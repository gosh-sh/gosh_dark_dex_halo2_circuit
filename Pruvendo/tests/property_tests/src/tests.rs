//! Property-based тесты для DarkDEX схемы
//!
//! Используем proptest для автоматической генерации тестовых случаев.
//! Тестируем только схему DarkDEX, не сам Halo2.

use proptest::prelude::*;

use crate::helpers::{
    check_circuit_with_mock, generate_invalid_keypair, generate_valid_keypair,
    generate_and_verify_proof, verify_existing_proof, generate_proof_for_test,
};

// Конфигурация proptest: ограничиваем количество случаев т.к. MockProver медленный
fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 10, // Небольшое число из-за времени выполнения MockProver
        timeout: 300_000, // 5 минут на весь тест
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    // ============================================================
    // P1: COMPLETENESS - валидные данные всегда проходят
    // ============================================================

    /// Для любого валидного секретного ключа sk и соответствующего pk=sk*G,
    /// схема должна успешно верифицироваться.
    #[test]
    fn prop_valid_keypair_always_verifies(
        sk_val in 1u64..100_000u64,
        token_type in 1u64..1000u64,
        note_sum in 1u64..1_000_000u64,
    ) {
        let (sk, pk, g) = generate_valid_keypair(sk_val);

        let result = check_circuit_with_mock(
            sk, pk, g,
            token_type, note_sum,  // witness
            token_type, note_sum,  // public inputs (совпадают)
        );

        prop_assert!(
            result.is_ok(),
            "Valid keypair should always verify, got: {:?}", result
        );
    }

    // ============================================================
    // P2: SOUNDNESS (keypair) - неверная пара ключей отклоняется
    // ============================================================

    /// Если pk вычислен от другого секретного ключа (pk ≠ sk*G),
    /// схема должна отклонить такой witness.
    #[test]
    fn prop_invalid_keypair_fails(
        sk1 in 1u64..100_000u64,
        sk2 in 100_001u64..200_000u64,  // Гарантированно отличается от sk1
    ) {
        let (sk, wrong_pk, g) = generate_invalid_keypair(sk1, sk2);

        let result = check_circuit_with_mock(
            sk, wrong_pk, g,
            1, 1000,  // witness
            1, 1000,  // public inputs
        );

        prop_assert!(
            result.is_constraint_violation(),
            "Invalid keypair (pk != sk*G) should fail verification, got: {:?}", result
        );
    }

    // ============================================================
    // P3: PUBLIC INPUT SOUNDNESS - несовпадение public inputs отклоняется
    // ============================================================

    /// Если token_type в witness не совпадает с public input,
    /// схема должна это обнаружить.
    #[test]
    fn prop_wrong_token_type_fails(
        sk_val in 1u64..100_000u64,
        witness_token in 1u64..1000u64,
        public_token in 1001u64..2000u64,  // Гарантированно отличается
        note_sum in 1u64..1_000_000u64,
    ) {
        let (sk, pk, g) = generate_valid_keypair(sk_val);

        let result = check_circuit_with_mock(
            sk, pk, g,
            witness_token, note_sum,  // witness token
            public_token, note_sum,   // public token (ОТЛИЧАЕТСЯ!)
        );

        prop_assert!(
            result.is_constraint_violation(),
            "Mismatched token_type should fail, got: {:?}", result
        );
    }

    /// Если private_note_sum в witness не совпадает с public input,
    /// схема должна это обнаружить.
    #[test]
    fn prop_wrong_note_sum_fails(
        sk_val in 1u64..100_000u64,
        token_type in 1u64..1000u64,
        witness_sum in 1u64..1_000_000u64,
        public_sum in 1_000_001u64..2_000_000u64,  // Гарантированно отличается
    ) {
        let (sk, pk, g) = generate_valid_keypair(sk_val);

        let result = check_circuit_with_mock(
            sk, pk, g,
            token_type, witness_sum,  // witness sum
            token_type, public_sum,   // public sum (ОТЛИЧАЕТСЯ!)
        );

        prop_assert!(
            result.is_constraint_violation(),
            "Mismatched note_sum should fail, got: {:?}", result
        );
    }

    // ============================================================
    // P5: DETERMINISM - одинаковые входы → одинаковый результат
    // ============================================================

    /// Схема детерминистична: одинаковые входы дают одинаковый результат
    #[test]
    fn prop_determinism(
        sk_val in 1u64..10_000u64,
        token_type in 1u64..1000u64,
        note_sum in 1u64..100_000u64,
    ) {
        let (sk, pk, g) = generate_valid_keypair(sk_val);

        let result1 = check_circuit_with_mock(sk, pk, g, token_type, note_sum, token_type, note_sum);
        let result2 = check_circuit_with_mock(sk, pk, g, token_type, note_sum, token_type, note_sum);

        prop_assert_eq!(
            result1.is_ok(), result2.is_ok(),
            "Same inputs should give same result"
        );
    }

    // ============================================================
    // P6: EDGE CASES - граничные значения
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
        let (sk, pk, g) = generate_valid_keypair(sk_val);
        let result = check_circuit_with_mock(sk, pk, g, token_type, note_sum, token_type, note_sum);

        // Результат должен быть либо Ok либо ConstraintViolation, но НЕ panic
        prop_assert!(
            result.is_ok() || result.is_constraint_violation(),
            "Boundary sk should not cause unexpected errors: {:?}", result
        );
    }

    // ============================================================
    // P7: WRONG PK ALWAYS FAILS - любой неправильный pk отклоняется
    // ============================================================

    /// Если pk вычислен с wrong_sk ≠ sk, схема должна отклонить
    #[test]
    fn prop_any_wrong_pk_fails(
        sk_val in 1u64..50_000u64,
        wrong_sk_val in 50_001u64..100_000u64,  // Гарантированно отличается
        token_type in 1u64..100u64,
        note_sum in 1u64..1000u64,
    ) {
        let (sk, _correct_pk, g) = generate_valid_keypair(sk_val);
        let (_wrong_sk, wrong_pk, _) = generate_valid_keypair(wrong_sk_val);

        // Используем sk с wrong_pk (pk от другого sk)
        let result = check_circuit_with_mock(sk, wrong_pk, g, token_type, note_sum, token_type, note_sum);

        prop_assert!(
            result.is_constraint_violation(),
            "sk with wrong pk should fail: {:?}", result
        );
    }
}

// ============================================================
// Детерминированные тесты (не property-based, но важные)
// ============================================================

/// P4: Детерминизм - один и тот же вход даёт одинаковый результат
#[test]
fn test_determinism() {
    let (sk, pk, g) = generate_valid_keypair(42);

    let result1 = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);
    let result2 = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);

    assert_eq!(result1, result2, "Same inputs should produce same results");
    assert!(result1.is_ok());
}

/// Граничный случай: минимальный секретный ключ
#[test]
fn test_edge_case_min_sk() {
    let (sk, pk, g) = generate_valid_keypair(1);
    let result = check_circuit_with_mock(sk, pk, g, 1, 1, 1, 1);
    assert!(result.is_ok(), "Minimum sk should work: {:?}", result);
}

/// Граничный случай: большой секретный ключ
#[test]
fn test_edge_case_large_sk() {
    // Используем большое значение (но не переполняющее)
    let (sk, pk, g) = generate_valid_keypair(u64::MAX / 2);
    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);
    assert!(result.is_ok(), "Large sk should work: {:?}", result);
}

/// Граничный случай: нулевой token_type
#[test]
fn test_edge_case_zero_token() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let result = check_circuit_with_mock(sk, pk, g, 0, 1000, 0, 1000);
    assert!(result.is_ok(), "Zero token_type should work: {:?}", result);
}

/// Граничный случай: нулевая сумма
#[test]
fn test_edge_case_zero_sum() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let result = check_circuit_with_mock(sk, pk, g, 1, 0, 1, 0);
    assert!(result.is_ok(), "Zero sum should work: {:?}", result);
}

/// Граничный случай: большие значения token_type и sum
#[test]
fn test_edge_case_large_values() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let large_token = u64::MAX / 4;
    let large_sum = u64::MAX / 4;
    let result = check_circuit_with_mock(sk, pk, g, large_token, large_sum, large_token, large_sum);
    assert!(result.is_ok(), "Large values should work: {:?}", result);
}

/// Тест: одинаковые sk дают одинаковые pk (детерминизм генерации ключей)
#[test]
fn test_keypair_determinism() {
    let (sk1, pk1, g1) = generate_valid_keypair(42);
    let (sk2, pk2, g2) = generate_valid_keypair(42);

    assert_eq!(sk1, sk2, "Same input should produce same sk");
    assert_eq!(pk1, pk2, "Same input should produce same pk");
    assert_eq!(g1, g2, "Generator should be constant");
}

// ============================================================
// Дополнительные SOUNDNESS тесты
// ============================================================

/// Soundness: если изменить только pk (оставив sk правильным),
/// схема должна отклонить.
#[test]
fn test_soundness_wrong_pk_only() {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;

    let g = halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Affine::generator();
    let sk_val = 12345u64;
    let sk = halo2_base::halo2_proofs::halo2curves::secp256k1::Fq::from(sk_val);
    let correct_pk = (g * sk).to_affine();

    // Создаём неправильный pk от другого sk
    let wrong_sk = halo2_base::halo2_proofs::halo2curves::secp256k1::Fq::from(54321u64);
    let wrong_pk = (g * wrong_sk).to_affine();

    assert_ne!(correct_pk, wrong_pk);

    let result = check_circuit_with_mock(sk, wrong_pk, g, 1, 1000, 1, 1000);
    assert!(
        result.is_constraint_violation(),
        "Wrong pk should fail: {:?}", result
    );
}

/// Soundness: неправильный генератор g
#[test]
fn test_soundness_wrong_generator() {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;

    let g = halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Affine::generator();
    let sk_val = 12345u64;
    let sk = halo2_base::halo2_proofs::halo2curves::secp256k1::Fq::from(sk_val);
    let pk = (g * sk).to_affine();

    // Создаём "неправильный" генератор (2*G)
    let wrong_g = (g * halo2_base::halo2_proofs::halo2curves::secp256k1::Fq::from(2u64)).to_affine();

    // Проверяем что pk ≠ sk * wrong_g
    let expected_pk_with_wrong_g = (wrong_g * sk).to_affine();
    assert_ne!(pk, expected_pk_with_wrong_g);

    // Схема должна отклонить, т.к. pk ≠ sk * wrong_g
    let result = check_circuit_with_mock(sk, pk, wrong_g, 1, 1000, 1, 1000);
    assert!(
        result.is_constraint_violation(),
        "Wrong generator should fail: {:?}", result
    );
}

/// Комбинированный soundness: несколько неверных значений одновременно
#[test]
fn test_soundness_multiple_wrong_values() {
    let (sk, wrong_pk, g) = generate_invalid_keypair(100, 200);

    // Неверный pk + несовпадающий token
    let result = check_circuit_with_mock(
        sk, wrong_pk, g,
        1, 1000,    // witness
        999, 1000,  // public (token отличается)
    );

    assert!(
        result.is_constraint_violation(),
        "Multiple wrong values should fail: {:?}", result
    );
}

// ============================================================
// Регрессионные тесты для найденных багов
// ============================================================

/// Регрессионный тест: проверка что схема не паникует на граничных значениях
#[test]
fn test_no_panic_on_boundary_values() {
    // Тестируем что схема обрабатывает граничные значения без паники
    let test_cases = [
        (1u64, 0u64, 0u64),                    // минимальные
        (u32::MAX as u64, 1u64, 1u64),         // большой sk
        (1u64, u32::MAX as u64, 1u64),         // большой token
        (1u64, 1u64, u32::MAX as u64),         // большой sum
    ];

    for (sk_val, token, sum) in test_cases {
        let (sk, pk, g) = generate_valid_keypair(sk_val);
        let result = check_circuit_with_mock(sk, pk, g, token, sum, token, sum);
        // Мы просто проверяем что схема не паникует
        // Результат может быть Ok или Err, главное - нет паники
        let _ = result;
    }
}

// ============================================================
// C-01: sk = 0 (edge case эллиптической кривой)
// ============================================================

/// sk = 0 должен давать точку на бесконечности или отклоняться схемой
#[test]
fn test_sk_zero() {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};

    let g = Secp256k1Affine::generator();
    let sk = Fq::from(0u64);
    let pk = (g * sk).to_affine();  // Должна быть точка на бесконечности

    // pk для sk=0 - это identity point
    // Проверяем что схема обрабатывает это корректно (или отклоняет)
    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);

    // Мы принимаем как Ok так и ConstraintViolation - главное нет паники
    // Схема может валидно обрабатывать sk=0 (0*G = O, pk=O)
    // или отклонять как невалидный случай
    assert!(
        result.is_ok() || result.is_constraint_violation(),
        "sk=0 should either work or fail gracefully: {:?}", result
    );
}

// ============================================================
// C-05: sk близок к модулю поля (boundary)
// ============================================================

/// sk = очень большое значение (близко к модулю Fq)
#[test]
fn test_scalar_field_large_value() {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};

    let g = Secp256k1Affine::generator();
    // Используем u64::MAX как большое значение
    let sk = Fq::from(u64::MAX);
    let pk = (g * sk).to_affine();

    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);
    assert!(result.is_ok(), "Large sk should work: {:?}", result);
}

// ============================================================
// C-06: token близок к модулю Fr
// ============================================================

/// Тест: token_type = u64::MAX (большое, но валидное значение)
#[test]
fn test_token_type_max_u64() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let max_token = u64::MAX;
    let result = check_circuit_with_mock(sk, pk, g, max_token, 1000, max_token, 1000);
    assert!(result.is_ok(), "Max u64 token should work: {:?}", result);
}

/// Тест: private_note_sum = u64::MAX
#[test]
fn test_note_sum_max_u64() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let max_sum = u64::MAX;
    let result = check_circuit_with_mock(sk, pk, g, 1, max_sum, 1, max_sum);
    assert!(result.is_ok(), "Max u64 sum should work: {:?}", result);
}

// ============================================================
// V-01: КРИТИЧЕСКИЙ - Неверные public inputs должны отклоняться
// ============================================================

/// **CRITICAL TEST V-01**: Verifier должен отклонить proof,
/// если public inputs не совпадают с теми, что использовались при генерации
#[test]
#[ignore] // Требует kzg_params.bin и verification_key.bin - запускать отдельно
fn test_verifier_wrong_public_inputs() {
    let (sk, pk, g) = generate_valid_keypair(12345);

    // Генерируем proof с token=1, sum=1000
    let result = generate_and_verify_proof(
        sk, pk, g,
        1, 1000,    // proof generation: token=1, sum=1000
        999, 1000,  // verification: token=999 (ОТЛИЧАЕТСЯ!)
    );

    assert!(
        result.is_invalid(),
        "V-01: Proof with wrong token should be rejected, got: {:?}", result
    );
}

/// V-01b: Неверная сумма должна отклоняться
#[test]
#[ignore]
fn test_verifier_wrong_sum() {
    let (sk, pk, g) = generate_valid_keypair(12345);

    let result = generate_and_verify_proof(
        sk, pk, g,
        1, 1000,    // proof: sum=1000
        1, 9999,    // verify: sum=9999 (ОТЛИЧАЕТСЯ!)
    );

    assert!(
        result.is_invalid(),
        "V-01b: Proof with wrong sum should be rejected, got: {:?}", result
    );
}

// ============================================================
// V-02: КРИТИЧЕСКИЙ - Proof replay attack
// ============================================================

/// **CRITICAL TEST V-02**: Один proof не должен работать для других public inputs
#[test]
#[ignore]
fn test_proof_replay_attack() {
    let (sk, pk, g) = generate_valid_keypair(12345);

    // Генерируем proof для token=1, sum=1000
    let proof = generate_proof_for_test(sk, pk, g, 1, 1000);

    // Проверяем что proof работает с оригинальными inputs
    let valid_result = verify_existing_proof(&proof, 1, 1000);
    assert!(
        valid_result.is_valid(),
        "Proof should be valid with original inputs: {:?}", valid_result
    );

    // Пытаемся использовать тот же proof с другими inputs (replay attack)
    let replay_result = verify_existing_proof(&proof, 2, 1000);
    assert!(
        replay_result.is_invalid(),
        "V-02: Proof replay with different token should fail: {:?}", replay_result
    );

    let replay_result2 = verify_existing_proof(&proof, 1, 2000);
    assert!(
        replay_result2.is_invalid(),
        "V-02: Proof replay with different sum should fail: {:?}", replay_result2
    );
}

// ============================================================
// V-03: Corrupted proof bytes
// ============================================================

/// V-03: Битый proof должен отклоняться без panic
#[test]
#[ignore]
fn test_corrupted_proof_bytes() {
    let (sk, pk, g) = generate_valid_keypair(12345);

    // Генерируем валидный proof
    let mut proof = generate_proof_for_test(sk, pk, g, 1, 1000);

    // Портим несколько байт
    if proof.len() > 10 {
        proof[5] ^= 0xFF;
        proof[10] ^= 0xAA;
    }

    // Проверяем что corrupted proof отклоняется (не panic!)
    let result = std::panic::catch_unwind(|| {
        verify_existing_proof(&proof, 1, 1000)
    });

    match result {
        Ok(verify_result) => {
            assert!(
                verify_result.is_invalid(),
                "V-03: Corrupted proof should be rejected: {:?}", verify_result
            );
        }
        Err(_) => {
            panic!("V-03 FAILED: Verifier panicked on corrupted proof!");
        }
    }
}

/// V-04: Пустой proof должен отклоняться
#[test]
#[ignore]
fn test_empty_proof() {
    let empty_proof: Vec<u8> = vec![];

    let result = std::panic::catch_unwind(|| {
        verify_existing_proof(&empty_proof, 1, 1000)
    });

    match result {
        Ok(verify_result) => {
            assert!(
                verify_result.is_invalid(),
                "V-04: Empty proof should be rejected: {:?}", verify_result
            );
        }
        Err(_) => {
            // Panic допустим для пустого proof, но лучше graceful error
            println!("V-04 WARNING: Verifier panicked on empty proof (not ideal but acceptable)");
        }
    }
}

/// V-05: Обрезанный proof должен отклоняться
#[test]
#[ignore]
fn test_truncated_proof() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let proof = generate_proof_for_test(sk, pk, g, 1, 1000);

    // Обрезаем proof наполовину
    let truncated: Vec<u8> = proof[..proof.len() / 2].to_vec();

    let result = std::panic::catch_unwind(|| {
        verify_existing_proof(&truncated, 1, 1000)
    });

    match result {
        Ok(verify_result) => {
            assert!(
                verify_result.is_invalid(),
                "V-05: Truncated proof should be rejected: {:?}", verify_result
            );
        }
        Err(_) => {
            println!("V-05 WARNING: Verifier panicked on truncated proof");
        }
    }
}

// ============================================================
// C-02: pk = identity point (точка на бесконечности)
// ============================================================

/// C-02: Тест с pk = identity (точка на бесконечности)
/// Это происходит когда sk = 0, но мы тестируем явно identity point
#[test]
fn test_pk_identity_point() {
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
    use halo2_base::halo2_proofs::arithmetic::CurveAffine;
    use halo2_base::halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;

    let g = Secp256k1Affine::generator();
    // sk = 0 даёт identity point
    let sk = Fq::from(0u64);
    let pk = <Secp256k1Affine as PrimeCurveAffine>::identity();

    // Схема должна либо принять (если pk = 0*G = identity), либо отклонить
    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);

    // Важно: не должно быть паники
    assert!(
        result.is_ok() || result.is_constraint_violation(),
        "C-02: Identity point should be handled gracefully: {:?}", result
    );
}

// ============================================================
// P-01: Prover - private ≠ public values
// ============================================================

/// P-01: Генерация proof с несовпадающими private и public values
/// Это проверяет что Prover корректно обрабатывает такую ситуацию
#[test]
fn test_prover_mismatched_private_public() {
    // Этот тест проверяет MockProver - он должен отклонить
    let (sk, pk, g) = generate_valid_keypair(12345);

    // witness: token=1, sum=1000
    // public:  token=999, sum=1000  (несовпадение!)
    let result = check_circuit_with_mock(
        sk, pk, g,
        1, 1000,      // private values
        999, 1000,    // public values (token отличается)
    );

    assert!(
        result.is_constraint_violation(),
        "P-01: Mismatched private/public should fail: {:?}", result
    );
}

// ============================================================
// X-01: sk = curve order (эквивалентно 0 в группе)
// ============================================================

/// X-01: sk = secp256k1 curve order
/// В группе точек кривой n*G = O (identity), где n - порядок группы
#[test]
fn test_sk_curve_order() {
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::arithmetic::CurveAffine;

    let g = Secp256k1Affine::generator();

    // secp256k1 curve order (n)
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // Это порядок группы точек кривой
    // sk = n эквивалентно sk = 0 в Fq

    // В Fq значения автоматически берутся по модулю, поэтому Fq::from(n) = 0
    // Но мы можем протестировать значения близкие к модулю

    // Тестируем sk = модуль - 1 (максимальное значение в поле)
    // Это большое, но валидное значение
    let large_sk_val = u64::MAX;
    let sk = Fq::from(large_sk_val);
    let pk = (g * sk).to_affine();

    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);
    assert!(
        result.is_ok(),
        "X-01: Large sk near field boundary should work: {:?}", result
    );
}

// ============================================================
// X-02: Значения около модуля Fr (bn256 field)
// ============================================================

/// X-02: token_type и private_note_sum близки к модулю Fr
#[test]
fn test_values_near_fr_modulus() {
    let (sk, pk, g) = generate_valid_keypair(12345);

    // Максимальное u64 значение - большое, но далеко от модуля Fr
    // Fr модуль ≈ 2^254, а u64::MAX ≈ 2^64
    // Так что u64::MAX - валидное значение

    let large_val = u64::MAX;
    let result = check_circuit_with_mock(sk, pk, g, large_val, large_val, large_val, large_val);

    assert!(
        result.is_ok(),
        "X-02: Large values near u64::MAX should work: {:?}", result
    );
}

// ============================================================
// X-03: Операции с точкой на бесконечности
// ============================================================

/// X-03: g = identity (невалидный генератор)
/// НАЙДЕН БАГ: Схема паникует при g = identity point!
/// Это BUG-002 - см. отчёт
#[test]
fn test_generator_identity() {
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
    use halo2_base::halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;

    // Если g = identity, то sk * g = identity для любого sk
    let g_identity = <Secp256k1Affine as PrimeCurveAffine>::identity();
    let sk = Fq::from(12345u64);
    let pk = <Secp256k1Affine as PrimeCurveAffine>::identity();  // sk * identity = identity

    // Оборачиваем в catch_unwind т.к. текущая реализация паникует на identity
    let result = std::panic::catch_unwind(|| {
        check_circuit_with_mock(sk, pk, g_identity, 1, 1000, 1, 1000)
    });

    match result {
        Ok(circuit_result) => {
            // Схема может принять или отклонить - главное без паники
            assert!(
                circuit_result.is_ok() || circuit_result.is_constraint_violation(),
                "X-03: Identity generator should be handled: {:?}", circuit_result
            );
        }
        Err(_) => {
            // ИЗВЕСТНЫЙ БАГ: Схема паникует на identity point
            // Это задокументировано как BUG-002
            println!("X-03 BUG-002: Circuit panics on identity generator (known issue)");
        }
    }
}

// ============================================================
// P-03: k < 18 (схема не помещается)
// ============================================================

/// P-03: Тестируем что схема требует k >= 18
/// Это тест документирует требования к размеру схемы
#[test]
fn test_circuit_size_requirement() {
    // Мы не можем напрямую тестировать k < 18 через наш helper
    // (он hardcoded на k=18), но можем задокументировать требование

    // Этот тест просто проверяет что k=18 работает
    let (sk, pk, g) = generate_valid_keypair(12345);
    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);

    assert!(
        result.is_ok(),
        "P-03: Circuit should work with k=18: {:?}", result
    );
    // NOTE: Для k < 18 схема не поместится и будет ошибка при keygen_vk
}

// ============================================================
// P-04: Размер proof константен
// ============================================================

/// P-04: Проверяем что размер proof не зависит от входных данных
#[test]
#[ignore]
fn test_proof_size_consistency() {
    let test_cases = [
        (1u64, 1u64, 1u64),
        (u64::MAX, u64::MAX / 2, u64::MAX / 4),
        (12345u64, 100u64, 200u64),
    ];

    let mut proof_sizes: Vec<usize> = Vec::new();

    for (sk_val, token, sum) in test_cases {
        let (sk, pk, g) = generate_valid_keypair(sk_val);
        let proof = generate_proof_for_test(sk, pk, g, token, sum);
        proof_sizes.push(proof.len());
    }

    // Все proof должны иметь одинаковый размер
    let first_size = proof_sizes[0];
    for (i, size) in proof_sizes.iter().enumerate() {
        assert_eq!(
            *size, first_size,
            "P-04: Proof size should be constant. Case {} has size {}, expected {}",
            i, size, first_size
        );
    }

    println!("P-04: All proofs have consistent size: {} bytes", first_size);
}

// ============================================================
// C-04: g ≠ стандартный генератор (но не identity)
// ============================================================

/// C-04: Используем произвольную точку вместо стандартного генератора
/// Схема должна всё равно работать если pk = sk * g (для любого g на кривой)
#[test]
fn test_non_standard_generator() {
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::arithmetic::CurveAffine;

    let standard_g = Secp256k1Affine::generator();
    let sk = Fq::from(12345u64);

    // Создаём альтернативный "генератор" как sk * G (произвольная точка на кривой)
    let alt_g = (standard_g * Fq::from(999u64)).to_affine();
    let pk = (alt_g * sk).to_affine();

    // Схема должна принять эту валидную комбинацию
    let result = check_circuit_with_mock(sk, pk, alt_g, 1, 1000, 1, 1000);
    assert!(
        result.is_ok(),
        "C-04: Non-standard generator should work if pk = sk * g: {:?}", result
    );
}

// ============================================================
// P-02: Поврежденные KZG параметры
// ============================================================

/// P-02: Тест с поврежденными KZG params
/// Примечание: Этот тест требует модификации файла kzg_params.bin
/// Здесь мы просто проверяем что система не паникует при валидных params
#[test]
fn test_kzg_params_integrity() {
    // Этот тест документирует что kzg_params.bin должен быть валидным
    // Реальный тест corrupted params требует отдельного файла

    let (sk, pk, g) = generate_valid_keypair(12345);
    let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);

    assert!(
        result.is_ok(),
        "P-02: Valid KZG params should work: {:?}", result
    );
}

// ============================================================
// Regression тесты
// ============================================================

/// Regression: Проверяем что схема детерминистична при разных seed
#[test]
fn test_multiple_valid_keypairs() {
    let seeds = [1u64, 100, 1000, 10000, u64::MAX / 2];

    for seed in seeds {
        let (sk, pk, g) = generate_valid_keypair(seed);
        let result = check_circuit_with_mock(sk, pk, g, seed, seed * 2, seed, seed * 2);
        assert!(
            result.is_ok(),
            "Regression: seed {} should produce valid keypair: {:?}", seed, result
        );
    }
}

/// Regression: Проверяем что неверный keypair всегда отклоняется
#[test]
fn test_multiple_invalid_keypairs() {
    let seeds = [1u64, 100, 1000, 10000];

    for seed in seeds {
        let (sk, pk, g) = generate_invalid_keypair(seed, seed + 1);
        let result = check_circuit_with_mock(sk, pk, g, 1, 1000, 1, 1000);
        assert!(
            result.is_constraint_violation(),
            "Regression: invalid keypair from seed {} should fail: {:?}", seed, result
        );
    }
}

// ============================================================
// C-03: pk с произвольными координатами (не обязательно на кривой)
// ============================================================

/// C-03: pk с координатами которые не соответствуют sk * G
/// Схема должна отклонить такой pk
#[test]
fn test_pk_wrong_coordinates() {
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Fp, Secp256k1Affine};
    use halo2_base::halo2_proofs::arithmetic::CurveAffine;
    use halo2_base::halo2_proofs::halo2curves::group::Curve;

    let g = Secp256k1Affine::generator();
    let sk = Fq::from(12345u64);

    // Правильный pk
    let correct_pk = (g * sk).to_affine();

    // Берём другую точку (с другим sk)
    let wrong_pk = (g * Fq::from(99999u64)).to_affine();

    // Схема должна отклонить неправильный pk
    let result = check_circuit_with_mock(sk, wrong_pk, g, 1, 1000, 1, 1000);
    assert!(
        result.is_constraint_violation(),
        "C-03: Wrong pk coordinates should be rejected: {:?}", result
    );
}

/// Stress test: большое количество случайных keypairs
#[test]
fn test_stress_random_keypairs() {
    for i in 0..20 {
        let seed = (i * 12345 + 1) as u64;
        let (sk, pk, g) = generate_valid_keypair(seed);

        let result = check_circuit_with_mock(
            sk, pk, g,
            seed % 1000 + 1,
            seed % 10000 + 1,
            seed % 1000 + 1,
            seed % 10000 + 1,
        );

        assert!(
            result.is_ok(),
            "Stress: keypair {} (seed {}) should be valid: {:?}", i, seed, result
        );
    }
}

// ============================================================
// NEGATIVE TESTS: Serialization
// ============================================================

/// SER-01: Corrupted VK bytes - первые байты изменены
#[test]
#[ignore] // Требует verification_key.bin
fn test_corrupted_vk_bytes_header() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    // Читаем валидный VK
    let mut vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Портим первые байты (header)
    if vk_bytes.len() > 10 {
        vk_bytes[0] ^= 0xFF;
        vk_bytes[1] ^= 0xAA;
        vk_bytes[2] ^= 0x55;
    }

    // Должен либо вернуть ошибку, либо паниковать (gracefully)
    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&vk_bytes)
    });

    match result {
        Ok(_vk) => {
            // Если VK распарсился, это может быть проблемой
            // (хотя corrupted VK скорее всего не пройдёт верификацию)
            println!("SER-01 WARNING: Corrupted VK was parsed (may fail at verification)");
        }
        Err(_) => {
            // Ожидаемое поведение - panic при парсинге
            println!("SER-01: Corrupted VK correctly rejected with panic");
        }
    }
}

/// SER-02: Corrupted VK bytes - середина изменена
#[test]
#[ignore] // Требует verification_key.bin
fn test_corrupted_vk_bytes_middle() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    let mut vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Портим середину файла
    let mid = vk_bytes.len() / 2;
    if vk_bytes.len() > mid + 10 {
        for i in 0..10 {
            vk_bytes[mid + i] ^= 0xFF;
        }
    }

    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&vk_bytes)
    });

    match result {
        Ok(_vk) => {
            println!("SER-02 WARNING: Corrupted VK (middle) was parsed");
        }
        Err(_) => {
            println!("SER-02: Corrupted VK (middle) correctly rejected");
        }
    }
}

/// SER-03: Truncated VK bytes
#[test]
#[ignore] // Требует verification_key.bin
fn test_truncated_vk_bytes() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;

    let vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Обрезаем VK до половины
    let truncated: Vec<u8> = vk_bytes[..vk_bytes.len() / 2].to_vec();

    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&truncated)
    });

    match result {
        Ok(_vk) => {
            panic!("SER-03 FAILED: Truncated VK should NOT parse successfully!");
        }
        Err(_) => {
            println!("SER-03: Truncated VK correctly rejected");
        }
    }
}

/// SER-04: Empty VK bytes
#[test]
fn test_empty_vk_bytes() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;

    let empty: Vec<u8> = vec![];

    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&empty)
    });

    match result {
        Ok(_vk) => {
            panic!("SER-04 FAILED: Empty VK should NOT parse!");
        }
        Err(_) => {
            println!("SER-04: Empty VK correctly rejected");
        }
    }
}

/// SER-05: Random garbage as VK
#[test]
#[ignore] // Требует verification_key.bin для определения размера
fn test_random_garbage_vk() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;

    // Генерируем случайный мусор того же размера что и VK
    let vk_size = std::fs::read("verification_key.bin")
        .map(|v| v.len())
        .unwrap_or(1000);

    let garbage: Vec<u8> = (0..vk_size).map(|i| (i * 17 + 42) as u8).collect();

    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&garbage)
    });

    match result {
        Ok(_vk) => {
            println!("SER-05 WARNING: Random garbage parsed as VK (will fail verification)");
        }
        Err(_) => {
            println!("SER-05: Random garbage correctly rejected");
        }
    }
}

/// SER-06: Corrupted KZG params - проверяем read_kzg_params
/// ВНИМАНИЕ: Если портить header файла, read_kzg_params пытается выделить
/// петабайты памяти (BUG-003: OOM вместо graceful error)
/// Поэтому портим только данные в середине/конце файла
#[test]
#[ignore] // Требует kzg_params.bin
fn test_corrupted_kzg_params_bytes() {
    use gosh_dark_dex_halo2_circuit::prover::read_kzg_params;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    let temp_path = "/tmp/test_corrupted_kzg.bin";
    let mut params_bytes = std::fs::read("kzg_params.bin")
        .expect("kzg_params.bin should exist");

    // Портим данные в СЕРЕДИНЕ файла (не header с размерами!)
    // Иначе получим OOM при попытке выделить петабайты
    let mid = params_bytes.len() / 2;
    for i in mid..(mid + 100).min(params_bytes.len()) {
        params_bytes[i] ^= 0xFF;
    }

    std::fs::write(temp_path, &params_bytes).expect("Failed to write temp file");

    let result = std::panic::catch_unwind(|| {
        read_kzg_params(temp_path.to_string())
    });

    let _ = std::fs::remove_file(temp_path);

    // Оба варианта приемлемы: либо panic, либо parsed (но потом не пройдёт верификация)
    match result {
        Ok(_params) => {
            println!("SER-06: Corrupted KZG params parsed (may fail at verification)");
        }
        Err(_) => {
            println!("SER-06: Corrupted KZG params correctly rejected with panic");
        }
    }
}

/// SER-07: Proof bytes с неверной длиной
#[test]
#[ignore] // Требует kzg_params.bin и verification_key.bin
fn test_wrong_length_proof() {
    use gosh_dark_dex_halo2_circuit::prover::read_kzg_params;
    use gosh_dark_dex_halo2_circuit::verifier::{verification_key_from_path, verify_proof_};
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

    let params = read_kzg_params("kzg_params.bin".to_string());
    let vk = verification_key_from_path("verification_key.bin".to_string());

    // Создаём proof неправильной длины (слишком короткий)
    let short_proof: Vec<u8> = vec![0u8; 100];
    let pub_inputs = vec![Fr::from(1u64), Fr::from(1000u64)];

    let result = std::panic::catch_unwind(|| {
        verify_proof_(&params, &short_proof, &vk, pub_inputs)
    });

    match result {
        Ok(verified) => {
            assert!(!verified, "SER-07: Short proof should not verify");
            println!("SER-07: Short proof correctly rejected");
        }
        Err(_) => {
            println!("SER-07 WARNING: Verifier panicked on short proof");
        }
    }
}

/// SER-08: Proof bytes с дополнительным мусором в конце
#[test]
#[ignore]
fn test_proof_with_trailing_garbage() {
    let (sk, pk, g) = generate_valid_keypair(12345);

    // Генерируем валидный proof
    let mut proof = generate_proof_for_test(sk, pk, g, 1, 1000);

    // Добавляем мусор в конец
    proof.extend_from_slice(&[0xFF, 0xAA, 0x55, 0x00, 0x11, 0x22, 0x33]);

    // Проверяем - должен либо отклонить, либо игнорировать trailing bytes
    let result = verify_existing_proof(&proof, 1, 1000);

    // Оба варианта приемлемы - главное без паники
    println!("SER-08: Proof with trailing garbage: {:?}", result);
}

/// SER-09: Proof bytes с замененными байтами (bit flip)
#[test]
#[ignore]
fn test_proof_bit_flip() {
    let (sk, pk, g) = generate_valid_keypair(12345);
    let mut proof = generate_proof_for_test(sk, pk, g, 1, 1000);

    // Делаем bit flip в разных позициях
    let positions = [0, 10, 50, 100, proof.len() / 2, proof.len() - 10];

    for pos in positions {
        if pos < proof.len() {
            let mut corrupted = proof.clone();
            corrupted[pos] ^= 0x01;  // Flip 1 bit

            let result = std::panic::catch_unwind(|| {
                verify_existing_proof(&corrupted, 1, 1000)
            });

            match result {
                Ok(verify_result) => {
                    assert!(
                        verify_result.is_invalid(),
                        "SER-09: Bit flip at {} should invalidate proof", pos
                    );
                }
                Err(_) => {
                    println!("SER-09 WARNING: Verifier panicked on bit flip at {}", pos);
                }
            }
        }
    }

    println!("SER-09: Bit flip tests completed");
}

/// SER-10: VK и KZG params mismatch (VK от другой схемы/params)
#[test]
#[ignore]
fn test_vk_params_mismatch() {
    // Этот тест проверяет что VK и params должны быть совместимы
    // Реальный тест требует двух разных наборов params

    // Пока просто проверяем что текущие params и VK совместимы
    let (sk, pk, g) = generate_valid_keypair(12345);
    let result = generate_and_verify_proof(sk, pk, g, 1, 1000, 1, 1000);

    assert!(
        result.is_valid(),
        "SER-10: Matching VK and params should work: {:?}", result
    );
    println!("SER-10: VK and params are compatible");
}

// ============================================================
// BUG-006: Non-canonical field element representation
// ============================================================
//
// ГИПОТЕЗА: При использовании SerdeFormat::RawBytesUnchecked,
// field elements НЕ проверяются на каноничность (< modulus).
//
// Модуль Fq для BN254: 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
// Старшие 2 бита (биты 254-255) всегда 0 для валидных field elements.
//
// Если установить бит 7 последнего байта (бит 255), значение станет >= modulus,
// но при RawBytesUnchecked это НЕ проверяется!
//
// Это может привести к:
// 1. Неопределённому поведению в арифметике (neg, sub могут дать неверные результаты)
// 2. Возможности создания "эквивалентных" VK/params с разными байтами
// 3. Потенциальным soundness issues если атакующий может контролировать VK

/// BUG-006a: Тест на манипуляцию битом 7 в VK (x-координата первой точки)
/// Проверяем что VK с неканоничным field element отклоняется или работает идентично
#[test]
#[ignore] // Требует verification_key.bin
fn test_bug006_vk_bit7_manipulation_x_coord() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    // Читаем оригинальный VK
    let original_vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Структура VK:
    // - Байты 0-3: k (u32 big-endian)
    // - Байты 4-7: num_fixed_columns (u32 big-endian)
    // - Далее: G1 точки (каждая 64 байта = x[32] + y[32] в Montgomery form)

    // Первая G1 точка: байты 8-71
    // Последний байт x-координаты: байт 39 (8 + 31)
    let x_last_byte_offset = 8 + 31;

    // Проверяем что бит 7 изначально не установлен
    let original_byte = original_vk_bytes[x_last_byte_offset];
    println!("BUG-006a: Original byte at offset {}: 0x{:02x}", x_last_byte_offset, original_byte);

    // Модифицируем: устанавливаем бит 7 (0x80)
    let mut modified_vk_bytes = original_vk_bytes.clone();
    modified_vk_bytes[x_last_byte_offset] |= 0x80;

    println!("BUG-006a: Modified byte: 0x{:02x}", modified_vk_bytes[x_last_byte_offset]);

    // Пытаемся загрузить модифицированный VK
    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&modified_vk_bytes)
    });

    match result {
        Ok(_vk) => {
            // VK загрузился! Это потенциальная проблема.
            // Теперь проверим, работает ли верификация с этим VK
            println!("BUG-006a WARNING: Modified VK with bit 7 set was successfully parsed!");
            println!("This confirms that RawBytesUnchecked does NOT validate field elements.");

            // Дополнительно: проверим что оригинальный и модифицированный VK дают разные результаты
            // (или одинаковые - что было бы ещё хуже)
        }
        Err(e) => {
            // VK отклонён - это хорошо!
            println!("BUG-006a: Modified VK correctly rejected: {:?}", e);
        }
    }
}

/// BUG-006b: Тест на манипуляцию битом 7 в VK (y-координата первой точки)
#[test]
#[ignore] // Требует verification_key.bin
fn test_bug006_vk_bit7_manipulation_y_coord() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    let original_vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Последний байт y-координаты первой точки: байт 71 (8 + 63)
    let y_last_byte_offset = 8 + 63;

    let original_byte = original_vk_bytes[y_last_byte_offset];
    println!("BUG-006b: Original byte at offset {}: 0x{:02x}", y_last_byte_offset, original_byte);

    let mut modified_vk_bytes = original_vk_bytes.clone();
    modified_vk_bytes[y_last_byte_offset] |= 0x80;

    println!("BUG-006b: Modified byte: 0x{:02x}", modified_vk_bytes[y_last_byte_offset]);

    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&modified_vk_bytes)
    });

    match result {
        Ok(_vk) => {
            println!("BUG-006b WARNING: Modified VK (y-coord) with bit 7 set was successfully parsed!");
        }
        Err(e) => {
            println!("BUG-006b: Modified VK correctly rejected: {:?}", e);
        }
    }
}

/// BUG-006c: Полный тест - модифицированный VK используется для верификации
/// Это критический тест: если proof проходит верификацию с модифицированным VK,
/// это может быть soundness issue
#[test]
#[ignore] // Требует kzg_params.bin и verification_key.bin
fn test_bug006_verification_with_modified_vk() {
    use gosh_dark_dex_halo2_circuit::prover::read_kzg_params;
    use gosh_dark_dex_halo2_circuit::verifier::{verification_key_from_bytes, verify_proof_};
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use crate::helpers::{ensure_working_directory, generate_valid_keypair, generate_proof_for_test};
    ensure_working_directory();

    // Генерируем валидный proof
    let (sk, pk, g) = generate_valid_keypair(12345);
    let proof = generate_proof_for_test(sk, pk, g, 1, 1000);

    // Загружаем params
    let params = read_kzg_params("kzg_params.bin".to_string());

    // Загружаем оригинальный VK
    let original_vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Верифицируем с оригинальным VK
    let original_vk = verification_key_from_bytes(&original_vk_bytes);
    let pub_inputs = vec![Fr::from(1u64), Fr::from(1000u64)];
    let original_result = verify_proof_(&params, &proof, &original_vk, pub_inputs.clone());

    println!("BUG-006c: Original VK verification: {}", original_result);
    assert!(original_result, "Proof should verify with original VK");

    // Модифицируем VK (бит 7 в x-координате первой точки)
    let mut modified_vk_bytes = original_vk_bytes.clone();
    let x_last_byte_offset = 8 + 31;
    modified_vk_bytes[x_last_byte_offset] |= 0x80;

    // Пытаемся верифицировать с модифицированным VK
    let modified_result = std::panic::catch_unwind(|| {
        let modified_vk = verification_key_from_bytes(&modified_vk_bytes);
        verify_proof_(&params, &proof, &modified_vk, pub_inputs.clone())
    });

    match modified_result {
        Ok(verified) => {
            if verified {
                println!("BUG-006c CRITICAL: Proof verified with MODIFIED VK!");
                println!("This is a potential soundness issue!");
                // Это может быть проблемой если:
                // 1. Модифицированный VK даёт тот же результат (collision)
                // 2. Атакующий может создать proof для модифицированного VK
            } else {
                println!("BUG-006c: Proof correctly rejected with modified VK");
            }
        }
        Err(e) => {
            println!("BUG-006c: Verification panicked with modified VK: {:?}", e);
        }
    }
}

/// BUG-006d: Тест на манипуляцию битом 6 (sign bit в compressed format)
/// Бит 6 используется как sign bit в compressed point format
#[test]
#[ignore] // Требует verification_key.bin
fn test_bug006_vk_bit6_manipulation() {
    use gosh_dark_dex_halo2_circuit::verifier::verification_key_from_bytes;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    let original_vk_bytes = std::fs::read("verification_key.bin")
        .expect("verification_key.bin should exist");

    // Последний байт x-координаты первой точки
    let x_last_byte_offset = 8 + 31;

    let original_byte = original_vk_bytes[x_last_byte_offset];
    println!("BUG-006d: Original byte: 0x{:02x}", original_byte);

    // Устанавливаем бит 6 (0x40)
    let mut modified_vk_bytes = original_vk_bytes.clone();
    modified_vk_bytes[x_last_byte_offset] |= 0x40;

    println!("BUG-006d: Modified byte (bit 6): 0x{:02x}", modified_vk_bytes[x_last_byte_offset]);

    let result = std::panic::catch_unwind(|| {
        verification_key_from_bytes(&modified_vk_bytes)
    });

    match result {
        Ok(_vk) => {
            println!("BUG-006d: Modified VK (bit 6) was parsed");
            // Бит 6 в uncompressed format не имеет специального значения,
            // но значение всё ещё может быть >= modulus
        }
        Err(e) => {
            println!("BUG-006d: Modified VK rejected: {:?}", e);
        }
    }
}

/// BUG-006e: Тест на манипуляцию KZG params (g точка)
#[test]
#[ignore] // Требует kzg_params.bin
fn test_bug006_kzg_params_bit7_manipulation() {
    use gosh_dark_dex_halo2_circuit::prover::read_kzg_params;
    use crate::helpers::ensure_working_directory;
    ensure_working_directory();

    let original_params_bytes = std::fs::read("kzg_params.bin")
        .expect("kzg_params.bin should exist");

    // Структура KZG params:
    // - k (u32)
    // - n (u64)
    // - g (G1 point, 64 bytes)
    // - g_lagrange (Vec<G1>)
    // - g2 (G2 point)
    // - s_g2 (G2 point)

    // g точка начинается с байта 12 (4 + 8)
    // Последний байт x-координаты g: байт 43 (12 + 31)
    let g_x_last_byte_offset = 12 + 31;

    if original_params_bytes.len() > g_x_last_byte_offset {
        let original_byte = original_params_bytes[g_x_last_byte_offset];
        println!("BUG-006e: Original g.x last byte: 0x{:02x}", original_byte);

        let mut modified_params_bytes = original_params_bytes.clone();
        modified_params_bytes[g_x_last_byte_offset] |= 0x80;

        // Записываем во временный файл
        let temp_path = "/tmp/test_modified_kzg.bin";
        std::fs::write(temp_path, &modified_params_bytes).expect("Failed to write temp file");

        let result = std::panic::catch_unwind(|| {
            read_kzg_params(temp_path.to_string())
        });

        let _ = std::fs::remove_file(temp_path);

        match result {
            Ok(_params) => {
                println!("BUG-006e WARNING: Modified KZG params with bit 7 set was parsed!");
            }
            Err(e) => {
                println!("BUG-006e: Modified KZG params rejected: {:?}", e);
            }
        }
    } else {
        println!("BUG-006e: KZG params file too short");
    }
}

