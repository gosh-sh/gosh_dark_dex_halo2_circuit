//! Real Prover Tests
//!
//! ВАЖНО: Эти тесты используют РЕАЛЬНЫЙ prover/verifier, а не MockProver.
//! Они медленнее, но тестируют фактическую криптографию.
//!
//! Отличия от MockProver:
//! - MockProver проверяет constraints в witness, но не создаёт proof
//! - Real prover создаёт криптографический proof (KZG commitment)
//! - Real verifier проверяет proof криптографически
//!
//! Эти тесты критически важны для обнаружения:
//! - Несоответствий между MockProver и реальным prover
//! - Ошибок сериализации/десериализации proof
//! - Проблем с KZG parameters
//! - Ошибок в transcript

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::helpers::{
    ensure_working_directory,
    generate_and_verify_proof, generate_proof_with_pub_inputs,
    verify_existing_proof_with_pub_inputs,
    compute_public_inputs, check_circuit_with_mock,
};

// ============================================================
// BASIC REAL PROVER TESTS
// ============================================================

/// Базовый тест: генерация и верификация proof
#[test]
fn test_real_prover_basic() {
    ensure_working_directory();
    
    let sk = Fr::from(12345u64);
    let result = generate_and_verify_proof(sk, 1, 1000);
    
    assert!(
        result.is_valid(),
        "Real prover should generate valid proof: {:?}", result
    );
}

/// Тест: proof с разными входными данными
#[test]
fn test_real_prover_various_inputs() {
    ensure_working_directory();
    
    let test_cases = [
        (1u64, 1u64, 1u64),           // Минимальные значения
        (42u64, 1u64, 1000u64),        // Типичный случай
        (u64::MAX/2, 100u64, 50000u64), // Большие значения
        (12345u64, 0u64, 0u64),        // Нулевые token и sum
    ];
    
    for (sk_val, token, sum) in test_cases {
        let sk = Fr::from(sk_val);
        let result = generate_and_verify_proof(sk, token, sum);
        
        assert!(
            result.is_valid(),
            "Real prover should work for sk={}, token={}, sum={}: {:?}",
            sk_val, token, sum, result
        );
    }
}

// ============================================================
// SOUNDNESS TESTS (NEGATIVE)
// ============================================================

/// Soundness: proof с неправильными public inputs должен НЕ верифицироваться
#[test]
fn test_real_prover_wrong_public_inputs() {
    ensure_working_directory();
    
    let sk = Fr::from(12345u64);
    let (proof, correct_pub_inputs) = generate_proof_with_pub_inputs(sk, 1, 1000);
    
    // Попробуем верифицировать с неправильными public inputs
    let mut wrong_pub_inputs = correct_pub_inputs.clone();
    wrong_pub_inputs[0] += Fr::one();  // Corrupt private_note_sum
    
    let result = verify_existing_proof_with_pub_inputs(&proof, wrong_pub_inputs);
    
    assert!(
        result.is_invalid(),
        "Proof with wrong public inputs should fail verification"
    );
}

/// Soundness: proof с неправильным digest должен НЕ верифицироваться
#[test]
fn test_real_prover_wrong_digest() {
    ensure_working_directory();
    
    let sk = Fr::from(12345u64);
    let (proof, correct_pub_inputs) = generate_proof_with_pub_inputs(sk, 1, 1000);
    
    // Corrupt digest (pub_inputs[2])
    let mut wrong_pub_inputs = correct_pub_inputs;
    wrong_pub_inputs[2] += Fr::one();
    
    let result = verify_existing_proof_with_pub_inputs(&proof, wrong_pub_inputs);
    
    assert!(
        result.is_invalid(),
        "Proof with wrong digest should fail verification"
    );
}

// ============================================================
// PROOF MANIPULATION TESTS
// ============================================================

/// Proof mutation: изменение байта в proof должно приводить к ошибке верификации
#[test]
fn test_real_prover_proof_mutation() {
    ensure_working_directory();
    
    let sk = Fr::from(12345u64);
    let (mut proof, pub_inputs) = generate_proof_with_pub_inputs(sk, 1, 1000);
    
    // Сначала проверим что оригинальный proof валидный
    let original_result = verify_existing_proof_with_pub_inputs(&proof, pub_inputs.clone());
    assert!(original_result.is_valid(), "Original proof should be valid");
    
    // Мутируем proof
    if !proof.is_empty() {
        let mid = proof.len() / 2;
        proof[mid] ^= 0xFF;  // Flip bits in the middle
    }
    
    let mutated_result = verify_existing_proof_with_pub_inputs(&proof, pub_inputs);

    assert!(
        mutated_result.is_invalid(),
        "Mutated proof should fail verification"
    );
}

// ============================================================
// CROSS-VERIFICATION TESTS
// ============================================================

/// Proof от одного sk не должен верифицироваться с public inputs от другого sk
#[test]
fn test_real_prover_cross_sk_attack() {
    ensure_working_directory();

    let sk1 = Fr::from(12345u64);
    let sk2 = Fr::from(67890u64);

    // Генерируем proof для sk1
    let (proof1, _) = generate_proof_with_pub_inputs(sk1, 1, 1000);

    // Вычисляем public inputs для sk2
    let pub_inputs_sk2 = compute_public_inputs(sk2, 1, 1000);

    // Пытаемся верифицировать proof1 с pub_inputs от sk2
    let result = verify_existing_proof_with_pub_inputs(&proof1, pub_inputs_sk2);

    assert!(
        result.is_invalid(),
        "Proof from sk1 should not verify with public inputs from sk2"
    );
}

/// Proof не должен быть replay-able с другими параметрами
#[test]
fn test_real_prover_replay_attack() {
    ensure_working_directory();

    let sk = Fr::from(12345u64);

    // Генерируем proof для 1000 токенов
    let (proof, _) = generate_proof_with_pub_inputs(sk, 1, 1000);

    // Пытаемся использовать proof для 2000 токенов
    let wrong_pub_inputs = compute_public_inputs(sk, 1, 2000);  // Different amount

    let result = verify_existing_proof_with_pub_inputs(&proof, wrong_pub_inputs);

    assert!(
        result.is_invalid(),
        "Proof should not be replayable with different amount"
    );
}

// ============================================================
// DETERMINISM TESTS
// ============================================================

/// Два proof от одинаковых входов должны верифицироваться одинаково
#[test]
fn test_real_prover_determinism() {
    ensure_working_directory();

    let sk = Fr::from(42u64);

    // Генерируем два proof
    let result1 = generate_and_verify_proof(sk, 1, 1000);
    let result2 = generate_and_verify_proof(sk, 1, 1000);

    // Оба должны быть валидны
    assert!(result1.is_valid(), "First proof should be valid");
    assert!(result2.is_valid(), "Second proof should be valid");
}

// ============================================================
// FR BOUNDARY TESTS WITH REAL PROVER
// ============================================================

/// Real prover с значениями близкими к модулю Fr
#[test]
fn test_real_prover_fr_boundary() {
    ensure_working_directory();

    // sk = p - 1 (maximum field element)
    let sk = Fr::zero() - Fr::one();

    let result = generate_and_verify_proof(sk, 1, 1000);

    assert!(
        result.is_valid(),
        "Real prover should handle Fr boundary values: {:?}", result
    );
}

/// Real prover с sk=0 (edge case)
#[test]
fn test_real_prover_zero_sk() {
    ensure_working_directory();

    let sk = Fr::zero();

    let result = generate_and_verify_proof(sk, 1, 1000);

    // sk=0 is valid field element, should work
    assert!(
        result.is_valid(),
        "Real prover should handle sk=0: {:?}", result
    );
}

// ============================================================
// CONSISTENCY TESTS: MockProver vs Real Prover
// ============================================================

/// MockProver и Real Prover должны давать согласованные результаты
#[test]
fn test_mockprover_vs_real_prover_consistency() {
    ensure_working_directory();

    let test_cases = [
        Fr::from(1u64),
        Fr::from(12345u64),
        Fr::from(u64::MAX),
        Fr::zero() - Fr::one(),  // p-1
    ];

    for sk in test_cases {
        let mock_result = check_circuit_with_mock(sk, 1, 1000);
        let real_result = generate_and_verify_proof(sk, 1, 1000);

        // If MockProver passes, Real Prover should also pass
        if mock_result.is_ok() {
            assert!(
                real_result.is_valid(),
                "MockProver passed but Real Prover failed for sk={:?}", sk
            );
        }
    }
}

