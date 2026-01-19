//! Integration Tests for DarkDexCircuit
//!
//! Версия: poseidon_instead_of_ecc
//!
//! End-to-end сценарии тестирования:
//! - Полный цикл proof generation/verification
//! - Multi-user сценарии
//! - Replay protection
//! - Cross-transaction attacks

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::dev::MockProver;
use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
use proptest::prelude::*;
use std::collections::HashMap;

use crate::helpers::{compute_sk_commitment, compute_digest};

// Новая архитектура: k=8 достаточно для схемы
const CIRCUIT_K: u32 = 8;

// =============================================================================
// Helper Functions
// =============================================================================

fn create_and_verify_circuit(
    sk_val: u64,
    token: u64,
    sum: u64,
) -> Result<(), String> {
    let sk = Fr::from(sk_val);
    let sk_commitment = compute_sk_commitment(sk);
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);

    let circuit = DarkDexCircuit::new(
        Some(token_fr), Some(sum_fr), Some(sk), Some(sk_commitment),
    );

    let digest = compute_digest(sk, token_fr, sum_fr);
    let pub_inputs = vec![sum_fr, token_fr, digest];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![pub_inputs])
        .map_err(|e| format!("MockProver::run failed: {:?}", e))?;

    prover.verify().map_err(|e| format!("Verification failed: {:?}", e))
}

// =============================================================================
// Multi-User Scenarios
// =============================================================================

#[test]
fn test_multi_user_independent_proofs() {
    // Несколько пользователей с разными sk
    let users = vec![
        (1u64, 1u64, 1000u64),      // User 1
        (42u64, 2u64, 2000u64),     // User 2
        (999u64, 3u64, 3000u64),    // User 3
        (12345u64, 1u64, 5000u64),  // User 4
    ];

    for (i, (sk_val, token, sum)) in users.iter().enumerate() {
        let result = create_and_verify_circuit(*sk_val, *token, *sum);
        assert!(result.is_ok(),
            "User {} should create valid proof: {:?}", i + 1, result);
    }
}

#[test]
fn test_same_user_different_transactions() {
    // Один пользователь делает несколько транзакций
    let sk_val = 12345u64;

    let transactions = vec![
        (1u64, 1000u64),   // Tx 1
        (1u64, 2000u64),   // Tx 2: same token, different sum
        (2u64, 1000u64),   // Tx 3: different token
        (1u64, 3000u64),   // Tx 4: same token, different sum
    ];

    for (i, (token, sum)) in transactions.iter().enumerate() {
        let result = create_and_verify_circuit(sk_val, *token, *sum);
        assert!(result.is_ok(),
            "Transaction {} should be valid: {:?}", i + 1, result);
    }
}

// =============================================================================
// Replay Protection Tests
// =============================================================================

#[test]
fn test_replay_attack_different_sum_rejected() {
    // Пользователь создаёт proof для sum=1000
    let sk = Fr::from(12345u64);
    let sk_commitment = compute_sk_commitment(sk);

    let token_fr = Fr::from(1u64);
    let sum1_fr = Fr::from(1000u64);
    let sum2_fr = Fr::from(2000u64);  // Атакующий хочет другую сумму

    // Создаём circuit с sum=1000
    let circuit = DarkDexCircuit::new(
        Some(token_fr), Some(sum1_fr), Some(sk), Some(sk_commitment),
    );

    // Но пытаемся верифицировать с sum=2000 (replay attack)
    let fake_digest = compute_digest(sk, token_fr, sum2_fr);
    let fake_pub_inputs = vec![sum2_fr, token_fr, fake_digest];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![fake_pub_inputs]).unwrap();
    assert!(prover.verify().is_err(),
        "Replay attack with different sum should be rejected");
}

#[test]
fn test_replay_attack_different_token_rejected() {
    let sk = Fr::from(12345u64);
    let sk_commitment = compute_sk_commitment(sk);
    
    let token1_fr = Fr::from(1u64);
    let token2_fr = Fr::from(2u64);  // Атакующий хочет другой токен
    let sum_fr = Fr::from(1000u64);

    // Создаём circuit с token=1
    let circuit = DarkDexCircuit::new(
        Some(token1_fr), Some(sum_fr), Some(sk), Some(sk_commitment),
    );

    // Пытаемся верифицировать с token=2
    let fake_digest = compute_digest(sk, token2_fr, sum_fr);
    let fake_pub_inputs = vec![sum_fr, token2_fr, fake_digest];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![fake_pub_inputs]).unwrap();
    assert!(prover.verify().is_err(),
        "Replay attack with different token should be rejected");
}

// =============================================================================
// Cross-User Attack Tests
// =============================================================================

#[test]
fn test_cross_user_commitment_swap_rejected() {
    // User A
    let sk_a = Fr::from(111u64);
    let sk_a_commitment = compute_sk_commitment(sk_a);

    // User B
    let sk_b = Fr::from(222u64);
    let sk_b_commitment = compute_sk_commitment(sk_b);

    let token_fr = Fr::from(1u64);
    let sum_fr = Fr::from(1000u64);

    // Атака: User A пытается использовать commitment от B
    let circuit = DarkDexCircuit::new(
        Some(token_fr), Some(sum_fr),
        Some(sk_a), Some(sk_b_commitment), // WRONG: commitment от B
    );

    // Digest вычислен для sk_a (правильный)
    let digest = compute_digest(sk_a, token_fr, sum_fr);
    let pub_inputs = vec![sum_fr, token_fr, digest];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![pub_inputs]).unwrap();
    assert!(prover.verify().is_err(),
        "Cross-user commitment swap should be rejected");
}

#[test]
fn test_cross_user_digest_swap_rejected() {
    // User A
    let sk_a = Fr::from(111u64);
    let sk_a_commitment = compute_sk_commitment(sk_a);

    // User B
    let sk_b = Fr::from(222u64);

    let token_fr = Fr::from(1u64);
    let sum_fr = Fr::from(1000u64);

    // User A создаёт свой circuit
    let circuit_a = DarkDexCircuit::new(
        Some(token_fr), Some(sum_fr), Some(sk_a), Some(sk_a_commitment),
    );

    // Но использует digest от User B
    let digest_b = compute_digest(sk_b, token_fr, sum_fr);
    let fake_pub_inputs = vec![sum_fr, token_fr, digest_b];

    let prover = MockProver::run(CIRCUIT_K, &circuit_a, vec![fake_pub_inputs]).unwrap();
    assert!(prover.verify().is_err(),
        "Using another user's digest should be rejected");
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_zero_sum_valid() {
    // Транзакция с sum=0 должна быть валидной
    let result = create_and_verify_circuit(12345, 1, 0);
    assert!(result.is_ok(), "Zero sum should be valid: {:?}", result);
}

#[test]
fn test_zero_token_valid() {
    // Транзакция с token=0 должна быть валидной
    let result = create_and_verify_circuit(12345, 0, 1000);
    assert!(result.is_ok(), "Zero token should be valid: {:?}", result);
}

#[test]
fn test_large_values_valid() {
    // Транзакция с большими значениями
    let result = create_and_verify_circuit(12345, u32::MAX as u64, u32::MAX as u64);
    assert!(result.is_ok(), "Large values should be valid: {:?}", result);
}

#[test]
fn test_minimum_sk_valid() {
    // sk = 1 (минимальное валидное значение)
    let result = create_and_verify_circuit(1, 1, 1000);
    assert!(result.is_ok(), "Minimum sk should be valid: {:?}", result);
}

// =============================================================================
// Consistency Tests
// =============================================================================

#[test]
fn test_digest_uniqueness() {
    // Новая архитектура: digest = poseidon(sk_commitment, sum, token, sk)
    // Разные входы должны давать разные digests
    let sk = Fr::from(12345u64);

    let mut digests: HashMap<[u8; 32], (u64, u64)> = HashMap::new();

    let test_cases = vec![
        (1u64, 1000u64),
        (1u64, 2000u64),
        (2u64, 1000u64),
        (10u64, 500u64),
    ];

    for (token, sum) in test_cases {
        let digest = compute_digest(sk, Fr::from(token), Fr::from(sum));
        let key = digest.to_bytes();
        if let Some(prev) = digests.get(&key) {
            panic!(
                "Digest collision!\n  Previous: token={}, sum={}\n  Current: token={}, sum={}\n  Digest: {:?}",
                prev.0, prev.1, token, sum, digest
            );
        }
        digests.insert(key, (token, sum));
    }
}

#[test]
fn test_digest_determinism() {
    // Одинаковые входы должны давать одинаковый digest
    let sk = Fr::from(12345u64);
    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);

    let digest1 = compute_digest(sk, token, sum);
    let digest2 = compute_digest(sk, token, sum);

    assert_eq!(digest1, digest2, "Same inputs should produce same digest");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_valid_circuit_always_passes(
        sk_val in 1u64..100_000u64,
        token in 0u64..1_000u64,
        sum in 0u64..1_000_000u64,
    ) {
        let result = create_and_verify_circuit(sk_val, token, sum);
        prop_assert!(result.is_ok(), "Valid circuit should pass: {:?}", result);
    }
}

