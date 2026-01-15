//! Integration Tests for DarkDexCircuit
//!
//! End-to-end сценарии тестирования:
//! - Полный цикл proof generation/verification
//! - Multi-user сценарии
//! - Replay protection
//! - Cross-transaction attacks

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::arithmetic::CurveAffine;
use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};
use proptest::prelude::*;
use std::collections::HashMap;

const CIRCUIT_K: u32 = 18;

// =============================================================================
// Helper Functions
// =============================================================================

fn generate_keypair(sk_val: u64) -> (Fq, Secp256k1Affine, Secp256k1Affine) {
    let sk = Fq::from(sk_val);
    let g = Secp256k1Affine::generator();
    let pk = (g * sk).to_affine();
    (sk, pk, g)
}

fn compute_digest(sk_val: u64, pk: &Secp256k1Affine, token: Fr, sum: Fr, vault: Fr) -> Fr {
    // Используем helpers модуль
    crate::helpers::compute_digest(sk_val, pk, token, sum, vault)
}

fn create_and_verify_circuit(
    sk_val: u64, 
    token: u64, 
    sum: u64, 
    vault: u64
) -> Result<(), String> {
    crate::helpers::ensure_working_directory();
    
    let (sk, pk, g) = generate_keypair(sk_val);
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);
    let vault_fr = Fr::from(vault);
    
    let circuit = DarkDexCircuit::new(
        Some(token_fr), Some(sum_fr), Some(vault_fr),
        Some(sk), Some(pk), Some(g),
    );
    
    let digest = compute_digest(sk_val, &pk, token_fr, sum_fr, vault_fr);
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
    // Несколько пользователей с разными keypairs
    let users = vec![
        (1u64, 1u64, 1000u64, 100u64),   // User 1
        (42u64, 2u64, 2000u64, 200u64),  // User 2
        (999u64, 3u64, 3000u64, 300u64), // User 3
        (12345u64, 1u64, 5000u64, 500u64), // User 4
    ];
    
    for (i, (sk_val, token, sum, vault)) in users.iter().enumerate() {
        let result = create_and_verify_circuit(*sk_val, *token, *sum, *vault);
        assert!(result.is_ok(), 
            "User {} should create valid proof: {:?}", i + 1, result);
    }
}

#[test]
fn test_same_user_different_transactions() {
    // Один пользователь делает несколько транзакций
    let sk_val = 12345u64;
    let (sk, pk, g) = generate_keypair(sk_val);
    
    let transactions = vec![
        (1u64, 1000u64, 100u64),   // Tx 1
        (1u64, 2000u64, 200u64),   // Tx 2: same token, different sum
        (2u64, 1000u64, 300u64),   // Tx 3: different token
        (1u64, 1000u64, 400u64),   // Tx 4: same token/sum, different vault
    ];
    
    for (i, (token, sum, vault)) in transactions.iter().enumerate() {
        let result = create_and_verify_circuit(sk_val, *token, *sum, *vault);
        assert!(result.is_ok(), 
            "Transaction {} should be valid: {:?}", i + 1, result);
    }
}

// =============================================================================
// Replay Protection Tests
// =============================================================================

#[test]
fn test_replay_attack_different_sum_rejected() {
    crate::helpers::ensure_working_directory();
    
    // Пользователь создаёт proof для sum=1000
    let sk_val = 12345u64;
    let (sk, pk, g) = generate_keypair(sk_val);
    
    let token_fr = Fr::from(1u64);
    let sum1_fr = Fr::from(1000u64);
    let sum2_fr = Fr::from(2000u64);  // Атакующий хочет другую сумму
    let vault_fr = Fr::from(100u64);
    
    // Создаём circuit с sum=1000
    let circuit = DarkDexCircuit::new(
        Some(token_fr), Some(sum1_fr), Some(vault_fr),
        Some(sk), Some(pk), Some(g),
    );
    
    // Но пытаемся верифицировать с sum=2000 (replay attack)
    let fake_digest = compute_digest(sk_val, &pk, token_fr, sum2_fr, vault_fr);
    let fake_pub_inputs = vec![sum2_fr, token_fr, fake_digest];
    
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![fake_pub_inputs]).unwrap();
    assert!(prover.verify().is_err(), 
        "Replay attack with different sum should be rejected");
}

#[test]
fn test_replay_attack_different_token_rejected() {
    crate::helpers::ensure_working_directory();
    
    let sk_val = 12345u64;
    let (sk, pk, g) = generate_keypair(sk_val);
    
    let token1_fr = Fr::from(1u64);
    let token2_fr = Fr::from(2u64);  // Атакующий хочет другой токен
    let sum_fr = Fr::from(1000u64);
    let vault_fr = Fr::from(100u64);
    
    // Создаём circuit с token=1
    let circuit = DarkDexCircuit::new(
        Some(token1_fr), Some(sum_fr), Some(vault_fr),
        Some(sk), Some(pk), Some(g),
    );
    
    // Пытаемся верифицировать с token=2
    let fake_digest = compute_digest(sk_val, &pk, token2_fr, sum_fr, vault_fr);
    let fake_pub_inputs = vec![sum_fr, token2_fr, fake_digest];
    
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![fake_pub_inputs]).unwrap();
    assert!(prover.verify().is_err(),
        "Replay attack with different token should be rejected");
}

// =============================================================================
// Cross-User Attack Tests
// =============================================================================

#[test]
fn test_cross_user_keypair_swap_rejected() {
    crate::helpers::ensure_working_directory();

    // User A создаёт keypair
    let sk_a_val = 111u64;
    let (sk_a, pk_a, g) = generate_keypair(sk_a_val);

    // User B создаёт keypair
    let sk_b_val = 222u64;
    let (_sk_b, pk_b, _) = generate_keypair(sk_b_val);

    let token_fr = Fr::from(1u64);
    let sum_fr = Fr::from(1000u64);
    let vault_fr = Fr::from(100u64);

    // Атака: User A пытается использовать pk_b с sk_a
    let circuit = DarkDexCircuit::new(
        Some(token_fr), Some(sum_fr), Some(vault_fr),
        Some(sk_a), Some(pk_b), // WRONG: pk_b не соответствует sk_a
        Some(g),
    );

    // Digest вычислен для pk_b (как будто это легитимная транзакция B)
    let digest = compute_digest(sk_a_val, &pk_b, token_fr, sum_fr, vault_fr);
    let pub_inputs = vec![sum_fr, token_fr, digest];

    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![pub_inputs]).unwrap();
    assert!(prover.verify().is_err(),
        "Cross-user keypair swap should be rejected (pk != sk * g)");
}

#[test]
fn test_cross_user_digest_swap_rejected() {
    crate::helpers::ensure_working_directory();

    // User A
    let sk_a_val = 111u64;
    let (sk_a, pk_a, g) = generate_keypair(sk_a_val);

    // User B
    let sk_b_val = 222u64;
    let (_sk_b, pk_b, _) = generate_keypair(sk_b_val);

    let token_fr = Fr::from(1u64);
    let sum_fr = Fr::from(1000u64);
    let vault_fr = Fr::from(100u64);

    // User A создаёт свой circuit
    let circuit_a = DarkDexCircuit::new(
        Some(token_fr), Some(sum_fr), Some(vault_fr),
        Some(sk_a), Some(pk_a), Some(g),
    );

    // Но использует digest от User B
    let digest_b = compute_digest(sk_b_val, &pk_b, token_fr, sum_fr, vault_fr);
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
    let result = create_and_verify_circuit(12345, 1, 0, 100);
    assert!(result.is_ok(), "Zero sum should be valid: {:?}", result);
}

#[test]
fn test_zero_token_valid() {
    // Транзакция с token=0 должна быть валидной
    let result = create_and_verify_circuit(12345, 0, 1000, 100);
    assert!(result.is_ok(), "Zero token should be valid: {:?}", result);
}

#[test]
fn test_large_values_valid() {
    // Транзакция с большими значениями
    let result = create_and_verify_circuit(12345, u32::MAX as u64, u32::MAX as u64, u32::MAX as u64);
    assert!(result.is_ok(), "Large values should be valid: {:?}", result);
}

#[test]
fn test_minimum_sk_valid() {
    // sk = 1 (минимальное валидное значение)
    let result = create_and_verify_circuit(1, 1, 1000, 100);
    assert!(result.is_ok(), "Minimum sk should be valid: {:?}", result);
}

// =============================================================================
// Consistency Tests
// =============================================================================

#[test]
fn test_digest_uniqueness() {
    crate::helpers::ensure_working_directory();

    // Разные транзакции с РАЗНЫМИ deposit_sum должны иметь разные digests
    // Примечание: deposit_sum = token + sum + vault
    // Если deposit_sum одинаковый (например, 1+1000+101 = 1+1001+100 = 1102),
    // то digest будет одинаковый - это ожидаемое поведение (см. BC-007)
    let sk_val = 12345u64;
    let (_, pk, _) = generate_keypair(sk_val);

    let mut digests: HashMap<[u8; 32], (u64, u64, u64, u64)> = HashMap::new();

    // Тестовые случаи с РАЗНЫМИ deposit_sum
    let test_cases = vec![
        (1u64, 1000u64, 100u64),   // deposit_sum = 1101
        (1u64, 1000u64, 200u64),   // deposit_sum = 1201
        (1u64, 2000u64, 100u64),   // deposit_sum = 2101
        (2u64, 1000u64, 100u64),   // deposit_sum = 1102
        (10u64, 500u64, 50u64),    // deposit_sum = 560
    ];

    for (token, sum, vault) in test_cases {
        let deposit_sum = token + sum + vault;
        let digest = compute_digest(
            sk_val, &pk,
            Fr::from(token), Fr::from(sum), Fr::from(vault)
        );
        // Используем bytes для уникального ключа
        let key = digest.to_bytes();
        if let Some(prev) = digests.get(&key) {
            panic!(
                "Digest collision for DIFFERENT deposit_sum!\n  Previous: token={}, sum={}, vault={}, deposit_sum={}\n  Current: token={}, sum={}, vault={}, deposit_sum={}\n  Digest: {:?}",
                prev.0, prev.1, prev.2, prev.3, token, sum, vault, deposit_sum, digest
            );
        }
        digests.insert(key, (token, sum, vault, deposit_sum));
    }
}

#[test]
fn test_digest_determinism() {
    // Одинаковые входы должны давать одинаковый digest
    let sk_val = 12345u64;
    let (_, pk, _) = generate_keypair(sk_val);

    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);
    let vault = Fr::from(100u64);

    let digest1 = compute_digest(sk_val, &pk, token, sum, vault);
    let digest2 = compute_digest(sk_val, &pk, token, sum, vault);

    assert_eq!(digest1, digest2, "Same inputs should produce same digest");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_valid_circuit_always_passes(
        sk_val in 1u64..100_000u64,
        token in 0u64..1_000u64,
        sum in 0u64..1_000_000u64,
        vault in 0u64..1_000u64
    ) {
        let result = create_and_verify_circuit(sk_val, token, sum, vault);
        prop_assert!(result.is_ok(), "Valid circuit should pass: {:?}", result);
    }
}

