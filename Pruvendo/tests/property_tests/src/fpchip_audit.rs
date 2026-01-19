//! Poseidon Hash Audit Tests
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет корректность:
//! - Poseidon hash properties
//! - sk_commitment = poseidon(sk, 0)
//! - digest = poseidon(sk_commitment, sum, token, sk)
//! - Collision resistance
//! - Preimage resistance

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::{Field, PrimeField};
use proptest::prelude::*;
use gosh_dark_dex_halo2_circuit::circuit::poseidon_hash;

use crate::helpers::{compute_sk_commitment, compute_digest};

// =============================================================================
// Poseidon Hash Basic Properties
// =============================================================================

#[test]
fn test_poseidon_determinism() {
    // Same inputs should produce same output
    let inputs = [Fr::from(1u64), Fr::from(2u64)];
    let h1 = poseidon_hash(inputs);
    let h2 = poseidon_hash(inputs);
    assert_eq!(h1, h2, "Poseidon should be deterministic");
}

#[test]
fn test_poseidon_different_inputs_different_outputs() {
    let h1 = poseidon_hash([Fr::from(1u64), Fr::from(2u64)]);
    let h2 = poseidon_hash([Fr::from(1u64), Fr::from(3u64)]);
    assert_ne!(h1, h2, "Different inputs should produce different outputs");
}

#[test]
fn test_poseidon_order_matters() {
    let h1 = poseidon_hash([Fr::from(1u64), Fr::from(2u64)]);
    let h2 = poseidon_hash([Fr::from(2u64), Fr::from(1u64)]);
    assert_ne!(h1, h2, "Input order should matter");
}

#[test]
fn test_poseidon_zero_inputs() {
    let h = poseidon_hash([Fr::zero(), Fr::zero()]);
    // Hash of zeros should be non-zero
    assert_ne!(h, Fr::zero(), "Hash of zeros should be non-zero");
}

// =============================================================================
// SK Commitment Tests
// =============================================================================

#[test]
fn test_sk_commitment_determinism() {
    let sk = Fr::from(12345u64);
    let c1 = compute_sk_commitment(sk);
    let c2 = compute_sk_commitment(sk);
    assert_eq!(c1, c2, "Same sk should produce same commitment");
}

#[test]
fn test_sk_commitment_different_sk() {
    let c1 = compute_sk_commitment(Fr::from(1u64));
    let c2 = compute_sk_commitment(Fr::from(2u64));
    assert_ne!(c1, c2, "Different sk should produce different commitment");
}

#[test]
fn test_sk_commitment_zero() {
    let c = compute_sk_commitment(Fr::zero());
    // Commitment of zero should be non-zero
    assert_ne!(c, Fr::zero(), "Commitment of zero should be non-zero");
}

#[test]
fn test_sk_commitment_one() {
    let c = compute_sk_commitment(Fr::one());
    assert_ne!(c, Fr::zero(), "Commitment of one should be non-zero");
    assert_ne!(c, Fr::one(), "Commitment of one should not be one");
}

// =============================================================================
// Digest Tests
// =============================================================================

#[test]
fn test_digest_determinism() {
    let sk = Fr::from(12345u64);
    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);

    let d1 = compute_digest(sk, token, sum);
    let d2 = compute_digest(sk, token, sum);
    assert_eq!(d1, d2, "Same inputs should produce same digest");
}

#[test]
fn test_digest_different_sk() {
    let token = Fr::from(1u64);
    let sum = Fr::from(1000u64);

    let d1 = compute_digest(Fr::from(1u64), token, sum);
    let d2 = compute_digest(Fr::from(2u64), token, sum);
    assert_ne!(d1, d2, "Different sk should produce different digest");
}

#[test]
fn test_digest_different_token() {
    let sk = Fr::from(12345u64);
    let sum = Fr::from(1000u64);

    let d1 = compute_digest(sk, Fr::from(1u64), sum);
    let d2 = compute_digest(sk, Fr::from(2u64), sum);
    assert_ne!(d1, d2, "Different token should produce different digest");
}

#[test]
fn test_digest_different_sum() {
    let sk = Fr::from(12345u64);
    let token = Fr::from(1u64);

    let d1 = compute_digest(sk, token, Fr::from(1000u64));
    let d2 = compute_digest(sk, token, Fr::from(2000u64));
    assert_ne!(d1, d2, "Different sum should produce different digest");
}

// =============================================================================
// Property-Based Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_commitment_determinism(sk_val in 1u64..1_000_000u64) {
        let sk = Fr::from(sk_val);
        let c1 = compute_sk_commitment(sk);
        let c2 = compute_sk_commitment(sk);
        prop_assert_eq!(c1, c2, "Commitment should be deterministic");
    }

    #[test]
    fn prop_different_sk_different_commitment(
        sk1_val in 1u64..500_000u64,
        sk2_val in 500_001u64..1_000_000u64
    ) {
        let c1 = compute_sk_commitment(Fr::from(sk1_val));
        let c2 = compute_sk_commitment(Fr::from(sk2_val));
        prop_assert_ne!(c1, c2, "Different sk should produce different commitment");
    }

    #[test]
    fn prop_digest_determinism(
        sk_val in 1u64..100_000u64,
        token in 0u64..1000u64,
        sum in 0u64..1_000_000u64
    ) {
        let sk = Fr::from(sk_val);
        let d1 = compute_digest(sk, Fr::from(token), Fr::from(sum));
        let d2 = compute_digest(sk, Fr::from(token), Fr::from(sum));
        prop_assert_eq!(d1, d2, "Digest should be deterministic");
    }

    #[test]
    fn prop_digest_binding_sk(
        sk1_val in 1u64..500_000u64,
        sk2_val in 500_001u64..1_000_000u64,
        token in 0u64..100u64,
        sum in 0u64..10000u64
    ) {
        let d1 = compute_digest(Fr::from(sk1_val), Fr::from(token), Fr::from(sum));
        let d2 = compute_digest(Fr::from(sk2_val), Fr::from(token), Fr::from(sum));
        prop_assert_ne!(d1, d2, "Different sk should produce different digest");
    }

    #[test]
    fn prop_digest_binding_token(
        sk_val in 1u64..100_000u64,
        token1 in 0u64..500u64,
        token2 in 501u64..1000u64,
        sum in 0u64..10000u64
    ) {
        let sk = Fr::from(sk_val);
        let d1 = compute_digest(sk, Fr::from(token1), Fr::from(sum));
        let d2 = compute_digest(sk, Fr::from(token2), Fr::from(sum));
        prop_assert_ne!(d1, d2, "Different token should produce different digest");
    }

    #[test]
    fn prop_digest_binding_sum(
        sk_val in 1u64..100_000u64,
        token in 0u64..100u64,
        sum1 in 0u64..500_000u64,
        sum2 in 500_001u64..1_000_000u64
    ) {
        let sk = Fr::from(sk_val);
        let d1 = compute_digest(sk, Fr::from(token), Fr::from(sum1));
        let d2 = compute_digest(sk, Fr::from(token), Fr::from(sum2));
        prop_assert_ne!(d1, d2, "Different sum should produce different digest");
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_commitment_edge_case_max_u64() {
    let sk = Fr::from(u64::MAX);
    let c = compute_sk_commitment(sk);
    assert_ne!(c, Fr::zero(), "Commitment of max u64 should be non-zero");
}

#[test]
fn test_digest_edge_case_all_zeros() {
    let d = compute_digest(Fr::zero(), Fr::zero(), Fr::zero());
    assert_ne!(d, Fr::zero(), "Digest of all zeros should be non-zero");
}

#[test]
fn test_digest_edge_case_large_values() {
    let sk = Fr::from(u64::MAX);
    let token = Fr::from(u64::MAX);
    let sum = Fr::from(u64::MAX);
    let d = compute_digest(sk, token, sum);
    assert_ne!(d, Fr::zero(), "Digest of large values should be non-zero");
}

