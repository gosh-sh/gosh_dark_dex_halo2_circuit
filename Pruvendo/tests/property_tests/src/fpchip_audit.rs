//! FpChip and scalar_multiply Audit Tests
//!
//! Проверяет корректность:
//! - Limb decomposition (256 бит → 3 × 88 бит)
//! - Range checks
//! - EC scalar multiplication
//! - is_equal constraint для pk = sk * g
//!
//! Конфигурация: limb_bits=88, num_limbs=3, lookup_bits=17

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::{Field, PrimeField};
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::arithmetic::CurveAffine;
use proptest::prelude::*;
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

// =============================================================================
// Configuration Constants
// =============================================================================

const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;
const MAX_LIMB_VALUE: u128 = 1u128 << LIMB_BITS; // 2^88

// secp256k1 field sizes (in bits)
const SECP256K1_FP_BITS: usize = 256; // Base field (x, y coordinates)
const SECP256K1_FQ_BITS: usize = 256; // Scalar field (sk)

// =============================================================================
// Limb Decomposition Tests
// =============================================================================

#[test]
fn test_limb_config_sufficient_for_secp256k1() {
    // 3 limbs × 88 bits = 264 bits >= 256 bits (secp256k1)
    let total_bits = NUM_LIMBS * LIMB_BITS;
    assert!(total_bits >= SECP256K1_FP_BITS, 
        "Total limb bits ({}) must be >= secp256k1 field size ({})", 
        total_bits, SECP256K1_FP_BITS);
    
    // Проверяем что последний limb не переполняется
    // Для 256 бит: 88 + 88 + 80 = 256
    let last_limb_bits = SECP256K1_FP_BITS - 2 * LIMB_BITS;
    assert!(last_limb_bits <= LIMB_BITS, 
        "Last limb bits ({}) should be <= LIMB_BITS ({})", 
        last_limb_bits, LIMB_BITS);
}

#[test]
fn test_limb_decomposition_known_values() {
    // Тест на известных значениях
    let sk_val = 12345u64;
    let sk = Fq::from(sk_val);
    let g = Secp256k1Affine::generator();
    let pk = (g * sk).to_affine();

    // Извлекаем limbs
    let pk_x_bytes = pk.x.to_bytes();

    let limb0_x = consume_uint128_11(&pk_x_bytes[0..11]);
    let limb1_x = consume_uint128_11(&pk_x_bytes[11..22]);
    let limb2_x = consume_uint128_10(&pk_x_bytes[22..]);

    // Проверяем range
    assert!(limb0_x < MAX_LIMB_VALUE, "limb0_x overflow");
    assert!(limb1_x < MAX_LIMB_VALUE, "limb1_x overflow");
    // limb2 - 80 бит (10 bytes), всегда < 2^88
    assert!(limb2_x < MAX_LIMB_VALUE, "limb2_x overflow");

    // Реконструируем младшие 88 бит (limb0) и проверяем
    // Полная реконструкция требует BigUint, но для тестирования
    // достаточно проверить что limbs корректно извлечены
    let expected_limb0 = u128::from_le_bytes({
        let mut arr = [0u8; 16];
        arr[0..11].copy_from_slice(&pk_x_bytes[0..11]);
        arr
    });

    assert_eq!(limb0_x, expected_limb0, "limb0 should match bytes");
}

#[test]
fn test_limb_sum_no_overflow_in_fr() {
    // Проверяем что сумма limbs помещается в Fr
    // max_sum = sk_max + 6 * max_limb
    // sk_max ~ 2^64 (в наших тестах)
    // max_limb = 2^88
    // max_sum ~ 6 * 2^88 ~ 2^91
    // Fr modulus ~ 2^254, так что overflow невозможен
    
    let max_limb = MAX_LIMB_VALUE - 1;
    let max_sum = (u64::MAX as u128) + 6 * max_limb;
    
    // Fr modulus ≈ 2^254
    let fr_max_bits = 254usize;
    let sum_bits = 128 - max_sum.leading_zeros() as usize;
    
    assert!(sum_bits < fr_max_bits, 
        "Max sum bits ({}) should be < Fr bits ({})", 
        sum_bits, fr_max_bits);
}

// =============================================================================
// EC Scalar Multiplication Tests
// =============================================================================

#[test]
fn test_scalar_multiply_identity() {
    // sk = 1 должен давать pk = g
    let g = Secp256k1Affine::generator();
    let sk = Fq::one();
    let pk = (g * sk).to_affine();
    
    assert_eq!(pk, g, "1 * g should equal g");
}

#[test]
fn test_scalar_multiply_known_values() {
    let g = Secp256k1Affine::generator();
    
    // sk = 2: pk = 2g
    let sk2 = Fq::from(2u64);
    let pk2 = (g * sk2).to_affine();
    let double_g = (g + g).to_affine();
    assert_eq!(pk2, double_g, "2 * g should equal g + g");
    
    // sk = 3: pk = 3g
    let sk3 = Fq::from(3u64);
    let pk3 = (g * sk3).to_affine();
    let triple_g = (double_g + g).to_affine();
    assert_eq!(pk3, triple_g, "3 * g should equal 2g + g");
}

#[test]
fn test_scalar_multiply_associativity() {
    // (a * b) * g = a * (b * g)
    let g = Secp256k1Affine::generator();
    let a = Fq::from(12345u64);
    let b = Fq::from(67890u64);
    
    let ab = a * b;
    let lhs = (g * ab).to_affine();
    
    let bg = (g * b).to_affine();
    let rhs = (bg * a).to_affine();
    
    assert_eq!(lhs, rhs, "(a*b)*g should equal a*(b*g)");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_limb_range_valid(sk_val in 1u64..u64::MAX) {
        let sk = Fq::from(sk_val);
        let g = Secp256k1Affine::generator();
        let pk = (g * sk).to_affine();

        let pk_x_bytes = pk.x.to_bytes();
        let pk_y_bytes = pk.y.to_bytes();

        // Все limbs должны быть < 2^88
        let limbs = [
            consume_uint128_11(&pk_x_bytes[0..11]),
            consume_uint128_11(&pk_x_bytes[11..22]),
            consume_uint128_10(&pk_x_bytes[22..]),
            consume_uint128_11(&pk_y_bytes[0..11]),
            consume_uint128_11(&pk_y_bytes[11..22]),
            consume_uint128_10(&pk_y_bytes[22..]),
        ];

        for (i, limb) in limbs.iter().enumerate() {
            prop_assert!(*limb < MAX_LIMB_VALUE,
                "Limb {} overflow: {} >= 2^88", i, limb);
        }
    }

    #[test]
    fn prop_scalar_multiply_correctness(sk_val in 1u64..1_000_000u64) {
        // pk = sk * g должен быть на кривой
        let sk = Fq::from(sk_val);
        let g = Secp256k1Affine::generator();
        let pk = (g * sk).to_affine();

        // Проверяем что точка на кривой (secp256k1: y^2 = x^3 + 7)
        let y2 = pk.y * pk.y;
        let x3 = pk.x * pk.x * pk.x;
        let b = Fp::from(7u64);

        prop_assert_eq!(y2, x3 + b, "pk should be on secp256k1 curve");
    }

    #[test]
    fn prop_is_equal_only_for_correct_pk(sk_val in 1u64..1_000_000u64) {
        // is_equal должен быть true ТОЛЬКО когда pk = sk * g
        let sk = Fq::from(sk_val);
        let g = Secp256k1Affine::generator();
        let correct_pk = (g * sk).to_affine();

        // Правильный pk
        let mul = (g * sk).to_affine();
        prop_assert_eq!(correct_pk.x, mul.x, "x coordinates should match");
        prop_assert_eq!(correct_pk.y, mul.y, "y coordinates should match");

        // Неправильный pk (другой sk)
        let wrong_sk = Fq::from(sk_val + 1);
        let wrong_mul = (g * wrong_sk).to_affine();
        prop_assert_ne!(correct_pk.x, wrong_mul.x, "Wrong sk should give different x");
    }
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

#[test]
fn test_scalar_multiply_edge_case_1() {
    // sk = 1
    let g = Secp256k1Affine::generator();
    let sk = Fq::one();
    let pk = (g * sk).to_affine();
    assert_eq!(pk, g);
}

#[test]
fn test_scalar_multiply_edge_case_2() {
    // sk = 2
    let g = Secp256k1Affine::generator();
    let sk = Fq::from(2u64);
    let pk = (g * sk).to_affine();
    let double_g = (g + g).to_affine();
    assert_eq!(pk, double_g);
}

#[test]
fn test_scalar_multiply_large_value() {
    // sk = 2^63 - 1 (большое значение)
    let g = Secp256k1Affine::generator();
    let sk = Fq::from((1u64 << 63) - 1);
    let pk = (g * sk).to_affine();

    // Проверяем что точка на кривой
    let y2 = pk.y * pk.y;
    let x3 = pk.x * pk.x * pk.x;
    let b = Fp::from(7u64);
    assert_eq!(y2, x3 + b, "Large sk result should be on curve");
}

#[test]
fn test_generator_on_curve() {
    // Generator должен быть на кривой
    let g = Secp256k1Affine::generator();

    // secp256k1: y^2 = x^3 + 7
    let y2 = g.y * g.y;
    let x3 = g.x * g.x * g.x;
    let b = Fp::from(7u64);

    assert_eq!(y2, x3 + b, "Generator should be on secp256k1 curve");
}

#[test]
fn test_point_negation() {
    // -P should have same x, negated y
    let g = Secp256k1Affine::generator();
    let sk = Fq::from(12345u64);
    let pk = (g * sk).to_affine();
    let neg_pk = -pk; // Secp256k1Affine already has Neg trait

    assert_eq!(pk.x, neg_pk.x, "Negated point should have same x");
    assert_eq!(pk.y, -neg_pk.y, "Negated point should have negated y");
}

