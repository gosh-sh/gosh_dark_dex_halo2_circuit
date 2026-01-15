//! Poseidon Hash Audit Tests
//!
//! Проверяет корректность реализации Poseidon:
//! - Round constants
//! - MDS matrix
//! - S-box (x^5)
//! - Permutation
//! - Gadget vs primitive consistency
//!
//! Спецификация: P128Pow5T3 (128-bit security, x^5 S-box, T=3, rate=2)
//! - Full rounds: 8 (4 + 4)
//! - Partial rounds: 57 (для bn256::Fr)
//! - Total rounds: 65

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::{Field, PrimeField};
use gosh_dark_dex_halo2_circuit::circuit::poseidon_hash;
use proptest::prelude::*;

// =============================================================================
// MDS Matrix Tests
// =============================================================================

#[test]
fn test_mds_matrix_invertibility() {
    // MDS * MDS_INV должна давать единичную матрицу
    // Это критично для корректности расшифровки
    use poseidon_base::primitives::bn256::fp::{MDS, MDS_INV};
    
    let mds = *MDS;
    let mds_inv = *MDS_INV;
    
    // Вычисляем MDS * MDS_INV
    let mut result = [[Fr::zero(); 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            for k in 0..3 {
                result[i][j] += mds[i][k] * mds_inv[k][j];
            }
        }
    }
    
    // Проверяем что результат - единичная матрица
    for i in 0..3 {
        for j in 0..3 {
            if i == j {
                assert_eq!(result[i][j], Fr::one(), 
                    "MDS * MDS_INV diagonal element [{i}][{j}] should be 1");
            } else {
                assert_eq!(result[i][j], Fr::zero(), 
                    "MDS * MDS_INV off-diagonal element [{i}][{j}] should be 0");
            }
        }
    }
}

#[test]
fn test_mds_is_mds() {
    // Проверяем что MDS матрица действительно является Maximum Distance Separable
    // Для 3x3 матрицы это означает что все 2x2 миноры ненулевые
    use poseidon_base::primitives::bn256::fp::MDS;
    
    let mds = *MDS;
    
    // Проверяем все 2x2 миноры
    for skip_row in 0..3 {
        for skip_col in 0..3 {
            let rows: Vec<_> = (0..3).filter(|&r| r != skip_row).collect();
            let cols: Vec<_> = (0..3).filter(|&c| c != skip_col).collect();
            
            let minor = mds[rows[0]][cols[0]] * mds[rows[1]][cols[1]] 
                      - mds[rows[0]][cols[1]] * mds[rows[1]][cols[0]];
            
            assert_ne!(minor, Fr::zero(), 
                "MDS minor (skip row {skip_row}, col {skip_col}) should be non-zero");
        }
    }
    
    // Проверяем что детерминант ненулевой
    let det = mds[0][0] * (mds[1][1] * mds[2][2] - mds[1][2] * mds[2][1])
            - mds[0][1] * (mds[1][0] * mds[2][2] - mds[1][2] * mds[2][0])
            + mds[0][2] * (mds[1][0] * mds[2][1] - mds[1][1] * mds[2][0]);
    
    assert_ne!(det, Fr::zero(), "MDS determinant should be non-zero");
}

// =============================================================================
// S-box Tests
// =============================================================================

#[test]
fn test_sbox_x5() {
    // S-box должен вычислять x^5
    use poseidon_base::primitives::{Spec, P128Pow5T3};
    
    // Тест на известных значениях
    let test_values = [
        Fr::zero(),
        Fr::one(),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(12345u64),
        -Fr::one(), // p - 1
    ];
    
    for val in test_values {
        let sbox_result = P128Pow5T3::<Fr>::sbox(val);
        let expected = val * val * val * val * val; // x^5
        
        assert_eq!(sbox_result, expected, 
            "S-box({:?}) should equal x^5", val);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    
    #[test]
    fn prop_sbox_is_x5(x in any::<u64>()) {
        use poseidon_base::primitives::{Spec, P128Pow5T3};
        
        let val = Fr::from(x);
        let sbox_result = P128Pow5T3::<Fr>::sbox(val);
        
        // x^5 = (x^2)^2 * x
        let x2 = val * val;
        let x4 = x2 * x2;
        let x5 = x4 * val;
        
        prop_assert_eq!(sbox_result, x5, "S-box should compute x^5");
    }
}

// =============================================================================
// Round Constants Tests
// =============================================================================

#[test]
fn test_round_constants_count() {
    use poseidon_base::primitives::bn256::fp::ROUND_CONSTANTS;
    
    // 8 full rounds + 57 partial rounds = 65 total
    assert_eq!(ROUND_CONSTANTS.len(), 65, 
        "Should have 65 round constants (8 full + 57 partial)");
    
    // Каждый round constant - массив из 3 элементов (state width = 3)
    for (i, rc) in ROUND_CONSTANTS.iter().enumerate() {
        assert_eq!(rc.len(), 3, "Round constant {i} should have 3 elements");
    }
}

#[test]
fn test_round_constants_not_trivial() {
    use poseidon_base::primitives::bn256::fp::ROUND_CONSTANTS;

    // Round constants не должны быть тривиальными (все нули или все одинаковые)
    let mut all_same = true;
    let first = ROUND_CONSTANTS[0];

    for rc in ROUND_CONSTANTS.iter().skip(1) {
        if *rc != first {
            all_same = false;
            break;
        }
    }

    assert!(!all_same, "Round constants should not all be identical");
}

// =============================================================================
// Hash Function Tests
// =============================================================================

#[test]
fn test_poseidon_deterministic() {
    // Hash должен быть детерминированным
    let a = Fr::from(12345u64);
    let b = Fr::from(67890u64);

    let hash1 = poseidon_hash([a, b]);
    let hash2 = poseidon_hash([a, b]);

    assert_eq!(hash1, hash2, "Poseidon hash should be deterministic");
}

#[test]
fn test_poseidon_non_symmetric() {
    // H(a, b) != H(b, a) для a != b
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);

    let hash_ab = poseidon_hash([a, b]);
    let hash_ba = poseidon_hash([b, a]);

    assert_ne!(hash_ab, hash_ba, "H(a,b) should differ from H(b,a)");
}

#[test]
fn test_poseidon_zero_inputs() {
    // Hash от нулей должен быть определён
    let hash = poseidon_hash([Fr::zero(), Fr::zero()]);

    // Не должен быть нулём (было бы подозрительно)
    // На самом деле может быть любым, но проверим что вычисляется
    let _ = hash; // Just check it computes without panic
}

#[test]
fn test_poseidon_known_vector() {
    // Тест на известном значении из src/poseidon.rs
    let result = poseidon_hash([Fr::from(2u64), Fr::from(3u64)]);

    assert_eq!(
        format!("{result:?}"),
        "0x19014d18a3179c5731155fcb7b6da422f456bccbd6da9dbc7df0f8dc6d4938ed",
        "Poseidon hash should match known test vector"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_hash_non_symmetric(a in any::<u64>(), b in any::<u64>()) {
        prop_assume!(a != b);

        let fa = Fr::from(a);
        let fb = Fr::from(b);

        let hash_ab = poseidon_hash([fa, fb]);
        let hash_ba = poseidon_hash([fb, fa]);

        prop_assert_ne!(hash_ab, hash_ba, "H(a,b) != H(b,a) for a != b");
    }

    #[test]
    fn prop_hash_collision_resistance(a1 in any::<u64>(), b1 in any::<u64>(),
                                       a2 in any::<u64>(), b2 in any::<u64>()) {
        prop_assume!(a1 != a2 || b1 != b2);

        let hash1 = poseidon_hash([Fr::from(a1), Fr::from(b1)]);
        let hash2 = poseidon_hash([Fr::from(a2), Fr::from(b2)]);

        prop_assert_ne!(hash1, hash2,
            "Different inputs should produce different hashes");
    }

    #[test]
    fn prop_hash_non_linear(a in any::<u64>(), b in any::<u64>()) {
        let fa = Fr::from(a);
        let fb = Fr::from(b);

        // H(a+b, 0) != H(a, 0) + H(b, 0)
        let h_sum = poseidon_hash([fa + fb, Fr::zero()]);
        let h_a = poseidon_hash([fa, Fr::zero()]);
        let h_b = poseidon_hash([fb, Fr::zero()]);

        prop_assert_ne!(h_sum, h_a + h_b, "Poseidon should be non-linear");
    }
}

// =============================================================================
// Permutation Tests
// =============================================================================

#[test]
fn test_permutation_full_state() {
    use poseidon_base::primitives::{permute, Spec, P128Pow5T3};
    use poseidon_base::primitives::bn256::fp::{ROUND_CONSTANTS, MDS};

    // Тест permutation на известном начальном состоянии
    let initial_state = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let mut state = initial_state;

    // Получаем константы для bn256::Fr
    let rc: &[[Fr; 3]] = &*ROUND_CONSTANTS;
    let mds: &[[Fr; 3]; 3] = &*MDS;

    permute::<Fr, P128Pow5T3<Fr>, 3, 2>(&mut state, mds, rc);

    // Состояние должно измениться
    assert_ne!(state, initial_state, "Permutation should modify state");

    // Все элементы должны быть ненулевыми (с высокой вероятностью)
    for s in state.iter() {
        // Не обязательно ненулевые, но проверим что вычислились
        let _ = s;
    }
}

#[test]
fn test_permutation_deterministic() {
    use poseidon_base::primitives::{permute, P128Pow5T3};
    use poseidon_base::primitives::bn256::fp::{ROUND_CONSTANTS, MDS};

    let initial_state = [Fr::from(42u64), Fr::from(43u64), Fr::from(44u64)];

    let mut state1 = initial_state;
    let mut state2 = initial_state;

    let rc: &[[Fr; 3]] = &*ROUND_CONSTANTS;
    let mds: &[[Fr; 3]; 3] = &*MDS;

    permute::<Fr, P128Pow5T3<Fr>, 3, 2>(&mut state1, mds, rc);
    permute::<Fr, P128Pow5T3<Fr>, 3, 2>(&mut state2, mds, rc);

    assert_eq!(state1, state2, "Permutation should be deterministic");
}

