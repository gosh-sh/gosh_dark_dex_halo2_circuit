//! Fuzz target: Cross-keypair attacks
//!
//! Проверяет: можно ли использовать proof от одного keypair
//! для верификации другого keypair?
//!
//! Атаки:
//! - Использовать pk1 с sk2
//! - Использовать sk1 с pk2
//! - Найти (sk1, pk1) и (sk2, pk2) с одинаковым key_data_sum
//!
//! Ожидание: каждый proof привязан к конкретной паре (sk, pk)
#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    ff::PrimeField,
};

/// Input for cross-keypair attack fuzzing
#[derive(Debug)]
struct CrossKeypairInput {
    sk1: u64,
    sk2: u64,
    attack_type: u8,
    token: u64,
    sum: u64,
    vault: u64,
}

impl<'a> Arbitrary<'a> for CrossKeypairInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        let sk1 = u.int_in_range(1..=u64::MAX)?;
        let sk2 = u.int_in_range(1..=u64::MAX)?;
        Ok(CrossKeypairInput {
            sk1,
            sk2,
            attack_type: u.int_in_range(0..=3)?,
            token: u.int_in_range(0..=1000u64)?,
            sum: u.int_in_range(0..=1000000u64)?,
            vault: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: CrossKeypairInput| {
    ensure_working_directory();
    
    // Генерируем два разных keypair
    if input.sk1 == input.sk2 {
        return; // Skip если одинаковые
    }
    
    let (sk1, pk1, g) = generate_valid_keypair(input.sk1);
    let (sk2, pk2, _) = generate_valid_keypair(input.sk2);
    
    match input.attack_type {
        0 => {
            // Attack 0: Использовать sk1 с pk2
            // Circuit должен отклонить: pk2 ≠ sk1 * g
            let result = check_circuit(
                sk1,   // sk1
                pk2,   // pk2 (неверный для sk1)
                g,
                input.token,
                input.sum,
                input.vault,
                input.sk1,  // Для digest используем sk1
            );
            
            assert!(
                result.is_err(),
                "SOUNDNESS VIOLATION: sk1 + pk2 accepted! sk1={}, sk2={}",
                input.sk1,
                input.sk2
            );
        },
        1 => {
            // Attack 1: Использовать sk2 с pk1
            let result = check_circuit(
                sk2,   // sk2
                pk1,   // pk1 (неверный для sk2)
                g,
                input.token,
                input.sum,
                input.vault,
                input.sk2,
            );
            
            assert!(
                result.is_err(),
                "SOUNDNESS VIOLATION: sk2 + pk1 accepted! sk1={}, sk2={}",
                input.sk1,
                input.sk2
            );
        },
        2 => {
            // Attack 2: Найти keypairs с близкими sk (sk2 = sk1 + 1)
            // Это особенно интересно для проверки уникальности key_data_sum
            let sk1_plus = Fq::from(input.sk1.saturating_add(1));
            let pk1_plus = Secp256k1Affine::from(g * sk1_plus);
            
            // Проверяем что sk1 с pk_(sk1+1) отклоняется
            let result = check_circuit(
                sk1,
                pk1_plus,
                g,
                input.token,
                input.sum,
                input.vault,
                input.sk1,
            );
            
            assert!(
                result.is_err(),
                "SOUNDNESS VIOLATION: Adjacent keypairs confused! sk={}",
                input.sk1
            );
        },
        _ => {
            // Attack 3: Swap - pk1 верный для sk1, но передаём sk2 в circuit
            // Это проверяет что circuit использует переданный sk, а не выводит из pk
            
            // Вычисляем digest для sk1/pk1 (правильный)
            // Но в circuit передаём sk2
            // Circuit должен fail потому что pk1 ≠ sk2 * g
            
            let result = check_circuit(
                sk2,   // Передаём sk2
                pk1,   // pk1 (правильный для sk1, неправильный для sk2)
                g,
                input.token,
                input.sum,
                input.vault,
                input.sk1,  // Digest для sk1
            );
            
            assert!(
                result.is_err(),
                "SOUNDNESS VIOLATION: Wrong sk accepted with correct pk!"
            );
        },
    }
});

