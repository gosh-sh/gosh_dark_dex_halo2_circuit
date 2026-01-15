//! Fuzz target: Public input mismatch attacks
//!
//! Проверяет: можно ли создать proof с одними public inputs,
//! а верифицировать с другими?
//!
//! Атаки:
//! - Изменить token_type в public inputs после proof generation
//! - Изменить private_note_sum в public inputs
//! - Изменить digest (подставить чужой)
//!
//! Ожидание: scheme должна ОТКЛОНИТЬ все несоответствия
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

/// Input for public input mismatch fuzzing
#[derive(Debug)]
struct PublicInputMismatchInput {
    sk: u64,
    token: u64,
    sum: u64,
    vault: u64,
    // Альтернативные значения для атаки
    alt_token: u64,
    alt_sum: u64,
    attack_type: u8,
}

impl<'a> Arbitrary<'a> for PublicInputMismatchInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        let token = u.int_in_range(0..=1000000u64)?;
        let sum = u.int_in_range(0..=1000000000u64)?;
        let alt_token = u.int_in_range(0..=1000000u64)?;
        let alt_sum = u.int_in_range(0..=1000000000u64)?;
        Ok(PublicInputMismatchInput {
            sk: u.int_in_range(1..=u64::MAX)?,
            token,
            sum,
            vault: u.arbitrary()?,
            alt_token,
            alt_sum,
            attack_type: u.int_in_range(0..=4)?,
        })
    }
}

fuzz_target!(|input: PublicInputMismatchInput| {
    ensure_working_directory();
    
    let (sk, pk, g) = generate_valid_keypair(input.sk);
    
    match input.attack_type {
        0 => {
            // Attack 0: Использовать circuit с token=T1 но public input token=T2
            if input.token == input.alt_token {
                return; // Skip если одинаковые
            }
            
            let result = check_circuit_with_custom_digest(
                sk, pk, g,
                input.alt_token,  // circuit использует alt_token
                input.sum,
                input.vault,
                input.sk,
                input.token,  // но digest вычислен для token
                input.sum,
                input.vault,
            );
            
            // Должно провалиться: token в circuit != token в digest
            assert!(
                result.is_err(),
                "ATTACK SUCCEEDED: Different token in circuit vs digest! token={} vs {}",
                input.alt_token,
                input.token
            );
        },
        1 => {
            // Attack 1: Использовать circuit с sum=S1 но public input sum=S2
            if input.sum == input.alt_sum {
                return;
            }
            
            let result = check_circuit_with_custom_digest(
                sk, pk, g,
                input.token,
                input.alt_sum,  // circuit использует alt_sum
                input.vault,
                input.sk,
                input.token,
                input.sum,  // но digest вычислен для sum
                input.vault,
            );
            
            assert!(
                result.is_err(),
                "ATTACK SUCCEEDED: Different sum in circuit vs digest! sum={} vs {}",
                input.alt_sum,
                input.sum
            );
        },
        2 => {
            // Attack 2: Подменить vault_rand_val при сохранении deposit_sum
            // Если token1 + sum1 + vault1 = token2 + sum2 + vault2
            // Это BC-007, но мы проверяем что схема его отклоняет
            let total = input.token + input.sum + input.vault;
            if input.alt_token + input.alt_sum >= total {
                return;
            }
            let alt_vault = total - input.alt_token - input.alt_sum;
            
            // Тот же deposit_sum, но разные компоненты
            let result = check_circuit_with_custom_digest(
                sk, pk, g,
                input.alt_token,
                input.alt_sum,
                alt_vault,
                input.sk,
                input.token,  // Оригинальные значения для digest
                input.sum,
                input.vault,
            );
            
            // Это МОЖЕТ пройти (BC-007), но token/sum - public inputs, verifier увидит разницу
            // Для данного теста мы проверяем что circuit отклоняет разные значения
            // даже если deposit_sum совпадает
            if input.token != input.alt_token || input.sum != input.alt_sum {
                assert!(
                    result.is_err(),
                    "BC-007 EXPLOITED? token={}/{} sum={}/{} vault={}/{}",
                    input.token, input.alt_token,
                    input.sum, input.alt_sum,
                    input.vault, alt_vault
                );
            }
        },
        _ => {
            // Default: просто проверяем что валидные данные работают
            let result = check_circuit(sk, pk, g, input.token, input.sum, input.vault, input.sk);
            // Не assert - просто проверяем что не panic
        },
    }
});

