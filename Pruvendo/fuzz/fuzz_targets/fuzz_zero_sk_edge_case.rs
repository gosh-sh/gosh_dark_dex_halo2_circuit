//! Fuzz target: Zero SK Edge Case
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Целенаправленно тестирует edge case sk=0:
//! - sk = 0 — валидный элемент поля Fr
//! - Может вызвать edge cases в Poseidon
//! - Может нарушить математические инварианты
//! - Важно для криптографической безопасности
//!
//! ВАЖНО: Этот тест НЕ фильтрует sk=0, в отличие от других тестов.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

mod common;
use common::*;

/// Варианты тестирования sk=0
#[derive(Debug, Arbitrary)]
enum ZeroSkVariant {
    /// sk=0 с разными token_type и sum
    ZeroSkRandomOthers { token_type: u64, note_sum: u64 },
    /// sk=0 и token_type=0
    AllZeroExceptSum { note_sum: u64 },
    /// sk=0 и sum=0
    AllZeroExceptToken { token_type: u64 },
    /// Все нули
    AllZero,
    /// sk=0 с большими значениями
    ZeroSkLargeValues,
    /// Сравнение sk=0 vs sk=1 (должны давать разные commitment)
    CompareZeroVsOne { token_type: u64, note_sum: u64 },
}

fuzz_target!(|variant: ZeroSkVariant| {
    ensure_working_directory();
    
    match variant {
        ZeroSkVariant::ZeroSkRandomOthers { token_type, note_sum } => {
            // sk=0 должен работать как валидный вход (не паниковать)
            let result = check_circuit(0, token_type, note_sum);
            // Проверяем что результат получен (Ok или Err - не важно, главное без паники)
            let _ = result.is_ok();
        }

        ZeroSkVariant::AllZeroExceptSum { note_sum } => {
            let result = check_circuit(0, 0, note_sum);
            let _ = result.is_ok();
        }

        ZeroSkVariant::AllZeroExceptToken { token_type } => {
            let result = check_circuit(0, token_type, 0);
            let _ = result.is_ok();
        }

        ZeroSkVariant::AllZero => {
            // Полностью нулевые входы
            let result = check_circuit(0, 0, 0);
            let _ = result.is_ok();
        }

        ZeroSkVariant::ZeroSkLargeValues => {
            // sk=0 с максимальными значениями
            let result = check_circuit(0, u64::MAX, u64::MAX);
            let _ = result.is_ok();
        }
        
        ZeroSkVariant::CompareZeroVsOne { token_type, note_sum } => {
            // commitment(0) должен отличаться от commitment(1)
            let c0 = compute_sk_commitment(Fr::zero());
            let c1 = compute_sk_commitment(Fr::one());
            
            assert_ne!(
                c0, c1,
                "Commitment of sk=0 must differ from commitment of sk=1"
            );
            
            // digest тоже должен отличаться
            let token = Fr::from(token_type);
            let sum = Fr::from(note_sum);
            let d0 = compute_digest(Fr::zero(), token, sum);
            let d1 = compute_digest(Fr::one(), token, sum);
            
            assert_ne!(
                d0, d1,
                "Digest with sk=0 must differ from digest with sk=1"
            );
        }
    }
});

