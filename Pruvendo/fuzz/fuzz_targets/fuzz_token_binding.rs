//! Fuzz target: Token Type Binding
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что token_type включён в digest и схема:
//! 1. ПРИНИМАЕТ правильный token_type (completeness)
//! 2. ОТКЛОНЯЕТ неправильный token_type (soundness)
//!
//! Находит: нарушения binding между приватным witness и публичным input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

mod common;
use common::*;

/// Структура входных данных для fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    sk_val: u64,
    token_type: u64,
    note_sum: u64,
    wrong_token: u64,
    test_completeness: bool,
}

fuzz_target!(|input: FuzzInput| {
    if input.sk_val == 0 {
        return;
    }

    ensure_working_directory();

    // Используем полный диапазон u64
    let token = input.token_type;
    let sum = input.note_sum;

    if input.test_completeness {
        // Test 1: Completeness - правильный token принимается
        let result = check_circuit(input.sk_val, token, sum);
        assert!(
            result.is_ok(),
            "COMPLETENESS VIOLATION: Valid token rejected!\nsk={}, token={}, sum={}\nError: {:?}",
            input.sk_val, token, sum, result
        );
    } else {
        // Test 2: Soundness - неправильный token отклоняется
        if input.wrong_token == token {
            return; // Skip if wrong_token == correct token
        }

        let sk = Fr::from(input.sk_val);

        // Вычисляем digest с неправильным token
        let wrong_digest = compute_digest(sk, Fr::from(input.wrong_token), Fr::from(sum));

        // Пробуем верифицировать с неправильным digest (wrong token)
        let result = check_circuit_with_custom_digest(
            sk,
            token,  // circuit использует правильный token
            sum,
            wrong_digest,  // но digest вычислен с wrong_token
        );

        assert!(
            result.is_err(),
            "SOUNDNESS VIOLATION: Wrong token accepted!\n\
             circuit_token={}, digest_token={}\n\
             Sum={}, sk={}",
            token, input.wrong_token, sum, input.sk_val
        );
    }
});

