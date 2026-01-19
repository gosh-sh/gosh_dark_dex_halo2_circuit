//! Fuzz target: Private Note Sum Binding
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет что sum включён в digest и схема:
//! 1. ПРИНИМАЕТ правильную сумму (completeness)
//! 2. ОТКЛОНЯЕТ неправильную сумму (soundness)
//!
//! Критично для безопасности: злоумышленник не должен иметь возможности
//! создать proof с одной суммой, а верифицировать с другой.

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
    wrong_sum: u64,
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
        // Test 1: Completeness - правильная сумма принимается
        let result = check_circuit(input.sk_val, token, sum);
        assert!(
            result.is_ok(),
            "COMPLETENESS VIOLATION: Valid sum rejected!\nsk={}, token={}, sum={}\nError: {:?}",
            input.sk_val, token, sum, result
        );
    } else {
        // Test 2: Soundness - неправильная сумма отклоняется
        if input.wrong_sum == sum {
            return; // Skip if wrong_sum == correct sum
        }

        let sk = Fr::from(input.sk_val);

        // Вычисляем digest с неправильной суммой
        let wrong_digest = compute_digest(sk, Fr::from(token), Fr::from(input.wrong_sum));

        // Пробуем верифицировать с неправильным digest (wrong sum)
        let result = check_circuit_with_custom_digest(
            sk,
            token,
            sum,  // circuit использует правильную sum
            wrong_digest,  // но digest вычислен с wrong_sum
        );

        assert!(
            result.is_err(),
            "SOUNDNESS VIOLATION: Wrong sum accepted!\n\
             circuit_sum={}, digest_sum={}\n\
             Token={}, sk={}",
            sum, input.wrong_sum, token, input.sk_val
        );
    }
});

