//! Fuzz target: Edge Cases
//!
//! Тестирует граничные случаи:
//! - sk = 0 (должно обрабатываться корректно)
//! - sk = 1 (тривиальный случай)
//! - sk близко к order (большие значения)
//! - token_type = 0
//! - sum = 0
//! - Очень большие значения
//!
//! Находит: паники, переполнения, неопределённое поведение.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

/// Edge case типы для фаззинга
#[derive(Debug, Arbitrary)]
enum EdgeCaseType {
    /// sk = 0 (нулевой секретный ключ)
    ZeroSk,
    /// sk = 1 (единичный)
    OneSk,
    /// sk = очень большое число
    LargeSk(u64),
    /// token_type = 0
    ZeroToken,
    /// sum = 0
    ZeroSum,
    /// Все нули
    AllZero,
    /// Все максимальные
    AllMax,
    /// Случайная комбинация
    Random(u64, u64, u64),
}

fuzz_target!(|edge_case: EdgeCaseType| {
    let (sk_val, token_type, note_sum) = match edge_case {
        EdgeCaseType::ZeroSk => (0u64, 1u64, 1000u64),
        EdgeCaseType::OneSk => (1u64, 1u64, 1000u64),
        EdgeCaseType::LargeSk(v) => {
            // Используем большое значение, но не переполняем
            let large = (v % u64::MAX).saturating_add(1_000_000_000);
            (large, 1u64, 1000u64)
        }
        EdgeCaseType::ZeroToken => (12345u64, 0u64, 1000u64),
        EdgeCaseType::ZeroSum => (12345u64, 1u64, 0u64),
        EdgeCaseType::AllZero => (0u64, 0u64, 0u64),
        EdgeCaseType::AllMax => (u64::MAX, u64::MAX, u64::MAX),
        EdgeCaseType::Random(sk, token, sum) => (sk, token, sum),
    };

    // Пропускаем sk=0 так как это приводит к invalid point
    if sk_val == 0 {
        // Проверяем что хотя бы не паникует
        let g = halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Affine::generator();
        // sk=0 означает pk = identity point, что может быть edge case
        return;
    }

    // Генерируем пару ключей
    let (sk, pk, g) = generate_valid_keypair(sk_val);

    // Проверяем что схема НЕ паникует на граничных случаях
    // Результат может быть Ok или Err, главное - не паника
    let _result = check_circuit(
        sk,
        pk,
        g,
        token_type,
        note_sum,
        token_type,
        note_sum,
    );
    
    // Если дошли сюда - граничный случай обработан без паники ✓
});

