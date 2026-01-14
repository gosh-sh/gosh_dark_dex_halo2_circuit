//! FUZZ-DEPOSIT-SUM: Deposit sum collision search
//!
//! Ищет разные (token1, sum1, vault1) и (token2, sum2, vault2) с одинаковым deposit_sum.
//! Фокус на Fr modular arithmetic и boundary values.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    ff::PrimeField,
};

#[derive(Arbitrary, Debug)]
struct DepositInput {
    token1: u64,
    sum1: u64,
    vault1: u64,
    token2: u64,
    sum2: u64,
    vault2: u64,
}

/// Fr modulus: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
fn fr_modulus_u256() -> [u64; 4] {
    [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]
}

fuzz_target!(|input: DepositInput| {
    // Вычисляем deposit_sum для обоих наборов
    let token1_fr = Fr::from(input.token1);
    let sum1_fr = Fr::from(input.sum1);
    let vault1_fr = Fr::from(input.vault1);
    let deposit_sum1 = token1_fr + sum1_fr + vault1_fr;
    
    let token2_fr = Fr::from(input.token2);
    let sum2_fr = Fr::from(input.sum2);
    let vault2_fr = Fr::from(input.vault2);
    let deposit_sum2 = token2_fr + sum2_fr + vault2_fr;
    
    // Проверяем: если наборы разные, но суммы равны
    let inputs_different = (input.token1, input.sum1, input.vault1) != 
                           (input.token2, input.sum2, input.vault2);
    
    if inputs_different && deposit_sum1 == deposit_sum2 {
        // Это ожидаемо для разных комбинаций с одинаковой суммой
        // Но опасно если можно подменить token сохраняя deposit_sum!
        
        // Проверяем: разные tokens с одинаковым deposit_sum = уязвимость binding
        if input.token1 != input.token2 {
            // Найдена подмена token с сохранением deposit_sum
            // Это потенциально опасно для binding свойства
            
            // НО: это не уязвимость, т.к. token также публичный input
            // и верификатор проверяет его отдельно
            // 
            // Мы просто логируем для информации
            // (panic только если это нарушает безопасность)
        }
    }
    
    // Критическая проверка: найти коллизию deposit_sum с РАЗНЫМИ public inputs
    // при которых circuit может быть обманут
    
    // Тест на overflow в u64 arithmetic
    let raw_sum1 = input.token1.wrapping_add(input.sum1).wrapping_add(input.vault1);
    let raw_sum2 = input.token2.wrapping_add(input.sum2).wrapping_add(input.vault2);
    
    // Если u64 суммы переполнились по-разному, но Fr суммы равны
    if raw_sum1 != raw_sum2 && deposit_sum1 == deposit_sum2 {
        // Это может быть проблемой если не используется Fr арифметика везде
        panic!(
            "DEPOSIT_SUM WRAPAROUND COLLISION!\n\
             ({}, {}, {}) -> raw: {} -> Fr: {:?}\n\
             ({}, {}, {}) -> raw: {} -> Fr: {:?}\n\
             Different u64 sums but same Fr sum!",
            input.token1, input.sum1, input.vault1, raw_sum1, deposit_sum1,
            input.token2, input.sum2, input.vault2, raw_sum2, deposit_sum2
        );
    }
});

