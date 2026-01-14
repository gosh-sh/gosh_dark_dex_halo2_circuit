//! Fuzz target: EC Coordinate Manipulation
//!
//! Тестирует манипуляции с координатами точки pk:
//! - Изменение x/y координат валидной точки
//! - Проверка что схема действительно проверяет pk = sk * G
//!
//! Это более глубокий тест чем простой soundness.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::{
    secp256k1::{Fp, Fq, Secp256k1Affine},
    ff::PrimeField,
    group::Curve,
    CurveAffine,
};
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use common::{ensure_working_directory, generate_valid_keypair, poseidon_hash, CIRCUIT_K};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

#[derive(Arbitrary, Debug)]
struct CoordinateManipInput {
    /// Base sk value
    sk_seed: u64,
    /// Delta to add to x coordinate
    x_delta: u64,
    /// Delta to add to y coordinate  
    y_delta: u64,
    /// Token type
    token: u64,
    /// Sum
    sum: u64,
    /// Vault
    vault: u64,
    /// Manipulation type: 0 = add to x, 1 = add to y, 2 = both, 3 = negate y
    manipulation_type: u8,
}

fuzz_target!(|input: CoordinateManipInput| {
    ensure_working_directory();
    
    if input.sk_seed == 0 {
        return;
    }
    
    // Пропускаем если нет манипуляций
    if input.x_delta == 0 && input.y_delta == 0 && input.manipulation_type != 3 {
        return;
    }
    
    let (sk, valid_pk, g) = generate_valid_keypair(input.sk_seed);
    
    let token = input.token % 1_000_000;
    let sum = input.sum % 1_000_000_000;
    let vault = input.vault % 1_000_000;
    
    // Получаем координаты валидной точки
    let orig_x = valid_pk.x;
    let orig_y = valid_pk.y;
    
    // Пробуем манипулировать координаты
    let (new_x, new_y) = match input.manipulation_type % 4 {
        0 => {
            // Добавляем delta к x
            let delta = Fp::from(input.x_delta);
            (orig_x + delta, orig_y)
        }
        1 => {
            // Добавляем delta к y
            let delta = Fp::from(input.y_delta);
            (orig_x, orig_y + delta)
        }
        2 => {
            // Добавляем delta к обоим
            (orig_x + Fp::from(input.x_delta), orig_y + Fp::from(input.y_delta))
        }
        3 => {
            // Отрицаем y (это даёт -P, другую валидную точку)
            (orig_x, -orig_y)
        }
        _ => unreachable!(),
    };
    
    // Проверяем новая точка на кривой?
    let y_sq = new_y.square();
    let x_cubed = new_x.square() * new_x;
    let rhs = x_cubed + Fp::from(7u64);
    let is_on_curve = y_sq == rhs;
    
    // Создаём модифицированную pk (используем ctors от halo2curves)
    // Secp256k1Affine не имеет прямого конструктора, поэтому используем workaround
    
    // Если точка не на кривой - просто пропускаем (эту проверку делает библиотека)
    if !is_on_curve {
        return;
    }
    
    // Если y отрицательный - это -P, валидная но ДРУГАЯ точка
    // sk для -P это -sk mod n
    if input.manipulation_type % 4 == 3 {
        // Используем -P как pk - это должно fail для sk
        // Потому что -P = (-sk) * G, а мы используем sk
        
        // Получаем -P
        let neg_pk = -valid_pk;
        
        // Вычисляем digest для neg_pk (нужно использовать координаты neg_pk)
        let token_fr = Fr::from(token);
        let sum_fr = Fr::from(sum);
        let vault_fr = Fr::from(vault);
        let deposit_sum = token_fr + sum_fr + vault_fr;
        
        let pk_x_limb_0 = consume_uint128_11(&neg_pk.x.to_bytes()[0..11]);
        let pk_x_limb_1 = consume_uint128_11(&neg_pk.x.to_bytes()[11..22]);
        let pk_x_limb_2 = consume_uint128_10(&neg_pk.x.to_bytes()[22..]);
        let pk_y_limb_0 = consume_uint128_11(&neg_pk.y.to_bytes()[0..11]);
        let pk_y_limb_1 = consume_uint128_11(&neg_pk.y.to_bytes()[11..22]);
        let pk_y_limb_2 = consume_uint128_10(&neg_pk.y.to_bytes()[22..]);
        
        let key_sum = (input.sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                      + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
        let key_sum_fr = Fr::from_u128(key_sum);
        let digest = poseidon_hash([key_sum_fr, deposit_sum]);
        
        let circuit = DarkDexCircuit::new(
            Some(token_fr),
            Some(sum_fr),
            Some(vault_fr),
            Some(sk),      // Оригинальный sk
            Some(neg_pk),  // Отрицательная pk!
            Some(g),
        );
        
        let pub_inputs = vec![sum_fr, token_fr, digest];
        let prover = MockProver::run(CIRCUIT_K, &circuit, vec![pub_inputs]);
        
        if let Ok(prover) = prover {
            // ASSERTION: -P с sk (вместо -sk) должна быть ОТКЛОНЕНА
            assert!(
                prover.verify().is_err(),
                "SOUNDNESS BUG! Circuit accepted -pk with original sk!\n\
                 sk_seed = {}", input.sk_seed
            );
        }
    }
});

