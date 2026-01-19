//! FUZZ-MULTIKEY: Multiple Keys Same Digest
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Ищет разные sk с одинаковым финальным Poseidon digest.
//! Коллизия в digest = критическая уязвимость (можно подменить ключ).

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

mod common;
use common::compute_digest;

#[derive(Arbitrary, Debug)]
struct MultiKeyInput {
    sk1_seed: u64,
    sk2_seed: u64,
    token1: u64,
    sum1: u64,
    token2: u64,
    sum2: u64,
}

fuzz_target!(|input: MultiKeyInput| {
    // Пропускаем если ключи одинаковые и все inputs одинаковые
    let same_key = input.sk1_seed == input.sk2_seed;
    let same_deposit = (input.token1, input.sum1) == (input.token2, input.sum2);

    if same_key && same_deposit {
        return;
    }

    // Пропускаем sk = 0
    if input.sk1_seed == 0 || input.sk2_seed == 0 {
        return;
    }

    // Key 1
    let sk1 = Fr::from(input.sk1_seed);
    let digest1 = compute_digest(sk1, Fr::from(input.token1), Fr::from(input.sum1));

    // Key 2
    let sk2 = Fr::from(input.sk2_seed);
    let digest2 = compute_digest(sk2, Fr::from(input.token2), Fr::from(input.sum2));

    // Проверяем на коллизию digest
    if digest1 == digest2 {
        // КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: разные inputs дают одинаковый digest!
        panic!(
            "POSEIDON DIGEST COLLISION FOUND!\n\
             Key1: sk_seed={}\n\
             Deposit1: token={}, sum={}\n\
             Key2: sk_seed={}\n\
             Deposit2: token={}, sum={}\n\
             SAME DIGEST: {:?}",
            input.sk1_seed,
            input.token1, input.sum1,
            input.sk2_seed,
            input.token2, input.sum2,
            digest1
        );
    }
});

