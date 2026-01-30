//! Генератор тестовых файлов для фаззинга
//!
//! Создаёт:
//! - kzg_params.bin - KZG параметры
//! - verification_key.bin - верификационный ключ
//! - proof.bin - валидный proof
//!
//! Использование:
//!   cd <project_root>
//!   cargo run --release --manifest-path Pruvendo/tests/property_tests/Cargo.toml --bin generate_test_fixtures

use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
use gosh_dark_dex_halo2_circuit::proof::Proof;
use gosh_dark_dex_halo2_circuit::snark_utils::{setup, read_kzg_params, setup_and_backup_kzg_params};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{keygen_vk, keygen_pk};
use halo2_proofs::SerdeFormat;
use rand::rngs::OsRng;

fn main() {
    let k = 8u32;
    
    // 1. Генерация KZG params (если не существует)
    let kzg_path = "kzg_params.bin".to_string();
    if !std::path::Path::new(&kzg_path).exists() {
        println!("Generating KZG params for k={}...", k);
        setup_and_backup_kzg_params(k, kzg_path.clone());
        println!("Created kzg_params.bin");
    } else {
        println!("kzg_params.bin already exists, skipping");
    }
    
    // 2. Загрузка params
    println!("Loading KZG params...");
    let params = read_kzg_params(kzg_path);
    
    // 3. Создание circuit с тестовыми значениями
    let token = 1u64;
    let sum = 1000u64;
    let sk = 12345u64;
    
    let sk_fr = Fr::from(sk);
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);
    let sk_commitment = poseidon_hash([sk_fr, Fr::zero()]);
    
    let circuit = DarkDexCircuit::new(
        Some(token_fr),
        Some(sum_fr),
        Some(sk_fr),
        Some(sk_commitment),
    );
    
    // 4. Генерация VK
    println!("Generating verification key...");
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk failed");
    
    let mut vk_bytes: Vec<u8> = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("VK serialization failed");
    std::fs::write("verification_key.bin", &vk_bytes).expect("Failed to write VK");
    println!("Created verification_key.bin ({} bytes)", vk_bytes.len());
    
    // 5. Генерация PK и Proof
    println!("Generating proving key and proof...");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk failed");
    
    // Public inputs
    let digest = poseidon_hash([sk_commitment, sum_fr, token_fr, sk_fr]);
    let pub_inputs = vec![sum_fr, token_fr, digest];
    let pub_inputs_slice: Vec<&[Fr]> = vec![pub_inputs.as_slice()];
    
    let proof = Proof::create(&params, &pk, circuit, &pub_inputs_slice, OsRng)
        .expect("Proof creation failed");
    
    std::fs::write("proof.bin", proof.as_bytes()).expect("Failed to write proof");
    println!("Created proof.bin ({} bytes)", proof.as_bytes().len());
    
    // 6. Верификация proof
    println!("Verifying proof...");
    let verify_result = proof.verify(&vk, &params, &pub_inputs_slice);
    match verify_result {
        Ok(()) => println!("✅ Proof verified successfully!"),
        Err(e) => println!("❌ Proof verification failed: {:?}", e),
    }
    
    println!("\nAll test fixtures generated successfully!");
    println!("Files created:");
    println!("  - kzg_params.bin");
    println!("  - verification_key.bin");
    println!("  - proof.bin");
}

