//! Генератор KZG параметров для тестов
//!
//! Использование:
//!   cd <project_root>
//!   cargo run --release --manifest-path Pruvendo/tests/property_tests/Cargo.toml --bin generate_kzg_params
//!
//! Создаёт файл kzg_params.bin в текущей директории.

use gosh_dark_dex_halo2_circuit::snark_utils::setup_and_backup_kzg_params;

fn main() {
    // k=8 - минимальный размер для DarkDex circuit с Poseidon
    let k = 8u32;
    let path = "kzg_params.bin".to_string();
    
    println!("Generating KZG params for k={}...", k);
    setup_and_backup_kzg_params(k, path.clone());
    
    let size = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(0);
    
    println!("Done! Created {} ({} bytes)", path, size);
}

