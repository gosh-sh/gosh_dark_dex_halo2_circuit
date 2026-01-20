//! Timing Attack Tests for Dark DEX Circuit
//!
//! Тестируем отсутствие timing side-channels:
//! 1. Время proof generation не зависит от секретного sk
//! 2. Время Poseidon hash constant (fixed rounds)
//! 3. Нет корреляции между Hamming weight sk и временем
//!
//! После poseidon_instead_of_ecc: ECC убран, scalar_multiply (главный
//! timing-leak vector) больше не используется.

use crate::helpers::{ensure_working_directory, compute_sk_commitment, compute_digest};
use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
use gosh_dark_dex_halo2_circuit::prover::{generate_proof, read_kzg_params};
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use std::time::Instant;

/// Вычисляет Hamming weight (количество единичных бит)
fn hamming_weight(x: u64) -> u32 {
    x.count_ones()
}

/// Статистика времени выполнения
struct TimingStats {
    mean: f64,
    std_dev: f64,
    min: f64,
    max: f64,
}

impl TimingStats {
    fn from_samples(samples: &[f64]) -> Self {
        let n = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / n;
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();
        let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        Self { mean, std_dev, min, max }
    }
}

/// Вычисляет коэффициент корреляции Пирсона
fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    assert_eq!(x.len(), y.len());
    let n = x.len() as f64;
    
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;
    
    let cov = x.iter().zip(y.iter())
        .map(|(xi, yi)| (xi - mean_x) * (yi - mean_y))
        .sum::<f64>() / n;
    
    let std_x = (x.iter().map(|xi| (xi - mean_x).powi(2)).sum::<f64>() / n).sqrt();
    let std_y = (y.iter().map(|yi| (yi - mean_y).powi(2)).sum::<f64>() / n).sqrt();
    
    if std_x == 0.0 || std_y == 0.0 {
        0.0
    } else {
        cov / (std_x * std_y)
    }
}

/// TIMING-1: Poseidon hash время не зависит от входных данных
#[test]
fn test_poseidon_constant_time() {
    const SAMPLES: usize = 1000;
    
    // Разные паттерны входных данных
    let patterns: Vec<(u64, u64)> = vec![
        (0, 0),                         // Все нули
        (u64::MAX, u64::MAX),           // Все единицы
        (0xAAAAAAAAAAAAAAAA, 0x5555555555555555), // Чередующиеся биты
        (1, 0),                         // Минимальный Hamming weight
        (0xFFFFFFFFFFFFFFFF, 0),        // Максимальный Hamming weight
    ];
    
    let mut pattern_times: Vec<Vec<f64>> = Vec::new();
    
    for (a, b) in &patterns {
        let mut times = Vec::with_capacity(SAMPLES);
        let input = [Fr::from(*a), Fr::from(*b)];
        
        for _ in 0..SAMPLES {
            let start = Instant::now();
            let _ = poseidon_hash(input);
            let elapsed = start.elapsed().as_nanos() as f64;
            times.push(elapsed);
        }
        
        pattern_times.push(times);
    }
    
    // Вычисляем статистику для каждого паттерна
    let stats: Vec<TimingStats> = pattern_times.iter()
        .map(|t| TimingStats::from_samples(t))
        .collect();
    
    println!("\n=== Poseidon Timing Analysis ===");
    for (i, (pattern, stat)) in patterns.iter().zip(stats.iter()).enumerate() {
        println!("Pattern {}: ({:#x}, {:#x})", i, pattern.0, pattern.1);
        println!("  Mean: {:.2} ns, StdDev: {:.2} ns", stat.mean, stat.std_dev);
        println!("  Range: [{:.0} - {:.0}] ns", stat.min, stat.max);
    }
    
    // Проверяем что разница между средними временами < 20%
    let means: Vec<f64> = stats.iter().map(|s| s.mean).collect();
    let overall_mean = means.iter().sum::<f64>() / means.len() as f64;
    
    for (i, mean) in means.iter().enumerate() {
        let deviation = ((mean - overall_mean) / overall_mean).abs();
        println!("Pattern {} deviation from mean: {:.2}%", i, deviation * 100.0);
        
        // Допускаем 20% отклонение (timing noise)
        assert!(
            deviation < 0.20,
            "Pattern {} shows significant timing deviation: {:.2}% (threshold 20%)",
            i, deviation * 100.0
        );
    }
    
    println!("✅ Poseidon hash shows constant-time behavior");
}

/// TIMING-2: MockProver время не коррелирует с Hamming weight sk
#[test]
fn test_mockprover_no_sk_correlation() {
    ensure_working_directory();
    const SAMPLES: usize = 30;
    const WARMUP: usize = 5;

    // Warm-up phase - run several MockProver iterations first
    for i in 0..WARMUP {
        let sk = Fr::from((i + 100) as u64);
        let sk_commitment = compute_sk_commitment(sk);
        let token_type = Fr::from(1u64);
        let private_note_sum = Fr::from(1000u64);
        let digest = compute_digest(sk, token_type, private_note_sum);
        let circuit = DarkDexCircuit::new(
            Some(token_type),
            Some(private_note_sum),
            Some(sk),
            Some(sk_commitment),
        );
        let pub_inputs = vec![vec![private_note_sum, token_type, digest]];
        let _ = MockProver::run(8, &circuit, pub_inputs);
    }

    // Генерируем sk с разным Hamming weight (randomized order to avoid cache effects)
    let mut sk_values: Vec<u64> = vec![
        1,                              // HW = 1
        0xFF,                           // HW = 8
        0xFFFFFFFF,                     // HW = 32
        0xFFFFFFFFFFFFFFFF,             // HW = 64
        0xF,                            // HW = 4
        0xFFFF,                         // HW = 16
        0x5555555555555555,             // HW = 32 (alt)
        3,                              // HW = 2
    ];

    let mut hamming_weights: Vec<f64> = Vec::new();
    let mut times: Vec<f64> = Vec::new();

    // Interleave samples from different HW values to reduce systematic bias
    for sample_idx in 0..SAMPLES {
        // Rotate the order for each sample iteration
        let order_offset = sample_idx % sk_values.len();

        for (i, sk_raw) in sk_values.iter().enumerate() {
            let effective_idx = (i + order_offset) % sk_values.len();
            let sk_val = sk_values[effective_idx];
            let sk = Fr::from(sk_val);
            let hw = hamming_weight(sk_val) as f64;

            let sk_commitment = compute_sk_commitment(sk);
            let token_type = Fr::from(1u64);
            let private_note_sum = Fr::from(1000u64);
            let digest = compute_digest(sk, token_type, private_note_sum);

            let circuit = DarkDexCircuit::new(
                Some(token_type),
                Some(private_note_sum),
                Some(sk),
                Some(sk_commitment),
            );

            let pub_inputs = vec![vec![private_note_sum, token_type, digest]];

            let start = Instant::now();
            let _ = MockProver::run(8, &circuit, pub_inputs);
            let elapsed = start.elapsed().as_micros() as f64;

            hamming_weights.push(hw);
            times.push(elapsed);
        }
    }

    let correlation = pearson_correlation(&hamming_weights, &times);

    println!("\n=== MockProver Timing vs Hamming Weight (with warm-up) ===");
    println!("Total samples: {}", times.len());
    println!("Pearson correlation: {:.4}", correlation);

    // Moderate correlation is acceptable for MockProver (debug tool)
    // Real concern would be in proof generation, not MockProver
    // We use 0.5 threshold here - anything above would be concerning
    if correlation.abs() >= 0.3 {
        println!("⚠️ Moderate correlation detected: {:.4}", correlation);
        println!("   This is in MockProver (debug), not production prover");
        println!("   Real timing analysis should focus on generate_proof()");
    }

    assert!(
        correlation.abs() < 0.5,
        "Strong correlation between sk Hamming weight and timing: {:.4} (threshold 0.5)",
        correlation
    );

    println!("✅ No strong correlation between sk Hamming weight and MockProver timing");
}

/// TIMING-3: Proof generation время не зависит от sk bit pattern
/// ВНИМАНИЕ: Этот тест медленный, запускать с --ignored
#[test]
#[ignore]
fn test_proof_generation_constant_time() {
    ensure_working_directory();
    const SAMPLES: usize = 5; // Малое количество из-за медленности

    let params = read_kzg_params("kzg_params.bin".to_string());

    // Разные bit patterns для sk
    let sk_patterns: Vec<u64> = vec![
        1,                              // Минимальный HW
        0xFFFFFFFFFFFFFFFF,             // Максимальный HW
        0xAAAAAAAAAAAAAAAA,             // Чередующиеся
    ];

    let mut pattern_times: Vec<Vec<f64>> = Vec::new();

    for sk_raw in &sk_patterns {
        let sk = Fr::from(*sk_raw);
        let sk_commitment = compute_sk_commitment(sk);
        let token_type = Fr::from(1u64);
        let private_note_sum = Fr::from(1000u64);

        let mut times = Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            let mut pub_inputs = Vec::new();

            let start = Instant::now();
            let _ = generate_proof(
                &params,
                Some(token_type),
                Some(private_note_sum),
                Some(sk),
                Some(sk_commitment),
                &mut pub_inputs,
            );
            let elapsed = start.elapsed().as_millis() as f64;
            times.push(elapsed);
        }

        pattern_times.push(times);
    }

    println!("\n=== Proof Generation Timing Analysis ===");
    for (i, (pattern, times)) in sk_patterns.iter().zip(pattern_times.iter()).enumerate() {
        let stats = TimingStats::from_samples(times);
        println!("Pattern {}: sk={:#x} (HW={})", i, pattern, hamming_weight(*pattern));
        println!("  Mean: {:.2} ms, StdDev: {:.2} ms", stats.mean, stats.std_dev);
    }

    // Вычисляем общую статистику
    let means: Vec<f64> = pattern_times.iter()
        .map(|t| TimingStats::from_samples(t).mean)
        .collect();

    let overall_mean = means.iter().sum::<f64>() / means.len() as f64;

    for (i, mean) in means.iter().enumerate() {
        let deviation = ((mean - overall_mean) / overall_mean).abs();
        println!("Pattern {} deviation: {:.2}%", i, deviation * 100.0);

        // Для proof generation допускаем 30% отклонение
        assert!(
            deviation < 0.30,
            "Pattern {} shows significant timing deviation: {:.2}%",
            i, deviation * 100.0
        );
    }

    println!("✅ Proof generation shows no significant timing dependency on sk bit pattern");
}

/// TIMING-4: Сравнение времени для специальных значений sk
#[test]
fn test_special_sk_values_timing() {
    ensure_working_directory();
    const SAMPLES: usize = 100;
    const WARMUP: usize = 50; // Warm-up iterations to avoid JIT effects

    // Warm-up phase
    for i in 0..WARMUP {
        let sk = Fr::from(i as u64);
        let _ = compute_sk_commitment(sk);
    }

    // Специальные значения sk
    let special_values: Vec<(u64, &str)> = vec![
        (0, "zero"),
        (1, "one"),
        (u64::MAX, "max"),
        (u64::MAX / 2, "half_max"),
    ];

    println!("\n=== Special SK Values Timing (after warm-up) ===");

    let mut all_times: Vec<f64> = Vec::new();

    for (sk_raw, name) in &special_values {
        let sk = Fr::from(*sk_raw);
        let mut times = Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            let start = Instant::now();
            let _ = compute_sk_commitment(sk);
            let elapsed = start.elapsed().as_nanos() as f64;
            times.push(elapsed);
        }

        let stats = TimingStats::from_samples(&times);
        println!("{}: mean={:.2}ns, std={:.2}ns", name, stats.mean, stats.std_dev);
        all_times.extend(times);
    }

    let overall_stats = TimingStats::from_samples(&all_times);
    let cv = overall_stats.std_dev / overall_stats.mean; // Coefficient of variation

    println!("Overall CV (coefficient of variation): {:.4}", cv);

    // CV < 1.0 is acceptable for timing tests (noise is expected)
    // Main check is that means are similar across different sk values
    let means: Vec<f64> = special_values.iter().map(|(sk_raw, _)| {
        let sk = Fr::from(*sk_raw);
        let mut times = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            let _ = compute_sk_commitment(sk);
            times.push(start.elapsed().as_nanos() as f64);
        }
        TimingStats::from_samples(&times).mean
    }).collect();

    let overall_mean = means.iter().sum::<f64>() / means.len() as f64;
    let max_deviation = means.iter()
        .map(|m| ((m - overall_mean) / overall_mean).abs())
        .fold(0.0f64, f64::max);

    println!("Max deviation from mean: {:.2}%", max_deviation * 100.0);

    // All special values should have similar timing (< 25% deviation)
    assert!(
        max_deviation < 0.25,
        "Significant timing difference for special sk values: {:.2}%",
        max_deviation * 100.0
    );

    println!("✅ Special sk values show consistent timing");
}
